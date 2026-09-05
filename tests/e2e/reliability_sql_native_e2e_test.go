package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Unlike fake_mysql.py, these fixtures invoke native database clients against
// opt-in, disposable loopback services. Enabling the lane makes missing clients
// or services a failure, never a successful skip.
func TestSQLRealEngineReliability(t *testing.T) {
	if testing.Short() || os.Getenv("SSHX_E2E_REAL_SQL") != "1" {
		t.Skip("requires SSHX_E2E_REAL_SQL=1 and disposable local PostgreSQL/MySQL sshx_e2e databases")
	}
	if runtime.GOOS == "windows" {
		t.Skip("native database fixture requires a POSIX remote shell; Windows CLI is tested separately")
	}
	for _, engine := range []string{"postgres", "mysql"} {
		t.Run(engine, func(t *testing.T) {
			native := newNativeSQLFixture(t, engine)
			suffix := randomHex(t, 5)
			table := "sshx_reliability_" + suffix
			reader := "sshx_reader_" + suffix
			const readerSecret = "sshx-isolated-reader" // #nosec G101 -- disposable integration database role.
			native.exec(t, fmt.Sprintf("CREATE TABLE %s (id INTEGER PRIMARY KEY, name VARCHAR(40) NOT NULL); INSERT INTO %s VALUES (1, 'old'), (2, 'keep');", table, table))
			t.Cleanup(func() { native.exec(t, "DROP TABLE IF EXISTS "+table+";") })
			if engine == "postgres" {
				native.exec(t, "CREATE ROLE "+reader+" LOGIN PASSWORD '"+readerSecret+"'; GRANT SELECT ON "+table+" TO "+reader+";")
				t.Cleanup(func() { native.exec(t, "REVOKE ALL ON "+table+" FROM "+reader+"; DROP ROLE "+reader+";") })
			} else {
				native.exec(t, "CREATE USER '"+reader+"'@'%' IDENTIFIED BY '"+readerSecret+"'; GRANT SELECT ON sshx_e2e."+table+" TO '"+reader+"'@'%';")
				t.Cleanup(func() { native.exec(t, "DROP USER '"+reader+"'@'%';") })
			}

			privateOptions := privateShellServerOptions(t, native.serve)
			server := startSSHServer(t, privateOptions)
			home := t.TempDir()
			base := []string{
				"sql", "-h=" + server.host, "-p=" + server.port, "-u=operator",
				"--no-key", "--accept-unknown-host", "--json", "--engine=" + engine,
				"--db=sshx_e2e", "--db-host=127.0.0.1", "--db-port=" + native.port,
				"--db-user=" + native.user, "--backup-dir=" + filepath.Join(server.root, "backups"),
			}
			run := func(statement string) cliResult {
				return runSSHX(t, home, append(append([]string{}, base...), statement), map[string]string{"SSH_PASSWORD": privateOptions.operatorPassword})
			}
			read := run("SELECT name FROM " + table + " WHERE id=1")
			require.Equal(t, 0, read.exitCode, read.stdout+read.stderr)
			require.Contains(t, read.stdout, "old")

			update := run("UPDATE " + table + " SET name='new' WHERE id=1")
			require.Equal(t, 0, update.exitCode, update.stdout+update.stderr)
			var payload map[string]any
			require.NoError(t, json.Unmarshal([]byte(update.stdout), &payload))
			assert.Equal(t, true, payload["success"])
			assert.Equal(t, float64(1), payload["affected_rows"])
			evidence := assertNativeSQLMutationEvidence(t, payload, engine)
			assert.Equal(t, "ready", evidence["backup_status"])
			assert.Equal(t, "locked_preimage", evidence["backup_consistency"])
			assert.NotContains(t, update.stdout+update.stderr, native.password)
			backup, ok := payload["backup"].(map[string]any)
			require.True(t, ok, "guarded update must retain real backup evidence")
			backupPath, ok := backup["path"].(string)
			require.True(t, ok)
			relative, err := filepath.Rel(server.root, backupPath)
			require.NoError(t, err)
			require.True(t, filepath.IsLocal(relative), "backup must remain in its isolated fixture directory")
			require.FileExists(t, backupPath)
			backupBytes, err := os.ReadFile(backupPath) // #nosec G304 -- backup path verified below the isolated fixture root.
			require.NoError(t, err)
			require.NotEmpty(t, backupBytes)
			if engine == "mysql" {
				assert.Equal(t, "mysql_hex_rows_v1", evidence["backup_format"])
				assert.Contains(t, string(backupBytes), "SSHX_MYSQL_HEX_ROWS_V1")
				assert.Contains(t, string(backupBytes), "H6F6C64", "hex snapshot must retain the old value")
			}
			assert.Contains(t, native.exec(t, "SELECT name FROM "+table+" WHERE id=1;"), "new")
			assert.Contains(t, native.exec(t, "SELECT name FROM "+table+" WHERE id=2;"), "keep")

			noOp := run("UPDATE " + table + " SET name='new' WHERE id=1")
			require.Equal(t, 0, noOp.exitCode, noOp.stdout+noOp.stderr)
			var noOpPayload map[string]any
			require.NoError(t, json.Unmarshal([]byte(noOp.stdout), &noOpPayload))
			noOpCount := float64(1) // PostgreSQL reports processed rows, including unchanged values.
			if engine == "mysql" {
				noOpCount = 0 // Default MySQL affected rows exclude unchanged values.
			}
			assert.Equal(t, noOpCount, noOpPayload["affected_rows"])
			assertNativeSQLMutationEvidence(t, noOpPayload, engine)
			zero := run("UPDATE " + table + " SET name='absent' WHERE id=999")
			require.Equal(t, 0, zero.exitCode, zero.stdout+zero.stderr)
			var zeroPayload map[string]any
			require.NoError(t, json.Unmarshal([]byte(zero.stdout), &zeroPayload))
			assert.Equal(t, float64(0), zeroPayload["affected_rows"])
			assertNativeSQLMutationEvidence(t, zeroPayload, engine)
			assert.NotContains(t, native.exec(t, "SELECT name FROM "+table+";"), "absent")

			readerNative := *native
			readerNative.password = readerSecret
			privateReaderOptions := privateShellServerOptions(t, readerNative.serve)
			readerServer := startSSHServer(t, privateReaderOptions)
			readerBase := []string{
				"sql", "-h=" + readerServer.host, "-p=" + readerServer.port, "-u=reader",
				"--no-key", "--accept-unknown-host", "--json", "--engine=" + engine,
				"--db=sshx_e2e", "--db-host=127.0.0.1", "--db-port=" + native.port, "--db-user=" + reader,
				"--backup-dir=" + filepath.Join(readerServer.root, "backups"),
			}
			readerHome := t.TempDir()
			readerEnv := map[string]string{"SSH_PASSWORD": privateReaderOptions.readerPassword}
			readerRead := runSSHX(t, readerHome, append(append([]string{}, readerBase...), "SELECT name FROM "+table+" WHERE id=1"), readerEnv)
			require.Equal(t, 0, readerRead.exitCode, readerRead.stdout+readerRead.stderr)
			denied := runSSHX(t, readerHome, append(append([]string{}, readerBase...), "UPDATE "+table+" SET name='forbidden' WHERE id=1"), readerEnv)
			require.NotEqual(t, 0, denied.exitCode, denied.stdout+denied.stderr)
			require.NoError(t, json.Unmarshal([]byte(denied.stdout), &payload))
			assert.Equal(t, false, payload["success"])
			assert.NotContains(t, native.exec(t, "SELECT name FROM "+table+";"), "forbidden")
			recovered := run("SELECT name FROM " + table + " WHERE id=1")
			require.Equal(t, 0, recovered.exitCode, recovered.stdout+recovered.stderr)
		})
	}
}

type nativeSQLFixture struct {
	engine, client, user, password, port string
}

func privateShellServerOptions(t *testing.T, handler func(ssh.Channel, string, string)) serverOptions {
	t.Helper()
	return serverOptions{
		execHandler:      handler,
		operatorPassword: randomHex(t, 32),
		readerPassword:   randomHex(t, 32),
	}
}

func assertNativeSQLMutationEvidence(t *testing.T, payload map[string]any, engine string) map[string]any {
	t.Helper()
	evidence, ok := payload["evidence"].(map[string]any)
	require.True(t, ok, "SQL results must expose engine execution evidence")
	assert.Equal(t, "acknowledged", evidence["commit"])
	assert.Equal(t, "protocol_verified", evidence["verification"])
	assert.Equal(t, "unknown", evidence["state_change"], "row counts do not verify a postimage")
	assert.Equal(t, "unsupported", evidence["effect_verification"])
	assert.Equal(t, false, evidence["outcome_uncertain"])
	semantics := "postgres_command_tag"
	if engine == "mysql" {
		semantics = "mysql_row_count"
	}
	assert.Equal(t, semantics, evidence["affected_rows_semantics"])
	return evidence
}

func newNativeSQLFixture(t *testing.T, engine string) *nativeSQLFixture {
	t.Helper()
	fixture := &nativeSQLFixture{engine: engine, client: "psql", user: "sshx", port: "5432", password: os.Getenv("SSHX_E2E_PG_PASSWORD")}
	if engine == "mysql" {
		fixture.client, fixture.user, fixture.port, fixture.password = "mysql", "root", "3306", os.Getenv("SSHX_E2E_MYSQL_PASSWORD")
	}
	require.NotEmpty(t, fixture.password, "explicit disposable database password required")
	_, err := exec.LookPath(fixture.client)
	require.NoError(t, err, "native %s client is a required integration prerequisite", fixture.client)
	fixture.exec(t, "SELECT 1;")
	return fixture
}

func (f *nativeSQLFixture) environment() []string {
	name := "PGPASSWORD"
	if f.engine == "mysql" {
		name = "MYSQL_PWD"
	}
	env := make([]string, 0, len(os.Environ())+1)
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if !strings.EqualFold(key, name) {
			env = append(env, item)
		}
	}
	return append(env, name+"="+f.password)
}

func (f *nativeSQLFixture) exec(t *testing.T, statement string) string {
	t.Helper()
	args := []string{"-X", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1", "-p", f.port, "-U", f.user, "-d", "sshx_e2e", "-A", "-t", "-c", statement}
	if f.engine == "mysql" {
		args = []string{"--no-defaults", "--batch", "--skip-column-names", "-h", "127.0.0.1", "-P", f.port, "-u", f.user, "-D", "sshx_e2e", "-e", statement}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, f.client, args...) // #nosec G204 -- fixed native clients against explicitly enabled disposable loopback databases.
	command.Env = f.environment()
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s fixture: %s", f.engine, output)
	return string(output)
}

func (f *nativeSQLFixture) serve(channel ssh.Channel, cmdline, _ string) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "sh", "-c", cmdline) // #nosec G204 -- loopback fixture protected by per-server, random SSH credentials for both accounts.
	command.Env = f.environment()
	command.Stdin = channel
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	_, _ = io.Copy(channel, &stdout)          //nolint:errcheck // client disconnect is a fixture teardown.
	_, _ = io.Copy(channel.Stderr(), &stderr) //nolint:errcheck // client disconnect is a fixture teardown.
	if err == nil {
		sendExitStatus(channel, 0)
		return
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		sendExitStatus(channel, uint32(exitErr.ExitCode())) // #nosec G115 -- native process exit code.
		return
	}
	sendExitStatus(channel, 126)
}
