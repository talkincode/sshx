package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLBlocksMySQLClients(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	base := []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
	}
	connectionsBefore := server.connections.Load()
	for _, cmd := range []string{
		`mysql -u app -e "DELETE FROM users"`,
		`mariadb -e "SELECT 1"`,
	} {
		blocked := runSSHX(t, home, append(append([]string{}, base...), cmd), map[string]string{
			"SSH_PASSWORD": operatorPassword,
		})
		assertSSHXFailure(t, blocked, "blocked")
	}
	assert.Equal(t, connectionsBefore, server.connections.Load(), "blocked mysql clients must not touch the network")
}

func TestSQLMySQLBlockedClassesDoNotConnect(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	connectionsBefore := server.connections.Load()
	for _, stmt := range []string{
		"LOAD DATA INFILE '/tmp/x' INTO TABLE users",
		"SELECT * FROM users INTO OUTFILE '/tmp/x'",
	} {
		blocked := runSSHX(t, home, []string{
			"sql",
			"-h=" + server.host,
			"-p=" + server.port,
			"-u=operator",
			"--engine=mysql",
			"--db=app",
			"--json",
			stmt,
		}, nil)
		assertSSHXFailure(t, blocked, "blocked")
	}
	assert.Equal(t, connectionsBefore, server.connections.Load())
}

// This is a fake-client protocol test, not a MySQL storage-engine test.
func TestSQLMySQLFakeProtocolReadAndGuardedUpdate(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	installFakeMySQL(t, server)
	home := t.TempDir()
	base := []string{
		"sql",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--engine=mysql",
		"--db=app",
		"--json",
	}
	env := map[string]string{"SSH_PASSWORD": operatorPassword}

	read := runSSHX(t, home, append(append([]string{}, base...), "SELECT name FROM users WHERE id=1"), env)
	require.Equal(t, 0, read.exitCode, read.stderr+"\n"+read.stdout)
	var readPayload sqlResult
	require.NoError(t, json.Unmarshal([]byte(read.stdout), &readPayload))
	assert.True(t, readPayload.Success)
	assert.Equal(t, "mysql", readPayload.Engine)
	assert.Equal(t, "read", readPayload.Class)
	assert.Contains(t, readPayload.Stdout, "old")

	update := runSSHX(t, home, append(append([]string{}, base...), "UPDATE users SET name='new' WHERE id=1"), env)
	require.Equal(t, 0, update.exitCode, update.stderr+"\n"+update.stdout)
	var updatePayload sqlResult
	require.NoError(t, json.Unmarshal([]byte(update.stdout), &updatePayload))
	assert.True(t, updatePayload.Success)
	assert.Equal(t, "dml", updatePayload.Class)
	require.NotNil(t, updatePayload.AffectedRows)
	assert.Equal(t, int64(1), *updatePayload.AffectedRows)
	assert.Equal(t, "mysql_row_count", updatePayload.Evidence.AffectedRowsSemantics)
	assert.Equal(t, "acknowledged", updatePayload.Evidence.Commit)
	assert.Equal(t, "ready", updatePayload.Evidence.BackupStatus)
	require.NotNil(t, updatePayload.Backup)
	assert.Equal(t, "rows", updatePayload.Backup.Kind)
	assert.NotEmpty(t, updatePayload.Backup.Path)

	backupPath := updatePayload.Backup.Path
	if !filepath.IsAbs(backupPath) {
		backupPath = filepath.Join(server.root, backupPath)
	}
	data, err := os.ReadFile(backupPath) // #nosec G304 -- isolated E2E backup under the fixture root
	require.NoError(t, err, backupPath)
	assert.Contains(t, string(data), "SSHX_MYSQL_HEX_ROWS_V1")
	assert.Contains(t, string(data), "H6f6c64", "preimage contains hex-encoded old value")
}

func TestSQLMySQLFakeProtocolFailuresPreserveEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, option, errorKind, backup, value string
	}{
		{"lost acknowledgement", "omit_commit_ack", "verification_failed", "ready", "new"},
		{"malformed affected rows", "bad_count", "protocol_error", "ready", "new"},
		{"mutation rollback", "fail_mutation", "remote_exit", "ready", "old"},
		{"unsupported engine", "unsupported_engine", "remote_exit", "planned", "old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := startSSHServer(t, serverOptions{})
			installFakeMySQL(t, server)
			options, err := json.Marshal(map[string]bool{tc.option: true})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(server.root, "mysql-fixture-options.json"), options, 0o600))
			args := []string{"sql", "-h=" + server.host, "-p=" + server.port, "-u=operator",
				"--no-key", "--accept-unknown-host", "--engine=mysql", "--db=app", "--json",
				"UPDATE users SET name='new' WHERE id=1"}
			result := runSSHX(t, t.TempDir(), args, map[string]string{"SSH_PASSWORD": operatorPassword})
			assert.NotEqual(t, 0, result.exitCode, result.stdout)
			var payload sqlResult
			require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload), result.stdout)
			assert.False(t, payload.Success)
			assert.Equal(t, tc.errorKind, payload.ErrorKind)
			assert.Equal(t, tc.backup, payload.Evidence.BackupStatus)
			assert.Equal(t, "unknown", payload.Evidence.Commit)
			assert.Equal(t, "unknown", payload.Evidence.StateChange)
			assert.True(t, payload.Evidence.OutcomeUncertain)
			args[len(args)-1] = "SELECT name FROM users WHERE id=1"
			require.NoError(t, os.WriteFile(filepath.Join(server.root, "mysql-fixture-options.json"), []byte("{}"), 0o600))
			read := runSSHX(t, t.TempDir(), args, map[string]string{"SSH_PASSWORD": operatorPassword})
			require.Equal(t, 0, read.exitCode, read.stdout+read.stderr)
			var after sqlResult
			require.NoError(t, json.Unmarshal([]byte(read.stdout), &after))
			assert.Contains(t, after.Stdout, tc.value)
		})
	}
}

func TestSQLMySQLFakeProtocolHumanLostAcknowledgementAudit(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	installFakeMySQL(t, server)
	require.NoError(t, os.WriteFile(filepath.Join(server.root, "mysql-fixture-options.json"), []byte(`{"omit_commit_ack":true}`), 0o600))
	home := t.TempDir()
	auditDir := filepath.Join(home, "audit")
	args := []string{
		"sql", "-h=" + server.host, "-p=" + server.port, "-u=operator",
		"--no-key", "--accept-unknown-host", "--engine=mysql", "--db=app",
		"--audit-output=" + auditDir, "UPDATE users SET name='new' WHERE id=1",
	}
	result := runSSHX(t, home, args, map[string]string{"SSH_PASSWORD": operatorPassword, "SSHX_NO_AUDIT": "false"})
	require.NotEqual(t, 0, result.exitCode)
	assert.Empty(t, result.stdout, "human failure finalization must not emit a JSON document")
	files, globErr := filepath.Glob(filepath.Join(auditDir, "*.jsonl"))
	require.NoError(t, globErr)
	require.Len(t, files, 1)
	data, readErr := os.ReadFile(files[0]) // #nosec G304 -- isolated audit artifact beneath fixture home
	require.NoError(t, readErr)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1)
	var event map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &event))
	assert.Equal(t, "unknown", event["change_state"])
	assert.Equal(t, "unknown", event["completion"])
	assert.Equal(t, true, event["executed"], "the affected-row frame acknowledges statement execution, not commit")
	assert.Equal(t, false, event["verified"])
	assert.Equal(t, "failed", event["verification"])
	assert.NotEmpty(t, event["execution_fingerprint"])
	evidence, ok := event["sql_evidence"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, evidence["outcome_uncertain"])
}

func TestSQLMySQLFakeProtocolUnavailableEstimate(t *testing.T) {
	for _, tc := range []struct {
		name, statement, backupKind string
		flags                       []string
	}{
		{"insert", "INSERT INTO users (id, name) VALUES (2, 'inserted')", "none", nil},
		{"insert bypass", "INSERT INTO users (id, name) VALUES (2, 'inserted')", "none", []string{"--force", "--no-backup"}},
		{"update backup", "UPDATE users SET name='new' WHERE id=1", "table", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := startSSHServer(t, serverOptions{})
			installFakeMySQL(t, server)
			require.NoError(t, os.WriteFile(filepath.Join(server.root, "mysql-fixture-options.json"), []byte(`{"omit_row_estimate":true}`), 0o600))
			args := []string{"sql", "-h=" + server.host, "-p=" + server.port, "-u=operator",
				"--no-key", "--accept-unknown-host", "--engine=mysql", "--db=app", "--json"}
			args = append(args, tc.flags...)
			args = append(args, tc.statement)
			result := runSSHX(t, t.TempDir(), args, map[string]string{"SSH_PASSWORD": operatorPassword})
			require.Equal(t, 0, result.exitCode, result.stdout+result.stderr)
			var payload sqlResult
			require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload))
			assert.True(t, payload.Success)
			assert.Nil(t, payload.EstimatedRows, "unavailable is not a zero-row estimate")
			require.NotNil(t, payload.AffectedRows)
			assert.Equal(t, int64(1), *payload.AffectedRows)
			require.NotNil(t, payload.Backup)
			assert.Equal(t, tc.backupKind, payload.Backup.Kind)
			assert.Equal(t, "acknowledged", payload.Evidence.Commit)
		})
	}
}

func TestSQLRealMySQLInsertUnavailableEstimate(t *testing.T) {
	if testing.Short() || os.Getenv("SSHX_E2E_REAL_SQL") != "1" {
		t.Skip("requires SSHX_E2E_REAL_SQL=1 and the disposable real MySQL fixture")
	}
	if runtime.GOOS == "windows" {
		t.Skip("real SQL SSH fixture requires a POSIX shell")
	}
	native := newNativeSQLFixture(t, "mysql")
	table := "sshx_insert_" + randomHex(t, 5)
	native.exec(t, "CREATE TABLE "+table+" (id INTEGER PRIMARY KEY, name VARCHAR(40) NOT NULL) ENGINE=InnoDB;")
	t.Cleanup(func() { native.exec(t, "DROP TABLE IF EXISTS "+table+";") })
	server := startSSHServer(t, serverOptions{execHandler: native.serve})
	base := []string{
		"sql", "-h=" + server.host, "-p=" + server.port, "-u=operator",
		"--no-key", "--accept-unknown-host", "--json", "--engine=mysql",
		"--db=sshx_e2e", "--db-host=127.0.0.1", "--db-port=" + native.port, "--db-user=" + native.user,
	}
	home := t.TempDir()
	for i, bypass := range []bool{false, true} {
		args := append([]string{}, base...)
		if bypass {
			args = append(args, "--force", "--no-backup")
		}
		statement := fmt.Sprintf("INSERT INTO %s (id, name) VALUES (%d, 'inserted')", table, i+1)
		args = append(args, statement)
		result := runSSHX(t, home, args, map[string]string{"SSH_PASSWORD": operatorPassword})
		require.Equal(t, 0, result.exitCode, result.stdout+result.stderr)
		var payload sqlResult
		require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload))
		assert.True(t, payload.Success)
		require.NotNil(t, payload.AffectedRows)
		assert.Equal(t, int64(1), *payload.AffectedRows)
		assert.Equal(t, "acknowledged", payload.Evidence.Commit)
		require.NotNil(t, payload.Backup)
		assert.Equal(t, "none", payload.Backup.Kind)
	}
	assert.Contains(t, native.exec(t, "SELECT count(*) FROM "+table+";"), "2")
}
