package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sqlsafe"
)

type sqlResult struct {
	Engine         string                `json:"engine"`
	Database       string                `json:"database"`
	Success        bool                  `json:"success"`
	ExitCode       int                   `json:"exit_code"`
	ErrorKind      string                `json:"error_kind"`
	Class          string                `json:"class"`
	Verb           string                `json:"verb"`
	Table          string                `json:"table"`
	Stdout         string                `json:"stdout"`
	AffectedRows   *int64                `json:"affected_rows"`
	EstimatedRows  *int64                `json:"estimated_rows"`
	Evidence       sqlsafe.Evidence      `json:"evidence"`
	Preconditions  []execution.Condition `json:"preconditions"`
	Postconditions []execution.Condition `json:"postconditions"`
	Backup         *struct {
		Kind        string `json:"kind"`
		Path        string `json:"path"`
		RestoreHint string `json:"restore_hint"`
	} `json:"backup"`
}

func TestSQLBlocksDirectDatabaseClients(t *testing.T) {
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
		"sqlite3 /tmp/app.db \"DELETE FROM users\"",
		"psql -d app -c 'DELETE FROM users'",
	} {
		blocked := runSSHX(t, home, append(append([]string{}, base...), cmd), map[string]string{
			"SSH_PASSWORD": operatorPassword,
		})
		assertSSHXFailure(t, blocked, "blocked")
	}
	assert.Equal(t, connectionsBefore, server.connections.Load(), "blocked database clients must not touch the network")
}

func TestSQLSQLiteDryRunDoesNotConnect(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	connectionsBefore := server.connections.Load()

	result := runSSHX(t, home, []string{
		"sql",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--engine=sqlite",
		"--db-file=/var/lib/app/app.db",
		"--dry-run",
		"--json",
		"UPDATE users SET active=0 WHERE id=1",
	}, nil)
	require.Equal(t, 0, result.exitCode, result.stderr)
	assert.Equal(t, connectionsBefore, server.connections.Load())
	assert.Contains(t, result.stdout, `"engine": "sqlite"`)
	assert.Contains(t, result.stdout, `"backup_kind": "table"`)
	assert.Contains(t, result.stdout, "sqlite3")
}

func TestSQLSQLiteReadAndGuardedUpdate(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 not installed")
	}
	server := startSSHServer(t, serverOptions{})
	dbPath := filepath.Join(server.root, "app.db")
	setup := exec.Command("sqlite3", dbPath, "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO users VALUES (1, 'old');") // #nosec G204 -- isolated fixture
	require.NoError(t, setup.Run())

	home := t.TempDir()
	base := []string{
		"sql",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--engine=sqlite",
		"--db-file=" + dbPath,
		"--json",
	}
	env := map[string]string{"SSH_PASSWORD": operatorPassword}

	read := runSSHX(t, home, append(append([]string{}, base...), "SELECT name FROM users WHERE id=1"), env)
	require.Equal(t, 0, read.exitCode, read.stderr+"\n"+read.stdout)
	var readPayload sqlResult
	require.NoError(t, json.Unmarshal([]byte(read.stdout), &readPayload))
	assert.True(t, readPayload.Success)
	assert.Equal(t, "unchanged", readPayload.Evidence.StateChange)
	assert.Equal(t, "protocol_verified", readPayload.Evidence.Verification)
	assert.Equal(t, "sqlite", readPayload.Engine)
	assert.Equal(t, "read", readPayload.Class)
	assert.Contains(t, readPayload.Stdout, "old")

	blocked := runSSHX(t, home, append(append([]string{}, base...), "ATTACH DATABASE '/tmp/x.db' AS extra"), env)
	assertSSHXFailure(t, blocked, "blocked")

	update := runSSHX(t, home, append(append([]string{}, base...), "UPDATE users SET name='new' WHERE id=1"), env)
	require.Equal(t, 0, update.exitCode, update.stderr+"\n"+update.stdout)
	var updatePayload sqlResult
	require.NoError(t, json.Unmarshal([]byte(update.stdout), &updatePayload))
	assert.True(t, updatePayload.Success)
	assert.Equal(t, "dml", updatePayload.Class)
	require.NotNil(t, updatePayload.AffectedRows)
	assert.Equal(t, int64(1), *updatePayload.AffectedRows)
	assert.Equal(t, "sqlite_changes", updatePayload.Evidence.AffectedRowsSemantics)
	assert.Equal(t, "unknown", updatePayload.Evidence.StateChange)
	assert.Equal(t, "acknowledged", updatePayload.Evidence.Commit)
	assert.Equal(t, "ready", updatePayload.Evidence.BackupStatus)
	assert.Contains(t, updatePayload.Postconditions, execution.Condition{
		Kind: "sql_commit", Subject: "sqlite:" + dbPath, Expected: "acknowledged", Observed: "acknowledged", Status: "passed",
	})
	assert.Contains(t, updatePayload.Postconditions, execution.Condition{
		Kind: "sql_affected_rows_semantics", Subject: "sqlite:" + dbPath + ":users", Expected: "sqlite_changes", Observed: "sqlite_changes", Status: "passed",
	})
	require.NotNil(t, updatePayload.Backup)
	assert.Equal(t, "table", updatePayload.Backup.Kind)
	assert.NotEmpty(t, updatePayload.Backup.Path)
	assert.Contains(t, updatePayload.Preconditions, execution.Condition{
		Kind: "sql_backup", Subject: updatePayload.Backup.Path, Expected: "ready", Observed: "ready", Status: "passed",
	})

	backupPath := updatePayload.Backup.Path
	if !filepath.IsAbs(backupPath) {
		backupPath = filepath.Join(server.root, backupPath)
	}
	data, err := os.ReadFile(backupPath) // #nosec G304 -- isolated E2E backup under the fixture root
	require.NoError(t, err, backupPath)
	assert.Contains(t, string(data), "old")

	got, err := exec.Command("sqlite3", dbPath, "SELECT name FROM users WHERE id=1;").Output() // #nosec G204 -- isolated fixture
	require.NoError(t, err)
	assert.Equal(t, "new\n", string(got))
}

func TestSQLSQLiteAuditCapturesAuthenticatedPeer(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("requires the real sqlite3 client")
	}
	for _, mode := range []string{"json", "human"} {
		t.Run(mode, func(t *testing.T) {
			server := startSSHServer(t, serverOptions{})
			db := filepath.Join(server.root, "audit.db")
			setup := exec.Command("sqlite3", db, "CREATE TABLE t(id INTEGER);") // #nosec G204 -- isolated SQLite fixture
			require.NoError(t, setup.Run())
			home := t.TempDir()
			auditDir := filepath.Join(home, "audit")
			args := []string{
				"sql", "-h=" + server.host, "-p=" + server.port, "-u=operator",
				"--no-key", "--accept-unknown-host", "--engine=sqlite", "--db-file=" + db,
				"--audit-output=" + auditDir,
			}
			if mode == "json" {
				args = append(args, "--json")
			}
			args = append(args, "SELECT 1")
			result := runSSHX(t, home, args, map[string]string{"SSH_PASSWORD": operatorPassword, "SSHX_NO_AUDIT": "false"})
			require.Equal(t, 0, result.exitCode, result.stdout+result.stderr)
			if mode == "human" {
				assert.Equal(t, "1\n", result.stdout, "human evidence finalization must not emit JSON")
			}
			files, globErr := filepath.Glob(filepath.Join(auditDir, "*.jsonl"))
			require.NoError(t, globErr)
			require.Len(t, files, 1)
			data, readErr := os.ReadFile(files[0]) // #nosec G304 -- isolated audit artifact beneath fixture home
			require.NoError(t, readErr)
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			require.Len(t, lines, 1)
			var event map[string]any
			require.NoError(t, json.Unmarshal([]byte(lines[0]), &event))
			assert.Equal(t, server.host+":"+server.port, event["peer_address"])
			assert.Equal(t, "password", event["auth_method"])
			fingerprint, ok := event["host_key_fingerprint"].(string)
			require.True(t, ok)
			assert.True(t, strings.HasPrefix(fingerprint, "SHA256:"))
			assert.NotEmpty(t, event["execution_fingerprint"])
			assert.Equal(t, true, event["executed"])
			peers, ok := event["peers"].([]any)
			require.True(t, ok)
			require.Len(t, peers, 1)
			peer, ok := peers[0].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "target", peer["role"])
			assert.Equal(t, fingerprint, peer["host_key_fingerprint"])
			assert.Equal(t, "operator", peer["user"])
		})
	}
}
