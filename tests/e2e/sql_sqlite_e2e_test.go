package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sqlResult struct {
	Engine       string `json:"engine"`
	Database     string `json:"database"`
	Success      bool   `json:"success"`
	ExitCode     int    `json:"exit_code"`
	ErrorKind    string `json:"error_kind"`
	Class        string `json:"class"`
	Verb         string `json:"verb"`
	Table        string `json:"table"`
	Stdout       string `json:"stdout"`
	AffectedRows *int64 `json:"affected_rows"`
	Backup       *struct {
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
	require.NotNil(t, updatePayload.Backup)
	assert.Equal(t, "table", updatePayload.Backup.Kind)
	assert.NotEmpty(t, updatePayload.Backup.Path)

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
