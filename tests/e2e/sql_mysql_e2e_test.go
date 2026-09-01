package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestSQLMySQLReadAndGuardedUpdate(t *testing.T) {
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
	require.NotNil(t, updatePayload.Backup)
	assert.Equal(t, "rows", updatePayload.Backup.Kind)
	assert.NotEmpty(t, updatePayload.Backup.Path)

	backupPath := updatePayload.Backup.Path
	if !filepath.IsAbs(backupPath) {
		backupPath = filepath.Join(server.root, backupPath)
	}
	data, err := os.ReadFile(backupPath) // #nosec G304 -- isolated E2E backup under the fixture root
	require.NoError(t, err, backupPath)
	assert.Contains(t, string(data), "old")
}
