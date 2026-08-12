package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsolatedKeyringProcessContractAndSudoExecution(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	keyringFile := filepath.Join(home, "keyring.json")
	key := "isolated-key"
	env := map[string]string{"SSHX_E2E_KEYRING_FILE": keyringFile}

	set := runSSHXWithTestKeyring(t, home, []string{"--password-set=" + key + ":" + operatorPassword, "--no-audit"}, env)
	require.Equal(t, 0, set.exitCode, set.stderr)
	info, err := os.Stat(keyringFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	get := runSSHXWithTestKeyring(t, home, []string{"--password-get=" + key, "--no-audit"}, env)
	require.Equal(t, 0, get.exitCode, get.stderr)
	assert.Equal(t, operatorPassword, get.stdout)

	sudo := runSSHXWithTestKeyring(t, home, []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--json",
		"-pk=" + key,
		"sudo whoami",
	}, env)
	require.Equal(t, 0, sudo.exitCode, sudo.stderr)
	var payload commandResult
	require.NoError(t, json.Unmarshal([]byte(sudo.stdout), &payload))
	assert.Equal(t, "sudo-ok\n", payload.Stdout)
	assert.NotContains(t, sudo.stdout, operatorPassword)
	assert.NotContains(t, sudo.stderr, operatorPassword)

	deleted := runSSHXWithTestKeyring(t, home, []string{"--password-delete=" + key, "--no-audit"}, env)
	require.Equal(t, 0, deleted.exitCode, deleted.stderr)
	missing := runSSHXWithTestKeyring(t, home, []string{"--password-get=" + key, "--no-audit"}, env)
	assert.Equal(t, 255, missing.exitCode)
}

func TestRealOSKeyringLifecycleAndSudoExecution(t *testing.T) {
	if os.Getenv("SSHX_E2E_REAL_KEYRING") != "1" {
		t.Skip("set SSHX_E2E_REAL_KEYRING=1 only in an isolated or ephemeral OS keyring session")
	}
	server := startSSHServer(t, serverOptions{})
	workDir := t.TempDir()
	key := "sshx-e2e-" + randomHex(t, 8)

	set := runSSHXWithNativeKeyring(t, workDir, []string{"--password-set=" + key + ":" + operatorPassword, "--no-audit"}, nil)
	require.Equal(t, 0, set.exitCode, set.stderr)
	t.Cleanup(func() {
		cleanup := runSSHXWithNativeKeyring(t, workDir, []string{"--password-delete=" + key, "--no-audit"}, nil)
		assert.Equal(t, 0, cleanup.exitCode, cleanup.stderr)
	})

	get := runSSHXWithNativeKeyring(t, workDir, []string{"--password-get=" + key, "--no-audit"}, nil)
	require.Equal(t, 0, get.exitCode, get.stderr)
	assert.Equal(t, operatorPassword, get.stdout)

	sudo := runSSHXWithNativeKeyring(t, workDir, []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--known-hosts=" + filepath.Join(workDir, "known_hosts"),
		"--json",
		"-pk=" + key,
		"sudo whoami",
	}, nil)
	require.Equal(t, 0, sudo.exitCode, sudo.stderr)
	var payload commandResult
	require.NoError(t, json.Unmarshal([]byte(sudo.stdout), &payload))
	assert.Equal(t, "sudo-ok\n", payload.Stdout)
	assert.NotContains(t, sudo.stdout, operatorPassword)
	assert.NotContains(t, sudo.stderr, operatorPassword)
}

func randomHex(t *testing.T, bytesLen int) string {
	t.Helper()
	data := make([]byte, bytesLen)
	_, err := rand.Read(data)
	require.NoError(t, err)
	return hex.EncodeToString(data)
}
