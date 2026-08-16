package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type applyResult struct {
	Success           bool   `json:"success"`
	Changed           bool   `json:"changed"`
	Created           bool   `json:"created"`
	Completion        string `json:"completion"`
	ErrorKind         string `json:"error_kind"`
	RemotePath        string `json:"remote_path"`
	BeforeSHA256      string `json:"before_sha256"`
	AfterSHA256       string `json:"after_sha256"`
	PayloadSHA256     string `json:"payload_sha256"`
	RollbackAvailable bool   `json:"rollback_available"`
	Backup            *struct {
		Kind        string `json:"kind"`
		Path        string `json:"path"`
		RestoreHint string `json:"restore_hint"`
	} `json:"backup"`
}

func TestApplyCreatesOverwritesAndProtectsHash(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	remote := filepath.Join(server.root, "app.conf")
	local := filepath.Join(home, "app.conf")
	require.NoError(t, os.WriteFile(local, []byte("first\n"), 0o600))

	base := []string{
		"apply",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"--path=" + filepath.ToSlash(remote),
	}
	env := map[string]string{"SSH_PASSWORD": operatorPassword}

	created := runSSHX(t, home, append(append([]string{}, base...),
		"--accept-unknown-host", "--from="+local), env)
	require.Equal(t, 0, created.exitCode, created.stderr)
	var createdResult applyResult
	require.NoError(t, json.Unmarshal([]byte(created.stdout), &createdResult))
	assert.True(t, createdResult.Success)
	assert.True(t, createdResult.Created)
	assert.True(t, createdResult.Changed)
	assert.Equal(t, "completed", createdResult.Completion)
	got, err := os.ReadFile(remote) // #nosec G304 -- path is inside this test's temporary SSH root.
	require.NoError(t, err)
	assert.Equal(t, "first\n", string(got))

	require.NoError(t, os.WriteFile(local, []byte("second\n"), 0o600))
	wrong := runSSHX(t, home, append(append([]string{}, base...),
		"--from="+local, "--expect-sha256="+sha256Hex([]byte("nope\n"))), env)
	require.Equal(t, 255, wrong.exitCode, wrong.stderr)
	var wrongResult applyResult
	require.NoError(t, json.Unmarshal([]byte(wrong.stdout), &wrongResult))
	assert.Equal(t, "precondition", wrongResult.ErrorKind)
	assert.Equal(t, "not_started", wrongResult.Completion)
	got, err = os.ReadFile(remote) // #nosec G304 -- path is inside this test's temporary SSH root.
	require.NoError(t, err)
	assert.Equal(t, "first\n", string(got), "hash mismatch must not change the target")

	updated := runSSHX(t, home, append(append([]string{}, base...),
		"--from="+local, "--expect-sha256="+sha256Hex([]byte("first\n"))), env)
	require.Equal(t, 0, updated.exitCode, updated.stderr)
	var updatedResult applyResult
	require.NoError(t, json.Unmarshal([]byte(updated.stdout), &updatedResult))
	assert.True(t, updatedResult.Changed)
	assert.False(t, updatedResult.Created)
	assert.True(t, updatedResult.RollbackAvailable)
	require.NotNil(t, updatedResult.Backup)
	assert.NotEmpty(t, updatedResult.Backup.Path)
	got, err = os.ReadFile(remote) // #nosec G304 -- path is inside this test's temporary SSH root.
	require.NoError(t, err)
	assert.Equal(t, "second\n", string(got))
	backup := updatedResult.Backup.Path
	if !filepath.IsAbs(backup) {
		backup = filepath.Join(server.root, backup)
	}
	saved, err := os.ReadFile(backup) // #nosec G304 -- path is inside this test's temporary SSH root.
	require.NoError(t, err)
	assert.Equal(t, "first\n", string(saved))

	same := runSSHX(t, home, append(append([]string{}, base...), "--from="+local), env)
	require.Equal(t, 0, same.exitCode, same.stderr)
	var sameResult applyResult
	require.NoError(t, json.Unmarshal([]byte(same.stdout), &sameResult))
	assert.True(t, sameResult.Success)
	assert.False(t, sameResult.Changed)
}

func TestApplyDryRunDoesNotConnect(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	local := filepath.Join(home, "app.conf")
	require.NoError(t, os.WriteFile(local, []byte("payload\n"), 0o600))
	before := server.connections.Load()

	result := runSSHX(t, home, []string{
		"apply",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--path=/tmp/app.conf",
		"--from=" + local,
		"--dry-run",
		"--json",
	}, nil)
	require.Equal(t, 0, result.exitCode, result.stderr)
	assert.Equal(t, before, server.connections.Load())
	assert.Contains(t, result.stdout, `"mode": "apply"`)
	assert.Contains(t, result.stdout, `"would_connect": true`)
	assert.Contains(t, result.stdout, `"would_mutate_remote": true`)
}

func TestApplyRejectsSymlinkAndReadOnlyTarget(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	local := filepath.Join(home, "app.conf")
	require.NoError(t, os.WriteFile(local, []byte("payload\n"), 0o600))
	link := filepath.Join(server.root, "linked.conf")
	require.NoError(t, os.WriteFile(filepath.Join(server.root, "real.conf"), []byte("orig\n"), 0o600))
	require.NoError(t, os.Symlink(filepath.Join(server.root, "real.conf"), link))

	env := map[string]string{"SSH_PASSWORD": operatorPassword}
	blocked := runSSHX(t, home, []string{
		"apply",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"--accept-unknown-host",
		"--path=" + filepath.ToSlash(link),
		"--from=" + local,
	}, env)
	require.Equal(t, 255, blocked.exitCode, blocked.stderr)
	var blockedResult applyResult
	require.NoError(t, json.Unmarshal([]byte(blocked.stdout), &blockedResult))
	assert.Equal(t, "blocked", blockedResult.ErrorKind)
	real, err := os.ReadFile(filepath.Join(server.root, "real.conf"))
	require.NoError(t, err)
	assert.Equal(t, "orig\n", string(real))

	readerHome := t.TempDir()
	readerLocal := filepath.Join(readerHome, "denied.conf")
	require.NoError(t, os.WriteFile(readerLocal, []byte("nope\n"), 0o600))
	denied := runSSHX(t, readerHome, []string{
		"apply",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=reader",
		"--no-key",
		"--json",
		"--accept-unknown-host",
		"--path=" + filepath.ToSlash(filepath.Join(server.root, "forbidden.conf")),
		"--from=" + readerLocal,
	}, map[string]string{"SSH_PASSWORD": readerPassword})
	require.Equal(t, 255, denied.exitCode, denied.stderr)
	_, err = os.Stat(filepath.Join(server.root, "forbidden.conf"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestApplySudoInstallsStagedPayload(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	keyringFile := filepath.Join(home, "keyring.json")
	key := "apply-sudo"
	env := map[string]string{
		"SSHX_E2E_KEYRING_FILE": keyringFile,
		"SSH_PASSWORD":          operatorPassword,
	}
	set := runSSHXWithTestKeyring(t, home, []string{"--password-set=" + key + ":" + operatorPassword, "--no-audit"}, env)
	require.Equal(t, 0, set.exitCode, set.stderr)

	remote := filepath.Join(server.root, "sudo.conf")
	require.NoError(t, os.WriteFile(remote, []byte("old\n"), 0o644)) // #nosec G306 -- fixture simulates a world-readable config file.
	local := filepath.Join(home, "sudo.conf")
	require.NoError(t, os.WriteFile(local, []byte("new\n"), 0o600))

	result := runSSHXWithTestKeyring(t, home, []string{
		"apply",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"--accept-unknown-host",
		"--sudo",
		"-pk=" + key,
		"--path=" + filepath.ToSlash(remote),
		"--from=" + local,
		"--expect-sha256=" + sha256Hex([]byte("old\n")),
	}, env)
	require.Equal(t, 0, result.exitCode, result.stderr+result.stdout)
	var decoded applyResult
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &decoded))
	assert.True(t, decoded.Changed)
	got, err := os.ReadFile(remote) // #nosec G304 -- path is inside this test's temporary SSH root.
	require.NoError(t, err)
	assert.Equal(t, "new\n", string(got))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
