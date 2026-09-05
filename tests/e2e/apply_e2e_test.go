package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
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
	ChangeState       string `json:"change_state"`
	Executed          *bool  `json:"executed"`
	Verified          bool   `json:"verified"`
	Verification      string `json:"verification"`
	PayloadBytes      int    `json:"payload_bytes"`
	Completion        string `json:"completion"`
	ErrorKind         string `json:"error_kind"`
	RemotePath        string `json:"remote_path"`
	BeforeSHA256      string `json:"before_sha256"`
	AfterSHA256       string `json:"after_sha256"`
	PayloadSHA256     string `json:"payload_sha256"`
	RollbackAvailable bool   `json:"rollback_available"`
	Peers             []struct {
		Role               string `json:"role"`
		Address            string `json:"address"`
		HostKeyFingerprint string `json:"host_key_fingerprint"`
		AuthMethod         string `json:"auth_method"`
		User               string `json:"user"`
	} `json:"peers"`
	Backup *struct {
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
	assert.Equal(t, "changed", createdResult.ChangeState)
	require.NotNil(t, createdResult.Executed)
	assert.True(t, *createdResult.Executed)
	assert.True(t, createdResult.Verified)
	require.Len(t, createdResult.Peers, 1)
	assert.Equal(t, "target", createdResult.Peers[0].Role)
	assert.Equal(t, net.JoinHostPort(server.host, server.port), createdResult.Peers[0].Address)
	assert.NotEmpty(t, createdResult.Peers[0].HostKeyFingerprint)
	assert.Equal(t, "password", createdResult.Peers[0].AuthMethod)
	assert.Equal(t, "operator", createdResult.Peers[0].User)
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
	assert.Equal(t, sha256Hex([]byte("first\n")), wrongResult.BeforeSHA256)
	assert.Equal(t, "unchanged", wrongResult.ChangeState)
	require.NotNil(t, wrongResult.Executed)
	assert.False(t, *wrongResult.Executed)
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
	assert.Equal(t, "unchanged", sameResult.ChangeState)
	assert.True(t, sameResult.Verified)
	require.NotNil(t, sameResult.Executed)
	assert.False(t, *sameResult.Executed)
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
	assert.True(t, decoded.Verified)
	assert.Equal(t, sha256Hex([]byte("old\n")), decoded.BeforeSHA256)
	assert.Equal(t, sha256Hex([]byte("new\n")), decoded.AfterSHA256)
	assert.True(t, decoded.RollbackAvailable)
	got, err := os.ReadFile(remote) // #nosec G304 -- path is inside this test's temporary SSH root.
	require.NoError(t, err)
	assert.Equal(t, "new\n", string(got))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestApplyZeroByteAndForceParity(t *testing.T) {
	for _, sudo := range []bool{false, true} {
		name := "sftp"
		if sudo {
			name = "sudo"
		}
		t.Run(name, func(t *testing.T) {
			server := startSSHServer(t, serverOptions{})
			home := t.TempDir()
			remote := filepath.Join(server.root, "empty.conf")
			local := filepath.Join(home, "empty.conf")
			require.NoError(t, os.WriteFile(local, []byte{}, 0o600))
			require.NoError(t, os.WriteFile(remote, []byte("before\n"), 0o640)) // #nosec G306 -- fixture verifies preservation of group-readable permissions.
			env := map[string]string{"SSH_PASSWORD": operatorPassword}
			base := []string{
				"apply", "-h=" + server.host, "-p=" + server.port, "-u=operator",
				"--no-key", "--json", "--accept-unknown-host", "--path=" + filepath.ToSlash(remote), "--from=" + local,
			}
			if sudo {
				env["SSHX_E2E_KEYRING_FILE"] = filepath.Join(home, "keyring.json")
				set := runSSHXWithTestKeyring(t, home, []string{"--password-set=apply-test:" + operatorPassword, "--no-audit"}, env)
				require.Equal(t, 0, set.exitCode, set.stderr)
				base = append(base, "--sudo", "-pk=apply-test")
			}
			run := func(extra ...string) applyResult {
				args := append(append([]string{}, base...), extra...)
				var result cliResult
				if sudo {
					result = runSSHXWithTestKeyring(t, home, args, env)
				} else {
					result = runSSHX(t, home, args, env)
				}
				require.Equal(t, 0, result.exitCode, result.stderr+result.stdout)
				var decoded applyResult
				require.NoError(t, json.Unmarshal([]byte(result.stdout), &decoded))
				return decoded
			}
			changed := run("--expect-sha256=" + sha256Hex([]byte("before\n")))
			require.Equal(t, "changed", changed.ChangeState)
			require.True(t, changed.Verified)
			require.Zero(t, changed.PayloadBytes)
			require.Equal(t, sha256Hex(nil), changed.PayloadSHA256)
			require.Equal(t, changed.PayloadSHA256, changed.AfterSHA256)
			data, err := os.ReadFile(remote) // #nosec G304 -- path is confined to this test's owned SSH root.
			require.NoError(t, err)
			require.Empty(t, data)
			info, err := os.Stat(remote)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
			same := run()
			require.Equal(t, "unchanged", same.ChangeState)
			require.NotNil(t, same.Executed)
			require.False(t, *same.Executed)
			require.True(t, same.Verified)
			require.NoError(t, os.WriteFile(local, []byte("forced\n"), 0o600))
			forced := run("--force", "--no-backup", "--expect-sha256="+sha256Hex([]byte("wrong")))
			require.True(t, forced.Verified)
			require.Equal(t, "changed", forced.ChangeState)
			require.False(t, forced.RollbackAvailable)
			entries, err := os.ReadDir(server.root)
			require.NoError(t, err)
			for _, entry := range entries {
				require.NotContains(t, entry.Name(), ".sshx.", "no owned target temp files remain")
			}
			if sudo {
				staged, readErr := os.ReadDir(filepath.Join(server.root, ".sshx", "apply-staging"))
				require.NoError(t, readErr)
				require.Empty(t, staged)
			}
		})
	}
}
