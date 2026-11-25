package e2e

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pkg/sftp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestROSExecutionBoundaries(t *testing.T) {
	t.Run("raw bytes and audit", func(t *testing.T) {
		wire := make(chan string, 1)
		server := startSSHServer(t, serverOptions{execHandler: func(ch ssh.Channel, command, _ string) { wire <- command; sendExitStatus(ch, 0) }})
		home := t.TempDir()
		cmd := `/container/add name=fixture cmd="--config /etc/rtp/config.toml --name demo"`
		result := runSSHX(t, home, []string{"ros", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--accept-unknown-host", "--allow-write", "--json", "raw", cmd}, map[string]string{"SSH_PASSWORD": operatorPassword, "SSHX_NO_AUDIT": "false"})
		require.Equal(t, 0, result.exitCode, result.stdout)
		assert.Equal(t, cmd, <-wire)
		var doc map[string]any
		require.NoError(t, json.Unmarshal([]byte(result.stdout), &doc))
		assert.Equal(t, "written", doc["audit_status"])
		files, err := filepath.Glob(filepath.Join(home, ".sshx", "audit", "*.jsonl"))
		require.NoError(t, err)
		require.Len(t, files, 1)
		b, err := os.ReadFile(files[0])
		require.NoError(t, err)
		var audit map[string]any
		require.NoError(t, json.Unmarshal(b, &audit))
		assert.NotEmpty(t, audit["action"])
		assert.NotEmpty(t, audit["command"])
		assert.Equal(t, true, audit["would_mutate_remote"])
		assert.Equal(t, doc["execution_fingerprint"], audit["execution_fingerprint"])
	})
	t.Run("device error with exit zero", func(t *testing.T) {
		server := startSSHServer(t, serverOptions{execHandler: func(ch ssh.Channel, _, _ string) {
			_, _ = io.WriteString(ch, "input does not match any value of value-name\n") //nolint:errcheck // fixture peer may disconnect
			sendExitStatus(ch, 0)
		}})
		result := runSSHX(t, t.TempDir(), []string{"ros", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--accept-unknown-host", "--json", "raw", "/container/print proplist=name,status"}, map[string]string{"SSH_PASSWORD": operatorPassword})
		require.Equal(t, 255, result.exitCode, result.stdout)
		assert.Contains(t, result.stdout, `"success":false`)
		assert.Contains(t, result.stdout, "ros_command_error")
	})
	t.Run("typed host probe and redacted device output", func(t *testing.T) {
		signer, keyPath := newClientKey(t)
		wire := make(chan string, 3)
		server := startSSHServer(t, serverOptions{authorizedKey: signer.PublicKey(), execHandler: func(ch ssh.Channel, cmd, _ string) {
			wire <- cmd
			_, _ = io.WriteString(ch, " log=-- reverse-\n    token abcd1234\n    defa5678\n file=ordinary.tgz\n") //nolint:errcheck // fixture peer may disconnect
			_, _ = io.WriteString(ch.Stderr(), "reverse-token: stderr-canary\n")                                  //nolint:errcheck // fixture peer may disconnect
			sendExitStatus(ch, 0)
		}})
		home := t.TempDir()
		env := map[string]string{"SSHX_E2E_KEYRING_FILE": filepath.Join(home, "keyring.json")}
		add := runSSHXWithTestKeyring(t, home, []string{"--host-add", "--host-name=ros-lab", "--host-type=routeros",
			"-h=" + server.host, "-p=" + server.port, "-u=operator", "-i=" + keyPath, "--ssh-password-key=missing"}, env)
		require.Zero(t, add.exitCode, "%s", add.stderr)
		result := runSSHXWithTestKeyring(t, home, []string{"ros", "-h=ros-lab", "--json", "--accept-unknown-host", "raw", "/system/identity/print"}, env)
		require.Zero(t, result.exitCode, "%s %s", result.stdout, result.stderr)
		assert.Equal(t, "/system/identity/print", <-wire)
		assert.Contains(t, result.stdout, "ordinary.tgz")
		assert.Contains(t, result.stdout, "redacted")
		assert.NotContains(t, result.stdout, "abcd1234")
		assert.NotContains(t, result.stdout, "defa5678")
		assert.NotContains(t, result.stdout, "stderr-canary")
		test := runSSHXWithTestKeyring(t, home, []string{"--host-test=ros-lab", "--json"}, env)
		require.Zero(t, test.exitCode, "%s %s", test.stdout, test.stderr)
		assert.Equal(t, "/system/identity/print", <-wire)
		assert.Contains(t, test.stdout, `"auth_method":"key"`)
	})
	t.Run("argument mistakes stay local", func(t *testing.T) {
		for _, tc := range []struct{ arg, hint string }{
			{"--pty", "unavailable for sshx ros"},
			{"--download=router.rsc", "file download"},
			{"--upload=router.rsc", "file upload"},
		} {
			doc := runSSHX(t, t.TempDir(), []string{"ros", "--dry-run", "--json", "raw", "/system/identity/print", tc.arg}, nil)
			require.NotZero(t, doc.exitCode)
			assert.Contains(t, doc.stdout, tc.hint)
		}
	})
	t.Run("non-atomic SFTP replacement retains a backup", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX permission and ownership fixture")
		}
		require.NoError(t, sftp.SetSFTPExtensions())
		t.Cleanup(func() {
			require.NoError(t, sftp.SetSFTPExtensions("hardlink@openssh.com", "posix-rename@openssh.com", "statvfs@openssh.com"))
		})
		server := startSSHServer(t, serverOptions{})
		home := t.TempDir()
		local, remote := filepath.Join(home, "upload.txt"), filepath.Join(server.root, "image.txt")
		require.NoError(t, os.WriteFile(local, []byte("new"), 0600))
		require.NoError(t, os.WriteFile(remote, []byte("old"), 0600))
		env := map[string]string{"SSH_PASSWORD": operatorPassword}
		args := []string{"ros", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--accept-unknown-host",
			"--json", "file", "upload", local, remote}
		refusal := runSSHX(t, home, args, env)
		require.NotZero(t, refusal.exitCode)
		assert.Contains(t, refusal.stdout, "existing destination preserved")
		allowed := runSSHX(t, home, append(args, "--allow-non-atomic"), env)
		require.Zero(t, allowed.exitCode, "%s %s", allowed.stdout, allowed.stderr)
		var result struct {
			Entries []struct {
				Verified   bool   `json:"verified"`
				BackupPath string `json:"backup_path"`
			} `json:"entries"`
		}
		require.NoError(t, json.Unmarshal([]byte(allowed.stdout), &result))
		require.Len(t, result.Entries, 1)
		assert.True(t, result.Entries[0].Verified)
		require.Equal(t, server.root, filepath.Dir(result.Entries[0].BackupPath))
		backup, err := os.ReadFile(result.Entries[0].BackupPath) // #nosec G304 -- verified fixture directory.
		require.NoError(t, err)
		assert.Equal(t, "old", string(backup))
		updated, err := os.ReadFile(remote) // #nosec G304 -- fixture file.
		require.NoError(t, err)
		assert.Equal(t, "new", string(updated))
	})
	t.Run("download preserves symlink target", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX symlink fixture")
		}
		server := startSSHServer(t, serverOptions{})
		home := t.TempDir()
		source := filepath.Join(server.root, "source")
		victim := filepath.Join(home, "victim")
		dest := filepath.Join(home, "link")
		require.NoError(t, os.WriteFile(source, []byte("new"), 0600))
		require.NoError(t, os.WriteFile(victim, []byte("old"), 0600))
		require.NoError(t, os.Symlink(victim, dest))
		result := runSSHX(t, home, []string{"ros", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--accept-unknown-host", "--json", "file", "download", source, dest}, map[string]string{"SSH_PASSWORD": operatorPassword})
		require.Equal(t, 255, result.exitCode, result.stdout)
		b, err := os.ReadFile(victim) // #nosec G304 -- isolated fixture target
		require.NoError(t, err)
		assert.Equal(t, "old", string(b))
	})
}
