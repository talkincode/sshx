package e2e

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

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
