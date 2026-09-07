package e2e

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJumpHostCommandUsesBastionChannel(t *testing.T) {
	target := startSSHServer(t, serverOptions{})
	rewriteKey := net.JoinHostPort("192.0.2.10", target.port)
	rewriteVal := net.JoinHostPort(target.host, target.port)
	jump := startSSHServer(t, serverOptions{directTCPIP: map[string]string{rewriteKey: rewriteVal}})
	home := t.TempDir()
	auditDir := filepath.Join(home, "audit")
	require.NoError(t, os.MkdirAll(auditDir, 0o700))

	addEdge := runSSHX(t, home, []string{
		"--host-add", "--host-name=edge",
		"-h=" + jump.host, "-p=" + jump.port, "-u=operator",
		"--json",
	}, nil)
	require.Equal(t, 0, addEdge.exitCode, addEdge.stderr+addEdge.stdout)

	addApp := runSSHX(t, home, []string{
		"--host-add", "--host-name=app",
		"-h=192.0.2.10", "-p=" + target.port, "-u=operator",
		"--via=edge", "--json",
	}, nil)
	require.Equal(t, 0, addApp.exitCode, addApp.stderr+addApp.stdout)

	dry := runSSHX(t, home, []string{
		"-h=app", "--no-key", "--dry-run", "--json", "probe",
	}, nil)
	require.Equal(t, 0, dry.exitCode, dry.stderr)
	var plan map[string]any
	require.NoError(t, json.Unmarshal([]byte(dry.stdout), &plan))
	assert.Equal(t, true, plan["valid"])
	assert.Equal(t, true, plan["would_connect"])
	assert.Equal(t, "edge", plan["via"])
	hops, ok := plan["hops"].([]any)
	require.True(t, ok)
	require.Len(t, hops, 1)

	beforeJump := jump.connections.Load()
	beforeTarget := target.connections.Load()
	result := runSSHX(t, home, []string{
		"-h=app", "--no-key", "--accept-unknown-host", "--json", "probe",
	}, map[string]string{
		"SSH_PASSWORD":      operatorPassword,
		"SSHX_NO_AUDIT":     "false",
		"SSHX_AUDIT_OUTPUT": auditDir,
	})
	require.Equal(t, 0, result.exitCode, "stderr=%s stdout=%s", result.stderr, result.stdout)
	var payload commandResult
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload))
	assert.True(t, payload.Success)
	assert.Equal(t, "probe-ok\n", payload.Stdout)
	assert.GreaterOrEqual(t, jump.directHits.Load(), int64(1))
	assert.Greater(t, jump.connections.Load(), beforeJump)
	assert.Greater(t, target.connections.Load(), beforeTarget)

	entries, err := os.ReadDir(auditDir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
}

func TestJumpUnknownViaIsConfigError(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	before := server.connections.Load()
	result := runSSHX(t, home, []string{
		"-h=" + server.host, "-p=" + server.port, "-u=operator",
		"--via=missing", "--no-key", "--json", "probe",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 255, result.exitCode, result.stdout+result.stderr)
	assert.Contains(t, result.stdout+result.stderr, "jump host")
	assert.Equal(t, before, server.connections.Load())
}

func TestJumpAddRejectsMissingVia(t *testing.T) {
	home := t.TempDir()
	result := runSSHX(t, home, []string{
		"--host-add", "--host-name=app", "-h=192.0.2.10", "--via=edge", "--json",
	}, nil)
	require.NotEqual(t, 0, result.exitCode)
	assert.Contains(t, result.stdout+result.stderr, "jump host")
}
