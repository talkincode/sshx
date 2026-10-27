package e2e

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestROSPreviewIsOfflineAndConservative(t *testing.T) {
	server := startSSHServer(t, serverOptions{execHandler: func(ch ssh.Channel, _, _ string) { sendExitStatus(ch, 0) }})
	home := t.TempDir()
	result := runSSHX(t, home, []string{"ros", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--accept-unknown-host", "--dry-run", "--json", "doctor", "--include-remote"}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, result.exitCode, result.stdout)
	assert.Zero(t, server.connections.Load())
	result = runSSHX(t, home, []string{"ros", "--dry-run", "--json", "raw", "/interface/print ; /ip/address/remove numbers=99"}, nil)
	require.Equal(t, 0, result.exitCode, result.stdout)
	assert.Contains(t, result.stdout, `"will_modify_routeros": true`)
}
