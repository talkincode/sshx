package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestAuditRedactsNamedTokensBeforeAdmission(t *testing.T) {
	home := t.TempDir()
	result := runSSHX(t, home, []string{"run", "--address=127.0.0.1", "--json", "--", "rm -rf /; tool --reverse-token FIXTURE_TOKEN Authorization=FIXTURE_HEADER"}, map[string]string{"SSHX_NO_AUDIT": "false"})
	require.Equal(t, 255, result.exitCode)
	files, err := filepath.Glob(filepath.Join(home, ".sshx", "audit", "*.jsonl"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, p := range files {
		data, err := os.ReadFile(p) // #nosec G304 -- isolated fixture audit directory
		require.NoError(t, err)
		assert.NotContains(t, string(data), "FIXTURE_TOKEN")
		assert.NotContains(t, string(data), "FIXTURE_HEADER")
	}
	assert.NotContains(t, result.stdout, "FIXTURE_TOKEN")
}

func TestHostDiagnosticsHonorsDeadline(t *testing.T) {
	signer := newHostSigner(t)
	server := startSSHServer(t, serverOptions{hostSigner: signer, execHandler: func(ch ssh.Channel, _, _ string) { time.Sleep(1500 * time.Millisecond); sendExitStatus(ch, 0) }})
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".ssh"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(knownhosts.Line([]string{net.JoinHostPort(server.host, server.port)}, signer.PublicKey())+"\n"), 0600))
	settings := map[string]any{"hosts": []any{map[string]any{"name": "fixture", "host": server.host, "port": server.port, "user": "operator"}}}
	data, err := json.Marshal(settings)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".sshx"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".sshx", "settings.json"), data, 0600))
	start := time.Now()
	result := runSSHX(t, home, []string{"--host-test=fixture", "--no-key", "--timeout=100ms", "--global-timeout=100ms", "--json"}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 255, result.exitCode, result.stdout)
	assert.Less(t, time.Since(start), time.Second)
	assert.Contains(t, result.stdout, `"error_kind":"timeout"`)
}

func TestHostKeyPrefersKnownAlgorithm(t *testing.T) {
	ed := newHostSigner(t)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ec, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	server := startSSHServer(t, serverOptions{hostSigner: ed, extraHostSigners: []ssh.Signer{ec}})
	home := t.TempDir()
	trust := filepath.Join(home, "known_hosts")
	require.NoError(t, os.WriteFile(trust, []byte(knownhosts.Line([]string{net.JoinHostPort(server.host, server.port)}, ed.PublicKey())+"\n"), 0600))
	result := runSSHX(t, home, []string{"-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--known-hosts=" + trust, "--json", "probe"}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, result.exitCode, result.stdout)
	assert.Contains(t, result.stdout, "probe-ok")
}
