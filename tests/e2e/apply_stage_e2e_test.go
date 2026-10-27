package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyExplicitStageDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX privileged apply fixture")
	}
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	env := map[string]string{"SSHX_E2E_KEYRING_FILE": filepath.Join(home, "keyring.json"), "SSH_PASSWORD": operatorPassword}
	set := runSSHXWithTestKeyring(t, home, []string{"--password-set=fixture:" + operatorPassword, "--no-audit"}, env)
	require.Equal(t, 0, set.exitCode, set.stderr)
	source := filepath.Join(home, "source")
	require.NoError(t, os.WriteFile(source, []byte("stage-fixture"), 0600))
	target := filepath.Join(server.root, "target")
	stage := filepath.Join(server.root, "data-stage")
	args := []string{"apply", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--accept-unknown-host", "-pk=fixture", "--sudo", "--path=" + target, "--from=" + source, "--stage-dir=" + stage, "--json"}
	preview := runSSHXWithTestKeyring(t, home, append(append([]string{}, args...), "--dry-run"), env)
	require.Equal(t, 0, preview.exitCode, preview.stdout)
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(preview.stdout), &doc))
	assert.Contains(t, preview.stdout, stage)
	other := append([]string{}, args...)
	other[len(other)-2] = "--stage-dir=" + stage + "-other"
	changed := runSSHXWithTestKeyring(t, home, append(other, "--dry-run"), env)
	require.Equal(t, 0, changed.exitCode, changed.stdout)
	var next map[string]any
	require.NoError(t, json.Unmarshal([]byte(changed.stdout), &next))
	assert.NotEqual(t, doc["plan_hash"], next["plan_hash"])
	result := runSSHXWithTestKeyring(t, home, args, env)
	require.Equal(t, 0, result.exitCode, "stdout=%s stderr=%s", result.stdout, result.stderr)
	data, err := os.ReadFile(target) // #nosec G304 -- isolated fixture target
	require.NoError(t, err)
	assert.Equal(t, "stage-fixture", string(data))
	entries, err := os.ReadDir(stage)
	require.NoError(t, err)
	assert.Empty(t, entries)
}
