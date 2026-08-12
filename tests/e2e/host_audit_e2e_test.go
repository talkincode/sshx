package e2e

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIHostImportIsUsableAndFailedSelectionIsAllOrNothing(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	sshConfig := filepath.Join(home, "ssh_config")
	configText := "Host imported\n" +
		"  HostName " + server.host + "\n" +
		"  Port " + server.port + "\n" +
		"  User operator\n\n" +
		"Host second\n" +
		"  HostName " + server.host + "\n" +
		"  Port 22\n" +
		"  User operator\n"
	require.NoError(t, os.WriteFile(sshConfig, []byte(configText), 0o600))

	imported := runSSHX(t, home, []string{
		"--host-import=imported",
		"--ssh-config=" + sshConfig,
		"--no-audit",
	}, nil)
	require.Equal(t, 0, imported.exitCode, imported.stderr)
	settingsPath := filepath.Join(home, ".sshx", "settings.json")
	settingsBeforeFailure, err := os.ReadFile(settingsPath) // #nosec G304 -- path is inside this test's temporary HOME.
	require.NoError(t, err)
	info, err := os.Stat(settingsPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	failed := runSSHX(t, home, []string{
		"--host-import=second,missing",
		"--ssh-config=" + sshConfig,
		"--no-audit",
	}, nil)
	require.Equal(t, 255, failed.exitCode)
	settingsAfterFailure, err := os.ReadFile(settingsPath) // #nosec G304 -- path is inside this test's temporary HOME.
	require.NoError(t, err)
	assert.Equal(t, settingsBeforeFailure, settingsAfterFailure, "failed selection must not partially update settings")

	command := runSSHX(t, home, []string{
		"-h=imported",
		"--no-key",
		"--accept-unknown-host",
		"--json",
		"probe",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, command.exitCode, command.stderr)
	var payload commandResult
	require.NoError(t, json.Unmarshal([]byte(command.stdout), &payload))
	assert.Equal(t, server.host, payload.Host)
	assert.Equal(t, server.port, payload.Port)
}

func TestCLIAuditRedactsSecretsAndRecoversAfterWriteFailure(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	knownHostArgs := []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
	}
	env := map[string]string{
		"SSH_PASSWORD":  operatorPassword,
		"SSHX_NO_AUDIT": "false",
	}

	invalidAuditTarget := filepath.Join(home, "audit-is-a-file")
	require.NoError(t, os.WriteFile(invalidAuditTarget, []byte("not a directory"), 0o600))
	writeFailure := runSSHX(t, home, append(append([]string{}, knownHostArgs...),
		"--accept-unknown-host", "--audit-output="+invalidAuditTarget, "probe"), env)
	require.Equal(t, 0, writeFailure.exitCode, writeFailure.stderr)
	assert.Contains(t, writeFailure.stderr, "failed to write audit event")

	auditDir := filepath.Join(home, "audit")
	const fakeSecret = "fixture-secret-value" // #nosec G101 -- redaction fixture, not a credential.
	audited := runSSHX(t, home, append(append([]string{}, knownHostArgs...),
		"--audit-output="+auditDir, "probe --token="+fakeSecret), env)
	require.Equal(t, 0, audited.exitCode, audited.stderr)

	entries, err := os.ReadDir(auditDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	file, err := os.Open(filepath.Join(auditDir, entries[0].Name())) // #nosec G304 -- isolated test directory entry.
	require.NoError(t, err)
	defer func() { _ = file.Close() }() //nolint:errcheck // best-effort fixture cleanup
	scanner := bufio.NewScanner(file)
	require.True(t, scanner.Scan())
	var event struct {
		Mode       string `json:"mode"`
		Command    string `json:"command"`
		AuthMethod string `json:"auth_method"`
		Outcome    struct {
			Status string `json:"status"`
		} `json:"outcome"`
		Redaction struct {
			Secrets bool `json:"secrets_redacted"`
		} `json:"redaction"`
	}
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
	assert.Equal(t, "ssh", event.Mode)
	assert.Equal(t, "password", event.AuthMethod)
	assert.Equal(t, "success", event.Outcome.Status)
	assert.True(t, event.Redaction.Secrets)
	assert.NotContains(t, event.Command, fakeSecret)
	assert.Contains(t, strings.ToLower(event.Command), "redacted")
	assert.False(t, scanner.Scan(), "one invocation must produce one audit event")
}
