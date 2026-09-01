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

func TestCLIHostAddJSONOmitsDefaultSudoKey(t *testing.T) {
	home := t.TempDir()
	added := runSSHX(t, home, []string{
		"--host-add", "--host-name=lab", "--host=127.0.0.1", "-u=probe", "--json", "--no-audit",
	}, nil)
	require.Equal(t, 0, added.exitCode, added.stderr)
	assert.NotContains(t, added.stdout, "added successfully")
	var addDoc struct {
		SchemaVersion string `json:"schema_version"`
		Success       bool   `json:"success"`
		Action        string `json:"action"`
		Host          struct {
			Name            string `json:"name"`
			SudoPasswordKey string `json:"sudo_password_key"`
		} `json:"host"`
	}
	require.NoError(t, json.Unmarshal([]byte(added.stdout), &addDoc))
	assert.Equal(t, "sshx.hosts.v1", addDoc.SchemaVersion)
	assert.True(t, addDoc.Success)
	assert.Equal(t, "add", addDoc.Action)
	assert.Empty(t, addDoc.Host.SudoPasswordKey)

	listed := runSSHX(t, home, []string{"--host-list", "--json", "--no-audit"}, nil)
	require.Equal(t, 0, listed.exitCode, listed.stderr)
	assert.NotContains(t, listed.stdout, `"sudo_password_key": "master"`)
}

func TestCLIAuditQueryByRunID(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	auditDir := filepath.Join(home, "audit")
	ran := runSSHX(t, home, []string{
		"run", "--address=" + server.host, "-p=" + server.port, "-u=operator",
		"--no-key", "--accept-unknown-host", "--json", "--audit-output=" + auditDir,
		"--", "probe",
	}, map[string]string{"SSH_PASSWORD": operatorPassword, "SSHX_NO_AUDIT": "false"})
	require.Equal(t, 0, ran.exitCode, "stderr=%s stdout=%s", ran.stderr, ran.stdout)
	var runDoc struct {
		RunID   string `json:"run_id"`
		Success bool   `json:"success"`
	}
	require.NoError(t, json.Unmarshal([]byte(ran.stdout), &runDoc))
	require.NotEmpty(t, runDoc.RunID)

	queried := runSSHX(t, home, []string{
		"audit", "query", "--run-id=" + runDoc.RunID, "--json", "--audit-output=" + auditDir,
	}, nil)
	require.Equal(t, 0, queried.exitCode, queried.stderr)
	var queryDoc struct {
		Success bool             `json:"success"`
		Count   int              `json:"count"`
		Events  []map[string]any `json:"events"`
	}
	require.NoError(t, json.Unmarshal([]byte(queried.stdout), &queryDoc))
	assert.True(t, queryDoc.Success)
	require.GreaterOrEqual(t, queryDoc.Count, 1)
	assert.Equal(t, runDoc.RunID, queryDoc.Events[0]["run_id"])

	empty := runSSHX(t, home, []string{
		"audit", "query", "--run-id=missing-run", "--json", "--audit-output=" + auditDir,
	}, nil)
	require.Equal(t, 0, empty.exitCode, empty.stderr)
	var emptyDoc struct {
		Success bool             `json:"success"`
		Count   int              `json:"count"`
		Events  []map[string]any `json:"events"`
	}
	require.NoError(t, json.Unmarshal([]byte(empty.stdout), &emptyDoc))
	assert.True(t, emptyDoc.Success)
	assert.Equal(t, 0, emptyDoc.Count)
}

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
		"--json",
		"--no-audit",
	}, nil)
	require.Equal(t, 0, imported.exitCode, imported.stderr)
	var importDoc struct {
		SchemaVersion string `json:"schema_version"`
		Success       bool   `json:"success"`
		Action        string `json:"action"`
		Count         int    `json:"count"`
		Hosts         []struct {
			Name string `json:"name"`
		} `json:"hosts"`
	}
	require.NoError(t, json.Unmarshal([]byte(imported.stdout), &importDoc))
	assert.Equal(t, "sshx.hosts.v1", importDoc.SchemaVersion)
	assert.True(t, importDoc.Success)
	assert.Equal(t, "import", importDoc.Action)
	assert.Equal(t, 1, importDoc.Count)
	require.Len(t, importDoc.Hosts, 1)
	assert.Equal(t, "imported", importDoc.Hosts[0].Name)
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
