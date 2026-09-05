package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCLIBoundUploadPreservesModeAndEvidence(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	source := filepath.Join(home, "source.txt")
	require.NoError(t, os.WriteFile(source, []byte("reviewed file bytes\n"), 0o600))
	destination := filepath.Join(server.root, "published.txt")
	require.NoError(t, os.WriteFile(destination, []byte("old file bytes\n"), 0o640)) // #nosec G306 -- fixture verifies preservation of group-read permission.
	beforeInfo, err := os.Stat(destination)
	require.NoError(t, err)
	env := map[string]string{"SSH_PASSWORD": operatorPassword, "SSHX_NO_AUDIT": "false"}
	base := []string{"-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--json"}
	bootstrap := runSSHX(t, home, append(append([]string{}, base...), "--accept-unknown-host", "probe"), env)
	require.Zero(t, bootstrap.exitCode, bootstrap.stderr)
	uploadArgs := append(append([]string{}, base...), "--upload="+source, "--to=published.txt")
	dry := runSSHX(t, home, append(append([]string{}, uploadArgs...), "--dry-run"), env)
	require.Zero(t, dry.exitCode, dry.stderr)
	var plan struct {
		PlanHash string `json:"plan_hash"`
	}
	require.NoError(t, json.Unmarshal([]byte(dry.stdout), &plan), dry.stdout)
	require.NotEmpty(t, plan.PlanHash)
	result := runSSHX(t, home, append(append([]string{}, uploadArgs...), "--expect-plan="+plan.PlanHash), env)
	require.Zero(t, result.exitCode, result.stderr)
	var evidence struct {
		PlanHash             string `json:"plan_hash"`
		ExecutionID          string `json:"execution_id"`
		ExecutionFingerprint string `json:"execution_fingerprint"`
		ChangeState          string `json:"change_state"`
		Verified             bool   `json:"verified"`
		Completion           string `json:"completion"`
		Entries              []struct {
			SHA256       string `json:"sha256"`
			SourceSHA256 string `json:"source_sha256"`
			Published    bool   `json:"published"`
		} `json:"entries"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &evidence), result.stdout)
	require.Equal(t, plan.PlanHash, evidence.PlanHash)
	require.Equal(t, "changed", evidence.ChangeState)
	require.True(t, evidence.Verified)
	require.Equal(t, "completed", evidence.Completion)
	require.Len(t, evidence.Entries, 1)
	require.True(t, evidence.Entries[0].Published)
	require.NotEmpty(t, evidence.Entries[0].SHA256)
	require.Equal(t, evidence.Entries[0].SHA256, evidence.Entries[0].SourceSHA256)
	actual, err := os.ReadFile(destination) // #nosec G304 -- destination is inside the isolated SSH fixture root.
	require.NoError(t, err)
	require.Equal(t, "reviewed file bytes\n", string(actual))
	destinationInfo, err := os.Stat(destination)
	require.NoError(t, err)
	require.Equal(t, beforeInfo.Mode().Perm(), destinationInfo.Mode().Perm())
	query := runSSHX(t, home, []string{"audit", "query", "--json", "--execution-id=" + evidence.ExecutionID}, nil)
	require.Zero(t, query.exitCode, query.stderr)
	var audit struct {
		Events []struct {
			ExecutionFingerprint string `json:"execution_fingerprint"`
			ChangeState          string `json:"change_state"`
			Verified             bool   `json:"verified"`
		} `json:"events"`
	}
	require.NoError(t, json.Unmarshal([]byte(query.stdout), &audit))
	require.Len(t, audit.Events, 1)
	require.Equal(t, evidence.ExecutionFingerprint, audit.Events[0].ExecutionFingerprint)
	require.Equal(t, evidence.ChangeState, audit.Events[0].ChangeState)
	require.Equal(t, evidence.Verified, audit.Events[0].Verified)
}
