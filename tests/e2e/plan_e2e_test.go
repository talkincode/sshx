package e2e

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCLIPlanIntegrityAndAuditCorrelation(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	env := map[string]string{"SSH_PASSWORD": operatorPassword, "SSHX_NO_AUDIT": "false"}
	base := []string{"-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--json"}
	bootstrap := runSSHX(t, home, append(append([]string{}, base...), "--accept-unknown-host", "probe"), env)
	require.Equal(t, 0, bootstrap.exitCode, bootstrap.stderr)

	before := server.connections.Load()
	dry := runSSHX(t, home, append(append([]string{}, base...), "--dry-run", "probe"), env)
	require.Equal(t, 0, dry.exitCode, dry.stderr)
	var plan struct {
		PlanHash string `json:"plan_hash"`
		Risk     string `json:"risk"`
		Plan     struct {
			SchemaVersion string `json:"schema_version"`
			Bindable      bool   `json:"bindable"`
		} `json:"plan"`
	}
	require.NoError(t, json.Unmarshal([]byte(dry.stdout), &plan), dry.stdout)
	require.Equal(t, "sshx.plan.v1", plan.Plan.SchemaVersion)
	require.True(t, plan.Plan.Bindable)
	require.Equal(t, "mutation", plan.Risk)
	require.Equal(t, before, server.connections.Load())

	mismatch := runSSHX(t, home, append(append([]string{}, base...), "--expect-plan="+plan.PlanHash, "different-command"), env)
	require.Equal(t, 255, mismatch.exitCode, mismatch.stderr)
	var rejected map[string]any
	require.NoError(t, json.Unmarshal([]byte(mismatch.stdout), &rejected), mismatch.stdout)
	require.Equal(t, "plan_mismatch", rejected["error_kind"])
	require.Equal(t, false, rejected["executed"])
	require.Equal(t, before, server.connections.Load())

	actual := runSSHX(t, home, append(append([]string{}, base...), "--expect-plan="+plan.PlanHash, "probe"), env)
	require.Equal(t, 0, actual.exitCode, actual.stderr)
	var result struct {
		PlanHash             string `json:"plan_hash"`
		ExecutionID          string `json:"execution_id"`
		ExecutionFingerprint string `json:"execution_fingerprint"`
		Executed             bool   `json:"executed"`
	}
	require.NoError(t, json.Unmarshal([]byte(actual.stdout), &result), actual.stdout)
	require.Equal(t, plan.PlanHash, result.PlanHash)
	require.True(t, result.Executed)
	require.NotEmpty(t, result.ExecutionID)
	require.NotEmpty(t, result.ExecutionFingerprint)

	query := runSSHX(t, home, []string{"audit", "query", "--json", "--execution-id=" + result.ExecutionID}, nil)
	require.Equal(t, 0, query.exitCode, query.stderr)
	var audit struct {
		Events []struct {
			PlanHash             string `json:"plan_hash"`
			ExecutionID          string `json:"execution_id"`
			ExecutionFingerprint string `json:"execution_fingerprint"`
		} `json:"events"`
	}
	require.NoError(t, json.Unmarshal([]byte(query.stdout), &audit), query.stdout)
	require.Len(t, audit.Events, 1)
	require.Equal(t, result.PlanHash, audit.Events[0].PlanHash)
	require.Equal(t, result.ExecutionID, audit.Events[0].ExecutionID)
	require.Equal(t, result.ExecutionFingerprint, audit.Events[0].ExecutionFingerprint)
}

func TestRunPlanRejectsTrustRelaxation(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	base := []string{"run", "--address=" + server.host, "-p=" + server.port, "-u=operator",
		"--no-key", "--accept-unknown-host", "--json"}
	dry := runSSHX(t, home, append(append([]string{}, base...), "--dry-run", "--", "probe"), nil)
	require.Equal(t, 0, dry.exitCode, dry.stderr)
	var plan struct {
		PlanHash string `json:"plan_hash"`
	}
	require.NoError(t, json.Unmarshal([]byte(dry.stdout), &plan), dry.stdout)
	require.NotEmpty(t, plan.PlanHash)
	rejected := runSSHX(t, home, append(append([]string{}, base...), "--expect-plan="+plan.PlanHash, "--", "probe"), nil)
	require.Equal(t, 255, rejected.exitCode, rejected.stderr)
	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(rejected.stdout), &result), rejected.stdout)
	require.Equal(t, "plan_unresolved", result["error_kind"])
	require.Zero(t, server.connections.Load())
}
