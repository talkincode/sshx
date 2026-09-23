package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/talkincode/sshx/internal/execution"
)

func TestPlanRunSudoIsIndependentOfAggregateRisk(t *testing.T) {
	config := planTestConfig(t)
	request := &execution.Request{
		Action: execution.ActionSpec{Kind: "script", Intent: execution.IntentChange},
		Limits: execution.Limits{Concurrency: 1},
	}
	snapshot := execution.TargetSnapshot{Count: 1, Targets: []execution.ResolvedTarget{{
		Address: config.Host, Port: config.Port, User: config.User, KeyPath: config.KeyPath,
	}}}
	payload := &execution.Payload{Bytes: []byte("sudo -n true\nid -u\n")}
	first, err := prepareRunPlan(config, request, &snapshot, payload)
	require.NoError(t, err)
	request.Action.UseSudo = true
	second, err := prepareRunPlan(config, request, &snapshot, payload)
	require.NoError(t, err)
	require.Equal(t, first.Effects, second.Effects)
	require.NotEqual(t, first.PlanHash, second.PlanHash)
}

func TestPlanTransferRetainsEndpointKeys(t *testing.T) {
	config := planTestConfig(t)
	sourceKey, destinationKey := config.KeyPath, filepath.Join(t.TempDir(), "destination-key")
	public, err := os.ReadFile(sourceKey + ".pub") // #nosec G304 -- public-key fixture created in this test's temporary directory.
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(destinationKey+".pub", public, 0o600)) // #nosec G703 -- public-key fixture under this test's temporary directory.
	require.NoError(t, SaveSettings(&Settings{Hosts: []HostConfig{
		{Name: "source", Host: "192.0.2.1", User: "worker", Key: sourceKey},
		{Name: "destination", Host: "192.0.2.2", User: "worker", Key: destinationKey},
	}}))
	config.Mode, config.Host, config.KeyPath = "transfer", "", ""
	config.TransferSrcHost, config.TransferSrcPath = "source", "input.txt"
	config.TransferDstHost, config.TransferDstPath = "destination", "output.txt"
	_, err = prepareOperation(config)
	require.NoError(t, err)
	require.Equal(t, sourceKey, config.TransferSource.KeyPath)
	require.Equal(t, destinationKey, config.TransferDestination.KeyPath)
}

func TestPlanPreservesScopedIPv6Bind(t *testing.T) {
	config := planTestConfig(t)
	config.Host = "2001:db8::1"
	config.Bind, config.BindSet = "fe80::1%en0", true
	first, err := prepareOperation(config)
	require.NoError(t, err)
	require.Equal(t, "fe80::1%en0", config.Bind)
	require.Equal(t, config.Bind, first.plan.Targets[0].Bind)
	config.Bind = "fe80::1%en1"
	second, err := prepareOperation(config)
	require.NoError(t, err)
	require.NotEqual(t, first.plan.PlanHash, second.plan.PlanHash)
}

func TestPlanInspectionNormalizesEffectiveDefaults(t *testing.T) {
	config := planTestConfig(t)
	config.Mode, config.Command = "inspect", ""
	config.InspectCapability, config.InspectCacheMode = "system.identity", "remote-prefer"
	explicit := *config
	first, err := prepareOperation(config)
	require.NoError(t, err)
	explicit.Timeout, explicit.InspectMaxAge = 30*time.Second, time.Hour
	require.Same(t, first.preview.resolvedPlugin, first.plugin)
	second, err := prepareOperation(&explicit)
	require.NoError(t, err)
	require.Equal(t, first.plan.PlanHash, second.plan.PlanHash)
	require.Equal(t, 30*time.Second, config.Timeout)
	require.Equal(t, time.Hour, config.InspectMaxAge)
}

func TestPlanSQLEndpointMustBeExplicit(t *testing.T) {
	config := planTestConfig(t)
	config.Mode, config.Command = "sql", ""
	config.SQLEngine, config.SQLStatement = "postgres", "SELECT 1"
	config.SQLDatabase, config.SQLUser = "app", "worker"
	prepared, err := prepareOperation(config)
	require.NoError(t, err)
	require.False(t, prepared.plan.Bindable)
	require.Contains(t, prepared.plan.Unresolved, "database host and port must be explicit")
	config.ExpectPlan = prepared.plan.PlanHash
	_, err = prepareOperation(config)
	require.Equal(t, "plan_unresolved", execution.Classify(err))
}

func TestPlanHashesFreeformBypassReason(t *testing.T) {
	config := planTestConfig(t)
	config.BypassReason = "investigate token=REDACTION_SENTINEL"
	first, err := prepareOperation(config)
	require.NoError(t, err)
	data, err := json.Marshal(first.plan)
	require.NoError(t, err)
	require.NotContains(t, string(data), "REDACTION_SENTINEL")
	config.BypassReason = "a different reason"
	second, err := prepareOperation(config)
	require.NoError(t, err)
	require.NotEqual(t, first.plan.PlanHash, second.plan.PlanHash)
}

func TestPlanPreparationErrorInvalidatesDryRun(t *testing.T) {
	config := planTestConfig(t)
	var runErr error
	output := captureStdout(t, func() {
		runErr = Run([]string{"sshx", "-h=" + config.Host, "--upload=" + filepath.Join(t.TempDir(), "missing"),
			"--to=output", "--dry-run", "--json", "--no-audit"})
	})
	require.NoError(t, runErr)
	var result dryRunPlan
	require.NoError(t, json.Unmarshal(output, &result))
	require.False(t, result.Valid)
	require.False(t, result.WouldConnect)
	require.False(t, result.WouldMutateRemote)
	require.Equal(t, "local_io", result.ConfigCheck.ErrorKind)
}

func TestPlanAdmissionPreservesDomainEnvelopes(t *testing.T) {
	setTestHome(t, t.TempDir())
	cases := []struct {
		name   string
		args   []string
		fields []string
	}{
		{"apply", []string{"apply", "--path=relative", "--from=missing"}, []string{"intent", "remote_path", "changed", "created", "rollback_available"}},
		{"inspect", []string{"inspect", "absent.capability"}, []string{"capability"}},
		{"sql", []string{"sql", "--sql=not valid sql"}, []string{"engine", "database", "statement", "statement_sha256", "has_where"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"sshx"}, tc.args...)
			args = append(args, "-h=192.0.2.1", "--json", "--no-audit")
			var runErr error
			output := captureStdout(t, func() { runErr = Run(args) })
			require.ErrorIs(t, runErr, ErrReported)
			var result map[string]any
			require.NoError(t, json.Unmarshal(output, &result), string(output))
			for _, field := range tc.fields {
				require.Contains(t, result, field)
			}
			require.Equal(t, false, result["executed"])
			require.Equal(t, execution.CompletionNotStarted, result["completion"])
		})
	}
}

// A missing host is the most common operator mistake; admission must surface
// the reason instead of collapsing it into the generic fallback message.
func TestPlanAdmissionReportsMissingHost(t *testing.T) {
	setTestHome(t, t.TempDir())

	var jsonRunErr error
	output := captureStdout(t, func() {
		jsonRunErr = Run([]string{"sshx", "--json", "--no-audit", "uptime"})
	})
	require.ErrorIs(t, jsonRunErr, ErrReported)
	var result map[string]any
	require.NoError(t, json.Unmarshal(output, &result), string(output))
	require.Equal(t, "config", result["error_kind"])
	require.Equal(t, "host is required", result["error"])

	humanErr := Run([]string{"sshx", "--no-audit", "uptime"})
	require.Error(t, humanErr)
	require.Contains(t, humanErr.Error(), "host is required")
	require.NotContains(t, humanErr.Error(), "invalid execution plan")
}

func TestPlanAdmissionReportsUnknownHostTest(t *testing.T) {
	setTestHome(t, t.TempDir())
	var runErr error
	output := captureStdout(t, func() {
		runErr = Run([]string{"sshx", "--host-test=no-such-host", "--dry-run", "--json", "--no-audit"})
	})
	require.NoError(t, runErr)
	var result dryRunPlan
	require.NoError(t, json.Unmarshal(output, &result), string(output))
	require.False(t, result.Valid)
	require.Equal(t, "config", result.ConfigCheck.ErrorKind)
	require.NotEmpty(t, result.ConfigCheck.Message)
}

// An empty SFTP path cannot produce a plan. Admission must reject it as a
// config error, matching the MCP adapter's pre-flight checks, rather than
// admitting the plan and reporting a later connection failure.
func TestPlanAdmissionRejectsEmptySFTPPaths(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := planTestConfig(t)
	cases := []struct {
		name    string
		args    []string
		message string
	}{
		{"upload without local path", []string{"--upload=", "--to=/remote/file"}, "--upload=<local-file> needs a local path"},
		{"upload without destination", []string{"--upload=/etc/hosts"}, "--upload needs a destination: add --to=<remote-path>"},
		{"download without local path", []string{"--download=/remote/file"}, "--download needs a destination: add --to=<local-path>"},
		{"download without remote path", []string{"--download=", "--to=/local/file"}, "--download=<remote-file> needs a remote path"},
		{"list without remote path", []string{"--list="}, "--list=<path> needs a remote path"},
		{"mkdir without remote path", []string{"--mkdir="}, "--mkdir=<path> needs a remote path"},
		{"remove without remote path", []string{"--rm="}, "--rm=<path> needs a remote path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"sshx", "-h=" + config.Host, "--dry-run", "--json", "--no-audit"}, tc.args...)
			var runErr error
			output := captureStdout(t, func() { runErr = Run(args) })
			require.NoError(t, runErr)
			var result dryRunPlan
			require.NoError(t, json.Unmarshal(output, &result), string(output))
			require.False(t, result.Valid)
			require.Equal(t, "config", result.ConfigCheck.ErrorKind)
			require.Equal(t, tc.message, result.ConfigCheck.Message)
			require.False(t, result.WouldConnect)
		})
	}

	t.Run("complete paths stay admitted", func(t *testing.T) {
		local := filepath.Join(t.TempDir(), "upload.txt")
		require.NoError(t, os.WriteFile(local, []byte("payload\n"), 0o600))
		args := []string{"sshx", "-h=" + config.Host, "--dry-run", "--json", "--no-audit",
			"--upload=" + local, "--to=/remote/file"}
		var runErr error
		output := captureStdout(t, func() { runErr = Run(args) })
		require.NoError(t, runErr)
		var result dryRunPlan
		require.NoError(t, json.Unmarshal(output, &result), string(output))
		require.True(t, result.Valid)
		require.True(t, result.WouldConnect)
	})
}
