package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func planTestConfig(t *testing.T) *sshclient.Config {
	t.Helper()
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("SSHX_HOME", filepath.Join(home, "runtime"))
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	privatePath := filepath.Join(home, "key")
	require.NoError(t, os.WriteFile(privatePath+".pub", ssh.MarshalAuthorizedKey(key), 0o600))
	trust := filepath.Join(home, "known_hosts")
	require.NoError(t, os.WriteFile(trust, []byte(knownhosts.Line([]string{"192.0.2.1"}, key)+"\n"), 0o600))
	return &sshclient.Config{
		Host: "192.0.2.1", Port: "22", User: "worker", Mode: "ssh", Command: "uname -a",
		KeyPath: privatePath, KnownHostsPath: trust, UseKeyAuth: true, SafetyCheck: true,
		DryRun: true, JSONOutput: true,
	}
}

func TestPlanPreparationReadsPublicIdentityOnly(t *testing.T) {
	config := planTestConfig(t)
	// There is no private key. A preview must not try to load one.
	prepared, err := prepareOperation(config)
	require.NoError(t, err)
	require.True(t, prepared.plan.Bindable, prepared.plan.Unresolved)
	require.NotEmpty(t, prepared.plan.PlanHash)
	require.Equal(t, execution.RiskRead, prepared.plan.Risk)
	root, err := GetSettingsDir()
	require.NoError(t, err)
	_, err = os.Stat(root)
	require.True(t, os.IsNotExist(err))
}

func TestPlanPreparationRejectsChangedInputsBeforeCredentials(t *testing.T) {
	config := planTestConfig(t)
	prepared, err := prepareOperation(config)
	require.NoError(t, err)
	config.ExpectPlan = prepared.plan.PlanHash
	config.SSHPasswordKey = "must-not-be-read"
	config.DryRun = false
	_, err = prepareOperation(config)
	var boundary *execution.BoundaryError
	require.ErrorAs(t, err, &boundary)
	require.Equal(t, "plan_mismatch", boundary.Kind)
}

func TestPlanApplySourcePathIsNotPayloadIdentity(t *testing.T) {
	config := planTestConfig(t)
	config.Mode, config.RemotePath = "apply", "/srv/config"
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")
	require.NoError(t, os.WriteFile(first, []byte("same bytes"), 0o600))
	require.NoError(t, os.WriteFile(second, []byte("same bytes"), 0o600))
	config.LocalPath = first
	a, err := prepareOperation(config)
	require.NoError(t, err)
	copyConfig := *config
	copyConfig.LocalPath, copyConfig.PreparedPayload = second, nil
	b, err := prepareOperation(&copyConfig)
	require.NoError(t, err)
	require.Equal(t, a.plan.PlanHash, b.plan.PlanHash)
	require.NoError(t, os.WriteFile(first, []byte("replaced"), 0o600))
	require.Equal(t, []byte("same bytes"), config.PreparedPayload)
	copyConfig.PreparedPayload = nil
	copyConfig.LocalPath = first
	copyConfig.ExpectPlan = a.plan.PlanHash
	_, err = prepareOperation(&copyConfig)
	require.Error(t, err)
	require.Equal(t, "plan_mismatch", execution.Classify(err))
}

func TestPlanCLIFlagsStayBeforeRemoteBoundary(t *testing.T) {
	for _, verb := range []string{"run", "apply", "sql", "inspect"} {
		config := ParseArgs([]string{"sshx", verb, "--expect-plan=sha256:abc", "--host-timeout=5s", "--global-timeout=1m"})
		require.Equal(t, "sha256:abc", config.ExpectPlan)
		require.Positive(t, config.HostTimeout)
		require.Positive(t, config.GlobalTimeout)
	}
	config := ParseArgs([]string{"sshx", "-h=server", "--", "echo", "--expect-plan=remote"})
	require.Empty(t, config.ExpectPlan)
	require.Equal(t, "echo --expect-plan=remote", config.Command)
	config = ParseArgs([]string{"sshx", "run", "--max-failures=0"})
	require.NotEmpty(t, config.ArgumentError)
}

func TestPlanMismatchStructuredFailure(t *testing.T) {
	config := planTestConfig(t)
	plan, err := prepareOperation(config)
	require.NoError(t, err)
	args := []string{"sshx", "-h=" + config.Host, "-p=" + config.Port, "-u=" + config.User,
		"-i=" + config.KeyPath, "--known-hosts=" + config.KnownHostsPath, "--json", "--no-audit",
		"--expect-plan=" + plan.plan.PlanHash, "--", "whoami"}
	var runErr error
	raw := captureStdout(t, func() { runErr = Run(args) })
	require.ErrorIs(t, runErr, ErrReported)
	var result map[string]any
	require.NoError(t, json.Unmarshal(raw, &result), string(raw))
	require.Equal(t, "plan_mismatch", result["error_kind"])
	require.Equal(t, false, result["executed"])
	require.Equal(t, "unchanged", result["change_state"])
}
