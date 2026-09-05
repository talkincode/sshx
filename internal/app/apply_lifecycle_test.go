package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestApplyRecordsPeerContextOnConnectionFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	config := ParseArgs([]string{
		"sshx", "apply", "-h=127.0.0.1", "-u=operator", "--path=/app.conf",
		"--from=not-reopened", "--no-key", "--insecure-hostkey", "--json", "--no-audit",
	})
	config.Context, config.Password, config.PreparedPayload = ctx, "fixture", []byte("new")
	prepared := &preparedOperation{meta: execution.NewMetadata(nil, "apply-connect-failure")}
	attachPrepared(config, prepared)
	captureStdout(t, func() { require.ErrorIs(t, HandleApply(config, nil), ErrReported) })
	require.Len(t, prepared.meta.Peers, 1)
	require.Equal(t, "target", prepared.meta.Peers[0].Role)
	require.Equal(t, "operator", prepared.meta.Peers[0].User)
	require.Empty(t, prepared.meta.Peers[0].Address)
	require.Empty(t, prepared.meta.Peers[0].HostKeyFingerprint)
}

func TestApplyHumanPathsFinalizeDomainAuditEvidence(t *testing.T) {
	for _, tc := range []struct {
		name         string
		success      bool
		executed     *bool
		state        string
		verification string
		completion   string
	}{
		{"changed", true, applyBool(true), "changed", "passed", "completed"},
		{"noop", true, applyBool(false), "unchanged", "passed", "completed"},
		{"post-write-failure", false, applyBool(true), "changed", "failed", "completed"},
		{"ack-loss", false, nil, "unknown", "unknown", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			setTestHome(t, dir)
			config := &sshclient.Config{
				Mode: "apply", Host: "127.0.0.1", User: "operator",
				RemotePath: "/app.conf", ExecutionID: "apply-human-" + tc.name,
				AuditEnabled: true, AuditOutput: filepath.Join(dir, "audit"),
			}

			audit := newAuditRecorder(config)
			prepared := &preparedOperation{meta: execution.NewMetadata(nil, config.ExecutionID), audit: audit}
			attachPrepared(config, prepared)
			run := &applyRun{
				config: config, audit: audit, start: time.Now(), phase: "apply", payload: []byte("new"),
				outcome: &sshclient.ApplyOutcome{
					BeforeSHA256: strings.Repeat("a", 64), PayloadSHA256: sshclient.SHA256Hex([]byte("new")),
					ChangeState: tc.state, Executed: tc.executed, Verified: tc.success,
					Verification: tc.verification, Changed: tc.state == "changed",
				},
			}
			if tc.success {
				run.outcome.AfterSHA256 = run.outcome.PayloadSHA256
			}
			raw := captureStdout(t, func() {
				if tc.success {
					require.NoError(t, run.succeed())
				} else {
					require.ErrorIs(t, run.fail("verification_failed", sshclient.ErrApplyVerification), sshclient.ErrApplyVerification)
				}
			})
			require.NotContains(t, string(raw), `"schema_version"`, "human mode must not emit a JSON envelope")
			require.True(t, audit.persisted)
			event := readSingleAuditEvent(t, config.AuditOutput)
			require.Equal(t, config.ExecutionID, event["execution_id"])
			require.Equal(t, tc.state, event["change_state"])
			require.Equal(t, tc.success, event["verified"])
			require.Equal(t, tc.verification, event["verification"])
			require.Equal(t, tc.completion, event["completion"])
			require.NotEmpty(t, event["execution_fingerprint"])
			if tc.executed == nil {
				require.Nil(t, event["executed"])
			} else {
				require.Equal(t, *tc.executed, event["executed"])
			}
		})
	}
}
