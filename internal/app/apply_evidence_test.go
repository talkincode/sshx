package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestApplyConditionsPreserveLatestPreconditionObservation(t *testing.T) {
	initial, latest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	run := applyRun{
		config: &sshclient.Config{RemotePath: "/app.conf", ApplyExpectSHA256: initial},
		phase:  "apply", start: time.Now(), payload: []byte{},
		outcome: &sshclient.ApplyOutcome{
			BeforeSHA256: initial, PayloadSHA256: sshclient.SHA256Hex(nil),
			PreconditionSHA256: latest, PreconditionStatus: "failed",
			ChangeState: "unchanged", Executed: applyBool(false), Verification: "not_performed",
		},
	}
	result := run.baseResult(false, -1, "precondition", sshclient.ErrPrecondition)
	require.Equal(t, initial, result.BeforeSHA256)
	require.Equal(t, execution.Condition{
		Kind: "sha256", Subject: "/app.conf", Expected: initial, Observed: latest, Status: "failed",
	}, result.Preconditions[0])
	require.Contains(t, result.Preconditions, execution.Condition{
		Kind: "before_sha256", Subject: "/app.conf", Observed: initial, Status: "passed",
	})
	require.Contains(t, result.Preconditions, execution.Condition{
		Kind: "payload_sha256", Subject: "/app.conf", Observed: sshclient.SHA256Hex(nil), Status: "passed",
	})
	require.Equal(t, []execution.Condition{{
		Kind: "sha256", Subject: "/app.conf", Expected: sshclient.SHA256Hex(nil), Status: "not_performed",
	}}, result.Postconditions)

	run.outcome.PreconditionStatus = "bypassed"
	run.outcome.Verification = "failed"
	run.outcome.ChangeState = "changed"
	run.outcome.Executed = applyBool(true)
	result = run.baseResult(false, -1, "verification_failed", sshclient.ErrApplyVerification)
	require.Equal(t, "bypassed", result.Preconditions[0].Status)
	require.Equal(t, "failed", result.Postconditions[0].Status)
	require.Empty(t, result.Postconditions[0].Observed)
}

func TestApplyPartialFailureFingerprintBindsDomainEvidence(t *testing.T) {
	uid, gid := uint32(42), uint32(7)
	payloadHash := sshclient.SHA256Hex([]byte("new"))
	base := sshclient.ApplyOutcome{
		BeforeSHA256: strings.Repeat("a", 64), PayloadSHA256: payloadHash,
		PreconditionSHA256: strings.Repeat("a", 64), PreconditionStatus: "passed",
		BackupPath: "/backups/app.conf", BackupVerified: true, Mode: "0640", UID: &uid, GID: &gid,
		ChangeState: "unknown", Verification: "unknown", Executed: nil,
		CleanupPending: []string{"/.app.conf.sshx.pending"}, ReplaceMethod: "posix_rename",
	}
	config := &sshclient.Config{
		Mode: "apply", RemotePath: "/app.conf", ExecutionID: "apply-partial-fingerprint",
		ApplyExpectSHA256: base.BeforeSHA256,
	}
	run := &applyRun{config: config, phase: "apply", start: time.Now(), payload: []byte("new"), outcome: &base}
	fingerprint := func(result applyJSONResult) string {
		result.Completion = execution.CompletionUnknown
		document, err := finalizeLifecycle(config, result)
		require.NoError(t, err)
		var digest string
		require.NoError(t, json.Unmarshal(document["execution_fingerprint"], &digest))
		require.NotEmpty(t, digest)
		return digest
	}
	baselineResult := run.baseResult(false, -1, "verification_failed", sshclient.ErrApplyVerification)
	baseline := fingerprint(baselineResult)
	require.Equal(t, baseline, fingerprint(baselineResult))
	for name, mutate := range map[string]func(*sshclient.ApplyOutcome){
		"before":              func(out *sshclient.ApplyOutcome) { out.BeforeSHA256 = strings.Repeat("b", 64) },
		"after":               func(out *sshclient.ApplyOutcome) { out.AfterSHA256 = strings.Repeat("b", 64) },
		"payload":             func(out *sshclient.ApplyOutcome) { out.PayloadSHA256 = strings.Repeat("b", 64) },
		"guard_observation":   func(out *sshclient.ApplyOutcome) { out.PreconditionSHA256 = strings.Repeat("b", 64) },
		"guard_bypass":        func(out *sshclient.ApplyOutcome) { out.PreconditionStatus = "bypassed" },
		"backup_path":         func(out *sshclient.ApplyOutcome) { out.BackupPath = "/backups/other.conf" },
		"backup_verification": func(out *sshclient.ApplyOutcome) { out.BackupVerified = false },
		"mode":                func(out *sshclient.ApplyOutcome) { out.Mode = "0600" },
		"uid":                 func(out *sshclient.ApplyOutcome) { value := uint32(43); out.UID = &value },
		"gid":                 func(out *sshclient.ApplyOutcome) { value := uint32(8); out.GID = &value },
		"cleanup":             func(out *sshclient.ApplyOutcome) { out.CleanupPending = []string{"/.other.sshx.pending"} },
		"replacement":         func(out *sshclient.ApplyOutcome) { out.ReplaceMethod = "sftp_rename" },
	} {
		t.Run(name, func(t *testing.T) {
			outcome := base
			mutate(&outcome)
			run.outcome = &outcome
			result := run.baseResult(false, -1, "verification_failed", sshclient.ErrApplyVerification)
			require.NotEqual(t, baseline, fingerprint(result))
			require.False(t, result.Verified)
			require.Nil(t, result.Executed)
		})
	}
}

func TestApplyUnverifiedCandidateAndCleanupDoNotClaimSuccess(t *testing.T) {
	run := &applyRun{
		config: &sshclient.Config{Mode: "apply", RemotePath: "/app.conf"},
		phase:  "apply", start: time.Now(), payload: []byte("new"),
		outcome: &sshclient.ApplyOutcome{
			BeforeSHA256: strings.Repeat("a", 64), BackupPath: "/backups/candidate",
			ChangeState: "unknown", Executed: nil, Verification: "unknown",
			CleanupPending: []string{"/.app.conf.sshx.pending"},
		},
	}
	result := run.baseResult(false, -1, "verification_failed", sshclient.ErrApplyVerification)
	require.Contains(t, result.Postconditions, execution.Condition{
		Kind: "backup_candidate", Subject: "/backups/candidate", Observed: "unknown", Status: "unknown",
	})
	require.Contains(t, result.Postconditions, execution.Condition{
		Kind: "cleanup", Subject: "/.app.conf.sshx.pending", Expected: "absent", Observed: "unknown", Status: "unknown",
	})
	for _, condition := range result.Postconditions {
		require.NotEqual(t, "backup_sha256", condition.Kind)
	}
	require.False(t, result.Verified)
	require.False(t, result.RollbackAvail)

	run.outcome = &sshclient.ApplyOutcome{
		Created: true, Changed: true, ChangeState: "changed", Executed: applyBool(true),
		Mode: "0600", Verified: true, Verification: "passed", AfterSHA256: sshclient.SHA256Hex(run.payload),
	}
	result = run.baseResult(true, 0, "", nil)
	require.Contains(t, result.Postconditions, execution.Condition{
		Kind: "install_mode", Subject: "/app.conf", Expected: "0600", Status: "not_performed",
	})
	require.True(t, result.Verified, "content verification must not be replaced by inferred metadata verification")
}

func TestEmitApplyJSONIncludesSharedMetadata(t *testing.T) {
	config := &sshclient.Config{Mode: "apply", RemotePath: "/app.conf", ExecutionID: "apply-test-id"}
	result := applyJSONResult{
		SchemaVersion: execution.ResultSchemaVersion, Action: execution.ActionApply,
		Status: execution.StatusFailed, Phase: "apply", Completion: execution.CompletionUnknown,
		ExitCode: -1, ChangeState: "unknown", Executed: nil, Verified: false, Verification: "unknown",
	}
	raw := captureStdout(t, func() { emitApplyJSON(config, result) })
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Equal(t, config.ExecutionID, decoded["execution_id"])
	require.NotEmpty(t, decoded["execution_fingerprint"])
	require.Equal(t, "unknown", decoded["change_state"])
	require.Contains(t, decoded, "executed")
	require.Nil(t, decoded["executed"])
	require.Equal(t, false, decoded["verified"])
	require.Equal(t, "unknown", decoded["verification"])
}
