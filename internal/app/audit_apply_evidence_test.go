package app

import (
	"errors"
	"testing"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestAuditApplyPreservesBackupOwnershipAndCleanupEvidence(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := &sshclient.Config{Mode: "apply", AuditEnabled: true, AuditOutput: t.TempDir()}
	recorder := newAuditRecorder(config)
	uid, gid := uint32(1000), uint32(1001)
	outcome := &sshclient.ApplyOutcome{
		PayloadSHA256: "payload", ExpectSHA256: "expected", BeforeSHA256: "before",
		BackupPath: "/backup/preimage", BackupVerified: false, Mode: "0640", UID: &uid, GID: &gid,
		CleanupPending: []string{"/owned/staging"}, ReplaceMethod: "posix-rename",
	}
	failure := errors.New("verification failed after publication")
	recorder.recordApplyOutcome(config, sshclient.AuthMethodKey, outcome, nil, "verify", -1, "verification_failed", failure)
	uid, gid = 2000, 2001
	outcome.CleanupPending[0] = "/mutated"
	recorder.event.Metadata = execution.Metadata{
		ChangeState: "unknown", Verification: "failed",
		CancellationCause: "deadline_exceeded", DeadlineScope: "host",
	}
	if err := recorder.finish(config, failure); err != nil {
		t.Fatal(err)
	}
	event := readSingleAuditEvent(t, config.AuditOutput)
	if event["apply_payload_sha256"] != "payload" || event["apply_expect_sha256"] != "expected" ||
		event["apply_backup_verified"] != false || event["apply_mode"] != "0640" ||
		event["apply_uid"] != float64(1000) || event["apply_gid"] != float64(1001) ||
		event["apply_replace_method"] != "posix-rename" {
		t.Fatalf("apply evidence lost: %+v", event)
	}
	cleanup, ok := event["apply_cleanup_pending"].([]any)
	if !ok || len(cleanup) != 1 || cleanup[0] != "/owned/staging" {
		t.Fatalf("cleanup evidence changed: %+v", event["apply_cleanup_pending"])
	}
	if event["cancellation_cause"] != "deadline_exceeded" || event["deadline_scope"] != "host" {
		t.Fatalf("shared cancellation metadata was shadowed: %+v", event)
	}
}

func TestAuditApplyHashesAdmittedEmptyPayload(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := &sshclient.Config{Mode: "apply", AuditEnabled: true}
	recorder := newAuditRecorder(config)
	recorder.recordApplyOutcome(config, sshclient.AuthMethodKey, &sshclient.ApplyOutcome{}, []byte{}, "done", 0, "", nil)
	if recorder.event.ApplyPayloadHash != sshclient.SHA256Hex(nil) {
		t.Fatalf("empty admitted payload has no digest: %+v", recorder.event)
	}
}
