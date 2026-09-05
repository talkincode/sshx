package app

import (
	"errors"
	"reflect"
	"testing"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestAuditLocalManagementRiskAndEffects(t *testing.T) {
	setTestHome(t, t.TempDir())
	tests := []struct {
		mode, action string
		risk         execution.Risk
		write        bool
	}{
		{"host", "add", execution.RiskMutation, true},
		{"host", "update", execution.RiskMutation, true},
		{"host", "import", execution.RiskMutation, true},
		{"host", "remove", execution.RiskDestructive, true},
		{"host", "list", execution.RiskRead, false},
		{"password", "set", execution.RiskMutation, true},
		{"password", "delete", execution.RiskDestructive, true},
		{"password", "check", execution.RiskRead, false},
		{"password", "list", execution.RiskRead, false},
		{"plugin", "create", execution.RiskMutation, true},
		{"plugin", "trust", execution.RiskMutation, true},
		{"plugin", "remove", execution.RiskDestructive, true},
		{"plugin", "validate", execution.RiskRead, false},
		{"skill", "install", execution.RiskMutation, true},
	}
	for _, tt := range tests {
		t.Run(tt.mode+"/"+tt.action, func(t *testing.T) {
			config := &sshclient.Config{Mode: tt.mode, AuditEnabled: true}
			config.HostAction, config.PasswordAction, config.PluginAction, config.SkillAction =
				tt.action, tt.action, tt.action, tt.action
			recorder := newAuditRecorder(config)
			if recorder.event.Risk != tt.risk || recorder.event.Effects.LocalWrite != tt.write ||
				recorder.event.Effects.RemoteWrite || recorder.event.Effects.Unknown ||
				recorder.event.WouldMutateRemote || recorder.event.WouldWriteLocalState != tt.write {
				t.Fatalf("local management effects = %+v", recorder.event)
			}
		})
	}
}

func TestAuditFinishPreservesLifecycleFinalizedFactsWithoutCompletedFlag(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := &sshclient.Config{
		Mode: "ssh", Host: "original", AuditEnabled: true, AuditOutput: t.TempDir(),
		ReportedErrorKind: "different_error", ReportedError: "must not replace the outcome",
	}
	recorder := newAuditRecorder(config)
	recorder.event.Metadata = execution.Metadata{
		ExecutionID: "invocation", ExecutionFingerprint: "finalized-fingerprint",
		ChangeState: "unknown", Verification: "unknown",
		CancellationCause: "deadline_exceeded", DeadlineScope: "global",
	}
	recorder.event.Phase = "execute"
	recorder.event.Completion = execution.CompletionUnknown
	recorder.event.ExitCode = intPtr(-1)
	recorder.event.Outcome = auditStatus{Status: "failure", ErrorKind: "timeout", Message: "original timeout"}
	before := recorder.event
	config.Host = "mutated"
	if err := recorder.finish(config, errors.New("output delivery failed")); err != nil {
		t.Fatal(err)
	}
	if !recorder.completed || !reflect.DeepEqual(before, recorder.event) {
		t.Fatalf("finalized lifecycle facts changed:\nbefore=%+v\nafter=%+v", before, recorder.event)
	}
	event := readSingleAuditEvent(t, config.AuditOutput)
	outcome, ok := event["outcome"].(map[string]any)
	if !ok || outcome["error_kind"] != "timeout" || event["host_resolved"] != "original" ||
		event["execution_fingerprint"] != "finalized-fingerprint" {
		t.Fatalf("persisted lifecycle facts changed: %+v", event)
	}
}
