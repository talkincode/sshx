package execution

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/talkincode/sshx/internal/sshclient"
)

func TestClassifyTypedBoundariesAndContext(t *testing.T) {
	tests := []struct {
		err  error
		kind string
	}{
		{context.Canceled, ErrorKindCancelled},
		{context.DeadlineExceeded, ErrorKindTimeout},
		{&sshclient.BoundaryError{Kind: ErrorKindProtocol, Err: errors.New("handshake failed")}, ErrorKindProtocol},
		{&sshclient.BoundaryError{Kind: ErrorKindAuth, Err: errors.New("write local file")}, ErrorKindAuth},
		{&sshclient.BoundaryError{Kind: ErrorKindConnect, Err: context.Canceled}, ErrorKindCancelled},
		{&sshclient.BoundaryError{Kind: ErrorKindConnect, Err: context.DeadlineExceeded}, ErrorKindTimeout},
		{&sshclient.BoundaryError{Kind: ErrorKindRemoteIO, Err: sshclient.ErrNoExitStatus}, ErrorKindExitMissing},
		{&sshclient.BoundaryError{Kind: ErrorKindRemoteIO, Err: sshclient.ErrCommandTimeout}, ErrorKindTimeout},
		{&BoundaryError{Kind: "plan_mismatch", Message: "host key differs in plan"}, "plan_mismatch"},
		{&BoundaryError{Kind: "plan_unresolved", Message: "known_hosts unresolved"}, "plan_unresolved"},
		{&BoundaryError{Kind: "verification_failed", Message: "read failed"}, "verification_failed"},
	}
	for _, tt := range tests {
		for _, err := range []error{tt.err, fmt.Errorf("outer dial message: %w", tt.err)} {
			if got := Classify(err); got != tt.kind {
				t.Errorf("Classify(%v)=%q want %q", err, got, tt.kind)
			}
		}
	}
}

func TestBuildErrorUnknownAndRiskyActionsNeverAutoRetryUncertainWork(t *testing.T) {
	for _, intent := range []string{IntentUnknown, IntentChange, "", string(RiskMutation), string(RiskPrivileged), string(RiskDestructive)} {
		for _, completion := range []string{CompletionPartial, CompletionUnknown, CompletionCompletedUnconfirmed, CompletionCompleted} {
			for _, kind := range []string{ErrorKindTimeout, ErrorKindConnect, ErrorKindProtocol, ErrorKindCancelled, "verification_failed"} {
				info := BuildError(errors.New("failure"), kind, intent, completion)
				if info.Retryable || info.RetrySafety == RetrySafe {
					t.Errorf("%s/%s/%s offered an unsafe retry: %+v", intent, completion, kind, info)
				}
			}
		}
	}
	if info := BuildError(errors.New("connection failed"), ErrorKindConnect, IntentUnknown, CompletionNotStarted); !info.Retryable || info.RetrySafety != RetrySafe {
		t.Fatalf("known not-started connection failure lost safe retry: %+v", info)
	}
	for _, kind := range []string{ErrorKindCancelled, "plan_mismatch", "plan_unresolved"} {
		if info := BuildError(errors.New("failure"), kind, IntentRead, CompletionNotStarted); info.Retryable {
			t.Fatalf("non-transient failure became retryable: %+v", info)
		}
	}
}

func TestCompletionForDoesNotInventAcknowledgements(t *testing.T) {
	for _, phase := range []string{PhaseResolve, PhaseAdmission, PhaseConnect, PhaseAuthenticate, PhaseExecute, PhaseCollect} {
		for _, kind := range []string{"", ErrorKindTimeout, ErrorKindCancelled, ErrorKindProtocol, ErrorKindExitMissing} {
			if got := CompletionFor(phase, kind, false, false); got != CompletionNotStarted {
				t.Errorf("phase=%s kind=%s without start became %s", phase, kind, got)
			}
			if got := CompletionFor(phase, kind, true, true); got != CompletionCompleted {
				t.Errorf("phase=%s kind=%s discarded observed exit: %s", phase, kind, got)
			}
		}
	}
	if got := CompletionFor(PhaseExecute, "", true, false); got != CompletionUnknown {
		t.Fatalf("unobserved exit became %s", got)
	}
	for _, kind := range []string{"", ErrorKindTimeout, ErrorKindCancelled, ErrorKindProtocol, ErrorKindConnect} {
		if got := CompletionForAttempt(PhaseExecute, kind, true, false, false); got != CompletionUnknown {
			t.Fatalf("attempted exec without acknowledgement became %s for %s", got, kind)
		}
		if got := CompletionForAttempt(PhaseExecute, kind, true, false, true); got != CompletionCompleted {
			t.Fatalf("observed exit became %s for %s", got, kind)
		}
	}
}

func TestClassify_InvalidBindIsConfig(t *testing.T) {
	if got := Classify(sshclient.ErrInvalidBind); got != ErrorKindConfig {
		t.Fatalf("Classify(ErrInvalidBind) = %q", got)
	}
	wrapped := fmt.Errorf("failed to dial: %w", sshclient.ErrInvalidBind)
	if got := Classify(wrapped); got != ErrorKindConfig {
		t.Fatalf("Classify(wrapped dial) = %q, want config not connect", got)
	}
}

func TestBuildDryRunPlan_InvalidBind(t *testing.T) {
	req := &Request{
		Action:  ActionSpec{Kind: ActionCommand, Command: "uptime", Intent: IntentRead},
		Targets: TargetSelector{Names: []string{"edge"}},
	}
	hosts := []HostRecord{{Name: "edge", Address: "203.0.113.1", Bind: "sshx-no-such-iface"}}
	plan := BuildDryRunPlan(req, hosts, HostRecord{}, nil)
	if plan.Valid {
		t.Fatal("invalid bind must fail dry-run")
	}
	if plan.Error == nil || plan.Error.Kind != ErrorKindConfig {
		t.Fatalf("error = %#v", plan.Error)
	}
	if plan.WouldConnect {
		t.Fatal("invalid bind must not connect")
	}
}
