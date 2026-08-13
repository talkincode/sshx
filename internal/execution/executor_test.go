package execution

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/talkincode/sshx/internal/sshclient"
)

type failDialer struct {
	err    error
	active *atomic.Int64
	peak   *atomic.Int64
	delay  time.Duration
	calls  atomic.Int64
}

func (d *failDialer) Connect(cfg *sshclient.Config) (*sshclient.SSHClient, error) {
	d.calls.Add(1)
	if d.active != nil {
		cur := d.active.Add(1)
		defer d.active.Add(-1)
		if d.peak != nil {
			for {
				max := d.peak.Load()
				if cur <= max || d.peak.CompareAndSwap(max, cur) {
					break
				}
			}
		}
	}
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	if d.err != nil {
		return nil, d.err
	}
	return nil, fmt.Errorf("connect refused to %s", cfg.Host)
}

func TestNormalizeRequest_BypassRequiresReason(t *testing.T) {
	req := &Request{
		Action:  ActionSpec{Kind: ActionCommand, Command: "uptime", Intent: IntentRead},
		Policy:  Policy{SafetyCheckEnabled: true, SafetyBypass: true},
		Targets: TargetSelector{Names: []string{"a"}},
	}
	if err := NormalizeRequest(req); err == nil {
		t.Fatal("expected bypass reason error")
	}
	req.Policy.BypassReason = "approved change window"
	if err := NormalizeRequest(req); err != nil {
		t.Fatalf("NormalizeRequest: %v", err)
	}
}

func TestNormalizeRequest_MutualExclusiveInputs(t *testing.T) {
	req := &Request{
		Action: ActionSpec{
			Kind:       ActionScript,
			ScriptPath: "a.sh",
			Command:    "echo hi",
			Intent:     IntentRead,
		},
		Targets: TargetSelector{Names: []string{"a"}},
	}
	if err := NormalizeRequest(req); err == nil {
		t.Fatal("expected mutual exclusion error")
	}
}

func TestProcessExitCode(t *testing.T) {
	if got := ProcessExitCode(RunCounts{Selected: 3, Succeeded: 3}, nil); got != 0 {
		t.Fatalf("got %d want 0", got)
	}
	if got := ProcessExitCode(RunCounts{Selected: 3, Succeeded: 2, Failed: 1}, nil); got != 1 {
		t.Fatalf("got %d want 1", got)
	}
	if got := ProcessExitCode(RunCounts{}, ErrNoTargets); got != 255 {
		t.Fatalf("got %d want 255", got)
	}
}

func TestExecute_FailFastSkipsRemaining(t *testing.T) {
	var active, peak atomic.Int64
	dialer := &failDialer{
		err:    errors.New("connection refused"),
		active: &active,
		peak:   &peak,
		delay:  20 * time.Millisecond,
	}
	hosts := make([]ResolvedTarget, 8)
	for i := range hosts {
		hosts[i] = ResolvedTarget{Index: i, Alias: fmt.Sprintf("h%d", i), Address: fmt.Sprintf("10.0.0.%d", i+1), Port: "22", User: "u"}
	}
	req := &Request{
		Action: ActionSpec{Kind: ActionCommand, Command: "probe", Intent: IntentRead},
		Limits: Limits{Concurrency: 2, MaxOutputBytesPerTarget: DefaultMaxOutput},
		Policy: Policy{FailureMode: FailureFailFast, SafetyCheckEnabled: true, UseKeyAuth: true},
	}
	var events []Event
	collector := &collectEvents{fn: func(e Event) { events = append(events, e) }}
	out, err := Execute(context.Background(), RunOptions{
		Request:  req,
		Snapshot: TargetSnapshot{Targets: hosts, Count: len(hosts), SelectorDigest: "x"},
		Dialer:   dialer,
		Events:   collector,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Counts.Selected != 8 {
		t.Fatalf("selected=%d", out.Counts.Selected)
	}
	if out.Counts.Failed+out.Counts.Skipped != 8 {
		t.Fatalf("counts=%+v", out.Counts)
	}
	if out.Counts.Skipped == 0 {
		t.Fatalf("expected some skipped under fail_fast, got %+v", out.Counts)
	}
	// Every selected target must have a terminal result.
	if len(out.Results) != 8 {
		t.Fatalf("results=%d", len(out.Results))
	}
	for _, r := range out.Results {
		if r.Status == "" {
			t.Fatalf("empty status: %#v", r)
		}
	}
	if peak.Load() > 2 {
		t.Fatalf("peak concurrency %d > 2", peak.Load())
	}
	// JSONL shape: one started/finished pair envelope.
	var started, finished int
	for _, e := range events {
		switch e.Kind {
		case EventRunStarted:
			started++
		case EventRunFinished:
			finished++
		}
	}
	if started != 1 || finished != 1 {
		t.Fatalf("run envelope started=%d finished=%d", started, finished)
	}
}

func TestBuildError_ChangeUncertainNeverSafeRetry(t *testing.T) {
	info := BuildError(errors.New("timeout"), ErrorKindTimeout, IntentChange, CompletionPartial)
	if info.Retryable {
		t.Fatal("expected retryable=false")
	}
	if info.RetrySafety == RetrySafe {
		t.Fatal("expected non-safe retry safety")
	}
}

func TestCompletionFor(t *testing.T) {
	if got := CompletionFor(PhaseConnect, ErrorKindConnect, false, false); got != CompletionNotStarted {
		t.Fatalf("got %s", got)
	}
	if got := CompletionFor(PhaseExecute, ErrorKindTimeout, true, false); got != CompletionPartial {
		t.Fatalf("got %s", got)
	}
	if got := CompletionFor(PhaseCollect, ErrorKindExitMissing, true, false); got != CompletionCompletedUnconfirmed {
		t.Fatalf("got %s", got)
	}
}

type collectEvents struct {
	mu sync.Mutex
	fn func(Event)
}

func (c *collectEvents) WriteEvent(e Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fn(e)
	return nil
}

func TestPublicPolicyOmitsPassword(t *testing.T) {
	p := PublicPolicy(Policy{SSHPassword: "secret", SudoPasswordKey: "sudo"})
	if p.SSHPasswordProvided != true {
		t.Fatal("expected password provided flag")
	}
	raw := fmt.Sprintf("%#v", p)
	if strings.Contains(raw, "secret") {
		t.Fatal("password leaked into public policy")
	}
}
