package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/talkincode/sshx/internal/sshclient"
)

type lifecycleDialer func(*sshclient.Config) (*sshclient.SSHClient, error)

func (d lifecycleDialer) Connect(cfg *sshclient.Config) (*sshclient.SSHClient, error) {
	return d(cfg)
}

type lifecycleEvents func(Event) error

func (w lifecycleEvents) WriteEvent(ev Event) error { return w(ev) }

type lifecycleSecrets struct {
	ssh  func(string) (string, error)
	sudo func(string) (string, error)
}

func (s lifecycleSecrets) GetSSHPassword(key string) (string, error) { return s.ssh(key) }
func (s lifecycleSecrets) GetSudoPassword(key string) (string, error) {
	return s.sudo(key)
}

func lifecycleRequest() *Request {
	return &Request{
		Action:     ActionSpec{Kind: ActionCommand, Command: "uptime", Intent: IntentRead},
		Limits:     Limits{Concurrency: 1},
		Policy:     Policy{SafetyCheckEnabled: true},
		JSONOutput: true,
	}
}

func lifecycleSnapshot(n int) TargetSnapshot {
	snap := TargetSnapshot{Count: n, SelectorDigest: "selector"}
	for i := 0; i < n; i++ {
		snap.Targets = append(snap.Targets, ResolvedTarget{
			Index: i, Address: fmt.Sprintf("192.0.2.%d", i+1), Port: "22", User: "test",
		})
	}
	return snap
}

func assertTerminalEvents(t *testing.T, events []Event, out RunOutcome) {
	t.Helper()
	finished := make(map[string]int)
	started := make(map[string]int)
	for i, ev := range events {
		if ev.Sequence != int64(i+1) {
			t.Fatalf("sequence[%d]=%d", i, ev.Sequence)
		}
		if ev.RunID != out.RunID {
			t.Fatalf("event run ID %q, want %q", ev.RunID, out.RunID)
		}
		switch ev.Kind {
		case EventTargetStarted:
			started[ev.ExecutionID]++
		case EventTargetFinished:
			finished[ev.ExecutionID]++
			if ev.Result == nil || !reflect.DeepEqual(ev.Metadata, ev.Result.Metadata) {
				t.Fatalf("terminal event metadata differs from result: %+v", ev)
			}
		}
	}
	if len(events) == 0 || events[0].Kind != EventRunStarted || events[len(events)-1].Kind != EventRunFinished {
		t.Fatal("missing run envelope")
	}
	last := events[len(events)-1]
	if !reflect.DeepEqual(last.Metadata, out.Metadata) || last.Counts == nil || *last.Counts != out.Counts {
		t.Fatalf("final event does not match outcome: %+v", last)
	}
	if len(finished) != out.Counts.Selected || len(started) != out.Counts.Started {
		t.Fatalf("terminal/started coverage %d/%d, counts=%+v", len(finished), len(started), out.Counts)
	}
	fingerprints := make([]string, 0, len(out.Results))
	for _, result := range out.Results {
		fingerprints = append(fingerprints, result.ExecutionFingerprint)
		if finished[result.ExecutionID] != 1 || started[result.ExecutionID] > 1 {
			t.Fatalf("duplicate or missing target event: %+v", result)
		}
		if result.ParentExecutionID != out.RunID || result.ExecutionFingerprint == "" || result.FinishedAt == "" {
			t.Fatalf("missing finalized identity: %+v", result)
		}
		if result.Status == StatusSkipped && started[result.ExecutionID] != 0 {
			t.Fatalf("skipped target was started: %+v", result)
		}
	}
	sort.Strings(fingerprints)
	if !reflect.DeepEqual(out.TargetFingerprints, fingerprints) {
		t.Fatalf("parent metadata omitted finalized target fingerprints: %+v", out.Metadata)
	}
}

func TestExecuteFailureBudgetAtomicAdmission(t *testing.T) {
	for _, budget := range []int{1, 3} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			for iteration := 0; iteration < 20; iteration++ {
				req := lifecycleRequest()
				req.Limits.Concurrency = 4
				req.Policy.MaxFailures = budget
				initial := make(chan struct{}, 4)
				release := make(chan struct{})
				var calls atomic.Int64
				dialer := lifecycleDialer(func(*sshclient.Config) (*sshclient.SSHClient, error) {
					if calls.Add(1) <= 4 {
						initial <- struct{}{}
						<-release
					}
					return nil, &sshclient.BoundaryError{Kind: ErrorKindConnect, Err: io.EOF}
				})
				var events []Event
				done := make(chan RunOutcome, 1)
				errs := make(chan error, 1)
				go func() {
					out, err := Execute(context.Background(), RunOptions{
						Request: req, Snapshot: lifecycleSnapshot(24), Dialer: dialer,
						Events: lifecycleEvents(func(ev Event) error {
							events = append(events, ev)
							runtime.Gosched()
							return nil
						}),
					})
					done <- out
					errs <- err
				}()
				for i := 0; i < 4; i++ {
					select {
					case <-initial:
					case <-time.After(5 * time.Second):
						close(release)
						t.Fatal("initial admitted cohort did not start")
					}
				}
				close(release)
				var out RunOutcome
				select {
				case out = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("fanout did not finish")
				}
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
				// Completing failures and admitting a replacement are atomic:
				// at most concurrency-1 previously admitted failures can overshoot.
				if calls.Load() > int64(budget+req.Limits.Concurrency-1) || calls.Load() < 4 {
					t.Fatalf("admitted %d targets for budget %d", calls.Load(), budget)
				}
				if out.Counts.Failed != int(calls.Load()) || out.Counts.Skipped != 24-int(calls.Load()) {
					t.Fatalf("bad counts: %+v calls=%d", out.Counts, calls.Load())
				}
				assertTerminalEvents(t, events, out)
			}
		})
	}
}

func TestExecuteFailFastDoesNotCancelAdmittedTargets(t *testing.T) {
	req := lifecycleRequest()
	req.Limits.Concurrency = 2
	req.Policy.FailureMode = FailureFailFast
	admitted := make(chan struct{}, 2)
	releaseFailure := make(chan struct{})
	releaseActive := make(chan struct{})
	failedEvent := make(chan struct{})
	var activeCancelled atomic.Bool
	dialer := lifecycleDialer(func(cfg *sshclient.Config) (*sshclient.SSHClient, error) {
		admitted <- struct{}{}
		if cfg.Host == "192.0.2.1" {
			<-releaseFailure
		} else {
			select {
			case <-cfg.Context.Done():
				activeCancelled.Store(true)
			case <-releaseActive:
			}
		}
		return nil, io.EOF
	})
	done := make(chan RunOutcome, 1)
	errs := make(chan error, 1)
	go func() {
		out, err := Execute(context.Background(), RunOptions{
			Request: req, Snapshot: lifecycleSnapshot(6), Dialer: dialer,
			Events: lifecycleEvents(func(ev Event) error {
				if ev.Kind == EventTargetFinished && ev.Target.Index == 0 {
					close(failedEvent)
				}
				return nil
			}),
		})
		errs <- err
		done <- out
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-admitted:
		case <-time.After(5 * time.Second):
			close(releaseFailure)
			close(releaseActive)
			t.Fatal("targets not admitted")
		}
	}
	close(releaseFailure)
	select {
	case <-failedEvent:
	case <-time.After(5 * time.Second):
		close(releaseActive)
		t.Fatal("failure was not published")
	}
	close(releaseActive)
	select {
	case out := <-done:
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		if activeCancelled.Load() || out.Counts.Started != 2 || out.Counts.Failed != 2 || out.Counts.Skipped != 4 {
			t.Fatalf("admission-only fail fast violated: %+v", out.Counts)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not finish")
	}
}

func TestExecuteCancellationAndGlobalDeadline(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			req := lifecycleRequest()
			req.Limits.Concurrency = 2
			if deadline {
				req.Limits.GlobalTimeout = 50 * time.Millisecond
				req.Limits.HostTimeout = time.Second
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int64
			dialer := lifecycleDialer(func(cfg *sshclient.Config) (*sshclient.SSHClient, error) {
				if calls.Add(1) == 2 && !deadline {
					cancel()
				}
				<-cfg.Context.Done()
				return nil, cfg.Context.Err()
			})
			var events []Event
			out, err := Execute(ctx, RunOptions{
				Request: req, Snapshot: lifecycleSnapshot(8), Dialer: dialer,
				Events: lifecycleEvents(func(ev Event) error { events = append(events, ev); return nil }),
			})
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 2 || out.Counts.Started != 2 || out.Counts.Failed != 2 || out.Counts.Skipped != 6 {
				t.Fatalf("deadline/cancellation admitted more work: %+v calls=%d", out.Counts, calls.Load())
			}
			kind := ErrorKindCancelled
			cause, scope := ErrorKindCancelled, ""
			if deadline {
				kind = ErrorKindTimeout
				cause, scope = "deadline_exceeded", "global"
			}
			if out.CancellationCause != cause || out.DeadlineScope != scope {
				t.Fatalf("run context evidence missing: %+v", out.Metadata)
			}
			for _, res := range out.Results {
				if res.Completion != CompletionNotStarted || res.Error == nil || res.Error.Kind != kind ||
					res.Executed == nil || *res.Executed || res.CancellationCause != cause || res.DeadlineScope != scope {
					t.Fatalf("unstarted cancellation evidence: %+v", res)
				}
			}
			assertTerminalEvents(t, events, out)
		})
	}
}

func TestExecuteHostDeadlineResetsOnlyForNextHost(t *testing.T) {
	req := lifecycleRequest()
	req.Limits.HostTimeout = 20 * time.Millisecond
	req.Limits.GlobalTimeout = time.Second
	var calls atomic.Int64
	var deadlines []time.Time
	dialer := lifecycleDialer(func(cfg *sshclient.Config) (*sshclient.SSHClient, error) {
		calls.Add(1)
		deadline, ok := cfg.Context.Deadline()
		if !ok {
			return nil, errors.New("host context has no deadline")
		}
		deadlines = append(deadlines, deadline)
		<-cfg.Context.Done()
		return nil, cfg.Context.Err()
	})
	out, err := Execute(context.Background(), RunOptions{
		Request: req, Snapshot: lifecycleSnapshot(2), Dialer: dialer, Events: noopEvents{},
	})
	if err != nil || calls.Load() != 2 || out.Counts.Failed != 2 {
		t.Fatalf("host limit must not cancel the run: %+v %v", out.Counts, err)
	}
	if len(deadlines) != 2 || !deadlines[1].After(deadlines[0]) {
		t.Fatalf("host deadlines=%v", deadlines)
	}
	if out.CancellationCause != "" || out.DeadlineScope != "" {
		t.Fatalf("host deadlines falsely marked the run canceled: %+v", out.Metadata)
	}
	for _, res := range out.Results {
		if res.Error == nil || res.Error.Kind != ErrorKindTimeout || res.Completion != CompletionNotStarted ||
			res.CancellationCause != "deadline_exceeded" || res.DeadlineScope != "host" {
			t.Fatalf("wrong host timeout result: %+v", res)
		}
	}
}

func TestExecutePreservesEarlierInheritedDeadlineScope(t *testing.T) {
	req := lifecycleRequest()
	req.Limits.GlobalTimeout, req.Limits.HostTimeout = time.Second, 2*time.Second
	ctx, cancel := WithScopedTimeout(context.Background(), 20*time.Millisecond, "global")
	defer cancel()
	out, err := Execute(ctx, RunOptions{
		Request: req, Snapshot: lifecycleSnapshot(3), Events: noopEvents{},
		Dialer: lifecycleDialer(func(cfg *sshclient.Config) (*sshclient.SSHClient, error) {
			<-cfg.Context.Done()
			return nil, cfg.Context.Err()
		}),
	})
	if err != nil || out.CancellationCause != "deadline_exceeded" || out.DeadlineScope != "global" {
		t.Fatalf("inherited run deadline lost its original scope: %+v %v", out.Metadata, err)
	}
	for _, res := range out.Results {
		if res.CancellationCause != out.CancellationCause || res.DeadlineScope != out.DeadlineScope {
			t.Fatalf("target lost the earlier global scope: %+v", res.Metadata)
		}
	}
}

func TestExecuteOneObservesDeadlineBeforeCleanup(t *testing.T) {
	req := lifecycleRequest()
	req.Limits.HostTimeout = 20 * time.Millisecond
	target := lifecycleSnapshot(1).Targets[0]
	res := executeOne(context.Background(), RunOptions{
		Request: req,
		Dialer: lifecycleDialer(func(cfg *sshclient.Config) (*sshclient.SSHClient, error) {
			<-cfg.Context.Done()
			return nil, cfg.Context.Err()
		}),
	}, target)
	if res.CancellationCause != "deadline_exceeded" || res.DeadlineScope != "host" {
		t.Fatalf("direct target execution missed deadline evidence: %+v", res.Metadata)
	}

	req.Limits.HostTimeout, req.Limits.GlobalTimeout = time.Second, time.Second
	out, err := Execute(context.Background(), RunOptions{
		Request: req, Snapshot: lifecycleSnapshot(1), Events: noopEvents{}, Dialer: &failDialer{err: io.EOF},
	})
	if err != nil || out.CancellationCause != "" || out.DeadlineScope != "" ||
		out.Results[0].CancellationCause != "" || out.Results[0].DeadlineScope != "" {
		t.Fatalf("ordinary context cleanup was misreported as cancellation: %+v %v", out, err)
	}
}

func TestExecuteAlreadyCancelledStillFinishesEveryTarget(t *testing.T) {
	req := lifecycleRequest()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dialer := &failDialer{}
	var events []Event
	out, err := Execute(ctx, RunOptions{
		Request: req, Snapshot: lifecycleSnapshot(5), Dialer: dialer,
		Events: lifecycleEvents(func(ev Event) error { events = append(events, ev); return nil }),
	})
	if err != nil || dialer.calls.Load() != 0 || out.Counts.Skipped != 5 || out.Counts.Started != 0 {
		t.Fatalf("canceled run=%+v err=%v", out.Counts, err)
	}
	assertTerminalEvents(t, events, out)
}

func TestExecuteChecksContextAfterEverySecretRead(t *testing.T) {
	for _, duringSSH := range []bool{true, false} {
		t.Run(fmt.Sprintf("SSH=%t", duringSSH), func(t *testing.T) {
			req := lifecycleRequest()
			req.Action.Command = "sudo id"
			req.Policy.SSHPasswordKey = "login"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sshCalls, sudoCalls := 0, 0
			secrets := lifecycleSecrets{
				ssh: func(string) (string, error) {
					sshCalls++
					if duringSSH {
						cancel()
					}
					return "never-serialized", nil
				},
				sudo: func(string) (string, error) {
					sudoCalls++
					cancel()
					return "never-serialized", nil
				},
			}
			dialer := &failDialer{}
			out, err := Execute(ctx, RunOptions{
				Request: req, Snapshot: lifecycleSnapshot(1), Secrets: secrets, Dialer: dialer, Events: noopEvents{},
			})
			if err != nil || sshCalls != 1 || dialer.calls.Load() != 0 || (duringSSH && sudoCalls != 0) {
				t.Fatalf("work continued after a canceled secret read: ssh=%d sudo=%d dial=%d err=%v",
					sshCalls, sudoCalls, dialer.calls.Load(), err)
			}
			res := out.Results[0]
			if res.Error == nil || res.Error.Kind != ErrorKindCancelled || res.Completion != CompletionNotStarted {
				t.Fatalf("wrong cancellation classification: %+v", res)
			}
		})
	}
}

func TestExecuteEventDeliveryFailureRetainsOutcomes(t *testing.T) {
	for _, failedKind := range []string{EventRunStarted, EventTargetStarted, EventTargetFinished, EventRunFinished} {
		t.Run(failedKind, func(t *testing.T) {
			req := lifecycleRequest()
			req.ExecutionID = "stable-run"
			run := func(events EventWriter) (RunOutcome, error) {
				return Execute(context.Background(), RunOptions{
					Request: req, Snapshot: lifecycleSnapshot(1), Events: events,
					Dialer: &failDialer{err: &sshclient.BoundaryError{Kind: ErrorKindConnect, Err: io.EOF}},
				})
			}
			expected, err := run(noopEvents{})
			if err != nil {
				t.Fatal(err)
			}
			broken, attemptedAfterBroken := false, false
			out, err := run(lifecycleEvents(func(ev Event) error {
				if broken {
					attemptedAfterBroken = true
				}
				if ev.Kind == failedKind {
					broken = true
					return io.ErrClosedPipe
				}
				return nil
			}))
			if !errors.Is(err, ErrLocalIO) || !errors.Is(err, io.ErrClosedPipe) || Classify(err) != ErrorKindLocalIO {
				t.Fatalf("missing delivery error: %v", err)
			}
			if attemptedAfterBroken || out.Single == nil || out.Counts != expected.Counts ||
				out.Single.ErrorKind != ErrorKindConnect || out.Single.ExecutionFingerprint != expected.Single.ExecutionFingerprint ||
				out.ExecutionFingerprint != expected.ExecutionFingerprint {
				t.Fatalf("delivery failure rewrote or discarded remote evidence: %+v", out)
			}
		})
	}
}

func TestExecuteSequenceIdentityAndNonContiguousIndices(t *testing.T) {
	req := lifecycleRequest()
	req.ExecutionID, req.RequestID = "caller-execution", "caller-correlation"
	req.Limits.Concurrency = 8
	req.Plan = &Plan{PlanHash: Digest([]byte("plan")), Risk: RiskMutation, Effects: Effects{Unknown: true}}
	snap := lifecycleSnapshot(20)
	for i := range snap.Targets {
		snap.Targets[i].Index = 100 - 2*i
	}
	var events []Event
	out, err := Execute(context.Background(), RunOptions{
		Request: req, Snapshot: snap, Dialer: &failDialer{err: io.EOF},
		Events: lifecycleEvents(func(ev Event) error { events = append(events, ev); return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.RunID != req.ExecutionID || out.ExecutionID != req.ExecutionID {
		t.Fatalf("execution ID not reused: %+v", out)
	}
	assertTerminalEvents(t, events, out)
	for i, res := range out.Results {
		if res.Target.Index != snap.Targets[i].Index ||
			res.ExecutionID != targetExecutionID(req.ExecutionID, snap.Targets[i]) {
			t.Fatalf("result order or identity changed: %+v", res)
		}
	}
	for _, ev := range events {
		if ev.PlanHash != req.Plan.PlanHash || ev.Risk != req.Plan.Risk ||
			ev.Effects != req.Plan.Effects || ev.RequestID != req.RequestID {
			t.Fatalf("event lost plan/correlation: %+v", ev)
		}
	}
}

func TestExecutionIDsDoNotUseCallerRequestID(t *testing.T) {
	var ids []string
	for i := 0; i < 2; i++ {
		req := lifecycleRequest()
		req.RequestID = "same-correlation"
		out, err := Execute(context.Background(), RunOptions{
			Request: req, Snapshot: lifecycleSnapshot(1), Dialer: &failDialer{}, Events: noopEvents{},
		})
		if err != nil || out.RunID == "" || out.Single == nil || out.Single.RequestID != req.RequestID {
			t.Fatalf("run identity: %+v err=%v", out, err)
		}
		ids = append(ids, out.RunID)
	}
	if ids[0] == ids[1] {
		t.Fatal("separate executions reused caller correlation as identity")
	}
	target := lifecycleSnapshot(1).Targets[0]
	first := targetExecutionID(ids[0], target)
	if first == targetExecutionID(ids[1], target) {
		t.Fatal("target ID omitted parent")
	}
	target.Index++
	if first == targetExecutionID(ids[0], target) {
		t.Fatal("target ID omitted index")
	}
	target.Index--
	target.Address = "192.0.2.200"
	if first == targetExecutionID(ids[0], target) {
		t.Fatal("target ID omitted address")
	}
}

func TestExecuteOnePassesLimitsIdentityAndTrust(t *testing.T) {
	req := lifecycleRequest()
	req.ExecutionID = "parent"
	req.Limits = Limits{
		Concurrency: 1, Timeout: time.Second, HostTimeout: 2 * time.Second,
		GlobalTimeout: 3 * time.Second, MaxOutputBytesPerTarget: 7, MaxPayloadBytes: 11,
	}
	req.Policy.MaxFailures = 2
	req.Plan = &Plan{PlanHash: Digest([]byte("plan")), Risk: RiskMutation, Effects: Effects{Unknown: true}}
	target := lifecycleSnapshot(1).Targets[0]
	target.KnownHostsData = []byte("snapshot")
	target.ExpectedKeyFingerprint = "expected-signer"
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "passed")
	var got *sshclient.Config
	res := executeOne(ctx, RunOptions{
		Request: req,
		Dialer: lifecycleDialer(func(cfg *sshclient.Config) (*sshclient.SSHClient, error) {
			got = cfg
			return nil, &sshclient.BoundaryError{Kind: ErrorKindHostKey, Err: io.EOF}
		}),
	}, target)
	if got == nil || got.Context.Value(key{}) != "passed" {
		t.Fatal("root context not passed")
	}
	if _, ok := got.Context.Deadline(); !ok {
		t.Fatal("host deadline not passed")
	}
	if got.MaxOutputBytes != 7 || got.MaxPayloadBytes != 11 || got.Timeout != time.Second ||
		got.HostTimeout != 2*time.Second || got.GlobalTimeout != 3*time.Second || got.MaxFailures != 2 ||
		got.PlanHash != req.Plan.PlanHash || got.ExecutionID != res.ExecutionID || got.Risk != string(req.Plan.Risk) ||
		string(got.KnownHostsData) != "snapshot" || got.ExpectedKeyFingerprint != target.ExpectedKeyFingerprint {
		t.Fatalf("configuration projection lost execution semantics: %+v", got)
	}
	if res.Phase != PhaseAuthenticate || res.Completion != CompletionNotStarted || res.Error.Kind != ErrorKindHostKey ||
		res.Executed == nil || *res.Executed || res.ChangeState != "unchanged" || res.ExecutionFingerprint == "" {
		t.Fatalf("host key failure execution evidence: %+v", res)
	}
	raw, err := json.Marshal(res)
	if err != nil || strings.Contains(string(raw), "snapshot") || strings.Contains(string(raw), "expected-signer") {
		t.Fatalf("private snapshots serialized: %s %v", raw, err)
	}
}

func TestExecuteOneDoesNotInferExecutionFromConnection(t *testing.T) {
	req := lifecycleRequest()
	target := lifecycleSnapshot(1).Targets[0]
	res := executeOne(context.Background(), RunOptions{
		Request: req,
		Dialer:  lifecycleDialer(sshclient.NewSSHClient),
	}, target)
	if res.Status != StatusFailed || res.Completion != CompletionNotStarted || res.Executed == nil || *res.Executed {
		t.Fatalf("client construction was mistaken for command start: %+v", res)
	}
}

func TestApplyExecResultUsesAcknowledgements(t *testing.T) {
	tests := []struct {
		name       string
		result     sshclient.ExecResult
		err        error
		kind       string
		completion string
		executed   bool
		succeeded  bool
	}{
		{"session failure", sshclient.ExecResult{ExitCode: -1}, io.EOF, ErrorKindUnknown, CompletionNotStarted, false, false},
		{"before start timeout", sshclient.ExecResult{ExitCode: -1}, context.DeadlineExceeded, ErrorKindTimeout, CompletionNotStarted, false, false},
		{"started timeout", sshclient.ExecResult{ExitCode: -1, Started: true}, context.DeadlineExceeded, ErrorKindTimeout, CompletionPartial, true, false},
		{"started cancel", sshclient.ExecResult{ExitCode: -1, Started: true}, context.Canceled, ErrorKindCancelled, CompletionPartial, true, false},
		{"exit missing", sshclient.ExecResult{ExitCode: -1, Started: true}, sshclient.ErrNoExitStatus, ErrorKindExitMissing, CompletionCompletedUnconfirmed, true, false},
		{"transport lost", sshclient.ExecResult{ExitCode: -1, Started: true}, &sshclient.BoundaryError{Kind: ErrorKindProtocol, Err: io.EOF}, ErrorKindProtocol, CompletionUnknown, true, false},
		{"exit before cancel", sshclient.ExecResult{ExitCode: 0, Started: true, ExitObserved: true}, context.Canceled, ErrorKindCancelled, CompletionCompleted, true, false},
		{"success", sshclient.ExecResult{ExitCode: 0, Started: true, ExitObserved: true}, nil, "", CompletionCompleted, true, true},
		{"remote exit 255", sshclient.ExecResult{ExitCode: 255, Started: true, ExitObserved: true}, nil, ErrorKindRemoteExit, CompletionCompleted, true, false},
		{"missing acknowledgement", sshclient.ExecResult{ExitCode: 0}, nil, ErrorKindProtocol, CompletionNotStarted, false, false},
		{"missing exit evidence", sshclient.ExecResult{ExitCode: -1, Started: true}, nil, ErrorKindExitMissing, CompletionCompletedUnconfirmed, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := lifecycleRequest()
			req.Action.Command = "opaque-wrapper"
			res := TargetResult{Metadata: requestMetadata(req, "execution"), Phase: PhaseExecute}
			tt.result.Stdout, tt.result.Stderr = "out", "err"
			tt.result.StdoutTruncated, tt.result.StderrTruncated = true, true
			applyExecResult(&res, req, tt.result, tt.err)
			finishTargetMetadata(&res)
			kind := ""
			if res.Error != nil {
				kind = res.Error.Kind
			}
			if kind != tt.kind || res.Completion != tt.completion ||
				res.Executed == nil || *res.Executed != tt.executed ||
				(res.Status == StatusSucceeded) != tt.succeeded || res.ExitCode != tt.result.ExitCode {
				t.Fatalf("unexpected execution evidence: %+v", res)
			}
			if res.Stdout != "out" || res.Stderr != "err" || !res.StdoutTruncated || !res.StderrTruncated {
				t.Fatalf("partial output was discarded: %+v", res)
			}
			if tt.executed && (res.Verified || res.ChangeState != "unknown") {
				t.Fatalf("opaque command falsely verified: %+v", res)
			}
			if res.Error != nil && tt.executed && (tt.completion == CompletionPartial || tt.completion == CompletionUnknown) &&
				(res.Error.Retryable || res.Error.RetrySafety == RetrySafe) {
				t.Fatalf("opaque command trusted caller intent for retry: %+v", res.Error)
			}
		})
	}
}

func TestApplyExecResultLostStartAcknowledgementIsUnknown(t *testing.T) {
	for _, err := range []error{
		nil, context.Canceled, context.DeadlineExceeded, io.EOF,
		&sshclient.BoundaryError{Kind: ErrorKindProtocol, Err: io.EOF},
		&sshclient.BoundaryError{Kind: ErrorKindConnect, Err: io.EOF},
	} {
		t.Run(fmt.Sprint(err), func(t *testing.T) {
			req := lifecycleRequest()
			req.Action.Command = "custom-mutating-wrapper"
			res := TargetResult{Metadata: requestMetadata(req, "attempt"), Phase: PhaseExecute}
			applyExecResult(&res, req, sshclient.ExecResult{
				ExitCode: -1, StartAttempted: true, Stdout: "partial output",
			}, err)
			finishTargetMetadata(&res)
			if res.Status != StatusFailed || res.Completion != CompletionUnknown || res.Executed != nil ||
				res.ChangeState != "unknown" || res.Verified || res.Error == nil ||
				res.Error.Retryable || res.Error.RetrySafety == RetrySafe || res.Stdout != "partial output" {
				t.Fatalf("lost acknowledgement falsely proved nonexecution or safe retry: %+v", res)
			}
			m := requestMetadata(req, "parent")
			finishRunMetadata(&m, []TargetResult{res}, RunCounts{Selected: 1, Started: 1, Failed: 1, Uncertain: 1})
			if m.Executed != nil || m.ChangeState != "unknown" {
				t.Fatalf("parent discarded unknown start evidence: %+v", m)
			}
		})
	}
}

func TestToResultCopiesFinalizedMetadata(t *testing.T) {
	req := lifecycleRequest()
	req.Plan = &Plan{PlanHash: Digest([]byte("plan")), Risk: RiskRead}
	tr := TargetResult{
		Metadata: requestMetadata(req, "target"), Target: lifecycleSnapshot(1).Targets[0],
		Action: req.Action, Status: StatusSucceeded, Phase: PhaseComplete, Completion: CompletionCompleted,
		Stdout: "output", Stderr: "diagnostics", StdoutTruncated: true, StderrTruncated: true,
		PeerAddress: "192.0.2.1:22", AuthMethod: "publickey", DurationMs: 17,
	}
	tr.ParentExecutionID = "parent"
	finishTargetMetadata(&tr)
	result := ToResult("parent", "request", tr)
	if !reflect.DeepEqual(result.Metadata, tr.Metadata) || result.Stdout != tr.Stdout || result.Stderr != tr.Stderr ||
		result.StdoutTruncated != tr.StdoutTruncated || result.StderrTruncated != tr.StderrTruncated ||
		result.PeerAddress != tr.PeerAddress || result.AuthMethod != tr.AuthMethod || result.DurationMs != 17 || !result.Success {
		t.Fatalf("single-target compatibility projection lost facts: %+v", result)
	}
}

func TestTargetFingerprintBindsObservedPeerAndPreservesCorrelation(t *testing.T) {
	req := lifecycleRequest()
	req.ExecutionID = "parent-peer-run"
	req.Plan = &Plan{PlanHash: Digest([]byte("reviewed-plan")), Risk: RiskMutation}
	target := lifecycleSnapshot(1).Targets[0]
	target.HostKeyFingerprint = "SHA256:reviewed"
	observed := PeerIdentity{
		Role: "target", Address: "192.0.2.99:2222", HostKeyFingerprint: "SHA256:observed",
		AuthMethod: "password", User: "principal", SSHPasswordKey: "login-reference", SudoPasswordKey: "sudo-reference",
	}
	finish := func(peer PeerIdentity) (TargetResult, Metadata) {
		res := TargetResult{
			Metadata: targetMetadata(req, target), Target: target, Action: req.Action,
			Status: StatusFailed, Phase: PhaseExecute, Completion: CompletionUnknown, ExitCode: -1,
			Error: BuildError(io.EOF, ErrorKindProtocol, IntentChange, CompletionUnknown),
		}
		observeTargetPeer(&res, peer)
		finishTargetMetadata(&res)
		parent := requestMetadata(req, req.ExecutionID)
		finishRunMetadata(&parent, []TargetResult{res}, RunCounts{Selected: 1, Started: 1, Failed: 1, Uncertain: 1})
		return res, parent
	}
	baseline, baselineParent := finish(observed)
	if len(baseline.Peers) != 1 || baseline.Peers[0] != observed ||
		baseline.PeerAddress != observed.Address || baseline.AuthMethod != observed.AuthMethod ||
		baseline.Target.HostKeyFingerprint != observed.HostKeyFingerprint {
		t.Fatalf("observed peer was not preserved before finalization: %+v", baseline)
	}
	projection := ToResult(req.ExecutionID, "request", baseline)
	if !reflect.DeepEqual(projection.Metadata, baseline.Metadata) ||
		projection.ParentExecutionID != req.ExecutionID ||
		baselineParent.TargetFingerprints[0] != projection.ExecutionFingerprint {
		t.Fatalf("result and parent lost target peer correlation: %+v", projection)
	}
	tests := map[string]func(*PeerIdentity){
		"address":       func(p *PeerIdentity) { p.Address = "192.0.2.100:2222" },
		"host key":      func(p *PeerIdentity) { p.HostKeyFingerprint = "SHA256:different" },
		"auth":          func(p *PeerIdentity) { p.AuthMethod = "publickey" },
		"principal":     func(p *PeerIdentity) { p.User = "other-principal" },
		"login ref":     func(p *PeerIdentity) { p.SSHPasswordKey = "other-login-reference" },
		"privilege ref": func(p *PeerIdentity) { p.SudoPasswordKey = "other-sudo-reference" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			peer := observed
			mutate(&peer)
			changed, parent := finish(peer)
			if changed.ExecutionFingerprint == baseline.ExecutionFingerprint ||
				parent.ExecutionFingerprint == baselineParent.ExecutionFingerprint {
				t.Fatal("changed observed peer was not bound by both target and parent fingerprints")
			}
			if changed.ExecutionID != baseline.ExecutionID || changed.ParentExecutionID != baseline.ParentExecutionID ||
				changed.PlanHash != baseline.PlanHash {
				t.Fatal("observed outcome changed invocation or reviewed-plan correlation")
			}
		})
	}
}

func TestExecuteOneRecordsEffectivePeerPrincipalAndCredentialReferences(t *testing.T) {
	req := lifecycleRequest()
	req.ExecutionID = "peer-references"
	req.Action.Command = "sudo id"
	req.Policy.SSHPasswordKey, req.Policy.SudoPasswordKey = "policy-login", "policy-sudo"
	target := lifecycleSnapshot(1).Targets[0]
	target.User = ""
	target.SSHPasswordKey, target.SudoPasswordKey = "target-login", "target-sudo"
	target.HostKeyFingerprint = "SHA256:not-observed"
	res := executeOne(context.Background(), RunOptions{
		Request: req, Dialer: lifecycleDialer(sshclient.NewSSHClient),
		Secrets: lifecycleSecrets{
			ssh:  func(string) (string, error) { return "login-secret-sentinel", nil },
			sudo: func(string) (string, error) { return "sudo-secret-sentinel", nil },
		},
	}, target)
	if len(res.Peers) != 1 {
		t.Fatalf("missing peer metadata: %+v", res)
	}
	peer := res.Peers[0]
	if peer.Role != "target" || peer.User != "master" || peer.SSHPasswordKey != "policy-login" ||
		peer.SudoPasswordKey != "policy-sudo" || peer.AuthMethod != string(sshclient.AuthMethodUnknown) {
		t.Fatalf("peer metadata did not use effective principal/credential references: %+v", peer)
	}
	if peer.Address != "" || peer.HostKeyFingerprint != "" {
		t.Fatalf("unobserved connection was fabricated from target configuration: %+v", peer)
	}
	raw, err := json.Marshal(res.Metadata)
	if err != nil || strings.Contains(string(raw), "secret-sentinel") {
		t.Fatalf("metadata leaked credential values: %s %v", raw, err)
	}
}

func TestParentFingerprintBindsTargetsIndependentOfCompletionOrder(t *testing.T) {
	req := lifecycleRequest()
	req.ExecutionID = "stable-parent"
	req.Limits.Concurrency = 2
	req.Plan = &Plan{PlanHash: Digest([]byte("plan")), Risk: RiskRead}
	run := func(snap TargetSnapshot, changeFailure bool) RunOutcome {
		out, err := Execute(context.Background(), RunOptions{
			Request: req, Snapshot: snap, Events: noopEvents{},
			Dialer: lifecycleDialer(func(cfg *sshclient.Config) (*sshclient.SSHClient, error) {
				kind := ErrorKindConnect
				if changeFailure && cfg.Host == "192.0.2.2" {
					kind = ErrorKindHostKey
				}
				return nil, &sshclient.BoundaryError{Kind: kind, Err: io.EOF}
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	snap := lifecycleSnapshot(2)
	first := run(snap, false)
	snap.Targets[0], snap.Targets[1] = snap.Targets[1], snap.Targets[0]
	reordered := run(snap, false)
	if first.ExecutionFingerprint != reordered.ExecutionFingerprint ||
		!reflect.DeepEqual(first.TargetFingerprints, reordered.TargetFingerprints) {
		t.Fatal("presentation/completion order changed the parent fingerprint")
	}
	changed := run(snap, true)
	if first.ExecutionFingerprint == changed.ExecutionFingerprint || first.Counts != changed.Counts {
		t.Fatal("a changed target outcome did not change parent fingerprint independently of aggregate counts")
	}

	single := run(lifecycleSnapshot(1), false)
	if single.Single == nil || single.Single.ExecutionFingerprint != single.Results[0].ExecutionFingerprint ||
		single.Single.ExecutionFingerprint == single.ExecutionFingerprint || len(single.TargetFingerprints) != 1 ||
		single.TargetFingerprints[0] != single.Single.ExecutionFingerprint {
		t.Fatalf("single target and parent run evidence not separately correlated: %+v", single)
	}
}

func TestMetadataFinishCanonicalizesTargetFingerprintsWithoutMutatingInput(t *testing.T) {
	input := []string{"z", "a"}
	first := NewMetadata(nil, "parent")
	first.TargetFingerprints = input
	first.Finish(StatusFailed, PhaseComplete, CompletionNotStarted, 1, "")
	second := NewMetadata(nil, "parent")
	second.TargetFingerprints = []string{"a", "z"}
	second.Finish(StatusFailed, PhaseComplete, CompletionNotStarted, 1, "")
	if !reflect.DeepEqual(input, []string{"z", "a"}) ||
		!reflect.DeepEqual(first.TargetFingerprints, []string{"a", "z"}) ||
		first.ExecutionFingerprint != second.ExecutionFingerprint {
		t.Fatalf("noncanonical or aliased target fingerprints: %+v", first)
	}
}

func TestNormalizeRequestFailureAndDeadlineLimits(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Request)
		wantErr bool
	}{
		{"negative failures", func(r *Request) { r.Policy.MaxFailures = -1 }, true},
		{"conflicting failures", func(r *Request) { r.Policy.FailureMode, r.Policy.MaxFailures = FailureFailFast, 2 }, true},
		{"equivalent failures", func(r *Request) { r.Policy.FailureMode, r.Policy.MaxFailures = FailureFailFast, 1 }, false},
		{"maximum failures", func(r *Request) { r.Policy.MaxFailures = 3 }, false},
		{"negative host timeout", func(r *Request) { r.Limits.HostTimeout = -time.Second }, true},
		{"negative global timeout", func(r *Request) { r.Limits.GlobalTimeout = -time.Second }, true},
		{"negative command timeout", func(r *Request) { r.Limits.Timeout = -time.Second }, true},
		{"no optional limits", func(*Request) {}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := lifecycleRequest()
			tt.mutate(req)
			err := NormalizeRequest(req)
			if (err != nil) != tt.wantErr || (err != nil && !errors.Is(err, ErrConfig)) {
				t.Fatalf("NormalizeRequest=%v wantErr=%t", err, tt.wantErr)
			}
			if !tt.wantErr && PublicPolicy(req.Policy).MaxFailures != req.Policy.MaxFailures {
				t.Fatal("public policy omitted failure limit")
			}
		})
	}
}

func TestDryRunRiskDoesNotTrustReadIntent(t *testing.T) {
	req := lifecycleRequest()
	req.Action.Command = "custom-wrapper"
	req.Targets.Address = "192.0.2.1"
	plan := BuildDryRunPlan(req, nil, HostRecord{}, nil)
	if !plan.Valid || plan.Risk != RiskMutation || !plan.Effects.Unknown || !plan.WouldMutateRemote {
		t.Fatalf("read intent downgraded opaque effects: %+v", plan)
	}
	if nilPlan := BuildDryRunPlan(nil, nil, HostRecord{}, nil); nilPlan.Valid || nilPlan.Error == nil {
		t.Fatal("nil request produced a valid dry run")
	}
}
