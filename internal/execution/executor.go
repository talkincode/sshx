package execution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/errutil"
)

// SecretResolver reads typed keyring references. Implementations must not be
// called during dry-run or selector-only operations.
type SecretResolver interface {
	// GetSSHPassword returns an SSH login password for the given keyring key.
	GetSSHPassword(key string) (string, error)
	// GetSudoPassword returns a sudo password for the given keyring key.
	GetSudoPassword(key string) (string, error)
}

// Dialer creates and connects an SSH client for one target.
type Dialer interface {
	Connect(cfg *sshclient.Config) (*sshclient.SSHClient, error)
}

// DefaultDialer uses sshclient.NewSSHClient + ConnectDirect.
type DefaultDialer struct{}

// Connect implements Dialer.
func (DefaultDialer) Connect(cfg *sshclient.Config) (*sshclient.SSHClient, error) {
	client, err := sshclient.NewSSHClient(cfg)
	if err != nil {
		return nil, err
	}
	if err := client.ConnectDirect(); err != nil {
		_ = client.ForceClose() //nolint:errcheck // best-effort cleanup
		return nil, err
	}
	return client, nil
}

// EventWriter receives ordered JSONL events.
type EventWriter interface {
	WriteEvent(Event) error
}

// JSONLWriter writes one JSON object per line to w.
type JSONLWriter struct {
	W   io.Writer
	mu  sync.Mutex
	enc *json.Encoder
}

// WriteEvent implements EventWriter.
func (j *JSONLWriter) WriteEvent(ev Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.enc == nil {
		j.enc = json.NewEncoder(j.W)
		j.enc.SetEscapeHTML(false)
	}
	return j.enc.Encode(ev)
}

// HumanWriter prints target-prefixed human output without interleaving lines.
type HumanWriter struct {
	W  io.Writer
	mu sync.Mutex
}

// WriteEvent implements EventWriter for human mode (subset of events).
func (h *HumanWriter) WriteEvent(ev Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch ev.Kind {
	case EventRunStarted:
		_, err := fmt.Fprintf(h.W, "run %s started targets=%d concurrency=%d\n", ev.RunID, ev.Counts.Selected, ev.Concurrency)
		return err
	case EventTargetFinished:
		if ev.Result == nil {
			return nil
		}
		alias := ev.Result.Target.Alias
		if alias == "" {
			alias = ev.Result.Target.Address
		}
		prefix := fmt.Sprintf("[%d:%s]", ev.Result.Target.Index, alias)
		if ev.Result.Stdout != "" {
			for _, line := range splitKeep(ev.Result.Stdout) {
				if _, err := fmt.Fprintf(h.W, "%s stdout: %s\n", prefix, line); err != nil {
					return err
				}
			}
		}
		if ev.Result.Stderr != "" {
			for _, line := range splitKeep(ev.Result.Stderr) {
				if _, err := fmt.Fprintf(h.W, "%s stderr: %s\n", prefix, line); err != nil {
					return err
				}
			}
		}
		status := ev.Result.Status
		if ev.Result.Error != nil {
			_, err := fmt.Fprintf(h.W, "%s %s exit=%d completion=%s error_kind=%s\n",
				prefix, status, ev.Result.ExitCode, ev.Result.Completion, ev.Result.Error.Kind)
			return err
		}
		_, err := fmt.Fprintf(h.W, "%s %s exit=%d completion=%s\n",
			prefix, status, ev.Result.ExitCode, ev.Result.Completion)
		return err
	case EventRunFinished:
		if ev.Counts == nil {
			return nil
		}
		_, err := fmt.Fprintf(h.W, "run %s finished selected=%d succeeded=%d failed=%d skipped=%d uncertain=%d\n",
			ev.RunID, ev.Counts.Selected, ev.Counts.Succeeded, ev.Counts.Failed, ev.Counts.Skipped, ev.Counts.Uncertain)
		return err
	}
	return nil
}

func splitKeep(s string) []string {
	if s == "" {
		return nil
	}
	// Trim a single trailing newline for cleaner display; keep internal newlines.
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	return splitLines(s)
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start <= len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// RunOptions configures one executor invocation.
type RunOptions struct {
	Request  *Request
	Snapshot TargetSnapshot
	Payload  *Payload
	Secrets  SecretResolver
	Dialer   Dialer
	Events   EventWriter
	// ActiveSessions is optional instrumentation for tests.
	ActiveSessions *atomic.Int64
	// MaxObserved is optional peak concurrent sessions counter.
	MaxObserved *atomic.Int64
}

// RunOutcome is the process-level summary for one accepted run.
type RunOutcome struct {
	RunID   string
	Counts  RunCounts
	Results []TargetResult
	// Single is set when exactly one target finished and JSON mode is requested.
	Single *Result
}

// NewRunID returns a random opaque run identifier.
func NewRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("run-%d", time.Now().UnixNano())
	}
	return "run-" + hex.EncodeToString(b[:])
}

// Execute runs the validated request against the frozen snapshot.
func Execute(ctx context.Context, opts RunOptions) (RunOutcome, error) {
	if opts.Request == nil {
		return RunOutcome{}, fmt.Errorf("%w: request is nil", ErrConfig)
	}
	req := opts.Request
	if err := NormalizeRequest(req); err != nil {
		return RunOutcome{}, err
	}
	if opts.Snapshot.Count == 0 || len(opts.Snapshot.Targets) == 0 {
		return RunOutcome{}, ErrNoTargets
	}
	if opts.Dialer == nil {
		opts.Dialer = DefaultDialer{}
	}
	if opts.Events == nil {
		if req.JSONLOutput {
			opts.Events = &JSONLWriter{W: os.Stdout}
		} else if !req.JSONOutput {
			opts.Events = &HumanWriter{W: os.Stdout}
		} else {
			opts.Events = noopEvents{}
		}
	}

	runID := NewRunID()
	var seq atomic.Int64
	var emitMu sync.Mutex
	emit := func(ev Event) {
		// Assign sequence and publish under one lock so JSONL stream order is
		// strictly monotonic even when workers finish concurrently.
		emitMu.Lock()
		defer emitMu.Unlock()
		ev.SchemaVersion = EventSchemaVersion
		ev.RunID = runID
		ev.RequestID = req.RequestID
		ev.Sequence = seq.Add(1)
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		_ = opts.Events.WriteEvent(ev) //nolint:errcheck // event write failure must not rewrite remote outcomes
	}

	counts := RunCounts{
		Selected: len(opts.Snapshot.Targets),
		Skipped:  len(opts.Snapshot.Skipped),
	}
	emit(Event{
		Kind:           EventRunStarted,
		Counts:         &counts,
		SelectorDigest: opts.Snapshot.SelectorDigest,
		Concurrency:    req.Limits.Concurrency,
		FailureMode:    req.Policy.FailureMode,
		Action:         &req.Action,
	})

	type job struct {
		target ResolvedTarget
	}
	jobs := make(chan job)
	results := make([]TargetResult, len(opts.Snapshot.Targets))
	var resultsMu sync.Mutex
	var startedCount atomic.Int64
	var failFast atomic.Bool
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			if ctx.Err() != nil || (req.Policy.FailureMode == FailureFailFast && failFast.Load()) {
				res := skippedResult(req, j.target, "not_admitted")
				resultsMu.Lock()
				results[j.target.Index] = res
				resultsMu.Unlock()
				emit(Event{Kind: EventTargetFinished, Target: &j.target, Result: &res})
				continue
			}
			startedCount.Add(1)
			emit(Event{Kind: EventTargetStarted, Target: &j.target})
			if opts.ActiveSessions != nil {
				cur := opts.ActiveSessions.Add(1)
				if opts.MaxObserved != nil {
					for {
						max := opts.MaxObserved.Load()
						if cur <= max || opts.MaxObserved.CompareAndSwap(max, cur) {
							break
						}
					}
				}
			}
			res := executeOne(ctx, opts, j.target)
			if opts.ActiveSessions != nil {
				opts.ActiveSessions.Add(-1)
			}
			resultsMu.Lock()
			results[j.target.Index] = res
			resultsMu.Unlock()
			emit(Event{Kind: EventTargetFinished, Target: &j.target, Result: &res})
			if res.Status != StatusSucceeded {
				if req.Policy.FailureMode == FailureFailFast {
					failFast.Store(true)
				}
			}
		}
	}

	nWorkers := req.Limits.Concurrency
	if nWorkers > len(opts.Snapshot.Targets) {
		nWorkers = len(opts.Snapshot.Targets)
	}
	wg.Add(nWorkers)
	for i := 0; i < nWorkers; i++ {
		go worker()
	}

sendLoop:
	for _, t := range opts.Snapshot.Targets {
		select {
		case <-ctx.Done():
			// Remaining targets get terminal skipped events after close.
			break sendLoop
		default:
		}
		if req.Policy.FailureMode == FailureFailFast && failFast.Load() {
			res := skippedResult(req, t, "fail_fast")
			resultsMu.Lock()
			results[t.Index] = res
			resultsMu.Unlock()
			emit(Event{Kind: EventTargetFinished, Target: &t, Result: &res})
			continue
		}
		select {
		case <-ctx.Done():
			res := skippedResult(req, t, "canceled")
			resultsMu.Lock()
			results[t.Index] = res
			resultsMu.Unlock()
			emit(Event{Kind: EventTargetFinished, Target: &t, Result: &res})
		case jobs <- job{target: t}:
		}
	}
	close(jobs)
	wg.Wait()

	// Ensure every selected target has a terminal result (canceled before admit).
	for i := range results {
		if results[i].Status == "" {
			t := opts.Snapshot.Targets[i]
			results[i] = skippedResult(req, t, "canceled")
			emit(Event{Kind: EventTargetFinished, Target: &t, Result: &results[i]})
		}
	}

	final := RunCounts{
		Selected: len(opts.Snapshot.Targets),
		Started:  int(startedCount.Load()),
	}
	for _, r := range results {
		switch {
		case r.Status == StatusSucceeded:
			final.Succeeded++
		case r.Status == StatusSkipped:
			// Runtime skips among the frozen selected set (fail_fast / cancel).
			final.Skipped++
		case r.Completion == CompletionPartial ||
			r.Completion == CompletionCompletedUnconfirmed ||
			r.Completion == CompletionUnknown:
			final.Failed++
			final.Uncertain++
		default:
			final.Failed++
		}
	}
	emit(Event{
		Kind:           EventRunFinished,
		Counts:         &final,
		SelectorDigest: opts.Snapshot.SelectorDigest,
		Concurrency:    req.Limits.Concurrency,
		FailureMode:    req.Policy.FailureMode,
		Action:         &req.Action,
	})

	out := RunOutcome{RunID: runID, Counts: final, Results: results}
	if len(results) == 1 {
		out.Single = ToResult(runID, req.RequestID, results[0])
	}
	return out, nil
}

type noopEvents struct{}

func (noopEvents) WriteEvent(Event) error { return nil }

func skippedResult(req *Request, t ResolvedTarget, reason string) TargetResult {
	return TargetResult{
		Target:     t,
		Action:     req.Action,
		Status:     StatusSkipped,
		Phase:      PhaseAdmission,
		Completion: CompletionNotStarted,
		ExitCode:   -1,
		Error: &ErrorInfo{
			Kind:        ErrorKindConfig,
			Message:     reason,
			Retryable:   false,
			RetrySafety: RetryUnknown,
		},
	}
}

func executeOne(ctx context.Context, opts RunOptions, target ResolvedTarget) TargetResult {
	req := opts.Request
	start := time.Now()
	res := TargetResult{
		Target:     target,
		Action:     req.Action,
		Status:     StatusFailed,
		Phase:      PhaseConnect,
		Completion: CompletionNotStarted,
		ExitCode:   -1,
	}

	if err := ctx.Err(); err != nil {
		res.Phase = PhaseAdmission
		res.Error = BuildError(err, ErrorKindConfig, req.Action.Intent, CompletionNotStarted)
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	cfg := buildSSHConfig(req, target)
	// Resolve secrets only for this target and only for required roles.
	if err := applySecrets(cfg, req, target, opts.Secrets); err != nil {
		res.Phase = PhaseAuthenticate
		res.Error = BuildError(err, ErrorKindAuth, req.Action.Intent, CompletionNotStarted)
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	if err := SafetyCheck(req, payloadBytes(opts.Payload)); err != nil {
		res.Phase = PhaseAdmission
		res.Error = BuildError(err, ErrorKindBlocked, req.Action.Intent, CompletionNotStarted)
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	client, err := opts.Dialer.Connect(cfg)
	if err != nil {
		kind := Classify(err)
		phase := PhaseConnect
		if kind == ErrorKindAuth || kind == ErrorKindHostKey {
			phase = PhaseAuthenticate
		}
		res.Phase = phase
		res.Completion = CompletionFor(phase, kind, false, false)
		res.Error = BuildError(err, kind, req.Action.Intent, res.Completion)
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	defer errutil.HandleCloseError(&err, client)

	res.AuthMethod = string(client.AuthMethodUsed())
	res.Phase = PhaseExecute
	remoteStarted := true

	var execRes sshclient.ExecResult
	var execErr error
	switch req.Action.Kind {
	case ActionCommand:
		cfg.Command = req.Action.Command
		execRes, execErr = client.RunCommand(true)
	case ActionScript:
		if opts.Payload == nil {
			execErr = fmt.Errorf("%w: missing script payload", ErrConfig)
		} else {
			useSudo := req.Action.UseSudo
			execRes, execErr = client.RunScriptWithShell(opts.Payload.Bytes, req.Action.ScriptRunner, useSudo)
		}
	default:
		execErr = fmt.Errorf("%w: action kind %q not executable by run executor", ErrConfig, req.Action.Kind)
	}

	res.DurationMs = time.Since(start).Milliseconds()
	res.Stdout = execRes.Stdout
	res.Stderr = execRes.Stderr
	res.StdoutTruncated = execRes.StdoutTruncated
	res.StderrTruncated = execRes.StderrTruncated
	res.AuthMethod = string(client.AuthMethodUsed())

	if execErr != nil {
		kind := Classify(execErr)
		exitObserved := false
		res.ExitCode = execRes.ExitCode
		if kind == ErrorKindExitMissing {
			res.Phase = PhaseCollect
		}
		res.Completion = CompletionFor(res.Phase, kind, remoteStarted, exitObserved)
		// Timeout after start is partial.
		if kind == ErrorKindTimeout {
			res.Phase = PhaseExecute
			res.Completion = CompletionPartial
		}
		res.Status = StatusFailed
		res.Error = BuildError(execErr, kind, req.Action.Intent, res.Completion)
		return res
	}

	res.ExitCode = execRes.ExitCode
	res.Phase = PhaseComplete
	res.Completion = CompletionCompleted
	if execRes.ExitCode != 0 {
		res.Status = StatusFailed
		res.Error = BuildError(
			fmt.Errorf("remote command exited with status %d", execRes.ExitCode),
			ErrorKindRemoteExit,
			req.Action.Intent,
			CompletionCompleted,
		)
		return res
	}
	res.Status = StatusSucceeded
	return res
}

func buildSSHConfig(req *Request, target ResolvedTarget) *sshclient.Config {
	cfg := &sshclient.Config{
		Host:                 target.Address,
		Port:                 target.Port,
		User:                 target.User,
		KeyPath:              firstNonEmpty(req.Policy.KeyPath, target.KeyPath),
		UseKeyAuth:           req.Policy.UseKeyAuth,
		Timeout:              req.Limits.Timeout,
		SafetyCheck:          req.Policy.SafetyCheckEnabled && !req.Policy.SafetyBypass,
		Force:                req.Policy.SafetyBypass,
		AcceptUnknownHost:    req.Policy.AcceptUnknownHost,
		AllowInsecureHostKey: req.Policy.AllowInsecureHostKey,
		KnownHostsPath:       req.Policy.KnownHostsPath,
		JSONOutput:           true,
		SudoKey:              firstNonEmpty(target.SudoPasswordKey, req.Policy.SudoPasswordKey),
		Command:              req.Action.Command,
		Mode:                 "ssh",
		Bind:                 target.Bind,
	}
	if cfg.Port == "" {
		cfg.Port = "22"
	}
	if cfg.User == "" {
		cfg.User = "master"
	}
	return cfg
}

func applySecrets(cfg *sshclient.Config, req *Request, target ResolvedTarget, secrets SecretResolver) error {
	// SSH login password: only explicit password, SSH_PASSWORD, or ssh_password_key.
	if req.Policy.SSHPassword != "" {
		cfg.Password = req.Policy.SSHPassword
	}
	sshKey := firstNonEmpty(req.Policy.SSHPasswordKey, target.SSHPasswordKey)
	if sshKey != "" {
		if secrets == nil {
			return fmt.Errorf("%w: ssh password key %q requested without secret resolver", ErrConfig, sshKey)
		}
		pw, err := secrets.GetSSHPassword(sshKey)
		if err != nil {
			return err
		}
		cfg.Password = pw
	}

	needSudo := req.Action.UseSudo || (req.Action.Kind == ActionCommand && sshclient.CommandUsesSudo(req.Action.Command))
	if !needSudo {
		return nil
	}
	sudoKey := firstNonEmpty(req.Policy.SudoPasswordKey, target.SudoPasswordKey)
	if sudoKey == "" {
		sudoKey = sshclient.DefaultSudoKey
	}
	cfg.SudoKey = sudoKey
	if secrets == nil {
		return fmt.Errorf("%w: sudo password key %q requested without secret resolver", ErrConfig, sudoKey)
	}
	pw, err := secrets.GetSudoPassword(sudoKey)
	if err != nil {
		// Match legacy behavior for command mode: continue without auto-fill.
		// For explicit script --sudo, fail closed.
		if req.Action.UseSudo && req.Action.Kind == ActionScript {
			return err
		}
		return nil
	}
	cfg.SudoPassword = pw
	return nil
}

// ToResult projects a TargetResult into the versioned single-target document
// with compatibility fields.
func ToResult(runID, requestID string, tr TargetResult) *Result {
	r := &Result{
		SchemaVersion:   ResultSchemaVersion,
		RunID:           runID,
		RequestID:       requestID,
		Target:          tr.Target,
		Action:          tr.Action,
		Status:          tr.Status,
		Phase:           tr.Phase,
		Completion:      tr.Completion,
		ExitCode:        tr.ExitCode,
		Success:         tr.Status == StatusSucceeded && tr.ExitCode == 0,
		Error:           tr.Error,
		Host:            tr.Target.Address,
		Port:            tr.Target.Port,
		User:            tr.Target.User,
		Command:         tr.Action.Command,
		Stdout:          tr.Stdout,
		Stderr:          tr.Stderr,
		StdoutTruncated: tr.StdoutTruncated,
		StderrTruncated: tr.StderrTruncated,
		DurationMs:      tr.DurationMs,
		AuthMethod:      tr.AuthMethod,
	}
	if tr.Error != nil {
		r.ErrorKind = tr.Error.Kind
	}
	return r
}

// ProcessExitCode maps a run outcome to the multi-target process exit code.
//
//	0   all selected targets completed successfully
//	1   run accepted but at least one selected target failed, was skipped, or is uncertain
//	255 request-level failure before a valid run could execute
func ProcessExitCode(counts RunCounts, requestErr error) int {
	if requestErr != nil {
		return 255
	}
	if counts.Selected == 0 {
		return 255
	}
	if counts.Succeeded == counts.Selected && counts.Failed == 0 && counts.Skipped == 0 && counts.Uncertain == 0 {
		return 0
	}
	return 1
}

// IsRequestLevelError reports whether err should become process exit 255.
func IsRequestLevelError(err error) bool {
	return err != nil && (errors.Is(err, ErrConfig) || errors.Is(err, ErrLocalIO) || errors.Is(err, ErrNoTargets) || errors.Is(err, ErrBlocked) && false)
}
