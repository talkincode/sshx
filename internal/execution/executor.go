package execution

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	Metadata
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
	if ctx == nil {
		ctx = context.Background()
	}
	if req.Limits.GlobalTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = WithScopedTimeout(ctx, req.Limits.GlobalTimeout, "global")
		defer cancel()
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

	runID := req.ExecutionID
	if runID == "" {
		runID = NewRunID()
		req.ExecutionID = runID
	}
	runMetadata := requestMetadata(req, runID)
	var seq int64
	var emitMu sync.Mutex
	var deliveryErr error
	emit := func(ev Event) {
		emitMu.Lock()
		defer emitMu.Unlock()
		// A broken stream cannot promise further terminal records. Preserve all
		// remote outcomes in memory and return the delivery failure separately.
		if deliveryErr != nil {
			return
		}
		if ev.Result != nil {
			ev.Metadata = ev.Result.Metadata
			ev.Target = &ev.Result.Target
		} else if ev.ExecutionID == "" {
			if ev.Target != nil {
				ev.Metadata = targetMetadata(req, *ev.Target)
			} else {
				ev.Metadata = runMetadata
			}
		}
		ev.SchemaVersion = EventSchemaVersion
		ev.RunID = runID
		ev.RequestID = req.RequestID
		seq++
		ev.Sequence = seq
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		if err := opts.Events.WriteEvent(ev); err != nil {
			deliveryErr = fmt.Errorf("%w: deliver %s event: %w", ErrLocalIO, ev.Kind, err)
		}
	}

	counts := RunCounts{
		Selected: len(opts.Snapshot.Targets),
	}
	emit(Event{
		Kind:           EventRunStarted,
		Counts:         &counts,
		SelectorDigest: opts.Snapshot.SelectorDigest,
		Concurrency:    req.Limits.Concurrency,
		FailureMode:    req.Policy.FailureMode,
		MaxFailures:    req.Policy.MaxFailures,
		Action:         &req.Action,
	})

	results := make([]TargetResult, len(opts.Snapshot.Targets))
	// Admission and completed-failure accounting share one linearization
	// point. A blocked event sink must not postpone the failure threshold.
	var admissionMu sync.Mutex
	next, failures, startedCount := 0, 0, 0
	maxFailures := req.Policy.MaxFailures
	if req.Policy.FailureMode == FailureFailFast {
		maxFailures = 1
	}
	admit := func() (int, bool) {
		admissionMu.Lock()
		defer admissionMu.Unlock()
		if next == len(results) || ctx.Err() != nil || (maxFailures > 0 && failures >= maxFailures) {
			return 0, false
		}
		pos := next
		next++
		startedCount++
		return pos, true
	}
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for {
			pos, ok := admit()
			if !ok {
				return
			}
			target := opts.Snapshot.Targets[pos]
			hostCtx := ctx
			cancel := func() {}
			if req.Limits.HostTimeout > 0 {
				hostCtx, cancel = WithScopedTimeout(ctx, req.Limits.HostTimeout, "host")
			}
			metadata := targetMetadata(req, target)
			emit(Event{Metadata: metadata, Kind: EventTargetStarted, Target: &target})
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
			res := executeOneWithMetadata(hostCtx, opts, target, metadata)
			cancel()
			if opts.ActiveSessions != nil {
				opts.ActiveSessions.Add(-1)
			}
			admissionMu.Lock()
			results[pos] = res
			if res.Status == StatusFailed {
				failures++
			}
			admissionMu.Unlock()
			emit(Event{Kind: EventTargetFinished, Target: &target, Result: &res})
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

	wg.Wait()

	reason := "max_failures"
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		reason = "deadline_exceeded"
	case ctx.Err() != nil:
		reason = "canceled"
	case req.Policy.FailureMode == FailureFailFast:
		reason = "fail_fast"
	}
	for i := range results {
		if results[i].Status == "" {
			t := opts.Snapshot.Targets[i]
			results[i] = skippedResult(ctx, req, t, reason)
			emit(Event{Kind: EventTargetFinished, Target: &t, Result: &results[i]})
		}
	}

	final := RunCounts{
		Selected: len(opts.Snapshot.Targets),
		Started:  startedCount,
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
	runMetadata.ObserveContext(ctx)
	finishRunMetadata(&runMetadata, results, final)
	emit(Event{
		Kind:           EventRunFinished,
		Counts:         &final,
		SelectorDigest: opts.Snapshot.SelectorDigest,
		Concurrency:    req.Limits.Concurrency,
		FailureMode:    req.Policy.FailureMode,
		MaxFailures:    req.Policy.MaxFailures,
		Action:         &req.Action,
	})

	out := RunOutcome{Metadata: runMetadata, RunID: runID, Counts: final, Results: results}
	if len(results) == 1 {
		out.Single = ToResult(runID, req.RequestID, results[0])
	}
	return out, deliveryErr
}

type noopEvents struct{}

func (noopEvents) WriteEvent(Event) error { return nil }

func requestRisk(req *Request) (Risk, Effects) {
	if req.Plan != nil {
		return req.Plan.Risk, req.Plan.Effects
	}
	action := req.Action.Kind
	if action == ActionSFTP {
		action = req.Action.SftpAction
	}
	return ClassifyRisk(action, req.Action.Command, req.Action.UseSudo)
}

func retryIntent(req *Request) string {
	risk, effects := requestRisk(req)
	if risk == RiskRead && !effects.Unknown && !effects.RemoteWrite && !effects.LocalWrite &&
		!effects.Privileged && !effects.Destructive {
		return IntentRead
	}
	return IntentChange
}

func requestMetadata(req *Request, id string) Metadata {
	m := NewMetadata(req.Plan, id)
	m.Risk, m.Effects = requestRisk(req)
	return m
}

func targetExecutionID(parent string, target ResolvedTarget) string {
	identity, err := json.Marshal(struct {
		Parent  string
		Index   int
		Address string
		Port    string
		User    string
	}{parent, target.Index, target.Address, target.Port, target.User})
	if err != nil {
		panic(err) // The identity projection contains only strings and an integer.
	}
	sum := sha256.Sum256(identity)
	return "target-" + hex.EncodeToString(sum[:])
}

func targetMetadata(req *Request, target ResolvedTarget) Metadata {
	m := requestMetadata(req, targetExecutionID(req.ExecutionID, target))
	m.ParentExecutionID = req.ExecutionID
	return m
}

func observeTargetPeer(res *TargetResult, peer PeerIdentity) {
	res.AuthMethod = peer.AuthMethod
	res.PeerAddress = peer.Address
	if peer.HostKeyFingerprint != "" {
		res.Target.HostKeyFingerprint = peer.HostKeyFingerprint
	}
	res.Peers = append(res.Peers, peer)
}

func finishTargetMetadata(res *TargetResult) {
	kind := ""
	if res.Error != nil {
		kind = res.Error.Kind
	}
	res.Finish(res.Status, res.Phase, res.Completion, res.ExitCode, kind)
}

func finishRunMetadata(m *Metadata, results []TargetResult, counts RunCounts) {
	status, completion, code := StatusSucceeded, CompletionCompleted, 0
	if counts.Succeeded != counts.Selected {
		status, code = StatusFailed, 1
	}
	executed, unknownExecution, anyCompleted := false, false, false
	m.ChangeState = "unchanged"
	m.TargetFingerprints = make([]string, 0, len(results))
	for _, r := range results {
		m.TargetFingerprints = append(m.TargetFingerprints, r.ExecutionFingerprint)
		if r.Executed == nil {
			unknownExecution = true
		} else if *r.Executed {
			executed = true
		}
		if r.Completion == CompletionCompleted {
			anyCompleted = true
		} else {
			completion = CompletionPartial
		}
		if r.ChangeState == "changed" {
			m.ChangeState = "changed"
		} else if r.ChangeState != "unchanged" && m.ChangeState != "changed" {
			m.ChangeState = "unknown"
		}
	}
	if !unknownExecution || executed {
		m.Executed = &executed
	}
	if !executed && !unknownExecution {
		completion = CompletionNotStarted
	} else if counts.Uncertain > 0 {
		completion = CompletionUnknown
	} else if !anyCompleted {
		completion = CompletionPartial
	}
	if executed {
		m.Verification = "unsupported"
	}
	m.Finish(status, PhaseComplete, completion, code, "")
}

func skippedResult(ctx context.Context, req *Request, t ResolvedTarget, reason string) TargetResult {
	kind := ErrorKindConfig
	switch reason {
	case "canceled":
		kind = ErrorKindCancelled
	case "deadline_exceeded":
		kind = ErrorKindTimeout
	}
	res := TargetResult{
		Metadata:   targetMetadata(req, t),
		Target:     t,
		Action:     req.Action,
		Status:     StatusSkipped,
		Phase:      PhaseAdmission,
		Completion: CompletionNotStarted,
		ExitCode:   -1,
		Error: &ErrorInfo{
			Kind:        kind,
			Message:     reason,
			Retryable:   false,
			RetrySafety: RetryUnknown,
		},
	}
	res.StartedAt = ""
	res.ObserveContext(ctx)
	finishTargetMetadata(&res)
	return res
}

func executeOne(ctx context.Context, opts RunOptions, target ResolvedTarget) TargetResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Request.Limits.HostTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = WithScopedTimeout(ctx, opts.Request.Limits.HostTimeout, "host")
		defer cancel()
	}
	return executeOneWithMetadata(ctx, opts, target, targetMetadata(opts.Request, target))
}

func executeOneWithMetadata(ctx context.Context, opts RunOptions, target ResolvedTarget, metadata Metadata) (res TargetResult) {
	req := opts.Request
	start := time.Now()
	res = TargetResult{
		Metadata:   metadata,
		Target:     target,
		Action:     req.Action,
		Status:     StatusFailed,
		Phase:      PhaseConnect,
		Completion: CompletionNotStarted,
		ExitCode:   -1,
	}
	defer func() {
		res.DurationMs = time.Since(start).Milliseconds()
		res.ObserveContext(ctx)
		finishTargetMetadata(&res)
	}()

	if err := ctx.Err(); err != nil {
		res.Phase = PhaseAdmission
		res.Error = BuildError(err, "", retryIntent(req), CompletionNotStarted)
		return res
	}

	if err := SafetyCheck(req, payloadBytes(opts.Payload)); err != nil {
		res.Phase = PhaseAdmission
		res.Error = BuildError(err, ErrorKindBlocked, retryIntent(req), CompletionNotStarted)
		return res
	}
	if req.Action.Kind != ActionCommand && req.Action.Kind != ActionScript {
		res.Phase = PhaseAdmission
		err := fmt.Errorf("%w: action kind %q not executable by run executor", ErrConfig, req.Action.Kind)
		res.Error = BuildError(err, "", retryIntent(req), CompletionNotStarted)
		return res
	}
	if req.Action.Kind == ActionScript && opts.Payload == nil {
		res.Phase = PhaseAdmission
		res.Error = BuildError(fmt.Errorf("%w: missing script payload", ErrConfig), "", retryIntent(req), CompletionNotStarted)
		return res
	}

	cfg := buildSSHConfig(req, target)
	cfg.Context = ctx
	if err := applySecrets(cfg, req, target, opts.Secrets); err != nil {
		res.Phase = PhaseAuthenticate
		kind := Classify(err)
		if kind == ErrorKindUnknown {
			kind = ErrorKindAuth
		}
		res.Error = BuildError(err, kind, retryIntent(req), CompletionNotStarted)
		return res
	}
	if err := ctx.Err(); err != nil {
		res.Phase = PhaseAdmission
		res.Error = BuildError(err, "", retryIntent(req), CompletionNotStarted)
		return res
	}

	dialer := opts.Dialer
	if dialer == nil {
		dialer = DefaultDialer{}
	}
	client, err := dialer.Connect(cfg)
	if err != nil {
		kind := Classify(err)
		phase := PhaseConnect
		if kind == ErrorKindAuth || kind == ErrorKindHostKey {
			phase = PhaseAuthenticate
		}
		res.Phase = phase
		res.Completion = CompletionFor(phase, kind, false, false)
		res.Error = BuildError(err, kind, retryIntent(req), res.Completion)
		return res
	}
	if client == nil {
		res.Error = BuildError(errors.New("dialer returned no client"), ErrorKindProtocol, retryIntent(req), CompletionNotStarted)
		return res
	}
	defer func() { _ = client.Close() }() //nolint:errcheck // teardown does not invalidate observed remote outcomes

	observeTargetPeer(&res, PeerIdentity{
		Role:               "target",
		Address:            client.PeerAddress(),
		HostKeyFingerprint: client.HostKeyFingerprint(),
		AuthMethod:         string(client.AuthMethodUsed()),
		User:               cfg.User,
		SSHPasswordKey:     firstNonEmpty(req.Policy.SSHPasswordKey, target.SSHPasswordKey),
		SudoPasswordKey:    cfg.SudoKey,
	})
	if err := ctx.Err(); err != nil {
		res.Error = BuildError(err, "", retryIntent(req), CompletionNotStarted)
		return res
	}
	res.Phase = PhaseExecute

	var execRes sshclient.ExecResult
	var execErr error
	switch req.Action.Kind {
	case ActionCommand:
		execRes, execErr = client.RunCommand(true)
	case ActionScript:
		execRes, execErr = client.RunScriptWithShell(opts.Payload.Bytes, req.Action.ScriptRunner, req.Action.UseSudo)
	}

	applyExecResult(&res, req, execRes, execErr)
	return res
}

func applyExecResult(res *TargetResult, req *Request, execRes sshclient.ExecResult, execErr error) {
	res.Stdout = execRes.Stdout
	res.Stderr = execRes.Stderr
	res.StdoutTruncated = execRes.StdoutTruncated
	res.StderrTruncated = execRes.StderrTruncated
	res.ExitCode = execRes.ExitCode
	executed := execRes.Started || execRes.ExitObserved
	res.Executed = &executed
	if execRes.StartAttempted && !executed {
		res.Executed = nil
	}
	if executed {
		res.Verification = "unsupported"
		if retryIntent(req) == IntentRead {
			res.ChangeState = "unchanged"
		}
	}
	if execErr == nil && !execRes.ExitObserved {
		if execRes.Started {
			execErr = sshclient.ErrNoExitStatus
		} else {
			execErr = &BoundaryError{Kind: ErrorKindProtocol, Message: "transport returned without an execution acknowledgement"}
		}
	}

	if execErr != nil {
		kind := Classify(execErr)
		if kind == ErrorKindExitMissing {
			res.Phase = PhaseCollect
		}
		res.Completion = CompletionForAttempt(res.Phase, kind, execRes.StartAttempted, execRes.Started, execRes.ExitObserved)
		res.Status = StatusFailed
		res.Error = BuildError(execErr, kind, retryIntent(req), res.Completion)
		return
	}

	res.Phase = PhaseComplete
	res.Completion = CompletionCompleted
	if execRes.ExitCode != 0 {
		res.Status = StatusFailed
		res.Error = BuildError(
			fmt.Errorf("remote command exited with status %d", execRes.ExitCode),
			ErrorKindRemoteExit,
			retryIntent(req),
			CompletionCompleted,
		)
		return
	}
	res.Status = StatusSucceeded
}

func buildSSHConfig(req *Request, target ResolvedTarget) *sshclient.Config {
	cfg := &sshclient.Config{
		Host:                   target.Address,
		Port:                   target.Port,
		User:                   target.User,
		KeyPath:                firstNonEmpty(req.Policy.KeyPath, target.KeyPath),
		UseKeyAuth:             req.Policy.UseKeyAuth,
		Timeout:                req.Limits.Timeout,
		HostTimeout:            req.Limits.HostTimeout,
		GlobalTimeout:          req.Limits.GlobalTimeout,
		MaxFailures:            req.Policy.MaxFailures,
		MaxOutputBytes:         req.Limits.MaxOutputBytesPerTarget,
		MaxPayloadBytes:        req.Limits.MaxPayloadBytes,
		ExecutionID:            targetExecutionID(req.ExecutionID, target),
		KnownHostsData:         target.KnownHostsData,
		ExpectedKeyFingerprint: target.ExpectedKeyFingerprint,
		SafetyCheck:            req.Policy.SafetyCheckEnabled && !req.Policy.SafetyBypass,
		Force:                  req.Policy.SafetyBypass,
		AcceptUnknownHost:      req.Policy.AcceptUnknownHost,
		AllowInsecureHostKey:   req.Policy.AllowInsecureHostKey,
		KnownHostsPath:         req.Policy.KnownHostsPath,
		JSONOutput:             true,
		SudoKey:                firstNonEmpty(target.SudoPasswordKey, req.Policy.SudoPasswordKey),
		Command:                req.Action.Command,
		Mode:                   "ssh",
		Bind:                   target.Bind,
	}
	risk, _ := requestRisk(req)
	cfg.Risk = string(risk)
	if req.Plan != nil {
		cfg.PlanHash = req.Plan.PlanHash
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
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
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
		if cause := ctx.Err(); cause != nil {
			return cause
		}
		if err != nil {
			return err
		}
		cfg.Password = pw
	}

	needSudo := req.Action.UseSudo || (req.Action.Kind == ActionCommand && sshclient.CommandUsesSudo(req.Action.Command))
	if !needSudo {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
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
	if cause := ctx.Err(); cause != nil {
		return cause
	}
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
		Metadata:        tr.Metadata,
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
		PeerAddress:     tr.PeerAddress,
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
