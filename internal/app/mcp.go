package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/logger"
)

// mcpEntryEnv marks child invocations spawned by the MCP server so audit
// events can attribute them to the MCP entry point. It is metadata only and
// never participates in trust or safety decisions.
const mcpEntryEnv = "SSHX_ENTRY=mcp"

// mcpDefaultProcessTimeout is an adapter watchdog, not a remote execution limit.
// A command timeout cannot bound fan-out: queued targets still need their turn.
const mcpDefaultProcessTimeout = 30 * time.Minute

// mcpProcessGrace lets the CLI report its own explicit global timeout first.
const mcpProcessGrace = 2 * time.Minute

const (
	mcpShutdownGrace     = 3 * time.Second
	mcpProgressGrace     = 250 * time.Millisecond
	mcpProgressQueueSize = 64
	mcpMaxStdoutBytes    = 64 << 20
	mcpMaxStderrBytes    = 1 << 20
	mcpMaxEventBytes     = 64 << 20 // JSON escaping can expand the CLI's 10 MiB output cap sixfold.
	mcpMaxEvents         = 100000
)

// parseMCPArgs configures the stdio MCP server mode. The subcommand takes no
// flags: the server is spawned and owned by an MCP client over stdio.
func parseMCPArgs(config *sshclient.Config, args []string) {
	config.Mode = "mcp"
	for _, arg := range args {
		config.ArgumentError = fmt.Sprintf("sshx mcp accepts no arguments, got %q", arg)
		return
	}
}

// RunMCPServer serves the Model Context Protocol over stdio. Every tool call
// self-executes the sshx binary as a one-shot child process with --json, so
// the MCP surface exposes exactly the CLI execution contract: same schemas,
// same safety gates, same audit trail. No remote sessions survive a tool call;
// the server lives and dies with the client that spawned it.
func RunMCPServer() error {
	return RunMCPServerContext(context.Background())
}

// RunMCPServerContext also cancels in-flight children when the root invocation
// is interrupted or the owning stdio client disconnects.
func RunMCPServerContext(ctx context.Context) error {
	input, output, err := mcpStdioFiles()
	if err != nil {
		return err
	}
	defer func() { mcpCleanup("stdin", input.Close()) }()
	defer func() { mcpCleanup("stdout", output.Close()) }()
	return runMCPServerContext(ctx, &mcp.IOTransport{Reader: input, Writer: output})
}

func runMCPServerContext(ctx context.Context, transport mcp.Transport) error {
	parent := ctx
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "sshx",
		Title:   "sshx — agent-native remote execution over SSH",
		Version: Version,
	}, nil)
	// The SDK detaches request contexts from the connection's root context.
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(callCtx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			callCtx, cancelCall := context.WithCancel(callCtx)
			stop := context.AfterFunc(ctx, cancelCall)
			defer stop()
			defer cancelCall()
			if ctx.Err() != nil {
				cancelCall()
			}
			return next(callCtx, method, req)
		}
	})
	registerMCPTools(server)
	err := server.Run(ctx, &mcpLifetimeTransport{Transport: transport, cancel: cancel})
	if parent.Err() != nil {
		return parent.Err()
	}
	if errors.Is(context.Cause(ctx), io.EOF) {
		return nil
	}
	if errors.Is(err, context.Canceled) && context.Cause(ctx) != nil {
		return context.Cause(ctx)
	}
	return err
}

type mcpLifetimeTransport struct {
	mcp.Transport
	cancel context.CancelCauseFunc
}

func (t *mcpLifetimeTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { mcpCleanup("transport", conn.Close()) })
	return &mcpLifetimeConnection{Connection: conn, cancel: t.cancel, stop: stop}, nil
}

type mcpLifetimeConnection struct {
	mcp.Connection
	cancel context.CancelCauseFunc
	stop   func() bool
}

func (c *mcpLifetimeConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	msg, err := c.Connection.Read(ctx)
	if err != nil {
		c.cancel(err)
	}
	return msg, err
}

func (c *mcpLifetimeConnection) Write(ctx context.Context, msg jsonrpc.Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { mcpCleanup("interrupted transport", c.Close()) })
	defer stop()
	err := c.Connection.Write(ctx, msg)
	if err != nil {
		c.cancel(err)
	}
	return err
}

func (c *mcpLifetimeConnection) Close() error {
	c.cancel(context.Canceled)
	c.stop()
	return c.Connection.Close()
}

func mcpCleanup(resource string, err error) {
	if err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, os.ErrProcessDone) {
		logger.GetLogger().Debug("mcp cleanup %s: %v", resource, err)
	}
}

// selfExecResult captures one child invocation outcome.
type selfExecResult struct {
	ExitCode     int
	Stdout       string
	Stderr       string
	AdapterError error
	validated    bool
}

// execSelf runs the current sshx binary with args as a one-shot child
// process, marking it as MCP-originated for audit purposes.
func execSelf(ctx context.Context, args []string, stdin string, globalTimeout time.Duration) (*selfExecResult, error) {
	res, _, err := execSelfJSONL(ctx, args, stdin, globalTimeout, nil)
	return res, err
}

func mcpProcessTimeout(globalTimeout time.Duration) time.Duration {
	if globalTimeout > 0 && globalTimeout < mcpDefaultProcessTimeout-mcpProcessGrace {
		return globalTimeout + mcpProcessGrace
	}
	return mcpDefaultProcessTimeout
}

func execSelfJSONL(ctx context.Context, args []string, stdin string, globalTimeout time.Duration, onEvent func(execution.Event)) (*selfExecResult, []execution.Event, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve sshx executable: %w", err)
	}
	cmd := exec.Command(exe, args...) // #nosec G204 -- our own binary, without shell interpretation.
	cmd.Env = append(os.Environ(), mcpEntryEnv)
	return execMCPCommand(ctx, cmd, stdin, globalTimeout, onEvent)
}

func execMCPCommand(ctx context.Context, cmd *exec.Cmd, stdin string, globalTimeout time.Duration, onEvent func(execution.Event)) (*selfExecResult, []execution.Event, error) {
	ctx, cancel := context.WithTimeout(ctx, mcpProcessTimeout(globalTimeout))
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("sshx mcp child not started: %w", err)
	}
	process, err := prepareMCPProcess(cmd)
	if err != nil {
		return nil, nil, err
	}
	defer process.close()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	// Command's copying goroutines drain both pipes independently. Output and
	// progress are bounded, and neither writer waits for an MCP client.
	progress, finishProgress := mcpProgressDispatcher(onEvent)
	defer finishProgress()
	stdout := mcpOutputCapture{limit: mcpMaxStdoutBytes, onEvent: progress, cancel: cancel}
	stderr := mcpBoundedBuffer{limit: mcpMaxStderrBytes}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = mcpShutdownGrace
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("spawn sshx child process: %w", err)
	}
	if err := process.started(); err != nil {
		mcpCleanup("failed child", cmd.Process.Kill())
		mcpCleanup("failed child wait", cmd.Wait())
		return nil, nil, err
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	var runErr, interruption error
	select {
	case runErr = <-wait:
	case <-ctx.Done():
		interruption = ctx.Err()
		mcpCleanup("child interruption", process.interrupt())
		timer := time.NewTimer(mcpShutdownGrace)
		select {
		case runErr = <-wait:
		case <-timer.C:
			mcpCleanup("child escalation", process.kill())
			runErr = <-wait
		}
		timer.Stop()
	}
	// A completed child must not leave descendants holding resources or pipes.
	mcpCleanup("child descendants", process.kill())
	stdout.finish()
	result := &selfExecResult{Stdout: stdout.String(), Stderr: stderr.String(), AdapterError: stdout.err}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
	} else if runErr != nil {
		result.ExitCode = -1
		result.AdapterError = errors.Join(result.AdapterError, fmt.Errorf("child output transport: %w", runErr))
	}
	if interruption != nil {
		label := "child invocation canceled"
		if errors.Is(interruption, context.DeadlineExceeded) {
			label = "child invocation exceeded the local process watchdog"
		}
		result.Stderr = strings.TrimSpace(result.Stderr + "\nsshx mcp: " + label)
	}
	events, outputErr := validateMCPOutput(result.Stdout)
	result.validated = true
	result.AdapterError = errors.Join(result.AdapterError, outputErr)
	if result.AdapterError != nil && interruption != nil {
		result.AdapterError = errors.Join(result.AdapterError, interruption)
	}
	return result, events, nil
}

// mcpToolResult converts a child invocation into an MCP tool result. The
// child's stdout (a single JSON document in --json mode) is the tool content;
// a non-zero exit marks the result as a tool error while preserving the
// structured payload so agents can still branch on error_kind and friends.
func mcpToolResult(res *selfExecResult) *mcp.CallToolResult {
	content := []mcp.Content{}
	if !res.validated && res.AdapterError == nil {
		_, res.AdapterError = validateMCPOutput(res.Stdout)
		res.validated = true
	}
	if res.AdapterError != nil {
		content = append(content, &mcp.TextContent{Text: "sshx mcp adapter failure: " + res.AdapterError.Error()})
	} else {
		content = append(content, &mcp.TextContent{Text: res.Stdout})
	}
	if strings.TrimSpace(res.Stderr) != "" {
		content = append(content, &mcp.TextContent{Text: "stderr:\n" + res.Stderr})
	}
	return &mcp.CallToolResult{Content: content, IsError: res.ExitCode != 0 || res.AdapterError != nil}
}

func runMCPTool(ctx context.Context, args []string, stdin string, globalTimeout time.Duration) (*mcp.CallToolResult, any, error) {
	res, err := execSelf(ctx, args, stdin, globalTimeout)
	if err != nil {
		return nil, nil, err
	}
	return mcpToolResult(res), nil, nil
}

func runMCPRun(ctx context.Context, req *mcp.CallToolRequest, in mcpRunInput) (*mcp.CallToolResult, any, error) {
	args, stdin, err := buildRunArgs(in)
	if err != nil {
		return nil, nil, err
	}
	token := any(nil)
	if req != nil {
		if req.Params != nil {
			token = req.Params.GetProgressToken()
		}
	}
	if token == nil {
		return runMCPTool(ctx, args, stdin, timeoutSeconds(in.GlobalTimeoutSecs))
	}
	for i, arg := range args {
		if arg == "--json" {
			args[i] = "--jsonl"
		}
	}
	var finished float64
	var total float64
	res, events, err := execSelfJSONL(ctx, args, stdin, timeoutSeconds(in.GlobalTimeoutSecs), func(ev execution.Event) {
		if ctx.Err() != nil {
			return
		}
		if ev.Kind == execution.EventRunStarted && ev.Counts != nil {
			total = float64(ev.Counts.Selected)
		}
		if ev.Kind != execution.EventTargetFinished || req.Session == nil {
			return
		}
		finished++
		alias := ""
		if ev.Target != nil {
			alias = ev.Target.Alias
		}
		notifyCtx, cancel := context.WithTimeout(ctx, mcpProgressGrace)
		defer cancel()
		if progErr := req.Session.NotifyProgress(notifyCtx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Progress:      finished,
			Total:         total,
			Message:       fmt.Sprintf("target_finished %s", alias),
		}); progErr != nil {
			logger.GetLogger().Debug("mcp progress notification failed: %v", progErr)
		}
	})
	if err != nil {
		return nil, nil, err
	}
	if res.AdapterError == nil {
		if synthesized := synthesizeRunJSONResult(events); synthesized != "" {
			res.Stdout = synthesized
		}
	}
	return mcpToolResult(res), nil, nil
}

func synthesizeRunJSONResult(events []execution.Event) string {
	if validateMCPEvents(events) != nil || events[0].Counts.Selected != 1 {
		return ""
	}
	var result *execution.Result
	for _, ev := range events {
		if ev.Kind == execution.EventTargetFinished {
			result = execution.ToResult(ev.RunID, ev.RequestID, *ev.Result)
		}
	}
	data, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	return string(data) + "\n"
}

type mcpBoundedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *mcpBoundedBuffer) Len() int { return b.buffer.Len() }

func (b *mcpBoundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > b.limit-b.Len() {
		p = p[:b.limit-b.Len()]
		b.truncated = true
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

func (b *mcpBoundedBuffer) String() string {
	if b.truncated {
		return b.buffer.String() + "\n[sshx mcp: stderr truncated]"
	}
	return b.buffer.String()
}

type mcpOutputCapture struct {
	buffer  bytes.Buffer
	limit   int
	line    []byte
	onEvent func(execution.Event)
	cancel  context.CancelFunc
	err     error
}

func (b *mcpOutputCapture) Len() int       { return b.buffer.Len() }
func (b *mcpOutputCapture) String() string { return b.buffer.String() }

func (b *mcpOutputCapture) fail(err error) {
	if b.err == nil {
		b.err = err
		b.cancel()
	}
}

func (b *mcpOutputCapture) Write(p []byte) (int, error) {
	n := len(p)
	if b.err != nil {
		return n, nil
	}
	if n > b.limit-b.Len() {
		b.fail(fmt.Errorf("child stdout exceeds %d byte adapter limit", b.limit))
		return n, nil
	}
	_, _ = b.buffer.Write(p)
	if b.onEvent == nil {
		return n, nil
	}
	// Unlike Scanner's default token limit, this accepts the CLI's bounded
	// output even after JSON escaping. Errors cancel the child, not pipe reads.
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			i = len(p)
		}
		if len(b.line)+i > mcpMaxEventBytes {
			b.fail(fmt.Errorf("child JSONL record exceeds %d bytes", mcpMaxEventBytes))
			return n, nil
		}
		b.line = append(b.line, p[:i]...)
		if i == len(p) {
			break
		}
		b.emitLine()
		if b.err != nil {
			return n, nil
		}
		p = p[i+1:]
	}
	return n, nil
}

func (b *mcpOutputCapture) emitLine() {
	line := bytes.TrimSpace(b.line)
	if len(line) > 0 {
		var ev execution.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			b.fail(fmt.Errorf("malformed child JSONL record: %w", err))
		} else if ev.Kind != "" {
			// Progress does not need target output or evidence; do not retain
			// potentially large result payloads in a slow notification queue.
			b.onEvent(execution.Event{Kind: ev.Kind, Target: ev.Target, Counts: ev.Counts})
		}
	}
	b.line = b.line[:0]
}

func (b *mcpOutputCapture) finish() {
	if b.onEvent != nil && b.err == nil && len(bytes.TrimSpace(b.line)) > 0 {
		b.fail(fmt.Errorf("incomplete child JSONL stream: missing final newline"))
	}
}

func mcpProgressDispatcher(onEvent func(execution.Event)) (func(execution.Event), func()) {
	if onEvent == nil {
		return nil, func() {}
	}
	queue := make(chan execution.Event, mcpProgressQueueSize)
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case ev, ok := <-queue:
				if !ok {
					return
				}
				onEvent(ev)
			}
		}
	}()
	var once sync.Once
	return func(ev execution.Event) {
			select {
			case queue <- ev:
			default: // Best-effort progress must never backpressure child stdout.
			}
		}, func() {
			once.Do(func() {
				close(queue)
				timer := time.NewTimer(mcpProgressGrace)
				defer timer.Stop()
				select {
				case <-done:
				case <-timer.C:
					close(stop)
				}
			})
		}
}

func validateMCPOutput(raw string) ([]execution.Event, error) {
	if len(raw) > mcpMaxStdoutBytes {
		return nil, fmt.Errorf("child stdout exceeds %d byte adapter limit", mcpMaxStdoutBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	var events []execution.Event
	documents := 0
	for {
		var value json.RawMessage
		err := decoder.Decode(&value)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("malformed or incomplete child JSON output: %w", err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(value, &fields); err != nil || len(fields) == 0 {
			return nil, fmt.Errorf("child JSON output is not a result object")
		}
		if _, isEvent := fields["kind"]; isEvent {
			if len(value) > mcpMaxEventBytes || len(events) >= mcpMaxEvents {
				return nil, fmt.Errorf("child event stream exceeds adapter retention limit")
			}
			var ev execution.Event
			if err := json.Unmarshal(value, &ev); err != nil {
				return nil, fmt.Errorf("invalid child event: %w", err)
			}
			events = append(events, ev)
		} else {
			var schema string
			if rawSchema, present := fields["schema_version"]; present {
				if schemaErr := json.Unmarshal(rawSchema, &schema); schemaErr != nil || schema == "" {
					return nil, fmt.Errorf("child JSON output has an invalid schema version")
				}
			}
			var legacy struct {
				Success  *bool  `json:"success"`
				ExitCode *int   `json:"exit_code"`
				DryRun   bool   `json:"dry_run"`
				Valid    *bool  `json:"valid"`
				Mode     string `json:"mode"`
			}
			legacyErr := json.Unmarshal(value, &legacy)
			compatibility := legacyErr == nil && ((legacy.Success != nil && legacy.ExitCode != nil) ||
				(legacy.DryRun && legacy.Valid != nil && legacy.Mode != ""))
			if schema == "" && !compatibility {
				return nil, fmt.Errorf("child JSON output lacks a result schema or compatibility envelope")
			}
			documents++
		}
	}
	if documents == 1 && len(events) == 0 {
		return nil, nil
	}
	if documents != 0 || len(events) == 0 {
		return nil, fmt.Errorf("missing or ambiguous child final JSON document")
	}
	if !strings.HasSuffix(raw, "\n") {
		return nil, fmt.Errorf("incomplete child JSONL stream: missing final newline")
	}
	if err := validateMCPEvents(events); err != nil {
		return nil, err
	}
	return events, nil
}

func validateMCPEvents(events []execution.Event) error {
	fail := func(reason string) error { return fmt.Errorf("invalid or incomplete child event stream: %s", reason) }
	if len(events) < 3 || len(events) > mcpMaxEvents {
		return fail("missing run boundaries or too many events")
	}
	first, last := events[0], events[len(events)-1]
	if first.Kind != execution.EventRunStarted || last.Kind != execution.EventRunFinished ||
		first.Counts == nil || last.Counts == nil || first.Counts.Selected < 1 || first.RunID == "" {
		return fail("missing run_started/run_finished with selected targets")
	}
	counts := execution.RunCounts{Selected: first.Counts.Selected}
	started := make(map[int]execution.ResolvedTarget)
	finished := make(map[int]bool)
	for i, ev := range events {
		if ev.SchemaVersion != execution.EventSchemaVersion || ev.RunID != first.RunID ||
			ev.RequestID != first.RequestID || ev.Sequence != int64(i+1) {
			return fail("schema, run/request identity, or sequence mismatch")
		}
		switch ev.Kind {
		case execution.EventRunStarted:
			if i != 0 || ev.Counts.Started != 0 || ev.Counts.Succeeded != 0 ||
				ev.Counts.Failed != 0 || ev.Counts.Uncertain != 0 || ev.Counts.Skipped < 0 {
				return fail("invalid run_started counts or duplicate boundary")
			}
		case execution.EventRunFinished:
			if i != len(events)-1 {
				return fail("premature run_finished")
			}
		case execution.EventTargetStarted, execution.EventTargetFinished:
			if ev.Target == nil || ev.Target.Index < 0 {
				return fail("missing or invalid target identity")
			}
			index := ev.Target.Index
			if finished[index] {
				return fail("duplicate or already finished target")
			}
			if ev.Kind == execution.EventTargetStarted {
				if _, ok := started[index]; ok {
					return fail("duplicate target_started")
				}
				started[index] = *ev.Target
				counts.Started++
				continue
			}
			tr := ev.Result
			if tr == nil || !reflect.DeepEqual(tr.Target, *ev.Target) {
				return fail("target result identity mismatch")
			}
			identity, admitted := started[index]
			// The connected peer fingerprint is observation evidence, not a
			// change to the selected target's public endpoint identity.
			if identity.HostKeyFingerprint == "" {
				identity.HostKeyFingerprint = tr.Target.HostKeyFingerprint
			}
			if admitted && !reflect.DeepEqual(identity, tr.Target) {
				return fail("started/finished target identity mismatch")
			}
			switch tr.Status {
			case execution.StatusSkipped:
				if admitted || tr.Completion != execution.CompletionNotStarted {
					return fail("skipped target was already started")
				}
				counts.Skipped++
			case execution.StatusSucceeded:
				if !admitted || tr.ExitCode != 0 || tr.Completion != execution.CompletionCompleted || tr.Error != nil {
					return fail("inconsistent successful target result")
				}
				counts.Succeeded++
			case execution.StatusFailed:
				if !admitted {
					return fail("failed target was not started")
				}
				counts.Failed++
				if tr.Completion == execution.CompletionUnknown ||
					tr.Completion == execution.CompletionPartial ||
					tr.Completion == execution.CompletionCompletedUnconfirmed {
					counts.Uncertain++
				}
			default:
				return fail("unknown target status")
			}
			finished[index] = true
		default:
			return fail("unknown event kind")
		}
	}
	if len(finished) != counts.Selected || *last.Counts != counts {
		return fail("terminal target coverage or final counts mismatch")
	}
	return nil
}

func timeoutSeconds(seconds int) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// --- tool inputs -----------------------------------------------------------

type mcpRunInput struct {
	ExpectPlan        string   `json:"expect_plan,omitempty" jsonschema:"Expected sha256 execution plan hash; mismatch is rejected before connecting."`
	HostTimeoutSecs   int      `json:"host_timeout_seconds,omitempty" jsonschema:"Optional whole-target budget in seconds, including connection and verification."`
	GlobalTimeoutSecs int      `json:"global_timeout_seconds,omitempty" jsonschema:"Optional whole-operation budget in seconds, including queue time. MCP has a separate 30-minute watchdog."`
	RequestID         string   `json:"request_id,omitempty" jsonschema:"Caller correlation identifier preserved in results and events."`
	FailFast          bool     `json:"fail_fast,omitempty" jsonschema:"Stop queued admission after the first failure; active targets finish."`
	MaxFailures       *int     `json:"max_failures,omitempty" jsonschema:"Positive failure threshold that stops queued admission; active targets finish."`
	Targets           []string `json:"targets,omitempty" jsonschema:"Configured host names to execute on (strict aliases, never DNS)."`
	Groups            []string `json:"groups,omitempty" jsonschema:"Configured host groups; union with targets."`
	Tags              []string `json:"tags,omitempty" jsonschema:"Tag filters in key=value form, combined with AND."`
	AllHosts          bool     `json:"all_hosts,omitempty" jsonschema:"Select all configured hosts before tag filters."`
	Address           string   `json:"address,omitempty" jsonschema:"Explicit single literal address (not for fan-out)."`
	Command           string   `json:"command,omitempty" jsonschema:"Remote command line. Exactly one of command or script is required."`
	Script            string   `json:"script,omitempty" jsonschema:"Byte-preserving script payload delivered over stdin. Exactly one of command or script is required."`
	Shell             string   `json:"shell,omitempty" jsonschema:"Script interpreter override: sh, bash, zsh, dash, ksh, or ash. Defaults to the script's shebang, then sh."`
	TimeoutSecs       int      `json:"timeout_seconds,omitempty" jsonschema:"Remote execution timeout in seconds (default 60)."`
	Concurrency       int      `json:"concurrency,omitempty" jsonschema:"Bounded fan-out (default 4, hard max 32)."`
	FailureMode       string   `json:"failure_mode,omitempty" jsonschema:"continue or fail_fast (default continue)."`
	Intent            string   `json:"intent,omitempty" jsonschema:"Declared action intent: read, change, or unknown."`
	DryRun            bool     `json:"dry_run,omitempty" jsonschema:"Preview the local execution plan without connecting or executing."`
	Force             bool     `json:"force,omitempty" jsonschema:"Bypass safety checks; requires bypass_reason and is recorded in results and audit."`
	NoSafetyCheck     bool     `json:"no_safety_check,omitempty" jsonschema:"Disable safety checks entirely; requires bypass_reason."`
	BypassReason      string   `json:"bypass_reason,omitempty" jsonschema:"Mandatory justification when force or no_safety_check is set."`
	Bind              string   `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpSQLInput struct {
	ExpectPlan        string `json:"expect_plan,omitempty" jsonschema:"Expected sha256 execution plan hash; mismatch is rejected before connecting."`
	HostTimeoutSecs   int    `json:"host_timeout_seconds,omitempty" jsonschema:"Optional whole-target budget in seconds."`
	GlobalTimeoutSecs int    `json:"global_timeout_seconds,omitempty" jsonschema:"Optional whole-operation budget in seconds; MCP also has a 30-minute watchdog."`
	BypassReason      string `json:"bypass_reason,omitempty" jsonschema:"Optional recorded justification for SQL policy bypasses."`
	Target            string `json:"target" jsonschema:"Configured host name or address to reach over SSH."`
	Statement         string `json:"statement" jsonschema:"Exactly one SQL statement; multi-statement input is blocked fail-closed."`
	Engine            string `json:"engine,omitempty" jsonschema:"postgres (default), sqlite, or mysql."`
	DB                string `json:"db,omitempty" jsonschema:"PostgreSQL database name."`
	DBFile            string `json:"db_file,omitempty" jsonschema:"Absolute SQLite database file path (required for engine=sqlite)."`
	DBUser            string `json:"db_user,omitempty" jsonschema:"Database role."`
	DBHost            string `json:"db_host,omitempty" jsonschema:"Database host as seen from the remote host."`
	DBPort            string `json:"db_port,omitempty" jsonschema:"Database port."`
	DBPasswordKey     string `json:"db_password_key,omitempty" jsonschema:"OS-keyring key holding the DB password; delivered via stdin, never argv."`
	Docker            string `json:"docker,omitempty" jsonschema:"Run the database client inside this container via docker exec -i."`
	DBCredFrom        string `json:"db_cred_from,omitempty" jsonschema:"Resolve credentials on the remote host: docker:<container> or env-file:<path>."`
	CredCache         string `json:"cred_cache,omitempty" jsonschema:"off or a duration for caching remotely resolved credentials (default 15m)."`
	CredRefresh       bool   `json:"cred_refresh,omitempty" jsonschema:"Drop the cached credential entry and re-resolve."`
	Explain           bool   `json:"explain,omitempty" jsonschema:"Run EXPLAIN only; never executes the statement."`
	RowThreshold      int    `json:"row_threshold,omitempty" jsonschema:"EXPLAIN row estimate that upgrades a row backup to a full-table snapshot (default 1000)."`
	AllowFullTable    bool   `json:"allow_full_table,omitempty" jsonschema:"Required for UPDATE/DELETE without a WHERE clause."`
	NoBackup          bool   `json:"no_backup,omitempty" jsonschema:"Skip the pre-change backup; requires force."`
	BackupDir         string `json:"backup_dir,omitempty" jsonschema:"Remote backup directory (default ~/.sshx/sql-backups)."`
	Sudo              bool   `json:"sudo,omitempty" jsonschema:"Run the remote database client via sudo -S when the SSH user cannot open the database file."`
	Force             bool   `json:"force,omitempty" jsonschema:"Confirms DDL; destructive DDL also requires no_backup."`
	DryRun            bool   `json:"dry_run,omitempty" jsonschema:"Preview the guarded SQL plan without connecting."`
	TimeoutSecs       int    `json:"timeout_seconds,omitempty" jsonschema:"Remote execution timeout in seconds."`
	Bind              string `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpApplyInput struct {
	ExpectPlan        string  `json:"expect_plan,omitempty" jsonschema:"Expected sha256 execution plan hash; mismatch is rejected before connecting."`
	HostTimeoutSecs   int     `json:"host_timeout_seconds,omitempty" jsonschema:"Optional whole-target budget in seconds."`
	GlobalTimeoutSecs int     `json:"global_timeout_seconds,omitempty" jsonschema:"Optional whole-operation budget in seconds; MCP also has a 30-minute watchdog."`
	Target            string  `json:"target" jsonschema:"Configured host name or address."`
	Path              string  `json:"path" jsonschema:"Absolute remote file path to replace."`
	FromPath          string  `json:"from_path,omitempty" jsonschema:"Local source file. Exactly one of from_path or content is required."`
	Content           *string `json:"content,omitempty" jsonschema:"Inline file content (including an empty file) written to a private temp file. Exactly one of from_path or content is required."`
	ExpectSHA256      string  `json:"expect_sha256,omitempty" jsonschema:"Fail closed unless the current remote hash matches."`
	NoBackup          bool    `json:"no_backup,omitempty" jsonschema:"Skip the pre-change backup; requires force."`
	BackupDir         string  `json:"backup_dir,omitempty" jsonschema:"Remote backup directory (default ~/.sshx/file-backups)."`
	Sudo              bool    `json:"sudo,omitempty" jsonschema:"Stage over SFTP, then install with a privileged stdin script."`
	Force             bool    `json:"force,omitempty" jsonschema:"Skip the hash precondition; required with no_backup."`
	BypassReason      string  `json:"bypass_reason,omitempty" jsonschema:"Required with force when overwriting critical identity files."`
	DryRun            bool    `json:"dry_run,omitempty" jsonschema:"Preview the apply plan without connecting."`
	TimeoutSecs       int     `json:"timeout_seconds,omitempty" jsonschema:"Remote execution timeout in seconds."`
	Bind              string  `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpInspectInput struct {
	ExpectPlan        string `json:"expect_plan,omitempty" jsonschema:"Expected sha256 execution plan hash; mismatch is rejected before connecting."`
	HostTimeoutSecs   int    `json:"host_timeout_seconds,omitempty" jsonschema:"Optional whole-target budget in seconds."`
	GlobalTimeoutSecs int    `json:"global_timeout_seconds,omitempty" jsonschema:"Optional whole-operation budget in seconds; MCP also has a 30-minute watchdog."`
	DryRun            bool   `json:"dry_run,omitempty" jsonschema:"Preview the inspection plan without connecting."`
	Target            string `json:"target" jsonschema:"Configured host name or address."`
	Capability        string `json:"capability" jsonschema:"Capability id, e.g. system.baseline, network.listeners, or a trusted local plugin id."`
	Cache             string `json:"cache,omitempty" jsonschema:"off (default) or remote-prefer to reuse/write a redacted remote observation."`
	Refresh           bool   `json:"refresh,omitempty" jsonschema:"Ignore a reusable observation and run the collector."`
	MaxAge            string `json:"max_age,omitempty" jsonschema:"Require observations no older than this duration (e.g. 30m)."`
	AllowStale        bool   `json:"allow_stale,omitempty" jsonschema:"Explicitly allow an expired observation."`
	Sudo              bool   `json:"sudo,omitempty" jsonschema:"Use sudo for an optional-privilege plugin."`
	TimeoutSecs       int    `json:"timeout_seconds,omitempty" jsonschema:"Remote execution timeout in seconds."`
	Bind              string `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpSFTPInput struct {
	ExpectPlan        string `json:"expect_plan,omitempty" jsonschema:"Expected sha256 execution plan hash; mismatch is rejected before connecting."`
	HostTimeoutSecs   int    `json:"host_timeout_seconds,omitempty" jsonschema:"Optional whole-target budget in seconds."`
	GlobalTimeoutSecs int    `json:"global_timeout_seconds,omitempty" jsonschema:"Optional whole-operation budget in seconds; MCP also has a 30-minute watchdog."`
	Target            string `json:"target" jsonschema:"Configured host name or address."`
	Action            string `json:"action" jsonschema:"upload, download, list, mkdir, or remove."`
	LocalPath         string `json:"local_path,omitempty" jsonschema:"Local file path (required for upload and download)."`
	RemotePath        string `json:"remote_path" jsonschema:"Remote path the action operates on."`
	DryRun            bool   `json:"dry_run,omitempty" jsonschema:"Preview the SFTP plan without connecting."`
	TimeoutSecs       int    `json:"timeout_seconds,omitempty" jsonschema:"Remote execution timeout in seconds."`
	Bind              string `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpTransferInput struct {
	ExpectPlan        string `json:"expect_plan,omitempty" jsonschema:"Expected sha256 execution plan hash; mismatch is rejected before connecting."`
	HostTimeoutSecs   int    `json:"host_timeout_seconds,omitempty" jsonschema:"Optional admitted-transfer budget in seconds."`
	GlobalTimeoutSecs int    `json:"global_timeout_seconds,omitempty" jsonschema:"Optional whole-operation budget in seconds; MCP also has a 30-minute watchdog."`
	SourceHost        string `json:"source_host" jsonschema:"Configured host name or address holding the source path."`
	SourcePath        string `json:"source_path" jsonschema:"Source file or directory path."`
	DestHost          string `json:"dest_host" jsonschema:"Configured host name or address receiving the data."`
	DestPath          string `json:"dest_path" jsonschema:"Destination path."`
	DryRun            bool   `json:"dry_run,omitempty" jsonschema:"Preview the transfer plan without connecting."`
	TimeoutSecs       int    `json:"timeout_seconds,omitempty" jsonschema:"Timeout in seconds for the streamed transfer."`
	Bind              string `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpHostListInput struct{}

// --- argument builders (unit-tested) ----------------------------------------

func buildRunArgs(in mcpRunInput) ([]string, string, error) {
	hasCommand := strings.TrimSpace(in.Command) != ""
	hasScript := in.Script != ""
	if hasCommand == hasScript {
		return nil, "", fmt.Errorf("exactly one of command or script is required")
	}
	args := []string{"run", "--json"}
	for _, t := range in.Targets {
		args = append(args, "--target="+t)
	}
	for _, g := range in.Groups {
		args = append(args, "--group="+g)
	}
	for _, tag := range in.Tags {
		args = append(args, "--tag="+tag)
	}
	if in.AllHosts {
		args = append(args, "--all-hosts")
	}
	if in.Address != "" {
		args = append(args, "--address="+in.Address)
	}
	var err error
	args, err = appendMCPLimits(args, in.ExpectPlan, in.TimeoutSecs, in.HostTimeoutSecs, in.GlobalTimeoutSecs)
	if err != nil {
		return nil, "", err
	}
	if in.Concurrency < 0 || in.Concurrency > execution.MaxConcurrency {
		return nil, "", fmt.Errorf("concurrency must be between 1 and %d when set", execution.MaxConcurrency)
	}
	if in.Concurrency > 0 {
		args = append(args, "--concurrency="+strconv.Itoa(in.Concurrency))
	}
	if in.FailureMode != "" {
		args = append(args, "--failure-mode="+in.FailureMode)
	}
	if in.FailFast {
		args = append(args, "--fail-fast")
	}
	if in.MaxFailures != nil {
		if *in.MaxFailures <= 0 {
			return nil, "", fmt.Errorf("max_failures must be positive")
		}
		args = append(args, "--max-failures="+strconv.Itoa(*in.MaxFailures))
	}
	if in.RequestID != "" {
		args = append(args, "--request-id="+in.RequestID)
	}
	if in.Intent != "" {
		args = append(args, "--intent="+in.Intent)
	}
	if in.DryRun {
		args = append(args, "--dry-run")
	}
	if in.Force {
		args = append(args, "--force")
	}
	if in.NoSafetyCheck {
		args = append(args, "--no-safety-check")
	}
	if in.BypassReason != "" {
		args = append(args, "--bypass-reason="+in.BypassReason)
	}
	args = appendBindArg(args, in.Bind)
	stdin := ""
	if hasScript {
		args = append(args, "--script-stdin")
		if in.Shell != "" {
			args = append(args, "--shell="+in.Shell)
		}
		stdin = in.Script
	} else {
		if in.Shell != "" {
			return nil, "", fmt.Errorf("shell only applies to a script payload")
		}
		args = append(args, "--", in.Command)
	}
	return args, stdin, nil
}

func buildSQLArgs(in mcpSQLInput) ([]string, error) {
	if in.RowThreshold < 0 {
		return nil, fmt.Errorf("row_threshold cannot be negative")
	}
	if strings.TrimSpace(in.Target) == "" {
		return nil, fmt.Errorf("target is required")
	}
	if strings.TrimSpace(in.Statement) == "" {
		return nil, fmt.Errorf("statement is required")
	}
	args := []string{"sql", "--json", "-h=" + in.Target}
	if in.Engine != "" {
		args = append(args, "--engine="+in.Engine)
	}
	if in.DB != "" {
		args = append(args, "--db="+in.DB)
	}
	if in.DBFile != "" {
		args = append(args, "--db-file="+in.DBFile)
	}
	if in.DBUser != "" {
		args = append(args, "--db-user="+in.DBUser)
	}
	if in.DBHost != "" {
		args = append(args, "--db-host="+in.DBHost)
	}
	if in.DBPort != "" {
		args = append(args, "--db-port="+in.DBPort)
	}
	if in.DBPasswordKey != "" {
		args = append(args, "--db-password-key="+in.DBPasswordKey)
	}
	if in.Docker != "" {
		args = append(args, "--docker="+in.Docker)
	}
	if in.DBCredFrom != "" {
		args = append(args, "--db-cred-from="+in.DBCredFrom)
	}
	if in.CredCache != "" {
		args = append(args, "--cred-cache="+in.CredCache)
	}
	if in.CredRefresh {
		args = append(args, "--cred-refresh")
	}
	if in.Explain {
		args = append(args, "--explain")
	}
	if in.RowThreshold > 0 {
		args = append(args, "--row-threshold="+strconv.Itoa(in.RowThreshold))
	}
	if in.AllowFullTable {
		args = append(args, "--allow-full-table")
	}
	if in.NoBackup {
		args = append(args, "--no-backup")
	}
	if in.BackupDir != "" {
		args = append(args, "--backup-dir="+in.BackupDir)
	}
	if in.Sudo {
		args = append(args, "--sudo")
	}
	if in.Force {
		args = append(args, "--force")
	}
	if in.BypassReason != "" {
		args = append(args, "--bypass-reason="+in.BypassReason)
	}
	if in.DryRun {
		args = append(args, "--dry-run")
	}
	var err error
	args, err = appendMCPLimits(args, in.ExpectPlan, in.TimeoutSecs, in.HostTimeoutSecs, in.GlobalTimeoutSecs)
	if err != nil {
		return nil, err
	}
	args = appendBindArg(args, in.Bind)
	args = append(args, "--", in.Statement)
	return args, nil
}

func buildApplyArgs(in mcpApplyInput, fromPath string) ([]string, error) {
	if strings.TrimSpace(in.Target) == "" {
		return nil, fmt.Errorf("target is required")
	}
	if strings.TrimSpace(in.Path) == "" {
		return nil, fmt.Errorf("path is required")
	}
	args := []string{"apply", "--json", "-h=" + in.Target, "--path=" + in.Path, "--from=" + fromPath}
	if in.ExpectSHA256 != "" {
		args = append(args, "--expect-sha256="+in.ExpectSHA256)
	}
	if in.NoBackup {
		args = append(args, "--no-backup")
	}
	if in.BackupDir != "" {
		args = append(args, "--backup-dir="+in.BackupDir)
	}
	if in.Sudo {
		args = append(args, "--sudo")
	}
	if in.Force {
		args = append(args, "--force")
	}
	if in.BypassReason != "" {
		args = append(args, "--bypass-reason="+in.BypassReason)
	}
	if in.DryRun {
		args = append(args, "--dry-run")
	}
	var err error
	args, err = appendMCPLimits(args, in.ExpectPlan, in.TimeoutSecs, in.HostTimeoutSecs, in.GlobalTimeoutSecs)
	if err != nil {
		return nil, err
	}
	args = appendBindArg(args, in.Bind)
	return args, nil
}

func buildInspectArgs(in mcpInspectInput) ([]string, error) {
	if strings.TrimSpace(in.Target) == "" {
		return nil, fmt.Errorf("target is required")
	}
	if strings.TrimSpace(in.Capability) == "" {
		return nil, fmt.Errorf("capability is required")
	}
	args := []string{"inspect", "--json", "-h=" + in.Target}
	if in.Cache != "" {
		args = append(args, "--cache="+in.Cache)
	}
	if in.Refresh {
		args = append(args, "--refresh")
	}
	if in.MaxAge != "" {
		args = append(args, "--max-age="+in.MaxAge)
	}
	if in.AllowStale {
		args = append(args, "--allow-stale")
	}
	if in.Sudo {
		args = append(args, "--sudo")
	}
	if in.DryRun {
		args = append(args, "--dry-run")
	}
	var err error
	args, err = appendMCPLimits(args, in.ExpectPlan, in.TimeoutSecs, in.HostTimeoutSecs, in.GlobalTimeoutSecs)
	if err != nil {
		return nil, err
	}
	args = appendBindArg(args, in.Bind)
	args = append(args, in.Capability)
	return args, nil
}

func buildSFTPArgs(in mcpSFTPInput) ([]string, error) {
	if strings.TrimSpace(in.Target) == "" {
		return nil, fmt.Errorf("target is required")
	}
	if strings.TrimSpace(in.RemotePath) == "" {
		return nil, fmt.Errorf("remote_path is required")
	}
	args := []string{"--json", "-h=" + in.Target}
	switch in.Action {
	case "upload":
		if in.LocalPath == "" {
			return nil, fmt.Errorf("local_path is required for upload")
		}
		args = append(args, "--upload="+in.LocalPath, "--to="+in.RemotePath)
	case "download":
		if in.LocalPath == "" {
			return nil, fmt.Errorf("local_path is required for download")
		}
		args = append(args, "--download="+in.RemotePath, "--to="+in.LocalPath)
	case "list":
		args = append(args, "--list="+in.RemotePath)
	case "mkdir":
		args = append(args, "--mkdir="+in.RemotePath)
	case "remove":
		args = append(args, "--rm="+in.RemotePath)
	default:
		return nil, fmt.Errorf("action must be one of upload, download, list, mkdir, remove")
	}
	if in.DryRun {
		args = append(args, "--dry-run")
	}
	var err error
	args, err = appendMCPLimits(args, in.ExpectPlan, in.TimeoutSecs, in.HostTimeoutSecs, in.GlobalTimeoutSecs)
	if err != nil {
		return nil, err
	}
	args = appendBindArg(args, in.Bind)
	return args, nil
}

func buildTransferArgs(in mcpTransferInput) ([]string, error) {
	for name, value := range map[string]string{
		"source_host": in.SourceHost, "source_path": in.SourcePath,
		"dest_host": in.DestHost, "dest_path": in.DestPath,
	} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%s is required", name)
		}
	}
	args := []string{"--json",
		"--transfer=" + in.SourceHost + ":" + in.SourcePath,
		"--to=" + in.DestHost + ":" + in.DestPath,
	}
	if in.DryRun {
		args = append(args, "--dry-run")
	}
	var err error
	args, err = appendMCPLimits(args, in.ExpectPlan, in.TimeoutSecs, in.HostTimeoutSecs, in.GlobalTimeoutSecs)
	if err != nil {
		return nil, err
	}
	args = appendBindArg(args, in.Bind)
	return args, nil
}

func appendBindArg(args []string, bind string) []string {
	if strings.TrimSpace(bind) == "" {
		return args
	}
	return append(args, "--bind="+bind)
}

func appendMCPLimits(args []string, expectPlan string, timeout, hostTimeout, globalTimeout int) ([]string, error) {
	if err := execution.ValidatePlanHash(expectPlan); err != nil {
		return nil, err
	}
	for _, limit := range []struct {
		field string
		flag  string
		value int
	}{
		{"timeout_seconds", "--timeout", timeout},
		{"host_timeout_seconds", "--host-timeout", hostTimeout},
		{"global_timeout_seconds", "--global-timeout", globalTimeout},
	} {
		if limit.value < 0 || uint64(limit.value) > uint64((1<<63-1)/time.Second) {
			return nil, fmt.Errorf("%s must be nonnegative and fit in a duration", limit.field)
		}
		if limit.value > 0 {
			args = append(args, limit.flag+"="+strconv.Itoa(limit.value)+"s")
		}
	}
	if expectPlan != "" {
		args = append(args, "--expect-plan="+expectPlan)
	}
	return args, nil
}

// --- registration -----------------------------------------------------------

func registerMCPTools(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "sshx_run",
		Description: "Execute one command or byte-preserving script on configured SSH hosts through the canonical sshx run contract: " +
			"strict selectors, bounded fan-out, dry-run preview, safety gates, versioned JSON result with per-target status, " +
			"completion certainty, error kind, and retry guidance. Destructive commands are blocked unless force plus bypass_reason is explicit. " +
			"When the client supplies a progressToken, multi-target JSONL events are forwarded as MCP progress notifications.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in mcpRunInput) (*mcp.CallToolResult, any, error) {
		return runMCPRun(ctx, req, in)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "sshx_sql",
		Description: "Run exactly one guarded SQL statement through the remote psql, sqlite3, or mysql/mariadb client: fail-closed classification, " +
			"policy gates, mandatory EXPLAIN and automatic row/table backups for data changes, structured JSON result, and audit. " +
			"Reads run read-only. Use this instead of invoking database clients via sshx_run (which blocks them).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSQLInput) (*mcp.CallToolResult, any, error) {
		args, err := buildSQLArgs(in)
		if err != nil {
			return nil, nil, err
		}
		return runMCPTool(ctx, args, "", timeoutSeconds(in.GlobalTimeoutSecs))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "sshx_apply",
		Description: "Replace exactly one remote regular file with a guarded pipeline: optional expect_sha256 precondition, " +
			"owner-only backup, atomic same-directory rename preserving mode and owner, and a JSON result with changed, hashes, " +
			"and rollback_available. Reload/restart is deliberately out of scope — run it separately via sshx_run.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpApplyInput) (*mcp.CallToolResult, any, error) {
		hasFrom := in.FromPath != ""
		hasContent := in.Content != nil
		if hasFrom == hasContent {
			return nil, nil, fmt.Errorf("exactly one of from_path or content is required")
		}
		fromPath := in.FromPath
		args, err := buildApplyArgs(in, fromPath)
		if err != nil {
			return nil, nil, err
		}
		if hasContent {
			dir, err := os.MkdirTemp("", "sshx-mcp-apply-")
			if err != nil {
				return nil, nil, fmt.Errorf("create temp payload dir: %w", err)
			}
			defer func() {
				mcpCleanup("inline apply payload", os.RemoveAll(dir))
			}()
			fromPath = filepath.Join(dir, "payload")
			if err := os.WriteFile(fromPath, []byte(*in.Content), 0o600); err != nil {
				return nil, nil, fmt.Errorf("write temp payload: %w", err)
			}
			for i, arg := range args {
				if strings.HasPrefix(arg, "--from=") {
					args[i] = "--from=" + fromPath
				}
			}
		}
		return runMCPTool(ctx, args, "", timeoutSeconds(in.GlobalTimeoutSecs))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "sshx_inspect",
		Description: "Run one structured host inspection over a single SSH connection: built-in system/network capabilities " +
			"(system.identity, system.resources, system.baseline, network.*) or trusted local plugins, with provenance, " +
			"freshness, and optional bounded observation reuse. Read-only on the remote host unless caching is enabled.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpInspectInput) (*mcp.CallToolResult, any, error) {
		args, err := buildInspectArgs(in)
		if err != nil {
			return nil, nil, err
		}
		return runMCPTool(ctx, args, "", timeoutSeconds(in.GlobalTimeoutSecs))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "sshx_sftp",
		Description: "One SFTP file action on a configured host: upload, download, list, mkdir, or remove, " +
			"with the same JSON result, dry-run, and audit semantics as the CLI.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSFTPInput) (*mcp.CallToolResult, any, error) {
		args, err := buildSFTPArgs(in)
		if err != nil {
			return nil, nil, err
		}
		return runMCPTool(ctx, args, "", timeoutSeconds(in.GlobalTimeoutSecs))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "sshx_transfer",
		Description: "Stream a file or directory directly from one SSH host to another through the local machine " +
			"without touching local disk, preserving permission bits.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpTransferInput) (*mcp.CallToolResult, any, error) {
		args, err := buildTransferArgs(in)
		if err != nil {
			return nil, nil, err
		}
		return runMCPTool(ctx, args, "", timeoutSeconds(in.GlobalTimeoutSecs))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "sshx_host_list",
		Description: "List configured named hosts (aliases, addresses, groups, tags, credential references) from " +
			"~/.sshx/settings.json. Read-only discovery; secrets never appear in the output.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ mcpHostListInput) (*mcp.CallToolResult, any, error) {
		return runMCPTool(ctx, []string{"--host-list", "--json"}, "", 0)
	})
}
