package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/talkincode/sshx/internal/execution"
)

func mcpTestEvents() []execution.Event {
	target := execution.ResolvedTarget{Alias: "lab", Address: "127.0.0.1", Port: "22", User: "probe"}
	events := []execution.Event{
		{Kind: execution.EventRunStarted, Action: &execution.ActionSpec{Command: "probe"}, Counts: &execution.RunCounts{Selected: 1}},
		{Kind: execution.EventTargetStarted, Target: &target},
		{
			Kind:   execution.EventTargetFinished,
			Target: &target,
			Result: &execution.TargetResult{
				Target:     target,
				Action:     execution.ActionSpec{Command: "probe"},
				Status:     execution.StatusSucceeded,
				Phase:      execution.PhaseComplete,
				Completion: execution.CompletionCompleted,
				ExitCode:   0,
			},
		},
		{Kind: execution.EventRunFinished, Counts: &execution.RunCounts{Selected: 1, Started: 1, Succeeded: 1}},
	}
	for i := range events {
		events[i].SchemaVersion = execution.EventSchemaVersion
		events[i].RunID = "run-1"
		events[i].RequestID = "caller-correlation"
		events[i].Sequence = int64(i + 1)
	}
	return events
}

func TestSynthesizeRunJSONResultSingleTarget(t *testing.T) {
	events := mcpTestEvents()
	executed := true
	events[2].Result.Metadata = execution.Metadata{
		PlanHash: "sha256:reviewed", ExecutionID: "target-execution", ParentExecutionID: "parent-execution",
		ExecutionFingerprint: "sha256:finalized", Risk: execution.RiskRead, ChangeState: "unchanged",
		Executed: &executed, Verified: true, Verification: "passed",
		Postconditions: []execution.Condition{{Kind: "observed", Status: "passed"}},
	}
	raw := synthesizeRunJSONResult(events)
	if raw == "" {
		t.Fatal("expected a synthesized single-target document")
	}
	if !strings.Contains(raw, `"schema_version":"sshx.result.v1"`) {
		t.Fatalf("synthesized = %s", raw)
	}
	require.Contains(t, raw, `"request_id":"caller-correlation"`)
	require.Contains(t, raw, `"execution_fingerprint":"sha256:finalized"`)
	require.Contains(t, raw, `"postconditions"`)
	want, err := json.Marshal(execution.ToResult(events[0].RunID, events[0].RequestID, *events[2].Result))
	require.NoError(t, err)
	assert.JSONEq(t, string(want), raw)
}

func TestMCPSynthesisPreservesNoncontiguousTargetIndex(t *testing.T) {
	events := mcpTestEvents()
	events[1].Target.Index = 7
	events[2].Result.Target.Index = 7
	require.NoError(t, validateMCPEvents(events))
	var result execution.Result
	require.NoError(t, json.Unmarshal([]byte(synthesizeRunJSONResult(events)), &result))
	assert.Equal(t, 7, result.Target.Index)
	assert.True(t, result.Success)
}

func TestMCPRejectsIncompleteOrInconsistentStreams(t *testing.T) {
	tests := map[string]func([]execution.Event) []execution.Event{
		"missing start":  func(events []execution.Event) []execution.Event { return events[1:] },
		"missing finish": func(events []execution.Event) []execution.Event { return events[:3] },
		"incomplete fanout": func(events []execution.Event) []execution.Event {
			events[0].Counts.Selected = 2
			events[3].Counts.Selected = 2
			return events
		},
		"wrong counts": func(events []execution.Event) []execution.Event {
			events[3].Counts.Failed = 1
			return events
		},
		"wrong run": func(events []execution.Event) []execution.Event {
			events[2].RunID = "other"
			return events
		},
		"wrong request": func(events []execution.Event) []execution.Event {
			events[2].RequestID = ""
			return events
		},
		"wrong schema": func(events []execution.Event) []execution.Event {
			events[0].SchemaVersion = "wrong"
			return events
		},
		"wrong sequence": func(events []execution.Event) []execution.Event {
			events[2].Sequence++
			return events
		},
		"wrong target": func(events []execution.Event) []execution.Event {
			events[2].Result.Target.Alias = "other"
			return events
		},
		"duplicate target": func(events []execution.Event) []execution.Event {
			events[1] = events[2]
			events[1].Sequence = 2
			return events
		},
		"missing result": func(events []execution.Event) []execution.Event {
			events[2].Result = nil
			return events
		},
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			events := corrupt(mcpTestEvents())
			require.Error(t, validateMCPEvents(events))
			assert.Empty(t, synthesizeRunJSONResult(events))
		})
	}
}

func TestMCPToolResultPreservesJSONAndRejectsMissingOutput(t *testing.T) {
	for _, stdout := range []string{"", "  \n", "{", "{}\n", "null\n", "true\n", "[]\n",
		"{\"success\":true}\n", "{\"schema_version\":\"sshx.result.v1\"}\n{\"oops\":1}\n"} {
		t.Run(fmt.Sprintf("%q", stdout), func(t *testing.T) {
			res := mcpToolResult(&selfExecResult{Stdout: stdout})
			assert.True(t, res.IsError)
			assert.Contains(t, mcpFirstText(t, res), "adapter failure")
			assert.NotContains(t, mcpFirstText(t, res), `"success":true`)
		})
	}
	const document = "{\"schema_version\":\"sshx.result.v1\",\"success\":false,\"exit_code\":1,\"extra\":{\"future\":true}}\n"
	res := mcpToolResult(&selfExecResult{Stdout: document, ExitCode: 1})
	assert.True(t, res.IsError)
	assert.Equal(t, document, mcpFirstText(t, res))
	const legacyPreview = "{\"dry_run\":true,\"valid\":true,\"mode\":\"apply\",\"plan_hash\":\"sha256:reviewed\"}\n"
	preview := mcpToolResult(&selfExecResult{Stdout: legacyPreview})
	assert.False(t, preview.IsError)
	assert.Equal(t, legacyPreview, mcpFirstText(t, preview))
}

func mcpFirstText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.NotEmpty(t, result.Content)
	content, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	return content.Text
}

func TestMCPOutputCaptureLimitsAndErrors(t *testing.T) {
	canceled := false
	capture := mcpOutputCapture{limit: 8, cancel: func() { canceled = true }}
	n, err := capture.Write([]byte("123456789"))
	require.NoError(t, err)
	assert.Equal(t, 9, n, "overflow must not stop draining")
	assert.True(t, canceled)
	assert.Error(t, capture.err)
	assert.LessOrEqual(t, capture.Len(), 8)

	stderr := mcpBoundedBuffer{limit: 8}
	n, err = stderr.Write([]byte("123456789"))
	require.NoError(t, err)
	assert.Equal(t, 9, n)
	assert.Equal(t, 8, stderr.Len())
	assert.Contains(t, stderr.String(), "stderr truncated")

	// os/exec uses io.Copy. An embedded bytes.Buffer.ReadFrom would bypass
	// Write, silently disabling both byte limits and progress notifications.
	copiedCapture := mcpOutputCapture{limit: 8, cancel: func() {}}
	copied, copyErr := io.Copy(&copiedCapture, io.LimitReader(strings.NewReader("123456789"), 9))
	require.NoError(t, copyErr)
	assert.EqualValues(t, 9, copied)
	assert.Error(t, copiedCapture.err)
	assert.LessOrEqual(t, copiedCapture.Len(), 8)
	copiedStderr := mcpBoundedBuffer{limit: 8}
	_, copyErr = io.Copy(&copiedStderr, io.LimitReader(strings.NewReader("123456789"), 9))
	require.NoError(t, copyErr)
	assert.Equal(t, 8, copiedStderr.Len())
	assert.True(t, copiedStderr.truncated)

	for _, raw := range []string{"not-json\n", "{\n", `{"schema_version":"sshx.result.v1"}`} {
		capture := mcpOutputCapture{limit: 1024, cancel: func() {}, onEvent: func(execution.Event) {}}
		_, err := capture.Write([]byte(raw))
		require.NoError(t, err)
		capture.finish()
		assert.Error(t, capture.err, "%q", raw)
	}
}

func TestMCPProcessWatchdogUsesGlobalBudget(t *testing.T) {
	assert.Equal(t, 30*time.Minute, mcpProcessTimeout(0))
	assert.Equal(t, 7*time.Minute, mcpProcessTimeout(5*time.Minute))
	assert.Equal(t, 30*time.Minute, mcpProcessTimeout(1*time.Hour))
	assert.Equal(t, 30*time.Minute, mcpProcessTimeout(time.Duration(1<<63-1)))
}

func TestMCPTransportCancellationUnblocksProgressWrite(t *testing.T) {
	server, client := net.Pipe()
	defer func() { require.NoError(t, client.Close()) }()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	transport := mcpLifetimeTransport{
		Transport: &mcp.IOTransport{Reader: server, Writer: server}, cancel: cancel,
	}
	conn, err := transport.Connect(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close()) }()
	writeCtx, cancelWrite := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelWrite()
	done := make(chan error, 1)
	go func() {
		done <- conn.Write(writeCtx, &jsonrpc.Request{Method: "notifications/progress"})
	}()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("blocked MCP progress writer did not unblock")
	}
	require.Error(t, ctx.Err())
}

func TestMCPServerHonorsRootContext(t *testing.T) {
	server, _ := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runMCPServerContext(ctx, server) }()
	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("MCP server ignored root cancellation")
	}
}

func TestMCPOptionalExecutionInputs(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	wantLimits := []string{"--timeout=5s", "--host-timeout=10s", "--global-timeout=20s", "--expect-plan=" + hash}
	maxFailures := 2
	run, _, err := buildRunArgs(mcpRunInput{
		Targets: []string{"h"}, Command: "probe", ExpectPlan: hash,
		TimeoutSecs: 5, HostTimeoutSecs: 10, GlobalTimeoutSecs: 20,
		MaxFailures: &maxFailures, RequestID: "correlation",
	})
	require.NoError(t, err)
	for _, want := range append(wantLimits, "--max-failures=2", "--request-id=correlation") {
		assert.Contains(t, run, want)
	}
	run, _, err = buildRunArgs(mcpRunInput{Command: "probe", FailFast: true})
	require.NoError(t, err)
	assert.Contains(t, run, "--fail-fast")

	cases := map[string]func() ([]string, error){
		"sql": func() ([]string, error) {
			return buildSQLArgs(mcpSQLInput{Target: "h", Statement: "SELECT 1", ExpectPlan: hash,
				TimeoutSecs: 5, HostTimeoutSecs: 10, GlobalTimeoutSecs: 20, BypassReason: "approved"})
		},
		"apply": func() ([]string, error) {
			return buildApplyArgs(mcpApplyInput{Target: "h", Path: "/r", ExpectPlan: hash,
				TimeoutSecs: 5, HostTimeoutSecs: 10, GlobalTimeoutSecs: 20}, "payload")
		},
		"inspect": func() ([]string, error) {
			return buildInspectArgs(mcpInspectInput{Target: "h", Capability: "system.baseline", ExpectPlan: hash,
				TimeoutSecs: 5, HostTimeoutSecs: 10, GlobalTimeoutSecs: 20, DryRun: true})
		},
		"sftp": func() ([]string, error) {
			return buildSFTPArgs(mcpSFTPInput{Target: "h", Action: "list", RemotePath: "/r", ExpectPlan: hash,
				TimeoutSecs: 5, HostTimeoutSecs: 10, GlobalTimeoutSecs: 20})
		},
		"transfer": func() ([]string, error) {
			return buildTransferArgs(mcpTransferInput{SourceHost: "a", SourcePath: "/s", DestHost: "b", DestPath: "/d",
				ExpectPlan: hash, TimeoutSecs: 5, HostTimeoutSecs: 10, GlobalTimeoutSecs: 20})
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			args, err := build()
			require.NoError(t, err)
			for _, want := range wantLimits {
				assert.Contains(t, args, want)
			}
			if name == "sql" {
				assert.Contains(t, args, "--bypass-reason=approved")
			}
			if name == "inspect" {
				assert.Contains(t, args, "--dry-run")
			}
		})
	}
}

func TestMCPRejectsNegativeOrOverflowedLimits(t *testing.T) {
	for _, values := range [][3]int{{-1, 0, 0}, {0, -1, 0}, {0, 0, -1}} {
		inputs := map[string]func() error{
			"run": func() error {
				_, _, err := buildRunArgs(mcpRunInput{Command: "probe", TimeoutSecs: values[0], HostTimeoutSecs: values[1], GlobalTimeoutSecs: values[2]})
				return err
			},
			"sql": func() error {
				_, err := buildSQLArgs(mcpSQLInput{Target: "h", Statement: "SELECT 1", TimeoutSecs: values[0], HostTimeoutSecs: values[1], GlobalTimeoutSecs: values[2]})
				return err
			},
			"apply": func() error {
				_, err := buildApplyArgs(mcpApplyInput{Target: "h", Path: "/r", TimeoutSecs: values[0], HostTimeoutSecs: values[1], GlobalTimeoutSecs: values[2]}, "payload")
				return err
			},
			"inspect": func() error {
				_, err := buildInspectArgs(mcpInspectInput{Target: "h", Capability: "system.baseline", TimeoutSecs: values[0], HostTimeoutSecs: values[1], GlobalTimeoutSecs: values[2]})
				return err
			},
			"sftp": func() error {
				_, err := buildSFTPArgs(mcpSFTPInput{Target: "h", Action: "list", RemotePath: "/r", TimeoutSecs: values[0], HostTimeoutSecs: values[1], GlobalTimeoutSecs: values[2]})
				return err
			},
			"transfer": func() error {
				_, err := buildTransferArgs(mcpTransferInput{SourceHost: "a", SourcePath: "/s", DestHost: "b", DestPath: "/d", TimeoutSecs: values[0], HostTimeoutSecs: values[1], GlobalTimeoutSecs: values[2]})
				return err
			},
		}
		for name, build := range inputs {
			require.Error(t, build(), "%s %+v", name, values)
		}
	}
	for _, value := range []int{-1, 0} {
		_, _, err := buildRunArgs(mcpRunInput{Command: "probe", MaxFailures: &value})
		require.Error(t, err)
	}
	_, _, err := buildRunArgs(mcpRunInput{Command: "probe", Concurrency: -1})
	require.Error(t, err)
	_, err = buildSQLArgs(mcpSQLInput{Target: "h", Statement: "SELECT 1", RowThreshold: -1})
	require.Error(t, err)
	_, err = appendMCPLimits(nil, "invalid", 0, 0, 0)
	require.Error(t, err)
	if strconv.IntSize == 64 {
		overflow := int64(1<<63-1)/int64(time.Second) + 1
		_, err = appendMCPLimits(nil, "", int(overflow), 0, 0)
		require.Error(t, err)
	}
}

func mcpTestCommand(t *testing.T, mode, ready string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(exe, "-test.run=^TestMCPChildHelperProcess$") // #nosec G204 -- Run this test binary's isolated helper.
	cmd.Env = append(os.Environ(), "SSHX_MCP_HELPER="+mode, "SSHX_MCP_READY="+ready)
	return cmd
}

func mcpWaitReady(t *testing.T, ready string) {
	t.Helper()
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(ready) // #nosec G304 G703 -- Parent-owned readiness file in the isolated test directory.
		return err == nil && len(data) > 0
	}, 5*time.Second, 10*time.Millisecond, "helper did not become ready")
}

func TestMCPChildHelperProcess(t *testing.T) {
	mode := os.Getenv("SSHX_MCP_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "copy":
		if _, err := io.Copy(os.Stdout, os.Stdin); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "cooperate":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt)
		require.NoError(t, os.WriteFile(os.Getenv("SSHX_MCP_READY"), []byte("ready"), 0o600)) // #nosec G703 -- The parent test supplies its isolated readiness path.
		<-signals
		fmt.Printf("{\"schema_version\":\"sshx.result.v1\",\"success\":false,\"exit_code\":1,\"error_kind\":%q}\n", execution.ErrorKindCancelled)
		os.Exit(1)
	case "ignore", "tree", "tree-exit":
		signal.Ignore(os.Interrupt)
		if mode != "ignore" {
			ready := os.Getenv("SSHX_MCP_READY")
			child := mcpTestCommand(t, "ignore", ready+".child")
			require.NoError(t, child.Start())
			mcpWaitReady(t, ready+".child")
			require.NoError(t, os.WriteFile(ready, []byte(fmt.Sprint(child.Process.Pid)), 0o600)) // #nosec G703 -- The parent test supplies its isolated readiness path.
			if mode == "tree-exit" {
				fmt.Println(`{"schema_version":"sshx.result.v1","success":true,"exit_code":0}`)
				os.Exit(0)
			}
		} else {
			require.NoError(t, os.WriteFile(os.Getenv("SSHX_MCP_READY"), []byte("ready"), 0o600)) // #nosec G703 -- The parent test supplies its isolated readiness path.
		}
		for {
			time.Sleep(time.Hour)
		}
	default:
		os.Exit(2)
	}
}

func TestMCPChildCooperativeCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("CTRL_BREAK requires an attached console; job escalation is tested separately")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := filepath.Join(t.TempDir(), "ready")
	done := make(chan *selfExecResult, 1)
	errs := make(chan error, 1)
	go func() {
		res, _, err := execMCPCommand(ctx, mcpTestCommand(t, "cooperate", ready), "", 0, nil)
		done <- res
		errs <- err
	}()
	mcpWaitReady(t, ready)
	cancel()
	select {
	case res := <-done:
		require.NoError(t, <-errs)
		require.NoError(t, res.AdapterError)
		assert.Contains(t, res.Stdout, `"error_kind":"`+execution.ErrorKindCancelled+`"`)
		assert.NotContains(t, res.Stderr, "timeout")
		assert.True(t, mcpToolResult(res).IsError)
	case <-time.After(mcpShutdownGrace + time.Second):
		t.Fatal("cooperative cancellation did not finish")
	}
}

func TestMCPChildEscalationHasNoFakeResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := filepath.Join(t.TempDir(), "ready")
	done := make(chan *selfExecResult, 1)
	errs := make(chan error, 1)
	go func() {
		res, _, err := execMCPCommand(ctx, mcpTestCommand(t, "ignore", ready), "", 0, nil)
		done <- res
		errs <- err
	}()
	mcpWaitReady(t, ready)
	cancel()
	select {
	case res := <-done:
		require.NoError(t, <-errs)
		require.Error(t, res.AdapterError)
		assert.True(t, errors.Is(res.AdapterError, context.Canceled))
		assert.Empty(t, res.Stdout)
		assert.NotContains(t, res.Stderr, "timeout")
		assert.True(t, mcpToolResult(res).IsError)
	case <-time.After(mcpShutdownGrace + 2*time.Second):
		t.Fatal("child escalation did not finish")
	}
}

func TestMCPChildDrainsLargeOutputDespiteSlowProgress(t *testing.T) {
	events := mcpTestEvents()
	events[2].Result.Stdout = strings.Repeat("large-output\n", 400000)
	var output bytes.Buffer
	for _, ev := range events {
		require.NoError(t, json.NewEncoder(&output).Encode(ev))
	}
	release := make(chan struct{})
	called := make(chan struct{}, 1)
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	res, gotEvents, err := execMCPCommand(ctx, mcpTestCommand(t, "copy", ""), output.String(), 0, func(execution.Event) {
		select {
		case called <- struct{}{}:
		default:
		}
		<-release
	})
	require.NoError(t, err)
	require.NoError(t, res.AdapterError)
	require.Equal(t, 4, len(gotEvents))
	assert.Equal(t, output.String(), res.Stdout)
	assert.Less(t, time.Since(start), 4*time.Second)
	select {
	case <-called:
	default:
		t.Fatal("progress callback was never called")
	}
}

func TestMCPMalformedChildOutputIsAnAdapterFailure(t *testing.T) {
	for name, raw := range map[string]string{
		"malformed":    "not JSON\n",
		"empty":        "",
		"truncated":    "{\"schema_version\":",
		"unterminated": "{\"schema_version\":\"sshx.event.v1\",\"kind\":\"run_started\"}",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			res, _, err := execMCPCommand(ctx, mcpTestCommand(t, "copy", ""), raw, 0, func(execution.Event) {})
			require.NoError(t, err)
			require.Error(t, res.AdapterError)
			assert.True(t, mcpToolResult(res).IsError)
			assert.Contains(t, mcpFirstText(t, mcpToolResult(res)), "adapter failure")
		})
	}
}

func TestBuildRunArgsCommand(t *testing.T) {
	args, stdin, err := buildRunArgs(mcpRunInput{
		Targets:      []string{"web-1", "web-2"},
		Groups:       []string{"prod"},
		Tags:         []string{"env=prod"},
		Command:      "systemctl is-active nginx",
		TimeoutSecs:  30,
		Concurrency:  8,
		FailureMode:  "fail_fast",
		Intent:       "read",
		DryRun:       true,
		Force:        true,
		BypassReason: "maintenance window",
	})
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	if stdin != "" {
		t.Fatalf("stdin = %q, want empty for command mode", stdin)
	}
	want := []string{
		"run", "--json",
		"--target=web-1", "--target=web-2",
		"--group=prod",
		"--tag=env=prod",
		"--timeout=30s",
		"--concurrency=8",
		"--failure-mode=fail_fast",
		"--intent=read",
		"--dry-run",
		"--force",
		"--bypass-reason=maintenance window",
		"--", "systemctl is-active nginx",
	}
	assertArgs(t, args, want)
}

func TestBuildRunArgsScriptStdin(t *testing.T) {
	script := "#!/bin/sh\necho hello\n"
	args, stdin, err := buildRunArgs(mcpRunInput{Targets: []string{"web-1"}, Script: script})
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	if stdin != script {
		t.Fatalf("stdin = %q, want the byte-preserved script", stdin)
	}
	assertArgs(t, args, []string{"run", "--json", "--target=web-1", "--script-stdin"})
}

func TestBuildRunArgsScriptShell(t *testing.T) {
	script := "#!/usr/bin/env bash\nset -o pipefail\n"
	args, stdin, err := buildRunArgs(mcpRunInput{
		Targets: []string{"web-1"},
		Script:  script,
		Shell:   "bash",
	})
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	if stdin != script {
		t.Fatalf("stdin = %q, want the byte-preserved script", stdin)
	}
	assertArgs(t, args, []string{"run", "--json", "--target=web-1", "--script-stdin", "--shell=bash"})
}

func TestBuildRunArgsRejectsShellWithoutScript(t *testing.T) {
	_, _, err := buildRunArgs(mcpRunInput{Targets: []string{"web-1"}, Command: "uptime", Shell: "bash"})
	if err == nil {
		t.Fatal("expected an error when shell is combined with a command payload")
	}
}

func TestBuildRunArgsRequiresExactlyOnePayload(t *testing.T) {
	if _, _, err := buildRunArgs(mcpRunInput{Targets: []string{"a"}}); err == nil {
		t.Fatal("expected error when neither command nor script is set")
	}
	if _, _, err := buildRunArgs(mcpRunInput{Targets: []string{"a"}, Command: "x", Script: "y"}); err == nil {
		t.Fatal("expected error when both command and script are set")
	}
}

func TestBuildSQLArgs(t *testing.T) {
	args, err := buildSQLArgs(mcpSQLInput{
		Target:        "db-1",
		Statement:     "SELECT count(*) FROM users",
		Engine:        "postgres",
		DB:            "app",
		DBUser:        "app",
		DBPasswordKey: "app-db",
		Explain:       true,
		RowThreshold:  500,
		Sudo:          true,
		DryRun:        true,
	})
	if err != nil {
		t.Fatalf("buildSQLArgs: %v", err)
	}
	want := []string{
		"sql", "--json", "-h=db-1",
		"--engine=postgres", "--db=app", "--db-user=app",
		"--db-password-key=app-db", "--explain", "--row-threshold=500",
		"--sudo", "--dry-run",
		"--", "SELECT count(*) FROM users",
	}
	assertArgs(t, args, want)
}

func TestBuildSQLArgsRequiredFields(t *testing.T) {
	if _, err := buildSQLArgs(mcpSQLInput{Statement: "SELECT 1"}); err == nil {
		t.Fatal("expected error without target")
	}
	if _, err := buildSQLArgs(mcpSQLInput{Target: "db-1"}); err == nil {
		t.Fatal("expected error without statement")
	}
}

func TestBuildApplyArgs(t *testing.T) {
	args, err := buildApplyArgs(mcpApplyInput{
		Target:       "prod",
		Path:         "/etc/nginx/nginx.conf",
		ExpectSHA256: "abc123",
		Sudo:         true,
		Force:        true,
		BypassReason: "planned change",
		TimeoutSecs:  45,
	}, "/tmp/payload")
	if err != nil {
		t.Fatalf("buildApplyArgs: %v", err)
	}
	want := []string{
		"apply", "--json", "-h=prod",
		"--path=/etc/nginx/nginx.conf", "--from=/tmp/payload",
		"--expect-sha256=abc123", "--sudo", "--force",
		"--bypass-reason=planned change", "--timeout=45s",
	}
	assertArgs(t, args, want)
}

func TestBuildApplyArgsRequiredFields(t *testing.T) {
	if _, err := buildApplyArgs(mcpApplyInput{Path: "/x"}, "/tmp/p"); err == nil {
		t.Fatal("expected error without target")
	}
	if _, err := buildApplyArgs(mcpApplyInput{Target: "h"}, "/tmp/p"); err == nil {
		t.Fatal("expected error without path")
	}
}

func TestBuildInspectArgs(t *testing.T) {
	args, err := buildInspectArgs(mcpInspectInput{
		Target:     "prod",
		Capability: "system.baseline",
		Cache:      "remote-prefer",
		MaxAge:     "30m",
		Sudo:       true,
	})
	if err != nil {
		t.Fatalf("buildInspectArgs: %v", err)
	}
	want := []string{
		"inspect", "--json", "-h=prod",
		"--cache=remote-prefer", "--max-age=30m", "--sudo",
		"system.baseline",
	}
	assertArgs(t, args, want)
}

func TestBuildSFTPArgs(t *testing.T) {
	cases := []struct {
		name  string
		in    mcpSFTPInput
		want  []string
		fails bool
	}{
		{
			name: "upload",
			in:   mcpSFTPInput{Target: "h", Action: "upload", LocalPath: "/l", RemotePath: "/r"},
			want: []string{"--json", "-h=h", "--upload=/l", "--to=/r"},
		},
		{
			name: "download",
			in:   mcpSFTPInput{Target: "h", Action: "download", LocalPath: "/l", RemotePath: "/r"},
			want: []string{"--json", "-h=h", "--download=/r", "--to=/l"},
		},
		{
			name: "list",
			in:   mcpSFTPInput{Target: "h", Action: "list", RemotePath: "/r"},
			want: []string{"--json", "-h=h", "--list=/r"},
		},
		{
			name: "mkdir",
			in:   mcpSFTPInput{Target: "h", Action: "mkdir", RemotePath: "/r"},
			want: []string{"--json", "-h=h", "--mkdir=/r"},
		},
		{
			name: "remove",
			in:   mcpSFTPInput{Target: "h", Action: "remove", RemotePath: "/r"},
			want: []string{"--json", "-h=h", "--rm=/r"},
		},
		{name: "upload without local path", in: mcpSFTPInput{Target: "h", Action: "upload", RemotePath: "/r"}, fails: true},
		{name: "unknown action", in: mcpSFTPInput{Target: "h", Action: "chmod", RemotePath: "/r"}, fails: true},
		{name: "missing target", in: mcpSFTPInput{Action: "list", RemotePath: "/r"}, fails: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, err := buildSFTPArgs(tc.in)
			if tc.fails {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildSFTPArgs: %v", err)
			}
			assertArgs(t, args, tc.want)
		})
	}
}

func TestBuildTransferArgs(t *testing.T) {
	args, err := buildTransferArgs(mcpTransferInput{
		SourceHost: "a", SourcePath: "/src", DestHost: "b", DestPath: "/dst", DryRun: true,
	})
	if err != nil {
		t.Fatalf("buildTransferArgs: %v", err)
	}
	assertArgs(t, args, []string{"--json", "--transfer=a:/src", "--to=b:/dst", "--dry-run"})

	if _, err := buildTransferArgs(mcpTransferInput{SourceHost: "a", SourcePath: "/s", DestHost: "b"}); err == nil {
		t.Fatal("expected error for missing dest_path")
	}
}

func TestParseMCPArgs(t *testing.T) {
	config := ParseArgs([]string{"sshx", "mcp"})
	if config.Mode != "mcp" {
		t.Fatalf("Mode = %q, want mcp", config.Mode)
	}
	if config.ArgumentError != "" {
		t.Fatalf("unexpected argument error: %s", config.ArgumentError)
	}

	config = ParseArgs([]string{"sshx", "mcp", "--port=8080"})
	if config.ArgumentError == "" {
		t.Fatal("expected argument error for unsupported mcp flag")
	}
}

func TestCurrentEntrySanitizes(t *testing.T) {
	cases := map[string]string{
		"mcp":                   "mcp",
		"ci-runner_1":           "ci-runner_1",
		"":                      "",
		"MCP":                   "",
		"mcp;rm -rf /":          "",
		strings.Repeat("a", 33): "",
		"with space":            "",
		"unicode-\u4f60\u597d":  "",
	}
	for input, want := range cases {
		t.Setenv("SSHX_ENTRY", input)
		if got := currentEntry(); got != want {
			t.Fatalf("currentEntry(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBuildRunArgsBind(t *testing.T) {
	args, _, err := buildRunArgs(mcpRunInput{Targets: []string{"web-1"}, Command: "uptime", Bind: "en0"})
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	assertArgs(t, args, []string{"run", "--json", "--target=web-1", "--bind=en0", "--", "uptime"})

	args, _, err = buildRunArgs(mcpRunInput{Targets: []string{"web-1"}, Command: "uptime"})
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	assertArgs(t, args, []string{"run", "--json", "--target=web-1", "--", "uptime"})
}

func TestBuildInspectArgsBind(t *testing.T) {
	args, err := buildInspectArgs(mcpInspectInput{Target: "prod", Capability: "system.baseline", Bind: "192.0.2.10"})
	if err != nil {
		t.Fatalf("buildInspectArgs: %v", err)
	}
	assertArgs(t, args, []string{"inspect", "--json", "-h=prod", "--bind=192.0.2.10", "system.baseline"})
}

func assertArgs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("args mismatch:\n got:  %q\n want: %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q\n got:  %q\n want: %q", i, got[i], want[i], got, want)
		}
	}
}
