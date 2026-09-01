package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/logger"
)

// mcpEntryEnv marks child invocations spawned by the MCP server so audit
// events can attribute them to the MCP entry point. It is metadata only and
// never participates in trust or safety decisions.
const mcpEntryEnv = "SSHX_ENTRY=mcp"

// mcpDefaultProcessTimeout bounds a child invocation when the caller does not
// provide an explicit timeout.
const mcpDefaultProcessTimeout = 30 * time.Minute

// mcpProcessGrace is added on top of an explicit remote timeout so the child
// process can classify the remote timeout itself before being killed.
const mcpProcessGrace = 2 * time.Minute

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
// same safety gates, same audit trail. The server holds no connections and no
// state; it lives and dies with the client that spawned it.
func RunMCPServer() error {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "sshx",
		Title:   "sshx — agent-native remote execution over SSH",
		Version: Version,
	}, nil)
	registerMCPTools(server)
	return server.Run(context.Background(), &mcp.StdioTransport{})
}

// selfExecResult captures one child invocation outcome.
type selfExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// execSelf runs the current sshx binary with args as a one-shot child
// process, marking it as MCP-originated for audit purposes.
func execSelf(ctx context.Context, args []string, stdin string, remoteTimeout time.Duration) (*selfExecResult, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve sshx executable: %w", err)
	}

	processTimeout := mcpDefaultProcessTimeout
	if remoteTimeout > 0 && remoteTimeout+mcpProcessGrace < processTimeout {
		processTimeout = remoteTimeout + mcpProcessGrace
	}
	ctx, cancel := context.WithTimeout(ctx, processTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, args...) // #nosec G204 -- args are built from schema-validated tool input for our own binary.
	cmd.Env = append(os.Environ(), mcpEntryEnv)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	result := &selfExecResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if runErr == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		if ctx.Err() != nil {
			result.Stderr = strings.TrimSpace(result.Stderr + "\nsshx mcp: child invocation killed by local process timeout")
		}
		return result, nil
	}
	return nil, fmt.Errorf("spawn sshx child process: %w", runErr)
}

// mcpToolResult converts a child invocation into an MCP tool result. The
// child's stdout (a single JSON document in --json mode) is the tool content;
// a non-zero exit marks the result as a tool error while preserving the
// structured payload so agents can still branch on error_kind and friends.
func mcpToolResult(res *selfExecResult) *mcp.CallToolResult {
	content := []mcp.Content{}
	if strings.TrimSpace(res.Stdout) != "" {
		content = append(content, &mcp.TextContent{Text: res.Stdout})
	}
	if strings.TrimSpace(res.Stderr) != "" {
		content = append(content, &mcp.TextContent{Text: "stderr:\n" + res.Stderr})
	}
	if len(content) == 0 {
		content = append(content, &mcp.TextContent{Text: fmt.Sprintf(`{"success":%t,"exit_code":%d}`, res.ExitCode == 0, res.ExitCode)})
	}
	return &mcp.CallToolResult{Content: content, IsError: res.ExitCode != 0}
}

func runMCPTool(ctx context.Context, args []string, stdin string, remoteTimeout time.Duration) (*mcp.CallToolResult, any, error) {
	res, err := execSelf(ctx, args, stdin, remoteTimeout)
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
		token = req.Params.GetProgressToken()
	}
	if token == nil {
		return runMCPTool(ctx, args, stdin, timeoutSeconds(in.TimeoutSecs))
	}
	for i, arg := range args {
		if arg == "--json" {
			args[i] = "--jsonl"
		}
	}
	var finished float64
	var total float64
	res, events, err := execSelfJSONL(ctx, args, stdin, timeoutSeconds(in.TimeoutSecs), func(ev execution.Event) {
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
		if progErr := req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
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
	if synthesized := synthesizeRunJSONResult(events); synthesized != "" {
		res.Stdout = synthesized
	}
	return mcpToolResult(res), nil, nil
}

func execSelfJSONL(ctx context.Context, args []string, stdin string, remoteTimeout time.Duration, onEvent func(execution.Event)) (*selfExecResult, []execution.Event, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve sshx executable: %w", err)
	}
	processTimeout := mcpDefaultProcessTimeout
	if remoteTimeout > 0 && remoteTimeout+mcpProcessGrace < processTimeout {
		processTimeout = remoteTimeout + mcpProcessGrace
	}
	ctx, cancel := context.WithTimeout(ctx, processTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, args...) // #nosec G204 -- args are built from schema-validated tool input for our own binary.
	cmd.Env = append(os.Environ(), mcpEntryEnv)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if startErr := cmd.Start(); startErr != nil {
		return nil, nil, fmt.Errorf("spawn sshx child process: %w", startErr)
	}

	var stdout bytes.Buffer
	var events []execution.Event
	scanner := bufio.NewScanner(io.TeeReader(stdoutPipe, &stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		var ev execution.Event
		if json.Unmarshal(line, &ev) != nil || ev.Kind == "" {
			continue
		}
		events = append(events, ev)
		if onEvent != nil {
			onEvent(ev)
		}
	}
	runErr := cmd.Wait()
	result := &selfExecResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if runErr == nil {
		return result, events, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		if ctx.Err() != nil {
			result.Stderr = strings.TrimSpace(result.Stderr + "\nsshx mcp: child invocation killed by local process timeout")
		}
		return result, events, nil
	}
	return nil, events, fmt.Errorf("spawn sshx child process: %w", runErr)
}

func synthesizeRunJSONResult(events []execution.Event) string {
	var finished []execution.Event
	var started *execution.Event
	for i := range events {
		ev := events[i]
		switch ev.Kind {
		case execution.EventRunStarted:
			started = &events[i]
		case execution.EventTargetFinished:
			finished = append(finished, ev)
		}
	}
	if len(finished) != 1 || finished[0].Result == nil {
		return ""
	}
	tr := finished[0].Result
	result := execution.Result{
		SchemaVersion:   execution.ResultSchemaVersion,
		RunID:           finished[0].RunID,
		Target:          tr.Target,
		Action:          tr.Action,
		Status:          tr.Status,
		Phase:           tr.Phase,
		Completion:      tr.Completion,
		ExitCode:        tr.ExitCode,
		Success:         tr.Status == execution.StatusSucceeded,
		Error:           tr.Error,
		Host:            tr.Target.Address,
		Port:            tr.Target.Port,
		User:            tr.Target.User,
		Stdout:          tr.Stdout,
		Stderr:          tr.Stderr,
		StdoutTruncated: tr.StdoutTruncated,
		StderrTruncated: tr.StderrTruncated,
		DurationMs:      tr.DurationMs,
		AuthMethod:      tr.AuthMethod,
	}
	if started != nil && started.Action != nil && result.Command == "" {
		result.Command = started.Action.Command
	}
	if tr.Error != nil {
		result.ErrorKind = tr.Error.Kind
	}
	data, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	return string(data) + "\n"
}

func timeoutSeconds(seconds int) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// --- tool inputs -----------------------------------------------------------

type mcpRunInput struct {
	Targets       []string `json:"targets,omitempty" jsonschema:"Configured host names to execute on (strict aliases, never DNS)."`
	Groups        []string `json:"groups,omitempty" jsonschema:"Configured host groups; union with targets."`
	Tags          []string `json:"tags,omitempty" jsonschema:"Tag filters in key=value form, combined with AND."`
	AllHosts      bool     `json:"all_hosts,omitempty" jsonschema:"Select all configured hosts before tag filters."`
	Address       string   `json:"address,omitempty" jsonschema:"Explicit single literal address (not for fan-out)."`
	Command       string   `json:"command,omitempty" jsonschema:"Remote command line. Exactly one of command or script is required."`
	Script        string   `json:"script,omitempty" jsonschema:"Byte-preserving script payload delivered over stdin. Exactly one of command or script is required."`
	Shell         string   `json:"shell,omitempty" jsonschema:"Script interpreter override: sh, bash, zsh, dash, ksh, or ash. Defaults to the script's shebang, then sh."`
	TimeoutSecs   int      `json:"timeout_seconds,omitempty" jsonschema:"Remote execution timeout in seconds (default 60)."`
	Concurrency   int      `json:"concurrency,omitempty" jsonschema:"Bounded fan-out (default 4, hard max 32)."`
	FailureMode   string   `json:"failure_mode,omitempty" jsonschema:"continue or fail_fast (default continue)."`
	Intent        string   `json:"intent,omitempty" jsonschema:"Declared action intent: read, change, or unknown."`
	DryRun        bool     `json:"dry_run,omitempty" jsonschema:"Preview the local execution plan without connecting or executing."`
	Force         bool     `json:"force,omitempty" jsonschema:"Bypass safety checks; requires bypass_reason and is recorded in results and audit."`
	NoSafetyCheck bool     `json:"no_safety_check,omitempty" jsonschema:"Disable safety checks entirely; requires bypass_reason."`
	BypassReason  string   `json:"bypass_reason,omitempty" jsonschema:"Mandatory justification when force or no_safety_check is set."`
	Bind          string   `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpSQLInput struct {
	Target         string `json:"target" jsonschema:"Configured host name or address to reach over SSH."`
	Statement      string `json:"statement" jsonschema:"Exactly one SQL statement; multi-statement input is blocked fail-closed."`
	Engine         string `json:"engine,omitempty" jsonschema:"postgres (default), sqlite, or mysql."`
	DB             string `json:"db,omitempty" jsonschema:"PostgreSQL database name."`
	DBFile         string `json:"db_file,omitempty" jsonschema:"Absolute SQLite database file path (required for engine=sqlite)."`
	DBUser         string `json:"db_user,omitempty" jsonschema:"Database role."`
	DBHost         string `json:"db_host,omitempty" jsonschema:"Database host as seen from the remote host."`
	DBPort         string `json:"db_port,omitempty" jsonschema:"Database port."`
	DBPasswordKey  string `json:"db_password_key,omitempty" jsonschema:"OS-keyring key holding the DB password; delivered via stdin, never argv."`
	Docker         string `json:"docker,omitempty" jsonschema:"Run the database client inside this container via docker exec -i."`
	DBCredFrom     string `json:"db_cred_from,omitempty" jsonschema:"Resolve credentials on the remote host: docker:<container> or env-file:<path>."`
	CredCache      string `json:"cred_cache,omitempty" jsonschema:"off or a duration for caching remotely resolved credentials (default 15m)."`
	CredRefresh    bool   `json:"cred_refresh,omitempty" jsonschema:"Drop the cached credential entry and re-resolve."`
	Explain        bool   `json:"explain,omitempty" jsonschema:"Run EXPLAIN only; never executes the statement."`
	RowThreshold   int    `json:"row_threshold,omitempty" jsonschema:"EXPLAIN row estimate that upgrades a row backup to a full-table snapshot (default 1000)."`
	AllowFullTable bool   `json:"allow_full_table,omitempty" jsonschema:"Required for UPDATE/DELETE without a WHERE clause."`
	NoBackup       bool   `json:"no_backup,omitempty" jsonschema:"Skip the pre-change backup; requires force."`
	BackupDir      string `json:"backup_dir,omitempty" jsonschema:"Remote backup directory (default ~/.sshx/sql-backups)."`
	Sudo           bool   `json:"sudo,omitempty" jsonschema:"Run the remote database client via sudo -S when the SSH user cannot open the database file."`
	Force          bool   `json:"force,omitempty" jsonschema:"Confirms DDL; destructive DDL also requires no_backup."`
	DryRun         bool   `json:"dry_run,omitempty" jsonschema:"Preview the guarded SQL plan without connecting."`
	TimeoutSecs    int    `json:"timeout_seconds,omitempty" jsonschema:"Remote execution timeout in seconds."`
	Bind           string `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpApplyInput struct {
	Target       string `json:"target" jsonschema:"Configured host name or address."`
	Path         string `json:"path" jsonschema:"Absolute remote file path to replace."`
	FromPath     string `json:"from_path,omitempty" jsonschema:"Local source file. Exactly one of from_path or content is required."`
	Content      string `json:"content,omitempty" jsonschema:"Inline file content written to a private temp file. Exactly one of from_path or content is required."`
	ExpectSHA256 string `json:"expect_sha256,omitempty" jsonschema:"Fail closed unless the current remote hash matches."`
	NoBackup     bool   `json:"no_backup,omitempty" jsonschema:"Skip the pre-change backup; requires force."`
	BackupDir    string `json:"backup_dir,omitempty" jsonschema:"Remote backup directory (default ~/.sshx/file-backups)."`
	Sudo         bool   `json:"sudo,omitempty" jsonschema:"Stage over SFTP, then install with a privileged stdin script."`
	Force        bool   `json:"force,omitempty" jsonschema:"Skip the hash precondition; required with no_backup."`
	BypassReason string `json:"bypass_reason,omitempty" jsonschema:"Required with force when overwriting critical identity files."`
	DryRun       bool   `json:"dry_run,omitempty" jsonschema:"Preview the apply plan without connecting."`
	TimeoutSecs  int    `json:"timeout_seconds,omitempty" jsonschema:"Remote execution timeout in seconds."`
	Bind         string `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpInspectInput struct {
	Target      string `json:"target" jsonschema:"Configured host name or address."`
	Capability  string `json:"capability" jsonschema:"Capability id, e.g. system.baseline, network.listeners, or a trusted local plugin id."`
	Cache       string `json:"cache,omitempty" jsonschema:"off (default) or remote-prefer to reuse/write a redacted remote observation."`
	Refresh     bool   `json:"refresh,omitempty" jsonschema:"Ignore a reusable observation and run the collector."`
	MaxAge      string `json:"max_age,omitempty" jsonschema:"Require observations no older than this duration (e.g. 30m)."`
	AllowStale  bool   `json:"allow_stale,omitempty" jsonschema:"Explicitly allow an expired observation."`
	Sudo        bool   `json:"sudo,omitempty" jsonschema:"Use sudo for an optional-privilege plugin."`
	TimeoutSecs int    `json:"timeout_seconds,omitempty" jsonschema:"Remote execution timeout in seconds."`
	Bind        string `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpSFTPInput struct {
	Target      string `json:"target" jsonschema:"Configured host name or address."`
	Action      string `json:"action" jsonschema:"upload, download, list, mkdir, or remove."`
	LocalPath   string `json:"local_path,omitempty" jsonschema:"Local file path (required for upload and download)."`
	RemotePath  string `json:"remote_path" jsonschema:"Remote path the action operates on."`
	DryRun      bool   `json:"dry_run,omitempty" jsonschema:"Preview the SFTP plan without connecting."`
	TimeoutSecs int    `json:"timeout_seconds,omitempty" jsonschema:"Remote execution timeout in seconds."`
	Bind        string `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
}

type mcpTransferInput struct {
	SourceHost  string `json:"source_host" jsonschema:"Configured host name or address holding the source path."`
	SourcePath  string `json:"source_path" jsonschema:"Source file or directory path."`
	DestHost    string `json:"dest_host" jsonschema:"Configured host name or address receiving the data."`
	DestPath    string `json:"dest_path" jsonschema:"Destination path."`
	DryRun      bool   `json:"dry_run,omitempty" jsonschema:"Preview the transfer plan without connecting."`
	TimeoutSecs int    `json:"timeout_seconds,omitempty" jsonschema:"Timeout in seconds for the streamed transfer."`
	Bind        string `json:"bind,omitempty" jsonschema:"Local source address: literal IP or network interface name."`
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
	if in.TimeoutSecs > 0 {
		args = append(args, "--timeout="+strconv.Itoa(in.TimeoutSecs)+"s")
	}
	if in.Concurrency > 0 {
		args = append(args, "--concurrency="+strconv.Itoa(in.Concurrency))
	}
	if in.FailureMode != "" {
		args = append(args, "--failure-mode="+in.FailureMode)
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
	if in.DryRun {
		args = append(args, "--dry-run")
	}
	if in.TimeoutSecs > 0 {
		args = append(args, "--timeout="+strconv.Itoa(in.TimeoutSecs)+"s")
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
	if in.TimeoutSecs > 0 {
		args = append(args, "--timeout="+strconv.Itoa(in.TimeoutSecs)+"s")
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
	if in.TimeoutSecs > 0 {
		args = append(args, "--timeout="+strconv.Itoa(in.TimeoutSecs)+"s")
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
	if in.TimeoutSecs > 0 {
		args = append(args, "--timeout="+strconv.Itoa(in.TimeoutSecs)+"s")
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
	if in.TimeoutSecs > 0 {
		args = append(args, "--timeout="+strconv.Itoa(in.TimeoutSecs)+"s")
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
		return runMCPTool(ctx, args, "", timeoutSeconds(in.TimeoutSecs))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "sshx_apply",
		Description: "Replace exactly one remote regular file with a guarded pipeline: optional expect_sha256 precondition, " +
			"owner-only backup, atomic same-directory rename preserving mode and owner, and a JSON result with changed, hashes, " +
			"and rollback_available. Reload/restart is deliberately out of scope — run it separately via sshx_run.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpApplyInput) (*mcp.CallToolResult, any, error) {
		hasFrom := in.FromPath != ""
		hasContent := in.Content != ""
		if hasFrom == hasContent {
			return nil, nil, fmt.Errorf("exactly one of from_path or content is required")
		}
		fromPath := in.FromPath
		if hasContent {
			dir, err := os.MkdirTemp("", "sshx-mcp-apply-")
			if err != nil {
				return nil, nil, fmt.Errorf("create temp payload dir: %w", err)
			}
			defer func() {
				_ = os.RemoveAll(dir) //nolint:errcheck // best-effort temp payload cleanup
			}()
			fromPath = filepath.Join(dir, "payload")
			if err := os.WriteFile(fromPath, []byte(in.Content), 0o600); err != nil {
				return nil, nil, fmt.Errorf("write temp payload: %w", err)
			}
		}
		args, err := buildApplyArgs(in, fromPath)
		if err != nil {
			return nil, nil, err
		}
		return runMCPTool(ctx, args, "", timeoutSeconds(in.TimeoutSecs))
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
		return runMCPTool(ctx, args, "", timeoutSeconds(in.TimeoutSecs))
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
		return runMCPTool(ctx, args, "", timeoutSeconds(in.TimeoutSecs))
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
		return runMCPTool(ctx, args, "", timeoutSeconds(in.TimeoutSecs))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "sshx_host_list",
		Description: "List configured named hosts (aliases, addresses, groups, tags, credential references) from " +
			"~/.sshx/settings.json. Read-only discovery; secrets never appear in the output.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ mcpHostListInput) (*mcp.CallToolResult, any, error) {
		return runMCPTool(ctx, []string{"--host-list", "--json"}, "", 0)
	})
}
