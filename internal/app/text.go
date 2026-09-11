package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/internal/textsafe"
	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
)

type textJSONResult struct {
	SchemaVersion   string              `json:"schema_version"`
	Host            string              `json:"host"`
	Port            string              `json:"port"`
	User            string              `json:"user"`
	Action          string              `json:"action"`
	UseSudo         bool                `json:"use_sudo,omitempty"`
	Source          textsafe.SourceInfo `json:"source"`
	Filter          textsafe.FilterInfo `json:"filter"`
	Stats           textsafe.Stats      `json:"stats"`
	Hits            []textsafe.Hit      `json:"hits"`
	Truncated       bool                `json:"truncated"`
	TruncatedReason string              `json:"truncated_reason,omitempty"`
	Redacted        bool                `json:"redacted"`
	LineOrigin      string              `json:"line_origin"`
	Status          string              `json:"status"`
	Phase           string              `json:"phase"`
	Completion      string              `json:"completion"`
	ExitCode        int                 `json:"exit_code"`
	Success         bool                `json:"success"`
	DurationMs      int64               `json:"duration_ms"`
	AuthMethod      string              `json:"auth_method,omitempty"`
	ErrorKind       string              `json:"error_kind,omitempty"`
	Error           string              `json:"error,omitempty"`
	ChangeState     string              `json:"change_state"`
	Executed        *bool               `json:"executed"`
	Verified        bool                `json:"verified"`
	Verification    string              `json:"verification"`
}

type textRun struct {
	config *sshclient.Config
	audit  *auditRecorder
	start  time.Time
	phase  string
	client *sshclient.SSHClient
	req    textsafe.Request
	scan   textsafe.Result
}

func textRequestFrom(config *sshclient.Config) (textsafe.Request, error) {
	req := textsafe.Request{
		Path:         config.RemotePath,
		JournalUnit:  config.TextJournal,
		Since:        config.TextSince,
		Until:        config.TextUntil,
		Presets:      append([]string(nil), config.TextPresets...),
		Pattern:      config.TextPattern,
		Context:      config.TextContext,
		AroundLine:   config.TextAroundLine,
		Offset:       config.TextOffset,
		Limit:        config.TextLimit,
		Tail:         config.TextTail,
		Scan:         config.TextScan,
		MaxHits:      config.TextMaxHits,
		MaxBytes:     config.TextMaxBytes,
		MaxScanBytes: config.TextMaxScanBytes,
		Redact:       config.TextRedact,
	}
	switch {
	case config.RemotePath != "" && config.TextJournal != "":
		req.Kind = ""
	case config.RemotePath != "":
		req.Kind = textsafe.SourceFile
	case config.TextJournal != "":
		req.Kind = textsafe.SourceJournal
	}
	if err := req.Normalize(); err != nil {
		return req, err
	}
	return req, nil
}

func HandleTextHelp(config *sshclient.Config) error {
	if config.JSONOutput {
		if err := encodeJSON(textsafe.Help()); err != nil {
			return fmt.Errorf("%w: deliver text help: %w", execution.ErrLocalIO, err)
		}
		return nil
	}
	PrintTextUsage()
	return nil
}

func HandleText(config *sshclient.Config, audit *auditRecorder) (err error) {
	run := &textRun{config: config, audit: audit, start: time.Now(), phase: "classify"}
	if config.ArgumentError != "" {
		return run.fail("config", fmt.Errorf("%s", config.ArgumentError))
	}
	if config.Timeout < 0 {
		return run.fail("config", fmt.Errorf("invalid --timeout value (use e.g. 30s, 2m, or 30)"))
	}
	if config.Host == "" {
		return run.fail("config", fmt.Errorf("host is required (use -h=<host> or --target=<name>)"))
	}
	req, reqErr := textRequestFrom(config)
	if reqErr != nil {
		return run.fail("config", reqErr)
	}
	run.req = req
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	if config.Host != "" && !isIPAddress(config.Host) {
		if resolveErr := resolveHostFromSettings(config); resolveErr != nil {
			logger.GetLogger().Info("Note: Could not find host '%s' in settings, using as hostname directly", config.Host)
		}
	}

	if config.TextUseSudo {
		password, pwdErr := sshclient.GetSudoPassword(config.SudoKey)
		if pwdErr != nil {
			return run.fail("secret", fmt.Errorf("resolve sudo password key %q: %w", config.SudoKey, pwdErr))
		}
		config.SudoPassword = password
	}

	run.phase = "connect"
	client, cliErr := sshclient.NewSSHClient(config)
	if cliErr != nil {
		return run.fail("config", fmt.Errorf("failed to create SSH client: %w", cliErr))
	}
	defer errutil.HandleCloseError(&err, client)
	run.client = client
	if connErr := client.Connect(); connErr != nil {
		return run.fail(classifyError(connErr), fmt.Errorf("failed to connect: %w", connErr))
	}
	recordConnectedHops(config, client)
	if audit != nil {
		audit.event.AuthMethod = string(client.AuthMethodUsed())
	}

	run.phase = "scan"
	scan, scanErr := run.collect(req)
	if scanErr != nil {
		return run.fail(classifyTextError(scanErr), scanErr)
	}
	run.scan = scan
	return run.succeed()
}

func (r *textRun) collect(req textsafe.Request) (textsafe.Result, error) {
	switch req.Kind {
	case textsafe.SourceFile:
		if r.config.TextUseSudo {
			return r.scanPrivilegedFile(req)
		}
		return r.scanSFTP(req)
	case textsafe.SourceJournal:
		return r.scanJournal(req)
	default:
		return textsafe.Result{}, fmt.Errorf("unsupported text source")
	}
}

func (r *textRun) scanSFTP(req textsafe.Request) (textsafe.Result, error) {
	fromEnd := req.Scan == textsafe.ScanEnd
	file, meta, err := r.client.OpenRemoteText(req.Path, fromEnd, req.MaxScanBytes)
	if err != nil {
		return textsafe.Result{}, err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // best-effort close after scan
	req.FileSize = meta.Size
	req.WindowStartByte = meta.StartByte
	req.SkipPartialFirst = meta.SkipPartial
	return textsafe.Scan(file, req)
}

func (r *textRun) scanPrivilegedFile(req textsafe.Request) (textsafe.Result, error) {
	fromEnd := req.Scan == textsafe.ScanEnd
	cmd := textsafe.FileReadCommand(req.Path, fromEnd, req.MaxScanBytes, true)
	stdin := []byte(r.config.SudoPassword + "\n")
	result, err := r.client.RunCommandWithInput(cmd, stdin)
	if err != nil {
		return textsafe.Result{}, err
	}
	if result.ExitCode != 0 {
		return textsafe.Result{}, fmt.Errorf("privileged file read exited %d: %s", result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	req.SkipPartialFirst = fromEnd && int64(len(result.Stdout)) >= req.MaxScanBytes
	return textsafe.Scan(strings.NewReader(result.Stdout), req)
}

func (r *textRun) scanJournal(req textsafe.Request) (textsafe.Result, error) {
	cmd := textsafe.JournalCommand(req, r.config.TextUseSudo)
	var stdin []byte
	if r.config.TextUseSudo {
		stdin = []byte(r.config.SudoPassword + "\n")
	}
	result, err := r.client.RunCommandWithInput(cmd, stdin)
	if err != nil {
		return textsafe.Result{}, err
	}
	if result.ExitCode != 0 {
		msg := strings.TrimSpace(result.Stderr)
		if strings.Contains(strings.ToLower(msg), "journalctl") && strings.Contains(strings.ToLower(msg), "not found") {
			return textsafe.Result{}, fmt.Errorf("journal source is unsupported on this host: %s", msg)
		}
		return textsafe.Result{}, fmt.Errorf("journalctl exited %d: %s", result.ExitCode, msg)
	}
	return textsafe.Scan(strings.NewReader(result.Stdout), req)
}

func (r *textRun) succeed() error {
	r.phase = "complete"
	r.recordAudit(0, "", nil)
	result := r.baseResult(true, 0, "", nil)
	if r.config.JSONOutput {
		return emitTextJSON(r.config, result)
	}
	if _, finalizeErr := finalizeLifecycle(r.config, result); finalizeErr != nil {
		logger.GetLogger().Error("failed to finalize text evidence: %v", finalizeErr)
	}
	printTextHits(result)
	return nil
}

func (r *textRun) fail(kind string, failErr error) error {
	r.recordAudit(-1, kind, failErr)
	result := r.baseResult(false, -1, kind, failErr)
	if r.config.JSONOutput {
		_ = emitTextJSON(r.config, result) //nolint:errcheck // failure path still reports
		return ErrReported
	}
	if _, finalizeErr := finalizeLifecycle(r.config, result); finalizeErr != nil {
		logger.GetLogger().Error("failed to finalize text evidence: %v", finalizeErr)
	}
	return failErr
}

func (r *textRun) baseResult(success bool, exitCode int, kind string, failErr error) textJSONResult {
	yes := success
	result := textJSONResult{
		SchemaVersion: textsafe.SchemaVersion,
		Host:          r.config.Host,
		Port:          r.config.Port,
		User:          r.config.User,
		Action:        "text",
		UseSudo:       r.config.TextUseSudo,
		Hits:          []textsafe.Hit{},
		Status:        execution.StatusFailed,
		Phase:         r.phase,
		Completion:    execution.CompletionNotStarted,
		ExitCode:      exitCode,
		Success:       success,
		DurationMs:    time.Since(r.start).Milliseconds(),
		ErrorKind:     kind,
		ChangeState:   "unchanged",
		Executed:      &yes,
		Verification:  "not_performed",
		Redacted:      r.req.Redact,
	}
	if r.client != nil {
		result.AuthMethod = string(r.client.AuthMethodUsed())
	}
	if r.scan.Source.Kind != "" || len(r.scan.Hits) > 0 || r.scan.Stats.LinesScanned > 0 {
		result.Source = r.scan.Source
		result.Filter = r.scan.Filter
		result.Stats = r.scan.Stats
		result.Hits = r.scan.Hits
		result.Truncated = r.scan.Truncated
		result.TruncatedReason = r.scan.TruncatedReason
		result.Redacted = r.scan.Redacted
		result.LineOrigin = r.scan.LineOrigin
	} else {
		result.Source = textsafe.SourceInfo{Kind: r.req.Kind, Path: r.req.Path, JournalUnit: r.req.JournalUnit, Scan: r.req.Scan}
		result.Filter = textsafe.FilterInfo{Presets: r.req.Presets, Pattern: r.req.Pattern, Context: r.req.Context}
	}
	if success {
		result.Status = execution.StatusSucceeded
		result.Completion = execution.CompletionCompleted
		result.Verified = true
		result.Verification = "content"
	}
	if failErr != nil {
		result.Error = redactError(failErr)
		result.Executed = boolPtr(r.phase == "scan")
		if r.phase != "scan" {
			result.Executed = boolPtr(false)
		}
	}
	return result
}

func (r *textRun) recordAudit(exitCode int, kind string, failErr error) {
	if r.audit == nil {
		return
	}
	authMethod := sshclient.AuthMethodUnknown
	if r.client != nil {
		authMethod = r.client.AuthMethodUsed()
	}
	r.audit.event.RemotePath = r.config.RemotePath
	r.audit.event.UsesSudo = r.config.TextUseSudo
	r.audit.recordCommandResult(r.config, authMethod, sshclient.ExecResult{ExitCode: exitCode}, time.Since(r.start), kind, failErr)
}

func emitTextJSON(config *sshclient.Config, result textJSONResult) error {
	if err := emitLifecycleJSON(config, result); err != nil {
		logger.GetLogger().Error("failed to encode JSON result: %v", err)
		return err
	}
	if !result.Success {
		return nil
	}
	return nil
}

func printTextHits(result textJSONResult) {
	if !result.Success {
		return
	}
	fmt.Printf("sshx text: %d hits (%d exception blocks), scanned %d lines\n",
		result.Stats.Returned, result.Stats.ExceptionBlocks, result.Stats.LinesScanned)
	for i, hit := range result.Hits {
		fmt.Printf("-- %d %s L%d-%d --\n%s\n", i+1, hit.Kind, hit.StartLine, hit.EndLine, hit.Text)
	}
	if result.Truncated {
		fmt.Printf("truncated: %s (total_hits=%d returned=%d)\n", result.TruncatedReason, result.Stats.TotalHits, result.Stats.Returned)
	}
}

func classifyTextError(err error) string {
	kind := classifyError(err)
	if kind != "" && kind != "error" {
		return kind
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unsupported"):
		return "unsupported"
	case strings.Contains(msg, "binary"):
		return "blocked"
	case strings.Contains(msg, "symlink"), strings.Contains(msg, "regular file"):
		return "blocked"
	default:
		return kind
	}
}
