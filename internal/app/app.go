package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
)

// ErrUsage is returned when only the usage information was printed.
var ErrUsage = errors.New("usage displayed")

// ErrReported signals that a structured (JSON) result has already been written
// to stdout, so the entry point should exit without printing anything further.
var ErrReported = errors.New("result already reported")

// ExitError carries a remote command's exit status so the process can exit with
// the same code (mirroring the behavior of the ssh client).
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("command exited with status %d", e.Code)
}

// commandJSONResult is the machine-readable result emitted in --json mode.
type commandJSONResult struct {
	Host            string `json:"host"`
	Port            string `json:"port"`
	User            string `json:"user"`
	Command         string `json:"command"`
	ExitCode        int    `json:"exit_code"`
	Success         bool   `json:"success"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	DurationMs      int64  `json:"duration_ms"`
	AuthMethod      string `json:"auth_method"`
	Bind            string `json:"bind,omitempty"`
	ErrorKind       string `json:"error_kind,omitempty"`
	Error           string `json:"error,omitempty"`
	Phase           string `json:"phase"`
	Completion      string `json:"completion"`
	Executed        *bool  `json:"executed"`
}

// Run executes the CLI using the provided arguments (typically os.Args).
func Run(args []string) (err error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return RunContext(ctx, args)
}

// RunContext lets one-shot adapters share cancellation with the CLI entry point.
func RunContext(ctx context.Context, args []string) (err error) {
	// Handle usage
	if len(args) < 2 {
		PrintUsage()
		return ErrUsage
	}

	// Do not implicitly load a working-directory .env file. Repository-local
	// files must not alter trust, safety, or host-key policy. Process env and
	// explicit CLI flags remain the supported configuration surfaces.

	// Set log level from environment variable
	if logLevelStr := os.Getenv("SSHX_LOG_LEVEL"); logLevelStr != "" {
		logLevel := logger.LogLevelFromString(logLevelStr)
		logger.GetLogger().SetLevel(logLevel)
	}

	// Parse command-line arguments
	config := ParseArgs(args)
	config.Context = ctx
	config.ExecutionID = execution.NewRunID()
	if config.ArgumentError != "" {
		if config.Mode == "run" {
			return reportRunRequestFailure(config, nil, fmt.Errorf("%w: %s", execution.ErrConfig, config.ArgumentError))
		}
		if config.Mode != "login" && (config.JSONOutput || config.JSONLOutput) {
			return reportPlanFailure(config, nil, fmt.Errorf("%w: %s", execution.ErrConfig, config.ArgumentError))
		}
		return fmt.Errorf("%w: %s", execution.ErrConfig, config.ArgumentError)
	}
	applyCommandModeBypassReason(config, args)
	if config.Mode == "run" && config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}

	// Serve the Model Context Protocol over stdio. The server writes no audit
	// event itself: every tool call re-enters sshx as a one-shot child process
	// that records its own audit trail with the MCP entry marker.
	if config.Mode == "mcp" {
		return RunMCPServerContext(ctx)
	}

	audit := newAuditRecorder(config)
	defer func() {
		if prepared := preparedFrom(config); prepared != nil && audit != nil && prepared.meta.ExecutionFingerprint == "" {
			meta := prepared.meta
			code := -1
			if audit.event.ExitCode != nil {
				code = *audit.event.ExitCode
			}
			completion := audit.event.Completion
			if completion == "" {
				completion = execution.CompletionUnknown
				if err == nil {
					completion = execution.CompletionCompleted
				}
			}
			meta.Finish(audit.event.Outcome.Status, audit.event.Phase, completion, code, audit.event.Outcome.ErrorKind)
			audit.event.Metadata = meta
		}
		if auditErr := audit.finish(config, err); auditErr != nil {
			logger.GetLogger().Error("failed to write audit event: %v", auditErr)
		}
	}()
	if config.ExpectPlan != "" && config.Mode != "run" && !remoteOperation(config) {
		return reportPlanFailure(config, audit, fmt.Errorf("%w: --expect-plan is only supported for noninteractive remote operations", execution.ErrConfig))
	}
	if config.GlobalTimeout > 0 {
		var cancel context.CancelFunc
		config.Context, cancel = execution.WithScopedTimeout(config.Context, config.GlobalTimeout, "global")
		defer cancel()
	}

	// Canonical multi-host / script execution contract.
	if config.Mode == "run" {
		return HandleRun(config, audit)
	}

	if config.Mode == "ssh" {
		if bypassErr := requireBypassReason(config); bypassErr != nil {
			return reportSSHFailure(config, audit, sshclient.AuthMethodUnknown, "config", bypassErr)
		}
	}

	if remoteOperation(config) {
		if config.Mode == "apply" && config.Timeout == 0 {
			config.Timeout = 60 * time.Second
		}
		prepared, prepareErr := prepareOperation(config)
		if prepared != nil {
			prepared.audit = audit
			if prepared.cleanup != nil {
				defer func() {
					if cleanupErr := prepared.cleanup(); cleanupErr != nil {
						logger.GetLogger().Error("failed to clean execution snapshot: %v", cleanupErr)
					}
				}()
			}
			attachPrepared(config, prepared)
		}
		if prepareErr != nil {
			if config.DryRun && config.ExpectPlan == "" && prepared != nil {
				if prepared.preview.Valid {
					prepared.preview.Valid = false
					prepared.preview.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: execution.Classify(prepareErr), Message: redactError(prepareErr)}
					fillDryRunEffects(config, &prepared.preview)
				}
				return emitDryRunPlan(config)
			}
			return reportPlanFailure(config, audit, prepareErr)
		}
	}

	if config.DryRun {
		return emitDryRunPlan(config)
	}
	if config.Mode != "run" && remoteOperation(config) {
		if config.HostTimeout > 0 {
			var cancel context.CancelFunc
			config.Context, cancel = execution.WithScopedTimeout(config.Context, config.HostTimeout, "host")
			defer cancel()
		}
		if contextErr := config.Context.Err(); contextErr != nil {
			return reportPlanFailure(config, audit, contextErr)
		}
		if secretErr := resolveSSHCredential(config); secretErr != nil {
			return reportPlanFailure(config, audit, secretErr)
		}
	}

	// Guarded SQL execution pipeline (owns its own SSH connection).
	if config.Mode == "sql" {
		return HandleSQL(config, audit)
	}

	if config.Mode == "apply" {
		if config.Timeout == 0 {
			config.Timeout = 60 * time.Second
		}
		return HandleApply(config, audit)
	}

	if config.Mode == "login" {
		return HandleLogin(config, audit)
	}

	if config.Mode == "audit" {
		return HandleAudit(config)
	}

	// Handle password management mode
	if config.Mode == "password" {
		if pwdErr := HandlePasswordManagement(config); pwdErr != nil {
			if errors.Is(pwdErr, ErrReported) {
				return pwdErr
			}
			return fmt.Errorf("password management failed: %w", pwdErr)
		}
		return nil
	}

	// Handle host management mode
	if config.Mode == "host" {
		if hostErr := HandleHostManagement(config); hostErr != nil {
			if errors.Is(hostErr, ErrReported) {
				return hostErr
			}
			return fmt.Errorf("host management failed: %w", hostErr)
		}
		return nil
	}

	// Handle the local Agent skill lifecycle without crossing the network.
	if config.Mode == "skill" {
		return HandleSkillManagement(config)
	}

	// Handle local plugin lifecycle mode.
	if config.Mode == "plugin" {
		if pluginErr := HandlePluginManagement(config); pluginErr != nil {
			return pluginErr
		}
		return nil
	}

	// Handle one-shot capability inspection. The handler owns one SSH
	// connection and any cache sessions created over it.
	if config.Mode == "inspect" {
		return HandleInspection(config, audit)
	}

	// Handle server-to-server transfer mode
	if config.Mode == "transfer" {
		if transferErr := HandleTransfer(config); transferErr != nil {
			if errors.Is(transferErr, ErrReported) {
				return transferErr
			}
			if prepared := preparedFrom(config); prepared != nil && prepared.meta.ExecutionFingerprint != "" {
				return transferErr
			}
			return reportPlanFailure(config, audit, fmt.Errorf("transfer failed: %w", transferErr))
		}
		return nil
	}

	// Validate flags that only apply to command execution.
	if config.Mode == "ssh" {
		if config.Timeout < 0 {
			return reportSSHFailure(config, audit, sshclient.AuthMethodUnknown, "config",
				fmt.Errorf("invalid --timeout value (use e.g. 30s, 2m, or 30)"))
		}
		if config.JSONOutput && config.UsePTY {
			return reportSSHFailure(config, audit, sshclient.AuthMethodUnknown, "config",
				fmt.Errorf("--pty cannot be combined with --json (a PTY merges stderr into stdout)"))
		}
		// Reject dangerous commands before doing any network work so the
		// rejection is deterministic and cheap, and reports a precise
		// error_kind ("blocked") instead of being masked by a connect error.
		if config.SafetyCheck && !config.Force {
			if blockErr := sshclient.ValidateCommand(config.Command); blockErr != nil {
				return reportSSHFailure(config, audit, sshclient.AuthMethodUnknown, classifyError(blockErr), blockErr)
			}
		}
	}

	// Try to resolve host from settings if not an IP address
	if config.Host != "" && !isIPAddress(config.Host) {
		if resolveErr := resolveHostFromSettings(config); resolveErr != nil {
			logger.GetLogger().Info("Note: Could not find host '%s' in settings, using as hostname directly", config.Host)
		}
	}

	// Auto-fill sudo password if needed
	if sshclient.CommandUsesSudo(config.Command) && config.SudoKey != "" {
		if contextErr := operationContextError(config); contextErr != nil {
			return reportPlanFailure(config, audit, contextErr)
		}
		password, pwdErr := sshclient.GetSudoPassword(config.SudoKey)
		if contextErr := operationContextError(config); contextErr != nil {
			return reportPlanFailure(config, audit, contextErr)
		}
		if pwdErr != nil {
			if config.ExpectPlan != "" {
				return reportSSHFailure(config, audit, sshclient.AuthMethodUnknown, "auth", fmt.Errorf("resolve admitted sudo credential: %w", pwdErr))
			}
			logger.GetLogger().Warning("failed to get sudo password from keyring: %v", pwdErr)
			logger.GetLogger().Info("Continuing without sudo password auto-fill...")
		} else {
			config.SudoPassword = password
			logger.GetLogger().Success("Sudo password will be auto-filled when prompted")
		}
	}

	// Create SSH client
	client, err := sshclient.NewSSHClient(config)
	if err != nil {
		return reportSSHFailure(config, audit, sshclient.AuthMethodUnknown, "config",
			fmt.Errorf("failed to create SSH client: %w", err))
	}
	defer errutil.HandleCloseError(&err, client)

	// Connect to remote host (use direct connection for CLI mode, no need for pooling)
	err = client.ConnectDirect()
	recordConnectedPeer(config, client, "target")
	if err != nil {
		return reportSSHFailure(config, audit, sshclient.AuthMethodUnknown, classifyError(err),
			fmt.Errorf("failed to connect: %w", err))
	}
	if audit != nil {
		audit.event.AuthMethod = string(client.AuthMethodUsed())
	}

	// Handle SFTP mode
	if config.Mode == "sftp" {
		return runSFTP(client, config, audit)
	}

	// Handle SSH command execution
	return runCommand(client, config, audit)
}

// runCommand runs the configured command and translates the result into either
// streamed human output or a single JSON object, then returns an error whose
// type tells the entry point which exit code to use.
func runCommand(client *sshclient.SSHClient, config *sshclient.Config, audit *auditRecorder) error {
	start := time.Now()
	res, execErr := client.RunCommand(config.JSONOutput)
	dur := time.Since(start)
	audit.recordCommandResult(config, client.AuthMethodUsed(), res, dur, classifyError(execErr), execErr)

	if config.JSONOutput {
		if outputErr := emitCommandJSON(config, client.AuthMethodUsed(), res, dur, classifyError(execErr), execErr); outputErr != nil {
			return outputErr
		}
		if execErr != nil {
			return ErrReported
		}
		if res.ExitCode != 0 {
			return &ExitError{Code: res.ExitCode}
		}
		return nil
	}
	if _, evidenceErr := finalizeLifecycle(config, commandResult(config, client.AuthMethodUsed(), res, dur, classifyError(execErr), execErr)); evidenceErr != nil {
		return evidenceErr
	}

	if execErr != nil {
		return fmt.Errorf("failed to execute command: %w", execErr)
	}
	if res.ExitCode != 0 {
		return &ExitError{Code: res.ExitCode}
	}
	return nil
}

// reportSSHFailure emits a JSON error object in --json command mode (and returns
// ErrReported so the caller exits silently), or returns the error unchanged for
// the normal streamed path.
func reportSSHFailure(config *sshclient.Config, audit *auditRecorder, authMethod sshclient.AuthMethod, kind string, err error) error {
	if preparedFrom(config) == nil {
		attachPrepared(config, &preparedOperation{meta: execution.NewMetadata(nil, config.ExecutionID), audit: audit})
	}
	audit.recordFailure(config, authMethod, kind, err)
	if config.JSONOutput && config.Mode == "ssh" {
		if outputErr := emitCommandJSON(config, authMethod, sshclient.ExecResult{ExitCode: -1}, 0, kind, err); outputErr != nil {
			return outputErr
		}
		return ErrReported
	}
	if config.JSONOutput && config.Mode == "sftp" {
		return reportPlanFailure(config, audit, err)
	}
	if config.Mode == "ssh" {
		if _, evidenceErr := finalizeLifecycle(config, commandResult(config, authMethod, sshclient.ExecResult{ExitCode: -1}, 0, kind, err)); evidenceErr != nil {
			return evidenceErr
		}
	}
	return err
}

// emitCommandJSON writes a single JSON result line to stdout. Diagnostic logs go
// to stderr, so stdout stays a pure machine-readable stream.
func emitCommandJSON(config *sshclient.Config, authMethod sshclient.AuthMethod, res sshclient.ExecResult, dur time.Duration, errKind string, execErr error) error {
	return emitLifecycleJSON(config, commandResult(config, authMethod, res, dur, errKind, execErr))
}

func commandResult(config *sshclient.Config, authMethod sshclient.AuthMethod, res sshclient.ExecResult, dur time.Duration, errKind string, execErr error) commandJSONResult {
	phase := execution.PhaseComplete
	if execErr != nil {
		phase = execution.PhaseExecute
		if !res.StartAttempted && !res.Started {
			phase = execution.PhaseAdmission
		}
	}
	var executed *bool
	if res.Started || !res.StartAttempted {
		observed := res.Started
		executed = &observed
	}
	result := commandJSONResult{
		Host:            config.Host,
		Port:            config.Port,
		User:            config.User,
		Command:         redactSensitiveText(config.Command),
		ExitCode:        res.ExitCode,
		Success:         execErr == nil && res.ExitCode == 0,
		Stdout:          res.Stdout,
		Stderr:          res.Stderr,
		StdoutTruncated: res.StdoutTruncated,
		StderrTruncated: res.StderrTruncated,
		DurationMs:      dur.Milliseconds(),
		AuthMethod:      string(authMethod),
		Bind:            config.Bind,
		ErrorKind:       errKind,
		Phase:           phase,
		Completion:      execution.CompletionForAttempt(phase, errKind, res.StartAttempted, res.Started, res.ExitObserved),
		Executed:        executed,
	}
	if execErr != nil {
		result.Error = redactError(execErr)
		if !res.ExitObserved {
			result.ExitCode = -1
		}
	}

	return result
}

// classifyError maps an sshx-level error to a stable machine-readable kind so an
// agent can branch on the failure category without parsing free-form text.
// Compatibility projection: unknown maps to the legacy "error" kind for the
// existing single-command JSON surface.
func classifyError(err error) string {
	kind := execution.Classify(err)
	if kind == execution.ErrorKindUnknown {
		return "error"
	}
	return kind
}

// applyCommandModeBypassReason lifts --bypass-reason= from argv for compatibility
// command mode, where ParseArgs historically treated the flag as the start of the
// remote command. It also strips a leftover flag token from Config.Command so it
// is never executed remotely.
func applyCommandModeBypassReason(config *sshclient.Config, args []string) {
	if config == nil || config.Mode != "ssh" {
		return
	}
	for _, arg := range args {
		if arg == "--" {
			return
		}
		if strings.HasPrefix(arg, "--bypass-reason=") {
			config.BypassReason = strings.SplitN(arg, "=", 2)[1]
			if config.Command == arg {
				config.Command = ""
			} else if strings.HasPrefix(config.Command, arg+" ") {
				config.Command = strings.TrimPrefix(config.Command, arg+" ")
			}
			return
		}
	}
}

// requireBypassReason enforces the run-mode rule on command mode: --force and
// --no-safety-check are explicit break-glass switches and must carry a
// non-empty --bypass-reason for audit. Skill/SQL --force keep their own
// semantics and are not gated here.
func requireBypassReason(config *sshclient.Config) error {
	if config == nil {
		return nil
	}
	if config.Force || !config.SafetyCheck {
		if strings.TrimSpace(config.BypassReason) == "" {
			return fmt.Errorf("safety bypass requires a non-empty --bypass-reason")
		}
	}
	return nil
}

// isIPAddress checks if a string is a valid IP address
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// resolveHostFromSettings tries to resolve host configuration from settings
func resolveHostFromSettings(config *sshclient.Config) error {
	if publiclyResolved(config) {
		return nil
	}
	// Load settings
	settings, err := LoadSettings()
	if err != nil {
		return err
	}

	// Try to find host by name
	hostConfig, err := GetHost(settings, config.Host)
	if err != nil {
		return err
	}

	logger.GetLogger().Success("Found host '%s' in settings", config.Host)

	// Update config with host settings
	config.Host = hostConfig.Host
	if config.Port == "" || config.Port == sshclient.DefaultSSHPort {
		if hostConfig.Port != "" {
			config.Port = hostConfig.Port
		}
	}
	if config.User == "" || config.User == sshclient.DefaultSSHUser {
		if hostConfig.User != "" {
			config.User = hostConfig.User
		}
	}

	// Use configured sudo password key if available (legacy password_key is sudo-only).
	sudoKey := hostConfig.EffectiveSudoPasswordKey()
	if sudoKey != "" && config.SudoKey == sshclient.DefaultSudoKey {
		config.SudoKey = sudoKey
		logger.GetLogger().Success("Using sudo password key: %s", sudoKey)
	}
	// SSH login password key is a distinct role and never falls back to sudo keys.
	if config.SSHPasswordKey == "" {
		if sshKey := hostConfig.EffectiveSSHPasswordKey(); sshKey != "" {
			config.SSHPasswordKey = sshKey
			logger.GetLogger().Success("Using SSH password key: %s", sshKey)
		}
	}

	if !config.BindSet && hostConfig.Bind != "" {
		config.Bind = hostConfig.Bind
	}

	// Use per-host SSH key if available, otherwise fall back to the default key
	if config.UseKeyAuth && config.KeyPath == "" {
		switch {
		case hostConfig.Key != "":
			config.KeyPath = hostConfig.Key
			logger.GetLogger().Success("Using host SSH key: %s", hostConfig.Key)
		case settings.Key != "":
			config.KeyPath = settings.Key
			logger.GetLogger().Success("Using SSH key: %s", settings.Key)
		}
	}

	// Resolve typed SSH login password only when that role is requested.
	if config.Password == "" && config.SSHPasswordKey != "" {
		if password, pwdErr := sshclient.GetSudoPassword(config.SSHPasswordKey); pwdErr != nil {
			logger.GetLogger().Warning("failed to get SSH password from keyring (%s): %v", config.SSHPasswordKey, pwdErr)
		} else {
			config.Password = password
		}
	}

	return nil
}
