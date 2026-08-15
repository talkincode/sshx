package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
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
	ErrorKind       string `json:"error_kind,omitempty"`
	Error           string `json:"error,omitempty"`
}

// Run executes the CLI using the provided arguments (typically os.Args).
func Run(args []string) (err error) {
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
	if config.ArgumentError != "" {
		return fmt.Errorf("%w: %s", execution.ErrConfig, config.ArgumentError)
	}
	audit := newAuditRecorder(config)
	defer func() {
		if auditErr := audit.finish(config, err); auditErr != nil {
			logger.GetLogger().Error("failed to write audit event: %v", auditErr)
		}
	}()

	// Canonical multi-host / script execution contract.
	if config.Mode == "run" {
		return HandleRun(config, audit)
	}

	if config.DryRun {
		return emitDryRunPlan(config)
	}

	// Guarded SQL execution pipeline (owns its own SSH connection).
	if config.Mode == "sql" {
		return HandleSQL(config, audit)
	}

	// Handle password management mode
	if config.Mode == "password" {
		if pwdErr := HandlePasswordManagement(config); pwdErr != nil {
			return fmt.Errorf("password management failed: %w", pwdErr)
		}
		return nil
	}

	// Handle host management mode
	if config.Mode == "host" {
		if hostErr := HandleHostManagement(config); hostErr != nil {
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
			return fmt.Errorf("transfer failed: %w", transferErr)
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
		password, pwdErr := sshclient.GetSudoPassword(config.SudoKey)
		if pwdErr != nil {
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
	if err = client.ConnectDirect(); err != nil {
		return reportSSHFailure(config, audit, sshclient.AuthMethodUnknown, classifyError(err),
			fmt.Errorf("failed to connect: %w", err))
	}
	if audit != nil {
		audit.event.AuthMethod = string(client.AuthMethodUsed())
	}

	// Handle SFTP mode
	if config.Mode == "sftp" {
		if err = client.ExecuteSftp(); err != nil {
			return fmt.Errorf("SFTP operation failed: %w", err)
		}
		return nil
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
		emitCommandJSON(config, client.AuthMethodUsed(), res, dur, classifyError(execErr), execErr)
		if execErr != nil {
			return ErrReported
		}
		if res.ExitCode != 0 {
			return &ExitError{Code: res.ExitCode}
		}
		return nil
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
	audit.recordFailure(config, authMethod, kind, err)
	if config.JSONOutput && config.Mode == "ssh" {
		emitCommandJSON(config, authMethod, sshclient.ExecResult{ExitCode: -1}, 0, kind, err)
		return ErrReported
	}
	return err
}

// emitCommandJSON writes a single JSON result line to stdout. Diagnostic logs go
// to stderr, so stdout stays a pure machine-readable stream.
func emitCommandJSON(config *sshclient.Config, authMethod sshclient.AuthMethod, res sshclient.ExecResult, dur time.Duration, errKind string, execErr error) {
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
		ErrorKind:       errKind,
	}
	if execErr != nil {
		result.Error = redactError(execErr)
		if result.ExitCode == 0 {
			result.ExitCode = -1
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		logger.GetLogger().Error("failed to encode JSON result: %v", err)
	}
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

// isIPAddress checks if a string is a valid IP address
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// resolveHostFromSettings tries to resolve host configuration from settings
func resolveHostFromSettings(config *sshclient.Config) error {
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
