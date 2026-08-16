package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
)

type applyBackupJSON struct {
	Kind        string `json:"kind"`
	Path        string `json:"path,omitempty"`
	RestoreHint string `json:"restore_hint,omitempty"`
}

type applyJSONResult struct {
	SchemaVersion  string           `json:"schema_version"`
	Host           string           `json:"host"`
	Port           string           `json:"port"`
	User           string           `json:"user"`
	Action         string           `json:"action"`
	Intent         string           `json:"intent"`
	RemotePath     string           `json:"remote_path"`
	LocalPath      string           `json:"local_path,omitempty"`
	PayloadSHA256  string           `json:"payload_sha256,omitempty"`
	PayloadBytes   int              `json:"payload_bytes,omitempty"`
	ExpectSHA256   string           `json:"expect_sha256,omitempty"`
	BeforeSHA256   string           `json:"before_sha256,omitempty"`
	AfterSHA256    string           `json:"after_sha256,omitempty"`
	Changed        bool             `json:"changed"`
	Created        bool             `json:"created"`
	RollbackAvail  bool             `json:"rollback_available"`
	Mode           string           `json:"mode,omitempty"`
	UseSudo        bool             `json:"use_sudo,omitempty"`
	Backup         *applyBackupJSON `json:"backup,omitempty"`
	Status         string           `json:"status"`
	Phase          string           `json:"phase"`
	Completion     string           `json:"completion"`
	ExitCode       int              `json:"exit_code"`
	Success        bool             `json:"success"`
	DurationMs     int64            `json:"duration_ms"`
	AuthMethod     string           `json:"auth_method,omitempty"`
	ErrorKind      string           `json:"error_kind,omitempty"`
	Error          string           `json:"error,omitempty"`
	ErrorRetryable bool             `json:"retryable,omitempty"`
	RetrySafety    string           `json:"retry_safety,omitempty"`
}

type applyRun struct {
	config  *sshclient.Config
	audit   *auditRecorder
	start   time.Time
	phase   string
	client  *sshclient.SSHClient
	payload []byte
	outcome *sshclient.ApplyOutcome
}

func HandleApply(config *sshclient.Config, audit *auditRecorder) (err error) {
	run := &applyRun{config: config, audit: audit, start: time.Now(), phase: "classify"}
	if cfgErr := validateApplyConfig(config); cfgErr != nil {
		return run.fail("config", cfgErr)
	}

	run.phase = "policy"
	if policyErr := applyPolicy(config); policyErr != nil {
		kind := classifyError(policyErr)
		if kind == "" || kind == "error" {
			kind = "blocked"
		}
		return run.fail(kind, policyErr)
	}

	payload, readErr := os.ReadFile(config.LocalPath)
	if readErr != nil {
		return run.fail("local_io", fmt.Errorf("read --from=%s: %w", config.LocalPath, readErr))
	}
	if len(payload) > sshclient.MaxApplyBytes {
		return run.fail("config", fmt.Errorf("payload exceeds %d-byte apply limit", sshclient.MaxApplyBytes))
	}
	run.payload = payload

	if config.Host != "" && !isIPAddress(config.Host) {
		if resolveErr := resolveHostFromSettings(config); resolveErr != nil {
			logger.GetLogger().Info("Note: Could not find host '%s' in settings, using as hostname directly", config.Host)
		}
	}

	if config.ApplyUseSudo {
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
	if connErr := client.ConnectDirect(); connErr != nil {
		return run.fail(classifyError(connErr), fmt.Errorf("failed to connect: %w", connErr))
	}
	run.client = client
	if audit != nil {
		audit.event.AuthMethod = string(client.AuthMethodUsed())
	}

	run.phase = "apply"
	outcome, applyErr := client.ApplyRegularFile(sshclient.ApplyRequest{
		RemotePath:   config.RemotePath,
		Payload:      payload,
		ExpectSHA256: config.ApplyExpectSHA256,
		Backup:       !config.ApplyNoBackup,
		BackupDir:    config.ApplyBackupDir,
		Force:        config.Force,
		UseSudo:      config.ApplyUseSudo,
	})
	if applyErr != nil {
		run.outcome = outcome
		return run.fail(classifyApplyError(applyErr), applyErr)
	}
	run.outcome = outcome
	return run.succeed()
}

func validateApplyConfig(config *sshclient.Config) error {
	if config.ArgumentError != "" {
		return fmt.Errorf("%s", config.ArgumentError)
	}
	if config.Host == "" {
		return fmt.Errorf("host is required (use -h=<host> or --target=<name>)")
	}
	if strings.TrimSpace(config.RemotePath) == "" {
		return fmt.Errorf("--path=<absolute-remote-file> is required")
	}
	if strings.TrimSpace(config.LocalPath) == "" {
		return fmt.Errorf("--from=<local-file> is required")
	}
	if err := sshclient.ValidateApplyPath(config.RemotePath); err != nil {
		return err
	}
	if config.ApplyBackupDir != "" {
		dir := path.Clean(config.ApplyBackupDir)
		if err := sshclient.ValidateApplyPath(dir + "/.keep"); err != nil {
			return fmt.Errorf("invalid --backup-dir: %w", err)
		}
		config.ApplyBackupDir = dir
	}
	normalized, err := sshclient.NormalizeApplySHA256(config.ApplyExpectSHA256)
	if err != nil {
		return fmt.Errorf("invalid --expect-sha256: %w", err)
	}
	config.ApplyExpectSHA256 = normalized
	if config.ApplyNoBackup && !config.Force {
		return fmt.Errorf("--no-backup requires --force")
	}
	if config.Timeout < 0 {
		return fmt.Errorf("invalid --timeout value (use e.g. 30s, 2m, or 30)")
	}
	return nil
}

func applyPolicy(config *sshclient.Config) error {
	if sshclient.ApplyPathBlocked(config.RemotePath) {
		if !config.Force || strings.TrimSpace(config.BypassReason) == "" {
			return fmt.Errorf("%w: %s is a critical identity file; pass --force --bypass-reason=", sshclient.ErrApplyBlocked, config.RemotePath)
		}
	}
	return nil
}

func (r *applyRun) succeed() error {
	r.phase = "complete"
	r.recordAudit(0, "", nil)
	if r.config.JSONOutput {
		emitApplyJSON(r.baseResult(true, 0, "", nil))
		return nil
	}
	if r.outcome != nil && !r.outcome.Changed {
		logger.GetLogger().Success("Unchanged %s (already matches payload)", r.config.RemotePath)
		return nil
	}
	logger.GetLogger().Success("Applied %s", r.config.RemotePath)
	if r.outcome != nil && r.outcome.BackupPath != "" {
		logger.GetLogger().Info("Backup: %s", r.outcome.BackupPath)
	}
	return nil
}

func (r *applyRun) fail(kind string, failErr error) error {
	completion := execution.CompletionNotStarted
	switch r.phase {
	case "apply":
		completion = execution.CompletionUnknown
		if kind == execution.ErrorKindPrecondition || kind == "blocked" || kind == "config" {
			completion = execution.CompletionNotStarted
		}
	}
	r.recordAudit(-1, kind, failErr)
	if r.config.JSONOutput {
		result := r.baseResult(false, -1, kind, failErr)
		result.Completion = completion
		if info := execution.BuildError(failErr, kind, execution.IntentChange, completion); info != nil {
			result.ErrorRetryable = info.Retryable
			result.RetrySafety = info.RetrySafety
		}
		emitApplyJSON(result)
		return ErrReported
	}
	return failErr
}

func (r *applyRun) baseResult(success bool, exitCode int, kind string, failErr error) applyJSONResult {
	result := applyJSONResult{
		SchemaVersion: execution.ResultSchemaVersion,
		Host:          r.config.Host,
		Port:          r.config.Port,
		User:          r.config.User,
		Action:        execution.ActionApply,
		Intent:        execution.IntentChange,
		RemotePath:    r.config.RemotePath,
		LocalPath:     r.config.LocalPath,
		ExpectSHA256:  r.config.ApplyExpectSHA256,
		UseSudo:       r.config.ApplyUseSudo,
		Status:        execution.StatusFailed,
		Phase:         r.phase,
		Completion:    execution.CompletionNotStarted,
		ExitCode:      exitCode,
		Success:       success,
		DurationMs:    time.Since(r.start).Milliseconds(),
		ErrorKind:     kind,
	}
	if success {
		result.Status = execution.StatusSucceeded
		result.Completion = execution.CompletionCompleted
	}
	if len(r.payload) > 0 {
		result.PayloadSHA256 = sshclient.SHA256Hex(r.payload)
		result.PayloadBytes = len(r.payload)
	}
	if r.client != nil {
		result.AuthMethod = string(r.client.AuthMethodUsed())
	}
	if r.outcome != nil {
		result.Changed = r.outcome.Changed
		result.Created = r.outcome.Created
		result.BeforeSHA256 = r.outcome.BeforeSHA256
		result.AfterSHA256 = r.outcome.AfterSHA256
		result.Mode = r.outcome.Mode
		if r.outcome.BackupPath != "" {
			result.RollbackAvail = true
			result.Backup = &applyBackupJSON{
				Kind:        "file",
				Path:        r.outcome.BackupPath,
				RestoreHint: applyRestoreHint(r.config.RemotePath, r.outcome.BackupPath),
			}
		} else if r.config.ApplyNoBackup {
			result.Backup = &applyBackupJSON{Kind: "none"}
		}
	}
	if failErr != nil {
		result.Error = redactError(failErr)
	}
	return result
}

func (r *applyRun) recordAudit(exitCode int, kind string, failErr error) {
	if r.audit == nil {
		return
	}
	authMethod := sshclient.AuthMethodUnknown
	if r.client != nil {
		authMethod = r.client.AuthMethodUsed()
	}
	r.audit.recordApplyOutcome(r.config, authMethod, r.outcome, r.payload, r.phase, exitCode, kind, failErr)
}

func applyRestoreHint(remotePath, backupPath string) string {
	return fmt.Sprintf("copy %s over %s after verifying the backup contents", backupPath, remotePath)
}

func classifyApplyError(err error) string {
	kind := classifyError(err)
	if kind != "" && kind != "error" {
		return kind
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "precondition"):
		return execution.ErrorKindPrecondition
	case strings.Contains(msg, "blocked"):
		return "blocked"
	default:
		return kind
	}
}

func emitApplyJSON(result applyJSONResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		logger.GetLogger().Error("failed to encode JSON result: %v", err)
	}
}
