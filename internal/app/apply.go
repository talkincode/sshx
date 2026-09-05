package app

import (
	"errors"
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
	Verified    bool   `json:"verified"`
}

type applyJSONResult struct {
	SchemaVersion  string                `json:"schema_version"`
	Host           string                `json:"host"`
	Port           string                `json:"port"`
	User           string                `json:"user"`
	Action         string                `json:"action"`
	Intent         string                `json:"intent"`
	RemotePath     string                `json:"remote_path"`
	LocalPath      string                `json:"local_path,omitempty"`
	PayloadSHA256  string                `json:"payload_sha256,omitempty"`
	PayloadBytes   int                   `json:"payload_bytes"`
	ExpectSHA256   string                `json:"expect_sha256,omitempty"`
	BeforeSHA256   string                `json:"before_sha256,omitempty"`
	AfterSHA256    string                `json:"after_sha256,omitempty"`
	Changed        bool                  `json:"changed"`
	Created        bool                  `json:"created"`
	ChangeState    string                `json:"change_state"`
	Executed       *bool                 `json:"executed"`
	Verified       bool                  `json:"verified"`
	Verification   string                `json:"verification"`
	Preconditions  []execution.Condition `json:"preconditions,omitempty"`
	Postconditions []execution.Condition `json:"postconditions,omitempty"`
	UID            *uint32               `json:"uid,omitempty"`
	GID            *uint32               `json:"gid,omitempty"`
	CleanupPending []string              `json:"cleanup_pending,omitempty"`
	ReplaceMethod  string                `json:"replace_method,omitempty"`
	RollbackAvail  bool                  `json:"rollback_available"`
	Mode           string                `json:"mode,omitempty"`
	UseSudo        bool                  `json:"use_sudo,omitempty"`
	Backup         *applyBackupJSON      `json:"backup,omitempty"`
	Status         string                `json:"status"`
	Phase          string                `json:"phase"`
	Completion     string                `json:"completion"`
	ExitCode       int                   `json:"exit_code"`
	Success        bool                  `json:"success"`
	DurationMs     int64                 `json:"duration_ms"`
	AuthMethod     string                `json:"auth_method,omitempty"`
	ErrorKind      string                `json:"error_kind,omitempty"`
	Error          string                `json:"error,omitempty"`
	ErrorRetryable bool                  `json:"retryable,omitempty"`
	RetrySafety    string                `json:"retry_safety,omitempty"`
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

	payload := config.PreparedPayload
	if payload == nil {
		var readErr error
		payload, readErr = os.ReadFile(config.LocalPath)
		if readErr != nil {
			return run.fail("local_io", fmt.Errorf("read --from=%s: %w", config.LocalPath, readErr))
		}
		if payload == nil {
			payload = []byte{}
		}
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
	run.client = client
	connErr := client.ConnectDirect()
	recordConnectedPeer(config, client, "target")
	if connErr != nil {
		return run.fail(classifyError(connErr), fmt.Errorf("failed to connect: %w", connErr))
	}
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
	result := r.baseResult(true, 0, "", nil)
	if r.config.JSONOutput {
		emitApplyJSON(r.config, result)
		return nil
	}
	if _, finalizeErr := finalizeLifecycle(r.config, result); finalizeErr != nil {
		logger.GetLogger().Error("failed to finalize apply evidence: %v", finalizeErr)
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
		if r.outcome != nil {
			switch {
			case r.outcome.Executed == nil:
				completion = execution.CompletionUnknown
			case *r.outcome.Executed:
				completion = execution.CompletionCompleted
			default:
				completion = execution.CompletionNotStarted
			}
		}
	}
	r.recordAudit(-1, kind, failErr)
	result := r.baseResult(false, -1, kind, failErr)
	result.Completion = completion
	if info := execution.BuildError(failErr, kind, execution.IntentChange, completion); info != nil {
		result.ErrorRetryable = info.Retryable
		result.RetrySafety = info.RetrySafety
	}
	if r.config.JSONOutput {
		emitApplyJSON(r.config, result)
		return ErrReported
	}
	if _, finalizeErr := finalizeLifecycle(r.config, result); finalizeErr != nil {
		logger.GetLogger().Error("failed to finalize apply evidence: %v", finalizeErr)
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
		ChangeState:   "unchanged",
		Verification:  "not_performed",
	}
	no := false
	result.Executed = &no
	if success {
		result.Status = execution.StatusSucceeded
		result.Completion = execution.CompletionCompleted
	}
	if r.payload != nil {
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
		result.ChangeState = r.outcome.ChangeState
		result.Executed = r.outcome.Executed
		result.Verified = r.outcome.Verified
		result.Verification = r.outcome.Verification
		result.UID, result.GID = r.outcome.UID, r.outcome.GID
		result.CleanupPending = r.outcome.CleanupPending
		result.ReplaceMethod = r.outcome.ReplaceMethod
		if r.outcome.PayloadSHA256 != "" {
			result.PayloadSHA256 = r.outcome.PayloadSHA256
		}
		if r.outcome.BackupPath != "" {
			result.RollbackAvail = r.outcome.BackupVerified
			result.Backup = &applyBackupJSON{
				Kind:        "file",
				Path:        r.outcome.BackupPath,
				RestoreHint: applyRestoreHint(r.config.RemotePath, r.outcome.BackupPath),
				Verified:    r.outcome.BackupVerified,
			}
		} else if r.config.ApplyNoBackup {
			result.Backup = &applyBackupJSON{Kind: "none"}
		}
	}
	if failErr != nil {
		result.Error = redactError(failErr)
	}
	if result.ExpectSHA256 != "" {
		condition := execution.Condition{
			Kind: "sha256", Subject: result.RemotePath, Expected: result.ExpectSHA256, Status: "not_performed",
		}
		if r.config.Force {
			condition.Status = "bypassed"
		}
		if r.outcome != nil {
			condition.Observed = r.outcome.PreconditionSHA256
			if r.outcome.PreconditionStatus != "" {
				condition.Status = r.outcome.PreconditionStatus
			}
		}
		result.Preconditions = []execution.Condition{condition}
	}
	if result.PayloadSHA256 != "" {
		result.Preconditions = append(result.Preconditions, execution.Condition{
			Kind: "payload_sha256", Subject: result.RemotePath, Observed: result.PayloadSHA256, Status: "passed",
		})
		result.Postconditions = []execution.Condition{{
			Kind: "sha256", Subject: result.RemotePath, Expected: result.PayloadSHA256,
			Observed: result.AfterSHA256, Status: result.Verification,
		}}
	}
	if r.outcome != nil {
		if result.BeforeSHA256 != "" {
			result.Preconditions = append(result.Preconditions, execution.Condition{
				Kind: "before_sha256", Subject: result.RemotePath, Observed: result.BeforeSHA256, Status: "passed",
			})
		} else if result.Created {
			result.Preconditions = append(result.Preconditions, execution.Condition{
				Kind: "before_presence", Subject: result.RemotePath, Observed: "absent", Status: "passed",
			})
		}
		if result.Mode != "" {
			if result.BeforeSHA256 != "" || result.UID != nil {
				result.Preconditions = append(result.Preconditions, execution.Condition{
					Kind: "before_mode", Subject: result.RemotePath, Observed: result.Mode, Status: "passed",
				})
			} else {
				// For a new target Mode is the requested install mode, not a
				// readback observation. Content verification does not verify it.
				result.Postconditions = append(result.Postconditions, execution.Condition{
					Kind: "install_mode", Subject: result.RemotePath, Expected: result.Mode, Status: "not_performed",
				})
			}
		}
		if result.UID != nil {
			result.Preconditions = append(result.Preconditions, execution.Condition{
				Kind: "before_uid", Subject: result.RemotePath, Observed: fmt.Sprint(*result.UID), Status: "passed",
			})
		}
		if result.GID != nil {
			result.Preconditions = append(result.Preconditions, execution.Condition{
				Kind: "before_gid", Subject: result.RemotePath, Observed: fmt.Sprint(*result.GID), Status: "passed",
			})
		}
		if result.Backup != nil && result.Backup.Path != "" {
			presence, status := "unknown", "unknown"
			if result.Backup.Verified {
				presence, status = "present", "passed"
			}
			result.Postconditions = append(result.Postconditions, execution.Condition{
				Kind: "backup_candidate", Subject: result.Backup.Path, Observed: presence, Status: status,
			})
			if result.Backup.Verified && result.BeforeSHA256 != "" {
				result.Postconditions = append(result.Postconditions, execution.Condition{
					Kind: "backup_sha256", Subject: result.Backup.Path,
					Expected: result.BeforeSHA256, Observed: result.BeforeSHA256, Status: "passed",
				})
			}
		}
		if result.ReplaceMethod != "" {
			status := "unknown"
			if result.Executed != nil && *result.Executed {
				status = "passed"
			}
			result.Postconditions = append(result.Postconditions, execution.Condition{
				Kind: "replace_method", Subject: result.RemotePath, Observed: result.ReplaceMethod, Status: status,
			})
		}
		for _, artifact := range result.CleanupPending {
			result.Postconditions = append(result.Postconditions, execution.Condition{
				Kind: "cleanup", Subject: artifact, Expected: "absent", Observed: "unknown", Status: "unknown",
			})
		}
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
	if errors.Is(err, sshclient.ErrApplyVerification) {
		return "verification_failed"
	}
	if errors.Is(err, sshclient.ErrPrecondition) {
		return execution.ErrorKindPrecondition
	}
	if errors.Is(err, sshclient.ErrApplyBlocked) {
		return "blocked"
	}
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

func emitApplyJSON(config *sshclient.Config, result applyJSONResult) {
	if err := emitLifecycleJSON(config, result); err != nil {
		logger.GetLogger().Error("failed to encode JSON result: %v", err)
	}
}
