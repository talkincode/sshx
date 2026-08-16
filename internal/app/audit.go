package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	pluginpkg "github.com/talkincode/sshx/internal/plugin"
	"github.com/talkincode/sshx/internal/sqlsafe"
	"github.com/talkincode/sshx/internal/sshclient"
)

const (
	auditSchemaVersion = "sshx.audit.v1"
	auditDirName       = "audit"
)

type auditStatus struct {
	Status    string `json:"status"`
	ErrorKind string `json:"error_kind,omitempty"`
	Message   string `json:"message,omitempty"`
}

type auditRedaction struct {
	SecretsRedacted bool `json:"secrets_redacted"`
	StdoutOmitted   bool `json:"stdout_omitted"`
	StderrOmitted   bool `json:"stderr_omitted"`
}

type auditEvent struct {
	SchemaVersion string `json:"schema_version"`
	EventID       string `json:"event_id"`
	Timestamp     string `json:"timestamp"`
	Version       string `json:"version,omitempty"`
	Actor         string `json:"actor,omitempty"`
	Entry         string `json:"entry,omitempty"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`

	Mode   string `json:"mode"`
	Action string `json:"action,omitempty"`

	HostInput      string `json:"host_input,omitempty"`
	HostResolved   string `json:"host_resolved,omitempty"`
	Port           string `json:"port,omitempty"`
	User           string `json:"user,omitempty"`
	HostName       string `json:"host_name,omitempty"`
	HostType       string `json:"host_type,omitempty"`
	HostDescSet    bool   `json:"host_description_set"`
	HostResolvedBy string `json:"host_resolved_by,omitempty"`

	Command    string `json:"command,omitempty"`
	SftpAction string `json:"sftp_action,omitempty"`
	LocalPath  string `json:"local_path,omitempty"`
	RemotePath string `json:"remote_path,omitempty"`

	TransferSource    string `json:"transfer_source,omitempty"`
	TransferDest      string `json:"transfer_destination,omitempty"`
	PluginID          string `json:"plugin_id,omitempty"`
	PluginDigest      string `json:"plugin_digest,omitempty"`
	PluginTrusted     bool   `json:"plugin_trusted,omitempty"`
	CacheMode         string `json:"cache_mode,omitempty"`
	CacheHit          bool   `json:"cache_hit,omitempty"`
	ObservationStatus string `json:"observation_status,omitempty"`

	UseKeyAuth            bool   `json:"use_key_auth"`
	KeyPath               string `json:"key_path,omitempty"`
	PasswordProvided      bool   `json:"password_provided"`
	PasswordValueProvided bool   `json:"password_value_provided"`
	PasswordKey           string `json:"password_key,omitempty"`
	UsesSudo              bool   `json:"uses_sudo"`
	SudoKey               string `json:"sudo_key,omitempty"`

	Timeout              string `json:"timeout,omitempty"`
	JSONOutput           bool   `json:"json_output"`
	UsePTY               bool   `json:"pty"`
	SafetyCheckEnabled   bool   `json:"safety_check_enabled"`
	Force                bool   `json:"force"`
	AcceptUnknownHost    bool   `json:"accept_unknown_host"`
	AllowInsecureHostKey bool   `json:"allow_insecure_host_key"`
	KnownHostsPath       string `json:"known_hosts_path,omitempty"`

	WouldReadSecret       bool `json:"would_read_secret"`
	WouldWriteLocalState  bool `json:"would_write_local_state"`
	WouldMutateRemote     bool `json:"would_mutate_remote"`
	WouldWriteRemoteState bool `json:"would_write_remote_state"`
	MayMutateKnownHosts   bool `json:"may_mutate_known_hosts"`

	AuthMethod string         `json:"auth_method,omitempty"`
	ExitCode   *int           `json:"exit_code,omitempty"`
	DurationMs int64          `json:"duration_ms"`
	Outcome    auditStatus    `json:"outcome"`
	Redaction  auditRedaction `json:"redaction"`

	// Run-contract correlation fields (additive).
	RunID          string `json:"run_id,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	SelectorDigest string `json:"selector_digest,omitempty"`
	PayloadSHA256  string `json:"payload_sha256,omitempty"`
	ActionIntent   string `json:"action_intent,omitempty"`
	BypassReason   string `json:"bypass_reason,omitempty"`
	Concurrency    int    `json:"concurrency,omitempty"`
	FailureMode    string `json:"failure_mode,omitempty"`
	TargetCount    int    `json:"target_count,omitempty"`
	TargetIndex    *int   `json:"target_index,omitempty"`
	Completion     string `json:"completion,omitempty"`
	Phase          string `json:"phase,omitempty"`

	// Guarded SQL execution fields (Mode == "sql", additive). Literal values
	// and comments are removed; the digest correlates the exact input without
	// persisting credentials or personal data embedded in SQL.
	SQLEngine        string `json:"sql_engine,omitempty"`
	SQLDatabase      string `json:"sql_database,omitempty"`
	SQLStatement     string `json:"sql_statement,omitempty"`
	SQLStatementHash string `json:"sql_statement_sha256,omitempty"`
	SQLClass         string `json:"sql_class,omitempty"`
	SQLVerb          string `json:"sql_verb,omitempty"`
	SQLTable         string `json:"sql_table,omitempty"`
	SQLHasWhere      bool   `json:"sql_has_where,omitempty"`
	SQLEstimatedRows *int64 `json:"sql_estimated_rows,omitempty"`
	SQLAffectedRows  *int64 `json:"sql_affected_rows,omitempty"`
	SQLBackupKind    string `json:"sql_backup_kind,omitempty"`
	SQLBackupPath    string `json:"sql_backup_path,omitempty"`
	SQLBackupRows    *int64 `json:"sql_backup_rows,omitempty"`
	SQLPhase         string `json:"sql_phase,omitempty"`
	SQLDocker        string `json:"sql_docker,omitempty"`
	SQLCredSource    string `json:"sql_cred_source,omitempty"`
	SQLCredCache     string `json:"sql_cred_cache,omitempty"`

	ApplyExpectSHA256 string `json:"apply_expect_sha256,omitempty"`
	ApplyPayloadHash  string `json:"apply_payload_sha256,omitempty"`
	ApplyBeforeHash   string `json:"apply_before_sha256,omitempty"`
	ApplyAfterHash    string `json:"apply_after_sha256,omitempty"`
	ApplyBackupPath   string `json:"apply_backup_path,omitempty"`
	ApplyChanged      bool   `json:"apply_changed,omitempty"`
	ApplyCreated      bool   `json:"apply_created,omitempty"`
}

type auditRecorder struct {
	started   time.Time
	event     auditEvent
	completed bool
}

var (
	sensitiveQuotedAssignmentRE = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)=("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`)
	sensitiveQuotedFlagRE       = regexp.MustCompile(`(?i)(--(?:password|passwd|token|secret|api-key|access-key)(?:=|\s+))("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`)
	sensitiveAssignmentRE       = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)=([^\s&;]+)`)
	sensitiveFlagRE             = regexp.MustCompile(`(?i)(--(?:password|passwd|token|secret|api-key|access-key)(?:=|\s+))([^\s]+)`)
)

func newAuditRecorder(config *sshclient.Config) *auditRecorder {
	if config == nil || !config.AuditEnabled || config.DryRun {
		return nil
	}

	started := time.Now()
	return &auditRecorder{
		started: started,
		event: auditEvent{
			SchemaVersion: auditSchemaVersion,
			EventID:       newAuditEventID(),
			Timestamp:     started.UTC().Format(time.RFC3339Nano),
			Version:       Version,
			Actor:         currentActor(),
			Entry:         currentEntry(),
			OS:            runtime.GOOS,
			Arch:          runtime.GOARCH,
			HostInput:     config.Host,
			Outcome:       auditStatus{Status: "started"},
			Redaction: auditRedaction{
				SecretsRedacted: true,
				StdoutOmitted:   true,
				StderrOmitted:   true,
			},
		},
	}
}

func (r *auditRecorder) recordCommandResult(config *sshclient.Config, authMethod sshclient.AuthMethod, res sshclient.ExecResult, dur time.Duration, errKind string, execErr error) {
	if r == nil {
		return
	}
	r.refresh(config)
	r.event.AuthMethod = string(authMethod)
	r.event.DurationMs = dur.Milliseconds()
	r.event.ExitCode = intPtr(res.ExitCode)
	if execErr != nil {
		r.event.Outcome = auditStatus{
			Status:    "failure",
			ErrorKind: errKind,
			Message:   redactSensitiveText(execErr.Error()),
		}
		r.completed = true
		return
	}
	if res.ExitCode != 0 {
		r.event.Outcome = auditStatus{
			Status:    "failure",
			ErrorKind: "remote_exit",
			Message:   fmt.Sprintf("command exited with status %d", res.ExitCode),
		}
		r.completed = true
		return
	}
	r.event.Outcome = auditStatus{Status: "success"}
	r.completed = true
}

func (r *auditRecorder) recordFailure(config *sshclient.Config, authMethod sshclient.AuthMethod, kind string, err error) {
	if r == nil {
		return
	}
	r.refresh(config)
	switch kind {
	case "blocked", "config":
		r.event.WouldReadSecret = false
		r.event.WouldMutateRemote = false
		r.event.MayMutateKnownHosts = false
	case "connect", "auth", "host_key":
		r.event.WouldMutateRemote = false
	}
	r.event.AuthMethod = string(authMethod)
	r.event.ExitCode = intPtr(-1)
	r.event.Outcome = auditStatus{
		Status:    "failure",
		ErrorKind: kind,
		Message:   redactError(err),
	}
	r.completed = true
}

// sqlAuditMeta captures the guarded-SQL pipeline facts for one invocation.
type sqlAuditMeta struct {
	Class         string
	Verb          string
	Table         string
	HasWhere      bool
	Phase         string
	Mutates       bool
	EstimatedRows *int64
	AffectedRows  *int64
	BackupKind    string
	BackupPath    string
	BackupRows    *int64
	CredSource    string
	CredCache     string
}

// recordSQLOutcome finalizes the audit event for one sql-mode invocation.
func (r *auditRecorder) recordSQLOutcome(config *sshclient.Config, authMethod sshclient.AuthMethod, meta sqlAuditMeta, exitCode int, errKind string, execErr error) {
	if r == nil {
		return
	}
	r.refresh(config)
	r.event.AuthMethod = string(authMethod)
	r.event.SQLClass = meta.Class
	r.event.SQLVerb = meta.Verb
	r.event.SQLTable = meta.Table
	r.event.SQLHasWhere = meta.HasWhere
	r.event.SQLPhase = meta.Phase
	r.event.SQLEstimatedRows = meta.EstimatedRows
	r.event.SQLAffectedRows = meta.AffectedRows
	r.event.SQLBackupKind = meta.BackupKind
	r.event.SQLBackupPath = meta.BackupPath
	r.event.SQLBackupRows = meta.BackupRows
	r.event.SQLDocker = config.SQLDockerContainer
	r.event.SQLCredSource = meta.CredSource
	r.event.SQLCredCache = meta.CredCache
	r.event.WouldMutateRemote = meta.Mutates
	r.event.DurationMs = time.Since(r.started).Milliseconds()
	r.event.ExitCode = intPtr(exitCode)
	if execErr != nil {
		r.event.Outcome = auditStatus{
			Status:    "failure",
			ErrorKind: errKind,
			Message:   redactError(execErr),
		}
	} else {
		r.event.Outcome = auditStatus{Status: "success"}
	}
	r.completed = true
}

func (r *auditRecorder) recordApplyOutcome(config *sshclient.Config, authMethod sshclient.AuthMethod, outcome *sshclient.ApplyOutcome, payload []byte, phase string, exitCode int, kind string, failErr error) {
	if r == nil {
		return
	}
	r.refresh(config)
	r.event.AuthMethod = string(authMethod)
	r.event.Phase = phase
	r.event.ActionIntent = "change"
	if len(payload) > 0 {
		r.event.ApplyPayloadHash = sshclient.SHA256Hex(payload)
		r.event.PayloadSHA256 = r.event.ApplyPayloadHash
	}
	r.event.ApplyExpectSHA256 = config.ApplyExpectSHA256
	if outcome != nil {
		r.event.ApplyBeforeHash = outcome.BeforeSHA256
		r.event.ApplyAfterHash = outcome.AfterSHA256
		r.event.ApplyBackupPath = outcome.BackupPath
		r.event.ApplyChanged = outcome.Changed
		r.event.ApplyCreated = outcome.Created
	}
	r.event.WouldMutateRemote = failErr == nil && outcome != nil && outcome.Changed
	r.event.DurationMs = time.Since(r.started).Milliseconds()
	r.event.ExitCode = intPtr(exitCode)
	if failErr != nil {
		r.event.Outcome = auditStatus{
			Status:    "failure",
			ErrorKind: kind,
			Message:   redactError(failErr),
		}
	} else {
		r.event.Outcome = auditStatus{Status: "success"}
	}
	r.completed = true
}

func (r *auditRecorder) finish(config *sshclient.Config, err error) error {
	if r == nil {
		return nil
	}
	if !r.completed {
		r.refresh(config)
		r.event.DurationMs = time.Since(r.started).Milliseconds()
		var exitErr *ExitError
		switch {
		case err == nil:
			r.event.Outcome = auditStatus{Status: "success"}
		case errors.As(err, &exitErr):
			r.event.ExitCode = intPtr(exitErr.Code)
			r.event.Outcome = auditStatus{
				Status:    "failure",
				ErrorKind: "remote_exit",
				Message:   exitErr.Error(),
			}
		case config.ReportedErrorKind != "":
			r.event.ExitCode = intPtr(-1)
			r.event.Outcome = auditStatus{
				Status:    "failure",
				ErrorKind: config.ReportedErrorKind,
				Message:   redactSensitiveText(config.ReportedError),
			}
		default:
			r.event.Outcome = auditStatus{
				Status:    "failure",
				ErrorKind: classifyError(err),
				Message:   redactError(err),
			}
		}
		r.completed = true
	}
	return writeAuditEvent(config, r.event, r.started)
}

func (r *auditRecorder) refresh(config *sshclient.Config) {
	if r == nil || config == nil {
		return
	}
	r.event.Mode = config.Mode
	r.event.Action = auditAction(config)
	r.event.HostResolved = config.Host
	r.event.Port = config.Port
	r.event.User = config.User
	r.event.HostName = config.HostName
	r.event.HostType = config.HostType
	r.event.HostDescSet = config.HostDescription != ""
	if r.event.HostInput != "" && r.event.HostResolved != "" && r.event.HostResolved != r.event.HostInput {
		r.event.HostResolvedBy = "settings"
	}
	r.event.Command = redactSensitiveText(config.Command)
	if config.Mode == "sql" {
		r.event.SQLEngine = config.SQLEngine
		r.event.SQLDatabase = config.SQLDatabase
		r.event.SQLStatement = sqlsafe.RedactForAudit(config.SQLStatement)
		r.event.SQLStatementHash = sqlStatementDigest(config.SQLStatement)
	}
	if config.Mode == "plugin" {
		r.event.PluginID = config.PluginID
	}

	if config.Mode == "inspect" {
		r.event.PluginID = config.InspectCapability
		r.event.CacheMode = config.InspectCacheMode
		if resolved, resolveErr := pluginpkg.Resolve(config.InspectCapability); resolveErr == nil {
			r.event.PluginDigest = resolved.Digest
			r.event.PluginTrusted = resolved.Trusted
		}
	}
	r.event.SftpAction = config.SftpAction
	r.event.LocalPath = config.LocalPath
	r.event.RemotePath = config.RemotePath
	if config.Mode == "transfer" {
		r.event.TransferSource = formatTransferEndpoint(config.TransferSrcHost, config.TransferSrcPath)
		r.event.TransferDest = formatTransferEndpoint(config.TransferDstHost, config.TransferDstPath)
	}
	r.event.UseKeyAuth = config.UseKeyAuth
	r.event.KeyPath = config.KeyPath
	r.event.PasswordProvided = config.Password != ""
	r.event.PasswordValueProvided = config.PasswordValue != ""
	r.event.PasswordKey = config.PasswordKey
	r.event.UsesSudo = sshclient.CommandUsesSudo(config.Command)
	if config.Mode == "apply" {
		r.event.UsesSudo = config.ApplyUseSudo
	}
	if config.Mode == "inspect" {
		if resolved, resolveErr := pluginpkg.Resolve(config.InspectCapability); resolveErr == nil {
			if useSudo, _, privilegeErr := inspectionPrivilege(config, resolved.Manifest); privilegeErr == nil {
				r.event.UsesSudo = useSudo
			}
		} else {
			r.event.UsesSudo = config.InspectUseSudo
		}
	}
	r.event.SudoKey = config.SudoKey
	if config.Timeout > 0 {
		r.event.Timeout = config.Timeout.String()
	}
	r.event.JSONOutput = config.JSONOutput
	r.event.UsePTY = config.UsePTY
	r.event.SafetyCheckEnabled = config.SafetyCheck
	r.event.Force = config.Force
	r.event.AcceptUnknownHost = config.AcceptUnknownHost
	r.event.AllowInsecureHostKey = config.AllowInsecureHostKey
	r.event.KnownHostsPath = config.KnownHostsPath
	r.event.WouldReadSecret = auditWouldReadSecret(config)
	r.event.WouldWriteLocalState = auditWouldWriteLocalState(config)
	r.event.WouldMutateRemote = auditWouldMutateRemote(config)
	r.event.WouldWriteRemoteState = config.Mode == "inspect" && config.InspectCacheMode == "remote-prefer"
	r.event.MayMutateKnownHosts = modeUsesSSHConnection(config) && config.AcceptUnknownHost
	if r.event.DurationMs == 0 {
		r.event.DurationMs = time.Since(r.started).Milliseconds()
	}
}

func sqlStatementDigest(statement string) string {
	sum := sha256.Sum256([]byte(statement))
	return fmt.Sprintf("%x", sum)
}

func writeAuditEvent(config *sshclient.Config, event auditEvent, now time.Time) error {
	dir, err := auditOutputDir(config)
	if err != nil {
		return err
	}
	if mkdirErr := os.MkdirAll(dir, 0o700); mkdirErr != nil {
		return fmt.Errorf("failed to create audit directory %s: %w", dir, mkdirErr)
	}
	path := filepath.Join(dir, fmt.Sprintf("sshx-%s.jsonl", now.Format("2006-01-02")))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- audit path is user-configurable by design.
	if err != nil {
		return fmt.Errorf("failed to open audit log %s: %w", path, err)
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // best effort after append

	enc := json.NewEncoder(file)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(event); err != nil {
		return fmt.Errorf("failed to write audit event: %w", err)
	}
	return nil
}

func auditOutputDir(config *sshclient.Config) (string, error) {
	if config != nil && config.AuditOutput != "" {
		return expandHome(config.AuditOutput)
	}
	settingsDir, err := GetSettingsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(settingsDir, auditDirName), nil
}

func expandHome(path string) (string, error) {
	if path == "" || path[0] != '~' {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	if path == "~" {
		return home, nil
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func auditAction(config *sshclient.Config) string {
	switch config.Mode {
	case "ssh":
		return "command"
	case "sftp":
		return config.SftpAction
	case "password":
		return config.PasswordAction
	case "host":
		return config.HostAction
	case "transfer":
		return "transfer"
	case "plugin":
		return config.PluginAction
	case "skill":
		return config.SkillAction
	case "inspect":
		return "inspect"
	case "sql":
		return "sql"
	case "apply":
		return "apply"
	default:
		return ""
	}
}

func formatTransferEndpoint(host, path string) string {
	if host == "" && path == "" {
		return ""
	}
	return host + ":" + path
}

func auditWouldReadSecret(config *sshclient.Config) bool {
	switch config.Mode {
	case "ssh":
		return sshclient.CommandUsesSudo(config.Command) && config.SudoKey != ""
	case "password":
		return config.PasswordAction == "get" || config.PasswordAction == "check" || config.PasswordAction == "delete" || config.PasswordAction == "list"
	case "host":
		return config.HostAction == "test" || config.HostAction == "test-all"
	case "inspect":
		if resolved, err := pluginpkg.Resolve(config.InspectCapability); err == nil {
			useSudo, _, privilegeErr := inspectionPrivilege(config, resolved.Manifest)
			return privilegeErr == nil && useSudo && config.SudoKey != ""
		}
		return config.InspectUseSudo && config.SudoKey != ""
	case "sql":
		return config.SQLPasswordKey != "" || config.SQLCredFrom != ""
	case "apply":
		return config.ApplyUseSudo && config.SudoKey != ""
	default:
		return false
	}
}

func auditWouldWriteLocalState(config *sshclient.Config) bool {
	switch config.Mode {
	case "password":
		return config.PasswordAction == "set" || config.PasswordAction == "delete"
	case "host":
		return config.HostAction == "add" || config.HostAction == "update" || config.HostAction == "remove" || config.HostAction == "import"
	case "plugin":
		return config.PluginAction == "create" || config.PluginAction == "trust" || config.PluginAction == "remove"
	case "skill":
		return config.SkillAction == "install"
	default:
		return false
	}
}

func auditWouldMutateRemote(config *sshclient.Config) bool {
	switch config.Mode {
	case "ssh":
		return config.Command != ""
	case "sftp":
		return config.SftpAction == "upload" || config.SftpAction == "mkdir" || config.SftpAction == "remove"
	case "transfer":
		return true
	case "host":
		return config.HostAction == "test" || config.HostAction == "test-all"
	case "inspect":
		return config.InspectCacheMode == "remote-prefer"
	case "sql":
		// Conservative: refined by the sql handler once the statement class
		// is known (reads do not mutate).
		return true
	case "apply":
		return true
	default:
		return false
	}
}

func redactSensitiveText(value string) string {
	if value == "" {
		return ""
	}
	value = sensitiveQuotedAssignmentRE.ReplaceAllString(value, "$1=<redacted>")
	value = sensitiveQuotedFlagRE.ReplaceAllString(value, "$1<redacted>")
	value = sensitiveAssignmentRE.ReplaceAllString(value, "$1=<redacted>")
	value = sensitiveFlagRE.ReplaceAllString(value, "$1<redacted>")
	return value
}

func redactError(err error) string {
	if err == nil {
		return ""
	}
	return redactSensitiveText(err.Error())
}

func newAuditEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func currentActor() string {
	for _, key := range []string{"USER", "USERNAME", "LOGNAME"} {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

// currentEntry reports the invocation entry point declared by a wrapping sshx
// process (currently "mcp" for the stdio MCP server). It is audit metadata
// only: the value never participates in trust, safety, or credential
// decisions, and anything but a short lowercase token is ignored.
func currentEntry() string {
	value := os.Getenv("SSHX_ENTRY")
	if value == "" || len(value) > 32 {
		return ""
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return ""
		}
	}
	return value
}

func intPtr(value int) *int {
	return &value
}
