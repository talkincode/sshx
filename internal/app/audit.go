package app

import (
	"crypto/rand"
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

	WouldReadSecret      bool `json:"would_read_secret"`
	WouldWriteLocalState bool `json:"would_write_local_state"`
	WouldMutateRemote    bool `json:"would_mutate_remote"`
	MayMutateKnownHosts  bool `json:"may_mutate_known_hosts"`

	AuthMethod string         `json:"auth_method,omitempty"`
	ExitCode   *int           `json:"exit_code,omitempty"`
	DurationMs int64          `json:"duration_ms"`
	Outcome    auditStatus    `json:"outcome"`
	Redaction  auditRedaction `json:"redaction"`
}

type auditRecorder struct {
	started   time.Time
	event     auditEvent
	completed bool
}

var (
	sensitiveAssignmentRE = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)=([^\s&;]+)`)
	sensitiveFlagRE       = regexp.MustCompile(`(?i)(--(?:password|passwd|token|secret|api-key|access-key)(?:=|\s+))([^\s]+)`)
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
	r.event.SftpAction = config.SftpAction
	r.event.LocalPath = config.LocalPath
	r.event.RemotePath = config.RemotePath
	r.event.UseKeyAuth = config.UseKeyAuth
	r.event.KeyPath = config.KeyPath
	r.event.PasswordProvided = config.Password != ""
	r.event.PasswordValueProvided = config.PasswordValue != ""
	r.event.PasswordKey = config.PasswordKey
	r.event.UsesSudo = sshclient.CommandUsesSudo(config.Command)
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
	r.event.MayMutateKnownHosts = modeUsesSSHConnection(config) && config.AcceptUnknownHost
	if r.event.DurationMs == 0 {
		r.event.DurationMs = time.Since(r.started).Milliseconds()
	}
}

func writeAuditEvent(config *sshclient.Config, event auditEvent, now time.Time) error {
	dir, err := auditOutputDir(config)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create audit directory %s: %w", dir, err)
	}
	path := filepath.Join(dir, fmt.Sprintf("sshx-%s.jsonl", now.Format("2006-01-02")))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // audit path is user-configurable by design.
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
	default:
		return ""
	}
}

func auditWouldReadSecret(config *sshclient.Config) bool {
	switch config.Mode {
	case "ssh":
		return sshclient.CommandUsesSudo(config.Command) && config.SudoKey != ""
	case "password":
		return config.PasswordAction == "get" || config.PasswordAction == "check" || config.PasswordAction == "delete" || config.PasswordAction == "list"
	case "host":
		return config.HostAction == "test" || config.HostAction == "test-all"
	default:
		return false
	}
}

func auditWouldWriteLocalState(config *sshclient.Config) bool {
	switch config.Mode {
	case "password":
		return config.PasswordAction == "set" || config.PasswordAction == "delete"
	case "host":
		return config.HostAction == "add" || config.HostAction == "update" || config.HostAction == "remove"
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
	case "host":
		return config.HostAction == "test" || config.HostAction == "test-all"
	default:
		return false
	}
}

func redactSensitiveText(value string) string {
	if value == "" {
		return ""
	}
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

func intPtr(value int) *int {
	return &value
}
