// Package execution defines the versioned agent execution contract used by
// sshx run and shared by compatibility adapters for single-host paths.
package execution

import (
	"time"
)

const (
	RequestSchemaVersion = "sshx.request.v1"
	ResultSchemaVersion  = "sshx.result.v1"
	EventSchemaVersion   = "sshx.event.v1"

	DefaultConcurrency = 4
	MaxConcurrency     = 32
	DefaultMaxOutput   = 10 << 20 // 10 MiB
	DefaultMaxPayload  = 10 << 20 // 10 MiB

	ActionCommand  = "command"
	ActionScript   = "script"
	ActionInspect  = "inspect"
	ActionSFTP     = "sftp"
	ActionTransfer = "transfer"
	ActionApply    = "apply"

	IntentRead    = "read"
	IntentChange  = "change"
	IntentUnknown = "unknown"

	FailureContinue = "continue"
	FailureFailFast = "fail_fast"

	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusSkipped   = "skipped"

	CompletionNotStarted           = "not_started"
	CompletionPartial              = "partial"
	CompletionCompleted            = "completed"
	CompletionCompletedUnconfirmed = "completed_unconfirmed"
	CompletionUnknown              = "unknown"

	PhaseResolve      = "resolve"
	PhaseAdmission    = "admission"
	PhaseConnect      = "connect"
	PhaseAuthenticate = "authenticate"
	PhaseExecute      = "execute"
	PhaseCollect      = "collect"
	PhasePersist      = "persist"
	PhaseComplete     = "complete"

	EventRunStarted     = "run_started"
	EventTargetStarted  = "target_started"
	EventTargetFinished = "target_finished"
	EventRunFinished    = "run_finished"

	RetrySafe        = "safe"
	RetryUnsafe      = "unsafe"
	RetryVerifyFirst = "verify_first"
	RetryUnknown     = "unknown"

	ErrorKindConnect      = "connect"
	ErrorKindAuth         = "auth"
	ErrorKindHostKey      = "host_key"
	ErrorKindBlocked      = "blocked"
	ErrorKindTimeout      = "timeout"
	ErrorKindCancelled    = "cancelled" //nolint:misspell // Preserve the machine-readable cancellation category.
	ErrorKindRemoteExit   = "remote_exit"
	ErrorKindExitMissing  = "exit_missing"
	ErrorKindProtocol     = "protocol"
	ErrorKindConfig       = "config"
	ErrorKindLocalIO      = "local_io"
	ErrorKindRemoteIO     = "remote_io"
	ErrorKindPrecondition = "precondition"
	ErrorKindUnknown      = "unknown"

	ScriptRunnerSH = "sh"
)

// TargetSelector describes how hosts are chosen for one execution request.
type TargetSelector struct {
	Names    []string          `json:"names,omitempty"`
	Groups   []string          `json:"groups,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
	AllHosts bool              `json:"all_hosts,omitempty"`
	// Address is an explicit single-target literal address path. It may not
	// combine with multi-host selectors.
	Address string `json:"address,omitempty"`
	Port    string `json:"port,omitempty"`
	User    string `json:"user,omitempty"`
}

// ActionSpec describes the single action admitted by one request.
type ActionSpec struct {
	Kind            string `json:"kind"`
	Intent          string `json:"intent"`
	Command         string `json:"command,omitempty"`
	ScriptPath      string `json:"script_path,omitempty"`
	ScriptFromStdin bool   `json:"script_from_stdin,omitempty"`
	ScriptRunner    string `json:"script_runner,omitempty"`
	UseSudo         bool   `json:"use_sudo,omitempty"`
	PayloadSHA256   string `json:"payload_sha256,omitempty"`
	PayloadBytes    int    `json:"payload_bytes,omitempty"`
	SftpAction      string `json:"sftp_action,omitempty"`
	LocalPath       string `json:"local_path,omitempty"`
	RemotePath      string `json:"remote_path,omitempty"`
}

// Limits bounds one process run.
type Limits struct {
	Concurrency             int           `json:"concurrency"`
	Timeout                 time.Duration `json:"timeout,omitempty"`
	HostTimeout             time.Duration `json:"host_timeout,omitempty"`
	GlobalTimeout           time.Duration `json:"global_timeout,omitempty"`
	MaxOutputBytesPerTarget int           `json:"max_output_bytes_per_target"`
	MaxPayloadBytes         int           `json:"max_payload_bytes,omitempty"`
}

// Policy captures high-risk decisions that must be explicit per request.
type Policy struct {
	FailureMode          string `json:"failure_mode"`
	MaxFailures          int    `json:"max_failures,omitempty"`
	SafetyCheckEnabled   bool   `json:"safety_check_enabled"`
	SafetyBypass         bool   `json:"safety_bypass"`
	BypassReason         string `json:"bypass_reason,omitempty"`
	AcceptUnknownHost    bool   `json:"accept_unknown_host"`
	AllowInsecureHostKey bool   `json:"allow_insecure_host_key"`
	KnownHostsPath       string `json:"known_hosts_path,omitempty"`
	UseKeyAuth           bool   `json:"use_key_auth"`
	KeyPath              string `json:"key_path,omitempty"`
	// SSHPasswordKey is a typed keyring reference for SSH login only.
	SSHPasswordKey string `json:"ssh_password_key,omitempty"`
	// SudoPasswordKey is a typed keyring reference for sudo auto-fill only.
	SudoPasswordKey string `json:"sudo_password_key,omitempty"`
	// SSHPassword is an already-resolved login password (for example SSH_PASSWORD).
	// It is never serialized into dry-run or audit payloads.
	SSHPassword string `json:"-"`
	// Bind is a local source address (literal IP or interface name).
	Bind string `json:"bind,omitempty"`
	// BindSet is true when the request explicitly set bind, including empty.
	BindSet bool `json:"-"`
}

// Request is the versioned internal execution unit.
type Request struct {
	Plan          *Plan          `json:"-"`
	ExecutionID   string         `json:"-"`
	SchemaVersion string         `json:"schema_version"`
	RequestID     string         `json:"request_id,omitempty"`
	Targets       TargetSelector `json:"targets"`
	Action        ActionSpec     `json:"action"`
	Limits        Limits         `json:"limits"`
	Policy        Policy         `json:"policy"`
	JSONOutput    bool           `json:"json_output,omitempty"`
	JSONLOutput   bool           `json:"jsonl_output,omitempty"`
	DryRun        bool           `json:"dry_run,omitempty"`
	AuditEnabled  bool           `json:"audit_enabled,omitempty"`
	AuditOutput   string         `json:"audit_output,omitempty"`
}

// ResolvedTarget is one frozen host from selector resolution.
type ResolvedTarget struct {
	Index                  int               `json:"index"`
	Alias                  string            `json:"alias,omitempty"`
	Address                string            `json:"address"`
	Port                   string            `json:"port"`
	User                   string            `json:"user"`
	KeyPath                string            `json:"key_path,omitempty"`
	SSHPasswordKey         string            `json:"ssh_password_key,omitempty"`
	SudoPasswordKey        string            `json:"sudo_password_key,omitempty"`
	Groups                 []string          `json:"groups,omitempty"`
	Tags                   map[string]string `json:"tags,omitempty"`
	HostKeyFingerprint     string            `json:"host_key_fingerprint,omitempty"`
	KnownHostsData         []byte            `json:"-"`
	ExpectedKeyFingerprint string            `json:"-"`
	Literal                bool              `json:"literal,omitempty"`
	Bind                   string            `json:"bind,omitempty"`
}

// SkippedTarget records a selector candidate that was not admitted.
type SkippedTarget struct {
	Alias  string `json:"alias,omitempty"`
	Reason string `json:"reason"`
}

// TargetSnapshot is the frozen, deterministic target set for one run.
type TargetSnapshot struct {
	Targets        []ResolvedTarget `json:"targets"`
	Skipped        []SkippedTarget  `json:"skipped,omitempty"`
	Count          int              `json:"count"`
	SelectorDigest string           `json:"selector_digest"`
}

// ErrorInfo is the structured failure surface for one target or run.
type ErrorInfo struct {
	Kind        string `json:"kind"`
	Message     string `json:"message"`
	Retryable   bool   `json:"retryable"`
	RetrySafety string `json:"retry_safety"`
}

// TargetResult is the finished-target document embedded in events and single-target results.
type TargetResult struct {
	Metadata
	Target          ResolvedTarget `json:"target"`
	Action          ActionSpec     `json:"action"`
	Status          string         `json:"status"`
	Phase           string         `json:"phase"`
	Completion      string         `json:"completion"`
	ExitCode        int            `json:"exit_code"`
	Error           *ErrorInfo     `json:"error,omitempty"`
	Stdout          string         `json:"stdout,omitempty"`
	Stderr          string         `json:"stderr,omitempty"`
	StdoutTruncated bool           `json:"stdout_truncated,omitempty"`
	StderrTruncated bool           `json:"stderr_truncated,omitempty"`
	DurationMs      int64          `json:"duration_ms"`
	AuthMethod      string         `json:"auth_method,omitempty"`
	PeerAddress     string         `json:"peer_address,omitempty"`
}

// RunCounts summarizes a finished multi-target run.
type RunCounts struct {
	Selected  int `json:"selected"`
	Started   int `json:"started"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`
	Uncertain int `json:"uncertain"`
}

// Event is one JSONL stream record for multi-target runs.
type Event struct {
	Metadata
	SchemaVersion  string          `json:"schema_version"`
	RunID          string          `json:"run_id"`
	RequestID      string          `json:"request_id,omitempty"`
	Sequence       int64           `json:"sequence"`
	Kind           string          `json:"kind"`
	Timestamp      string          `json:"timestamp"`
	Target         *ResolvedTarget `json:"target,omitempty"`
	Result         *TargetResult   `json:"result,omitempty"`
	Counts         *RunCounts      `json:"counts,omitempty"`
	SelectorDigest string          `json:"selector_digest,omitempty"`
	Concurrency    int             `json:"concurrency,omitempty"`
	FailureMode    string          `json:"failure_mode,omitempty"`
	MaxFailures    int             `json:"max_failures,omitempty"`
	Action         *ActionSpec     `json:"action,omitempty"`
	Error          *ErrorInfo      `json:"error,omitempty"`
}

// Result is the single-target versioned document (and compatibility envelope).
type Result struct {
	Metadata
	SchemaVersion string         `json:"schema_version"`
	RunID         string         `json:"run_id"`
	RequestID     string         `json:"request_id,omitempty"`
	Target        ResolvedTarget `json:"target"`
	Action        ActionSpec     `json:"action"`
	Status        string         `json:"status"`
	Phase         string         `json:"phase"`
	Completion    string         `json:"completion"`
	ExitCode      int            `json:"exit_code"`
	Success       bool           `json:"success"`
	Error         *ErrorInfo     `json:"error,omitempty"`
	// Compatibility fields retained for current major version agents.
	Host            string `json:"host"`
	Port            string `json:"port"`
	User            string `json:"user"`
	Command         string `json:"command,omitempty"`
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	DurationMs      int64  `json:"duration_ms"`
	AuthMethod      string `json:"auth_method,omitempty"`
	PeerAddress     string `json:"peer_address,omitempty"`
	// ErrorKind is a compatibility projection of Error.Kind for agents that
	// still branch on the flat field from single-command JSON.
	ErrorKind string `json:"error_kind,omitempty"`
}

// DryRunPlan is the validated local plan for sshx run --dry-run.
type DryRunPlan struct {
	Plan                *Plan          `json:"plan,omitempty"`
	PlanHash            string         `json:"plan_hash,omitempty"`
	Risk                Risk           `json:"risk,omitempty"`
	Effects             Effects        `json:"effects"`
	SchemaVersion       string         `json:"schema_version"`
	DryRun              bool           `json:"dry_run"`
	Valid               bool           `json:"valid"`
	RequestID           string         `json:"request_id,omitempty"`
	Action              ActionSpec     `json:"action"`
	Limits              Limits         `json:"limits"`
	Policy              PolicyPublic   `json:"policy"`
	Snapshot            TargetSnapshot `json:"snapshot"`
	WouldConnect        bool           `json:"would_connect"`
	WouldExecute        bool           `json:"would_execute"`
	WouldReadSecret     bool           `json:"would_read_secret"`
	WouldWriteLocal     bool           `json:"would_write_local_state"`
	WouldMutateRemote   bool           `json:"would_mutate_remote"`
	MayMutateKnownHosts bool           `json:"may_mutate_known_hosts"`
	SecretBackend       string         `json:"secret_backend,omitempty"`
	SecretUnlock        string         `json:"secret_unlock,omitempty"`
	Notes               []string       `json:"notes,omitempty"`
	Error               *ErrorInfo     `json:"error,omitempty"`
}

// PolicyPublic is the audit/dry-run view of Policy without secret values.
type PolicyPublic struct {
	FailureMode          string `json:"failure_mode"`
	MaxFailures          int    `json:"max_failures,omitempty"`
	SafetyCheckEnabled   bool   `json:"safety_check_enabled"`
	SafetyBypass         bool   `json:"safety_bypass"`
	BypassReason         string `json:"bypass_reason,omitempty"`
	AcceptUnknownHost    bool   `json:"accept_unknown_host"`
	AllowInsecureHostKey bool   `json:"allow_insecure_host_key"`
	KnownHostsPath       string `json:"known_hosts_path,omitempty"`
	UseKeyAuth           bool   `json:"use_key_auth"`
	KeyPath              string `json:"key_path,omitempty"`
	SSHPasswordKey       string `json:"ssh_password_key,omitempty"`
	SudoPasswordKey      string `json:"sudo_password_key,omitempty"`
	SSHPasswordProvided  bool   `json:"ssh_password_provided"`
	Bind                 string `json:"bind,omitempty"`
	BindSet              bool   `json:"bind_set,omitempty"`
}

// PublicPolicy projects Policy without secret material.
func PublicPolicy(p Policy) PolicyPublic {
	return PolicyPublic{
		FailureMode:          p.FailureMode,
		MaxFailures:          p.MaxFailures,
		SafetyCheckEnabled:   p.SafetyCheckEnabled,
		SafetyBypass:         p.SafetyBypass,
		BypassReason:         p.BypassReason,
		AcceptUnknownHost:    p.AcceptUnknownHost,
		AllowInsecureHostKey: p.AllowInsecureHostKey,
		KnownHostsPath:       p.KnownHostsPath,
		UseKeyAuth:           p.UseKeyAuth,
		KeyPath:              p.KeyPath,
		SSHPasswordKey:       p.SSHPasswordKey,
		SudoPasswordKey:      p.SudoPasswordKey,
		SSHPasswordProvided:  p.SSHPassword != "",
		Bind:                 p.Bind,
		BindSet:              p.BindSet,
	}
}
