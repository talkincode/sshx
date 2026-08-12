package plugin

import "time"

const (
	ManifestFile   = "manifest.json"
	SchemaVersion  = "sshx.dev/plugin/v1"
	ObservationV1  = "sshx.observation/v1"
	LockFile       = "plugin-lock.json"
	MaxManifest    = 1 << 20
	MaxSchema      = 2 << 20
	MaxCollector   = 2 << 20
	MaxFixture     = 10 << 20
	DefaultTimeout = 30 * time.Second
)

type Manifest struct {
	APIVersion       string          `json:"api_version"`
	ID               string          `json:"id"`
	Version          string          `json:"version"`
	Kind             string          `json:"kind"`
	Description      string          `json:"description,omitempty"`
	Platforms        []string        `json:"platforms"`
	Runner           Runner          `json:"runner"`
	RequiredCommands []string        `json:"required_commands,omitempty"`
	Privilege        string          `json:"privilege"`
	Timeout          string          `json:"timeout"`
	Effects          []string        `json:"effects"`
	Output           OutputContract  `json:"output"`
	Cache            CachePolicy     `json:"cache"`
	Redaction        RedactionPolicy `json:"redaction"`
}

type Runner struct {
	Type       string `json:"type"`
	Entrypoint string `json:"entrypoint"`
}

type OutputContract struct {
	Schema string `json:"schema"`
}

type CachePolicy struct {
	RecommendedTTL string `json:"recommended_ttl"`
	HardMaxAge     string `json:"hard_max_age"`
}

type RedactionPolicy struct {
	DenyFields []string `json:"deny_fields,omitempty"`
}

type Evidence struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
}

type ResultError struct {
	Kind    string `json:"kind"`
	Section string `json:"section,omitempty"`
	Message string `json:"message,omitempty"`
}

type Result struct {
	Status   string         `json:"status"`
	Facts    map[string]any `json:"facts"`
	Evidence []Evidence     `json:"evidence"`
	Errors   []ResultError  `json:"errors"`
}

type CapabilityRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Builtin bool   `json:"builtin"`
}

type TargetRef struct {
	Host               string `json:"host"`
	Port               string `json:"port"`
	User               string `json:"user"`
	UID                string `json:"uid,omitempty"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
	Platform           string `json:"platform"`
	BootID             string `json:"boot_id,omitempty"`
}

type CacheState struct {
	Mode       string `json:"mode"`
	Hit        bool   `json:"hit"`
	Stale      bool   `json:"stale"`
	AgeSeconds int64  `json:"age_seconds,omitempty"`
}

type Observation struct {
	Schema      string         `json:"schema"`
	Capability  CapabilityRef  `json:"capability"`
	Target      TargetRef      `json:"target"`
	CollectedAt time.Time      `json:"collected_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	Status      string         `json:"status"`
	Privilege   string         `json:"privilege"`
	Parameters  string         `json:"parameters_digest"`
	Cache       CacheState     `json:"cache"`
	Facts       map[string]any `json:"facts"`
	Evidence    []Evidence     `json:"evidence"`
	Errors      []ResultError  `json:"errors"`
	Redaction   []string       `json:"redacted_fields,omitempty"`
}

type Resolved struct {
	Manifest  Manifest `json:"manifest"`
	Path      string   `json:"path"`
	Digest    string   `json:"digest"`
	Trusted   bool     `json:"trusted"`
	Builtin   bool     `json:"builtin"`
	Collector []byte   `json:"-"`
	Schema    any      `json:"-"`
}

type Summary struct {
	ID          string `json:"id"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Path        string `json:"path"`
	Digest      string `json:"digest,omitempty"`
	Trusted     bool   `json:"trusted"`
	Builtin     bool   `json:"builtin"`
	Valid       bool   `json:"valid"`
	ErrorKind   string `json:"error_kind,omitempty"`
	Error       string `json:"error,omitempty"`
}

type Lock struct {
	Version int                  `json:"version"`
	Plugins map[string]LockEntry `json:"plugins"`
}

type LockEntry struct {
	Digest    string    `json:"digest"`
	TrustedAt time.Time `json:"trusted_at"`
}

type ActionResult struct {
	Success     bool      `json:"success"`
	Action      string    `json:"action"`
	PluginID    string    `json:"plugin_id,omitempty"`
	Path        string    `json:"path,omitempty"`
	BackupPath  string    `json:"backup_path,omitempty"`
	Digest      string    `json:"digest,omitempty"`
	Trusted     bool      `json:"trusted,omitempty"`
	Valid       bool      `json:"valid,omitempty"`
	Files       []string  `json:"files,omitempty"`
	Plugins     []Summary `json:"plugins,omitempty"`
	Plugin      *Summary  `json:"plugin,omitempty"`
	Manifest    *Manifest `json:"manifest,omitempty"`
	TestResult  *Result   `json:"test_result,omitempty"`
	Fixture     string    `json:"fixture,omitempty"`
	NextActions []string  `json:"next_actions,omitempty"`
	ErrorKind   string    `json:"error_kind,omitempty"`
	Error       string    `json:"error,omitempty"`
}
