package sshclient

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	DefaultSSHPort    = "22"
	DefaultSSHUser    = "master"
	DefaultSudoKey    = "master"
	DefaultTimeout    = 30 * time.Second
	SudoPrompt        = "[sudo] password"
	PasswordPromptEnd = ": "
)

// AuthMethod indicates which authentication mechanism was used for the SSH connection.
type AuthMethod string

const (
	AuthMethodUnknown          AuthMethod = "unknown"
	AuthMethodKey              AuthMethod = "key"
	AuthMethodPassword         AuthMethod = "password"
	AuthMethodPasswordFallback AuthMethod = "password-fallback"
)

// Config represents SSH configuration properties for connecting to remote hosts.
type Config struct {
	Host         string
	Port         string
	User         string
	Password     string
	SudoPassword string
	KeyPath      string
	UseKeyAuth   bool
	SudoKey      string
	// SudoKeySet is true when -pk/--password-key/--sudo-password-key was
	// present on the command line, including an explicit empty value.
	// Host inventory must persist the key only when this is set; the
	// runtime default "master" is an execution fallback, not inventory.
	SudoKeySet  bool
	Command     string
	Mode        string
	DialTimeout time.Duration
	// Timeout bounds the execution of a single remote command. Zero means no
	// command timeout (the dial timeout still applies).
	Timeout time.Duration
	// JSONOutput emits a single structured JSON result instead of streaming
	// human-readable output. It implies clean, separated stdout/stderr capture.
	JSONOutput bool
	// UsePTY requests a pseudo-terminal for command execution. It is off by
	// default because a PTY merges stderr into stdout and injects terminal
	// control characters; it is ignored in JSON/capture mode.
	UsePTY bool
	// DryRun emits a local execution plan without connecting, executing, reading
	// keyring secrets, or mutating local/remote state.
	DryRun bool
	// AuditEnabled controls whether sshx writes a local structured audit event.
	AuditEnabled bool
	// AuditOutput overrides the directory where audit JSONL files are written.
	AuditOutput string

	SafetyCheck bool
	Force       bool
	// AcceptUnknownHost controls whether sshx will automatically add
	// previously unseen host keys to the user's known_hosts file.
	AcceptUnknownHost bool
	// AllowInsecureHostKey controls whether sshx may fall back to
	// ssh.InsecureIgnoreHostKey (legacy behavior). Disabled by default.
	AllowInsecureHostKey bool
	// KnownHostsPath allows overriding the path to the known_hosts file.
	KnownHostsPath string

	SftpAction string
	LocalPath  string
	RemotePath string

	// Server-to-server transfer fields (Mode == "transfer").
	TransferSrcHost string
	TransferSrcPath string
	TransferDstHost string
	TransferDstPath string

	PasswordAction string
	PasswordKey    string
	PasswordValue  string

	// Host management fields
	HostAction      string
	HostName        string
	HostDescription string
	HostType        string
	// HostImportNames is a comma-separated list of ssh_config aliases to
	// import non-interactively (HostAction == "import"). Empty means
	// interactive selection.
	HostImportNames string
	// SSHConfigPath overrides the OpenSSH client config file read by
	// --host-import (default ~/.ssh/config).
	SSHConfigPath string

	// Plugin lifecycle fields (Mode == "plugin").
	PluginAction    string
	PluginID        string
	PluginRunner    string
	PluginPlatform  string
	PluginPrivilege string
	PluginTemplate  string
	PluginFixture   string
	PluginReplace   bool

	// Agent skill lifecycle fields (Mode == "skill").
	SkillAction string
	SkillDir    string

	// Inspection fields (Mode == "inspect").
	InspectCapability  string
	InspectCacheMode   string
	InspectRefresh     bool
	InspectMaxAge      time.Duration
	InspectAllowStale  bool
	InspectUseSudo     bool
	HostKeyFingerprint string
	ArgumentError      string
	ReportedErrorKind  string
	ReportedError      string

	// Run-mode execution contract fields (Mode == "run").
	RequestID      string
	RunTargets     []string
	RunGroups      []string
	RunTags        map[string]string
	RunAllHosts    bool
	RunAddress     string
	RunActionKind  string
	RunIntent      string
	RunUseSudo     bool
	RunConcurrency int
	FailureMode    string
	BypassReason   string
	ScriptFile     string
	ScriptStdin    bool
	// ScriptShell overrides the interpreter used for --script-file /
	// --script-stdin payloads. Empty means: follow the payload's shebang, or
	// fall back to sh.
	ScriptShell     string
	JSONLOutput     bool
	MaxOutputBytes  int
	MaxPayloadBytes int
	SSHPasswordKey  string

	// Guarded SQL execution fields (Mode == "sql").
	SQLStatement string
	// SQLEngine names the database engine: "postgres" (default) or "sqlite".
	SQLEngine   string
	SQLDatabase string
	// SQLFile is the --db-file path for --engine=sqlite. Copied into
	// SQLDatabase after validation so JSON/audit keep a single identity field.
	SQLFile string
	// SQLUser is the database role (-U), distinct from the SSH user.
	SQLUser string
	// SQLHost/SQLPort locate the database as seen from the remote host.
	// SQLHost defaults to the local socket, or 127.0.0.1 when a password key
	// is used (password auth implies TCP).
	SQLHost string
	SQLPort string
	// SQLPasswordKey names the keyring entry holding the database password.
	// The secret is delivered on the remote command's stdin, never in argv.
	SQLPasswordKey string
	// SQLRowThreshold switches from a row-level CSV snapshot to a full table
	// dump when the EXPLAIN row estimate exceeds it (0 = package default).
	SQLRowThreshold int64
	// SQLAllowFullTable permits UPDATE/DELETE without a top-level WHERE.
	SQLAllowFullTable bool
	// SQLNoBackup skips pre-change backups; requires Force.
	SQLNoBackup bool
	// SQLExplainOnly stops after the remote EXPLAIN gate.
	SQLExplainOnly bool
	// SQLBackupDir overrides the remote backup directory.
	SQLBackupDir string
	// SQLDockerContainer runs psql inside this container via
	// `docker exec -i` for databases deployed with Docker.
	SQLDockerContainer string
	// SQLCredFrom resolves database credentials on the remote host instead of
	// the local keyring: "docker:<container>" or "env-file:<path>".
	SQLCredFrom string
	// SQLCredCacheTTL keeps remotely resolved credentials reusable in the OS
	// keyring for this duration (0 = caching disabled).
	SQLCredCacheTTL time.Duration
	// SQLCredRefresh forces re-resolution, replacing any cached entry.
	SQLCredRefresh bool
	// SQLUseSudo runs the remote database client via sudo -S. Use it when the
	// SSH user cannot read or write the database file (typical for service-
	// owned SQLite). The sudo password is delivered on stdin ahead of SQL.
	SQLUseSudo bool

	// Audit query/export fields (Mode == "audit").
	AuditAction     string
	AuditSince      string
	AuditUntil      string
	AuditFilterHost string
	AuditFilterAct  string
	AuditRunID      string
	AuditErrorKind  string
	AuditBypassOnly bool
	AuditExportPath string

	// Guarded file apply fields (Mode == "apply").
	ApplyExpectSHA256 string
	ApplyNoBackup     bool
	ApplyBackupDir    string
	ApplyUseSudo      bool

	// Interactive login fields (Mode == "login").
	LoginUseSudo     bool
	LoginLiteralHost bool

	// Bind is a local source address: a literal IP or a network interface name.
	// BindSet distinguishes "flag not provided" from an explicit empty --bind=
	// that must clear a named host's persisted bind.
	Bind    string
	BindSet bool
}

// SSHClient wraps one ssh.Client with execution and SFTP helpers.
type SSHClient struct {
	config         *Config
	client         *ssh.Client
	sftpClient     *sftp.Client
	authMethodUsed AuthMethod
}

// AuthMethodUsed returns the authentication method used for the current connection.
func (c *SSHClient) AuthMethodUsed() AuthMethod {
	if c == nil {
		return AuthMethodUnknown
	}
	if c.authMethodUsed == "" {
		return AuthMethodUnknown
	}
	return c.authMethodUsed
}

// getHostKeyCallback returns a secure host key callback function.
// It enforces strict host key checking and only falls back to the insecure
// mode when explicitly requested via configuration.

// NewSSHClient 创建SSH客户端
func NewSSHClient(config *Config) (*SSHClient, error) {
	if config.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if config.Port == "" {
		config.Port = DefaultSSHPort
	}
	if config.User == "" {
		config.User = DefaultSSHUser
	}
	// Default to key authentication unless explicitly disabled
	if !config.UseKeyAuth {
		config.KeyPath = ""
	}
	if config.UseKeyAuth && config.KeyPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			config.KeyPath = filepath.Join(home, ".ssh", "id_rsa")
		}
	}

	return &SSHClient{config: config, authMethodUsed: AuthMethodUnknown}, nil
}

// Close closes the SFTP and SSH connections.
func (c *SSHClient) Close() error {
	var firstErr error
	if c.sftpClient != nil {
		if err := c.sftpClient.Close(); err != nil {
			firstErr = err
		}
		c.sftpClient = nil
	}
	if c.client != nil {
		if err := c.client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.client = nil
	}
	return firstErr
}

// ForceClose forcefully closes the underlying SSH connection.
func (c *SSHClient) ForceClose() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}
