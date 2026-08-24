package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/talkincode/sshx/internal/keyringstore"
	pluginpkg "github.com/talkincode/sshx/internal/plugin"
	"github.com/talkincode/sshx/internal/sqlsafe"
	"github.com/talkincode/sshx/internal/sshclient"
)

type dryRunStatus struct {
	Status    string `json:"status"`
	ErrorKind string `json:"error_kind,omitempty"`
	Message   string `json:"message,omitempty"`
}

type dryRunPlan struct {
	DryRun bool `json:"dry_run"`
	Valid  bool `json:"valid"`

	Mode   string `json:"mode"`
	Action string `json:"action,omitempty"`

	HostInput      string       `json:"host_input,omitempty"`
	HostResolved   string       `json:"host_resolved,omitempty"`
	HostResolution dryRunStatus `json:"host_resolution,omitempty"`
	Port           string       `json:"port,omitempty"`
	User           string       `json:"user,omitempty"`

	Command    string `json:"command,omitempty"`
	SftpAction string `json:"sftp_action,omitempty"`
	LocalPath  string `json:"local_path,omitempty"`
	RemotePath string `json:"remote_path,omitempty"`

	TransferSource  string   `json:"transfer_source,omitempty"`
	TransferDest    string   `json:"transfer_destination,omitempty"`
	PluginID        string   `json:"plugin_id,omitempty"`
	PluginPath      string   `json:"plugin_path,omitempty"`
	PluginDigest    string   `json:"plugin_digest,omitempty"`
	PluginTrusted   bool     `json:"plugin_trusted,omitempty"`
	PluginRunner    string   `json:"plugin_runner,omitempty"`
	PluginPrivilege string   `json:"plugin_privilege,omitempty"`
	CacheMode       string   `json:"cache_mode,omitempty"`
	PluginEffects   []string `json:"plugin_effects,omitempty"`
	PluginPlatforms []string `json:"plugin_platforms,omitempty"`

	UseKeyAuth       bool   `json:"use_key_auth"`
	KeyPath          string `json:"key_path,omitempty"`
	PasswordProvided bool   `json:"password_provided"`
	UsesSudo         bool   `json:"uses_sudo"`
	SudoKey          string `json:"sudo_key,omitempty"`

	Timeout              string `json:"timeout,omitempty"`
	JSONOutput           bool   `json:"json_output"`
	UsePTY               bool   `json:"pty"`
	SafetyCheckEnabled   bool   `json:"safety_check_enabled"`
	Force                bool   `json:"force"`
	AcceptUnknownHost    bool   `json:"accept_unknown_host"`
	AllowInsecureHostKey bool   `json:"allow_insecure_host_key"`
	KnownHostsPath       string `json:"known_hosts_path,omitempty"`

	ConfigCheck dryRunStatus `json:"config_check"`
	SafetyCheck dryRunStatus `json:"safety_check"`

	WouldConnect          bool `json:"would_connect"`
	WouldExecute          bool `json:"would_execute"`
	WouldReadSecret       bool `json:"would_read_secret"`
	WouldWriteLocalState  bool `json:"would_write_local_state"`
	WouldMutateRemote     bool `json:"would_mutate_remote"`
	WouldWriteRemoteState bool `json:"would_write_remote_state"`
	MayMutateKnownHosts   bool `json:"may_mutate_known_hosts"`
	WouldPromptForSecret  bool `json:"would_prompt_for_secret"`
	WouldLookupHostConfig bool `json:"would_lookup_host_config"`

	SecretBackend string `json:"secret_backend,omitempty"`
	SecretUnlock  string `json:"secret_unlock,omitempty"`

	Notes []string `json:"notes,omitempty"`

	// SQL is the guarded-SQL local plan (Mode == "sql").
	SQL *sqlDryRunPlan `json:"sql,omitempty"`
	// Apply is the guarded file-apply local plan (Mode == "apply").
	Apply *applyDryRunPlan `json:"apply,omitempty"`

	hostTestReadsSecret bool
}

type applyDryRunPlan struct {
	RemotePath    string `json:"remote_path"`
	LocalPath     string `json:"local_path"`
	PayloadSHA256 string `json:"payload_sha256,omitempty"`
	PayloadBytes  int    `json:"payload_bytes,omitempty"`
	ExpectSHA256  string `json:"expect_sha256,omitempty"`
	Backup        string `json:"backup"`
	BackupDir     string `json:"backup_dir,omitempty"`
	UseSudo       bool   `json:"use_sudo"`
	Force         bool   `json:"force,omitempty"`
}

// sqlDryRunPlan is the local (connection-free) plan for one sql invocation.
// The backup decision shown here uses no EXPLAIN estimate; a row-level backup
// may still upgrade to a table dump at execution time.
type sqlDryRunPlan struct {
	Engine         string       `json:"engine"`
	Database       string       `json:"database"`
	Statement      string       `json:"statement"`
	StatementHash  string       `json:"statement_sha256"`
	Class          string       `json:"class,omitempty"`
	Verb           string       `json:"verb,omitempty"`
	Table          string       `json:"table,omitempty"`
	HasWhere       bool         `json:"has_where"`
	Docker         string       `json:"docker,omitempty"`
	CredSource     string       `json:"cred_source,omitempty"`
	CredCache      string       `json:"cred_cache,omitempty"`
	PolicyCheck    dryRunStatus `json:"policy_check"`
	BackupKind     string       `json:"backup_kind,omitempty"`
	BackupReason   string       `json:"backup_reason,omitempty"`
	ExplainCommand string       `json:"explain_command,omitempty"`
	ExecuteCommand string       `json:"execute_command,omitempty"`
	UseSudo        bool         `json:"use_sudo,omitempty"`
}

func emitDryRunPlan(config *sshclient.Config) error {
	plan := buildDryRunPlan(config)
	if config.JSONOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(plan)
	}
	printDryRunPlan(plan)
	return nil
}

func buildDryRunPlan(config *sshclient.Config) dryRunPlan {
	plan := dryRunPlan{
		DryRun:               true,
		Valid:                true,
		Mode:                 config.Mode,
		UseKeyAuth:           config.UseKeyAuth,
		PasswordProvided:     config.Password != "",
		JSONOutput:           config.JSONOutput,
		UsePTY:               config.UsePTY,
		SafetyCheckEnabled:   config.SafetyCheck,
		Force:                config.Force,
		AcceptUnknownHost:    config.AcceptUnknownHost,
		AllowInsecureHostKey: config.AllowInsecureHostKey,
		KnownHostsPath:       config.KnownHostsPath,
		ConfigCheck:          dryRunStatus{Status: "passed"},
		SafetyCheck:          dryRunStatus{Status: "not_applicable"},
		Notes: []string{
			"dry-run does not connect, execute, read secrets, mutate known_hosts, or write local/remote state",
		},
	}

	applyDryRunDefaults(config, &plan)
	fillDryRunAction(config, &plan)
	fillDryRunHost(config, &plan)
	fillDryRunKeyDefault(config, &plan)
	fillDryRunSudo(config, &plan)
	fillDryRunValidation(config, &plan)
	fillDryRunSecretBackend(config, &plan)
	fillDryRunSQL(config, &plan)
	fillDryRunApply(config, &plan)
	fillDryRunEffects(config, &plan)

	return plan
}

func applyDryRunDefaults(config *sshclient.Config, plan *dryRunPlan) {
	if config.Port == "" && modeUsesSSHConnection(config) {
		config.Port = sshclient.DefaultSSHPort
	}
	if config.User == "" && modeUsesSSHConnection(config) {
		config.User = sshclient.DefaultSSHUser
	}
	plan.Port = config.Port
	plan.User = config.User
	if config.Timeout > 0 {
		plan.Timeout = config.Timeout.String()
	}
}

func fillDryRunAction(config *sshclient.Config, plan *dryRunPlan) {
	switch config.Mode {
	case "ssh":
		plan.Action = "command"
		plan.Command = config.Command
	case "sftp":
		plan.Action = config.SftpAction
		plan.SftpAction = config.SftpAction
		plan.LocalPath = config.LocalPath
		plan.RemotePath = config.RemotePath
	case "password":
		plan.Action = config.PasswordAction
	case "host":
		plan.Action = config.HostAction
	case "transfer":
		plan.Action = "transfer"
		plan.TransferSource = formatTransferEndpoint(config.TransferSrcHost, config.TransferSrcPath)
		plan.TransferDest = formatTransferEndpoint(config.TransferDstHost, config.TransferDstPath)
	case "plugin":
		plan.Action = config.PluginAction
		plan.PluginID = config.PluginID
	case "inspect":
		plan.Action = "inspect"
		plan.PluginID = config.InspectCapability
		plan.CacheMode = config.InspectCacheMode
	case "sql":
		plan.Action = "sql"
	case "apply":
		plan.Action = "apply"
		plan.LocalPath = config.LocalPath
		plan.RemotePath = config.RemotePath
	case "login":
		plan.Action = "login"
		if config.LoginUseSudo {
			plan.Action = "login-sudo"
			plan.Command = sshclient.PrivilegedLoginCommand
		} else {
			plan.Command = "interactive-shell"
		}
	}
}

func fillDryRunHost(config *sshclient.Config, plan *dryRunPlan) {
	switch {
	case config.Mode == "host" && (config.HostAction == "test" || config.HostAction == "remove" || config.HostAction == "update"):
		plan.HostInput = config.HostName
	case config.Mode == "host":
		plan.HostInput = firstNonEmpty(config.HostName, config.Host)
	default:
		plan.HostInput = config.Host
	}

	if config.Mode == "ssh" || config.Mode == "sftp" || config.Mode == "inspect" || config.Mode == "sql" || config.Mode == "apply" || config.Mode == "login" {
		resolveDryRunSSHHost(config, plan)
		return
	}
	if config.Mode == "host" && config.HostAction == "test" && config.HostName != "" {
		resolveDryRunHostTest(config, plan)
		return
	}

	if plan.HostInput != "" {
		plan.HostResolved = config.Host
	}
}

func resolveDryRunSSHHost(config *sshclient.Config, plan *dryRunPlan) {
	if config.Host == "" {
		plan.HostResolution = dryRunStatus{Status: "missing", ErrorKind: "config", Message: "host is required"}
		plan.Valid = false
		return
	}
	if isIPAddress(config.Host) || config.LoginLiteralHost {
		plan.HostResolved = config.Host
		plan.HostResolution = dryRunStatus{Status: "direct"}
		return
	}

	plan.WouldLookupHostConfig = true
	settings, err := LoadSettings()
	if err != nil {
		plan.HostResolved = config.Host
		plan.HostResolution = dryRunStatus{Status: "error_used_direct", ErrorKind: "config", Message: err.Error()}
		return
	}
	hostConfig, err := GetHost(settings, config.Host)
	if err != nil {
		plan.HostResolved = config.Host
		plan.HostResolution = dryRunStatus{Status: "not_found_used_direct", Message: err.Error()}
		return
	}

	originalHost := config.Host
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
	if sudoKey := hostConfig.EffectiveSudoPasswordKey(); sudoKey != "" && config.SudoKey == sshclient.DefaultSudoKey {
		config.SudoKey = sudoKey
	}
	if config.SSHPasswordKey == "" {
		config.SSHPasswordKey = hostConfig.EffectiveSSHPasswordKey()
	}
	if config.UseKeyAuth && config.KeyPath == "" {
		switch {
		case hostConfig.Key != "":
			config.KeyPath = hostConfig.Key
		case settings.Key != "":
			config.KeyPath = settings.Key
		}
	}

	plan.HostInput = originalHost
	plan.HostResolved = config.Host
	plan.Port = config.Port
	plan.User = config.User
	plan.KeyPath = config.KeyPath
	plan.HostResolution = dryRunStatus{Status: "resolved", Message: fmt.Sprintf("matched host %q in settings", originalHost)}
}

func fillDryRunKeyDefault(config *sshclient.Config, plan *dryRunPlan) {
	if config.UseKeyAuth && config.KeyPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			config.KeyPath = filepath.Join(home, ".ssh", "id_rsa")
		}
	}
	plan.KeyPath = config.KeyPath
}

func resolveDryRunHostTest(config *sshclient.Config, plan *dryRunPlan) {
	plan.WouldLookupHostConfig = true
	settings, err := LoadSettings()
	if err != nil {
		plan.HostResolution = dryRunStatus{Status: "error", ErrorKind: "config", Message: err.Error()}
		plan.Valid = false
		return
	}
	hostConfig, err := GetHost(settings, config.HostName)
	if err != nil {
		plan.HostResolution = dryRunStatus{Status: "not_found", ErrorKind: "config", Message: err.Error()}
		plan.Valid = false
		return
	}
	config.Host = hostConfig.Host
	config.Port = firstNonEmpty(hostConfig.Port, sshclient.DefaultSSHPort)
	config.User = firstNonEmpty(hostConfig.User, sshclient.DefaultSSHUser)
	if config.UseKeyAuth && config.KeyPath == "" {
		config.KeyPath = firstNonEmpty(hostConfig.Key, settings.Key)
	}
	// Host diagnostics only read an SSH login password key — never sudo keys.
	if sshKey := hostConfig.EffectiveSSHPasswordKey(); sshKey != "" {
		config.SSHPasswordKey = sshKey
		plan.hostTestReadsSecret = true
	}
	if sudoKey := hostConfig.EffectiveSudoPasswordKey(); sudoKey != "" {
		config.SudoKey = sudoKey
	}

	plan.HostResolved = config.Host
	plan.Port = config.Port
	plan.User = config.User
	plan.KeyPath = config.KeyPath
	plan.SudoKey = config.SudoKey
	plan.HostResolution = dryRunStatus{Status: "resolved", Message: fmt.Sprintf("matched host %q in settings", config.HostName)}
}

func fillDryRunSudo(config *sshclient.Config, plan *dryRunPlan) {
	if config.Mode == "ssh" {
		plan.UsesSudo = sshclient.CommandUsesSudo(config.Command)
		plan.SudoKey = config.SudoKey
		return
	}
	if config.Mode == "inspect" {
		plan.UsesSudo = config.InspectUseSudo
		plan.SudoKey = config.SudoKey
	}
	if config.Mode == "apply" {
		plan.UsesSudo = config.ApplyUseSudo
		plan.SudoKey = config.SudoKey
	}
	if config.Mode == "sql" {
		plan.UsesSudo = config.SQLUseSudo
		plan.SudoKey = config.SudoKey
	}
	if config.Mode == "login" {
		plan.UsesSudo = config.LoginUseSudo
		plan.SudoKey = config.SudoKey
	}
	if config.Mode == "host" && config.HostAction == "test" {
		return
	}
	plan.SudoKey = config.SudoKey
}

func fillDryRunSecretBackend(config *sshclient.Config, plan *dryRunPlan) {
	status := keyringstore.Inspect()
	plan.SecretBackend = status.Backend
	if status.Unlock != keyringstore.UnlockNone {
		plan.SecretUnlock = status.Unlock
	}
	if !plan.Valid {
		return
	}
	if _, err := keyringstore.Backend(); err != nil {
		plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: err.Error()}
		plan.Valid = false
		return
	}
	if config.Mode == "password" && config.PasswordAction == "get" && !keyringstore.CanReveal() {
		plan.ConfigCheck = dryRunStatus{
			Status:    "error",
			ErrorKind: "config",
			Message:   "local vault is write-only; --password-get cannot display secrets",
		}
		plan.Valid = false
	}
}

func fillDryRunValidation(config *sshclient.Config, plan *dryRunPlan) {
	if config.ArgumentError != "" {
		plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: config.ArgumentError}
		plan.Valid = false
		return
	}
	if config.Mode == "transfer" {
		if config.TransferSrcHost == "" || config.TransferSrcPath == "" {
			plan.ConfigCheck = dryRunStatus{
				Status:    "error",
				ErrorKind: "config",
				Message:   "source must be specified as --transfer=<host>:<path>",
			}
			plan.Valid = false
			return
		}
		if config.TransferDstHost == "" || config.TransferDstPath == "" {
			plan.ConfigCheck = dryRunStatus{
				Status:    "error",
				ErrorKind: "config",
				Message:   "destination must be specified as --to=<host>:<path>",
			}
			plan.Valid = false
		}
		return
	}
	if config.Mode == "ssh" {
		if config.Timeout < 0 {
			plan.ConfigCheck = dryRunStatus{
				Status:    "error",
				ErrorKind: "config",
				Message:   "invalid --timeout value (use e.g. 30s, 2m, or 30)",
			}
			plan.Valid = false
		}

		if config.JSONOutput && config.UsePTY {
			plan.ConfigCheck = dryRunStatus{
				Status:    "error",
				ErrorKind: "config",
				Message:   "--pty cannot be combined with --json for real command execution",
			}
			plan.Valid = false
		}

		if config.SafetyCheck && !config.Force {
			if blockErr := sshclient.ValidateCommand(config.Command); blockErr != nil {
				plan.SafetyCheck = dryRunStatus{
					Status:    "blocked",
					ErrorKind: classifyError(blockErr),
					Message:   blockErr.Error(),
				}
				plan.Valid = false
				return
			}
			plan.SafetyCheck = dryRunStatus{Status: "passed"}
			return
		}
		if config.Force {
			plan.SafetyCheck = dryRunStatus{Status: "bypassed", Message: "force mode skips safety checks"}
			return
		}
		plan.SafetyCheck = dryRunStatus{Status: "disabled"}
	}
	if config.Mode == "plugin" {
		if config.PluginAction == "" {
			plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: "plugin action is required"}
			plan.Valid = false
			return
		}
		if config.PluginAction != "list" && config.PluginID == "" {
			plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: "plugin id is required"}
			plan.Valid = false
		}
		return
	}
	if config.Mode == "inspect" {
		if config.Timeout < 0 || config.InspectMaxAge < 0 {
			plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: "timeout and max-age values must be valid non-negative durations"}
			plan.Valid = false
			return
		}
		if config.InspectCapability == "" {
			plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: "inspection capability is required"}
			plan.Valid = false
			return
		}
		resolved, err := pluginpkg.Resolve(config.InspectCapability)
		if err != nil {
			plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: classifyPluginError(err), Message: err.Error()}
			plan.Valid = false
			return
		}
		plan.PluginPath = resolved.Path
		plan.PluginDigest = resolved.Digest
		plan.PluginTrusted = resolved.Trusted
		plan.PluginRunner = resolved.Manifest.Runner.Type
		plan.PluginPrivilege = resolved.Manifest.Privilege
		plan.PluginEffects = append([]string(nil), resolved.Manifest.Effects...)
		plan.PluginPlatforms = append([]string(nil), resolved.Manifest.Platforms...)
		if !resolved.Trusted {
			plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "untrusted_plugin", Message: "plugin digest is not trusted"}
			plan.Valid = false
			return
		}
		if config.InspectCacheMode != "off" && config.InspectCacheMode != "remote-prefer" {
			plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: "cache mode must be off or remote-prefer"}
			plan.Valid = false
			return
		}
		useSudo, _, err := inspectionPrivilege(config, resolved.Manifest)
		if err != nil {
			plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: err.Error()}
			plan.Valid = false
			return
		}
		plan.UsesSudo = useSudo
		if _, _, err := inspectionFreshness(config, resolved.Manifest); err != nil {
			plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: err.Error()}
			plan.Valid = false
		}
	}
	if config.Mode == "login" {
		fillDryRunLogin(config, plan)
	}
}

func fillDryRunLogin(config *sshclient.Config, plan *dryRunPlan) {
	plan.Notes = append(plan.Notes,
		"login is a human-only interactive session; it is not an Agent contract",
		"login has no command timeout",
	)
	if config.LoginUseSudo {
		plan.Notes = append(plan.Notes, "would start a privileged login shell after sudo -S; the password is never placed in argv")
	}
	if !sshclient.InteractiveLoginSupported() {
		plan.Notes = append(plan.Notes, "interactive login session is not supported on this platform; dry-run still previews the local plan")
	}
	if config.JSONOutput && !config.DryRun {
		plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: "login --json requires --dry-run"}
		plan.Valid = false
	}
}

func fillDryRunEffects(config *sshclient.Config, plan *dryRunPlan) {
	canProceed := plan.Valid && plan.ConfigCheck.Status != "error" && plan.SafetyCheck.Status != "blocked"

	switch config.Mode {
	case "ssh":
		plan.WouldConnect = canProceed
		plan.WouldExecute = plan.WouldConnect
		plan.WouldReadSecret = canProceed && plan.UsesSudo && config.SudoKey != ""
		plan.WouldMutateRemote = plan.WouldExecute
	case "sftp":
		plan.WouldConnect = canProceed
		plan.WouldMutateRemote = plan.WouldConnect && (config.SftpAction == "upload" || config.SftpAction == "mkdir" || config.SftpAction == "remove")
	case "transfer":
		plan.WouldConnect = canProceed
		plan.WouldMutateRemote = canProceed
	case "password":
		plan.WouldReadSecret = canProceed && (config.PasswordAction == "get" || config.PasswordAction == "check" || config.PasswordAction == "delete" || config.PasswordAction == "list")
		plan.WouldWriteLocalState = canProceed && (config.PasswordAction == "set" || config.PasswordAction == "delete")
		plan.WouldPromptForSecret = canProceed && config.PasswordAction == "set" && config.PasswordValue == ""
	case "host":
		plan.WouldConnect = canProceed && (config.HostAction == "test" || config.HostAction == "test-all")
		plan.WouldWriteLocalState = canProceed && (config.HostAction == "add" || config.HostAction == "update" || config.HostAction == "remove" || config.HostAction == "import")
		switch config.HostAction {
		case "test":
			plan.WouldReadSecret = canProceed && plan.hostTestReadsSecret
		case "test-all":
			plan.WouldReadSecret = canProceed
		}
	case "plugin":
		plan.WouldWriteLocalState = canProceed && (config.PluginAction == "create" || config.PluginAction == "trust" || config.PluginAction == "remove")
	case "inspect":
		plan.WouldConnect = canProceed
		plan.WouldExecute = canProceed
		plan.WouldReadSecret = canProceed && plan.UsesSudo && config.SudoKey != ""
		plan.WouldWriteRemoteState = canProceed && config.InspectCacheMode == "remote-prefer"
		plan.WouldMutateRemote = plan.WouldWriteRemoteState
	case "sql":
		plan.WouldConnect = canProceed
		plan.WouldExecute = canProceed && !config.SQLExplainOnly
		plan.WouldReadSecret = canProceed && (config.SQLPasswordKey != "" || config.SQLCredFrom != "" || (config.SQLUseSudo && config.SudoKey != ""))
		plan.WouldWriteLocalState = canProceed && config.SQLCredFrom != "" && config.SQLCredCacheTTL > 0
		mutates := plan.SQL != nil && plan.SQL.Class != "" && plan.SQL.Class != string(sqlsafe.ClassRead)
		plan.WouldMutateRemote = plan.WouldExecute && mutates
		plan.WouldWriteRemoteState = plan.WouldExecute && plan.SQL != nil && plan.SQL.BackupKind != "" && plan.SQL.BackupKind != string(sqlsafe.BackupNone)
	case "apply":
		plan.WouldConnect = canProceed
		plan.WouldExecute = canProceed
		plan.WouldReadSecret = canProceed && config.ApplyUseSudo && config.SudoKey != ""
		plan.WouldMutateRemote = canProceed
		plan.WouldWriteRemoteState = canProceed && !config.ApplyNoBackup
	case "login":
		plan.WouldConnect = canProceed
		plan.WouldExecute = canProceed
		plan.WouldReadSecret = canProceed && ((config.LoginUseSudo && config.SudoKey != "") || config.SSHPasswordKey != "")
		plan.WouldMutateRemote = canProceed
	}
	plan.MayMutateKnownHosts = plan.WouldConnect && config.AcceptUnknownHost
}

// fillDryRunSQL builds the local guarded-SQL plan: classification, policy
// gates, and the planned pipeline commands — all without connecting. The
// backup decision is previewed without an EXPLAIN row estimate.
func fillDryRunSQL(config *sshclient.Config, plan *dryRunPlan) {
	if config.Mode != "sql" {
		return
	}
	if err := validateSQLConfig(config); err != nil {
		plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: err.Error()}
		plan.Valid = false
		return
	}

	sqlPlan := &sqlDryRunPlan{
		Engine:        config.SQLEngine,
		Database:      config.SQLDatabase,
		Statement:     sqlsafe.RedactForAudit(config.SQLStatement),
		StatementHash: sqlStatementDigest(config.SQLStatement),
		Docker:        config.SQLDockerContainer,
		UseSudo:       config.SQLUseSudo,
	}
	if config.SQLCredFrom != "" {
		sqlPlan.CredSource = config.SQLCredFrom
		if config.SQLCredCacheTTL > 0 {
			sqlPlan.CredCache = config.SQLCredCacheTTL.String()
		} else {
			sqlPlan.CredCache = "off"
		}
		if sqlPlan.Database == "" {
			sqlPlan.Database = "(from credential source)"
		}
	}
	plan.SQL = sqlPlan
	plan.Command = sqlPlan.Statement

	cls, err := sqlsafe.ClassifyFor(config.SQLEngine, config.SQLStatement)
	if err != nil {
		plan.SafetyCheck = dryRunStatus{Status: "blocked", ErrorKind: "blocked", Message: err.Error()}
		sqlPlan.PolicyCheck = plan.SafetyCheck
		plan.Valid = false
		return
	}
	sqlPlan.Class = string(cls.Class)
	sqlPlan.Verb = cls.Verb
	sqlPlan.Table = cls.Table
	sqlPlan.HasWhere = cls.HasWhere

	opts := sqlOptions(config)
	if perr := sqlsafe.CheckPolicy(cls, opts); perr != nil {
		plan.SafetyCheck = dryRunStatus{Status: "blocked", ErrorKind: "blocked", Message: perr.Error()}
		sqlPlan.PolicyCheck = plan.SafetyCheck
		plan.Valid = false
		return
	}
	plan.SafetyCheck = dryRunStatus{Status: "passed"}
	sqlPlan.PolicyCheck = plan.SafetyCheck

	var backup sqlsafe.BackupPlan
	if sqlsafe.NormalizeEngine(config.SQLEngine) == sqlsafe.EngineSQLite {
		backup, err = sqlsafe.DecideSQLiteBackup(cls, opts)
	} else {
		backup, err = sqlsafe.DecideBackup(cls, -1, opts)
	}
	if err != nil {
		plan.SafetyCheck = dryRunStatus{Status: "blocked", ErrorKind: "blocked", Message: err.Error()}
		sqlPlan.PolicyCheck = plan.SafetyCheck
		plan.Valid = false
		return
	}
	sqlPlan.BackupKind = string(backup.Kind)
	sqlPlan.BackupReason = backup.Reason
	if backup.Kind == sqlsafe.BackupRows {
		sqlPlan.BackupReason += " (may upgrade to a full-table CSV snapshot if the EXPLAIN estimate exceeds the row threshold)"
	}
	if cls.Class == sqlsafe.ClassDML && !opts.NoBackup && backup.Kind != sqlsafe.BackupFile {
		sqlPlan.BackupReason += " (runtime catalog preflight blocks triggers, rewrite rules, partitions, and cascading referential actions)"
	}

	conn := newSQLExecutor(config, "")
	if cls.Class == sqlsafe.ClassDML || config.SQLExplainOnly {
		sqlPlan.ExplainCommand = conn.ExplainCommand(cls.Statement).Command
	}
	if !config.SQLExplainOnly {
		switch {
		case cls.Class == sqlsafe.ClassRead:
			sqlPlan.ExecuteCommand = conn.ExecuteReadCommand(cls.Statement).Command
		case backup.Kind != sqlsafe.BackupNone:
			previewPath := "backup.csv"
			if backup.Kind == sqlsafe.BackupFile {
				previewPath = "backup.db"
			}
			transactional, buildErr := conn.ExecuteWithBackupCommand(
				cls.Statement, cls.Table, cls.WhereClause, previewPath, backup.Kind,
			)
			if buildErr != nil {
				plan.SafetyCheck = dryRunStatus{Status: "blocked", ErrorKind: "blocked", Message: buildErr.Error()}
				sqlPlan.PolicyCheck = plan.SafetyCheck
				plan.Valid = false
				return
			}
			sqlPlan.ExecuteCommand = transactional.Command
		default:
			sqlPlan.ExecuteCommand = conn.ExecuteCommand(cls.Statement).Command
		}
	}
	if config.SQLUseSudo {
		sqlPlan.ExplainCommand = sqlsafe.WrapSudoStdin(sqlPlan.ExplainCommand)
		sqlPlan.ExecuteCommand = sqlsafe.WrapSudoStdin(sqlPlan.ExecuteCommand)
	}
}

func fillDryRunApply(config *sshclient.Config, plan *dryRunPlan) {
	if config.Mode != "apply" {
		return
	}
	if err := validateApplyConfig(config); err != nil {
		plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: classifyError(err), Message: err.Error()}
		if plan.ConfigCheck.ErrorKind == "error" {
			plan.ConfigCheck.ErrorKind = "config"
		}
		plan.Valid = false
		return
	}
	if err := applyPolicy(config); err != nil {
		plan.SafetyCheck = dryRunStatus{Status: "blocked", ErrorKind: "blocked", Message: err.Error()}
		plan.Valid = false
		return
	}
	applyPlan := &applyDryRunPlan{
		RemotePath:   config.RemotePath,
		LocalPath:    config.LocalPath,
		ExpectSHA256: config.ApplyExpectSHA256,
		Backup:       "file",
		BackupDir:    config.ApplyBackupDir,
		UseSudo:      config.ApplyUseSudo,
		Force:        config.Force,
	}
	if config.ApplyNoBackup {
		applyPlan.Backup = "none"
	}
	if data, err := os.ReadFile(config.LocalPath); err == nil {
		if len(data) > sshclient.MaxApplyBytes {
			plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "config", Message: fmt.Sprintf("payload exceeds %d-byte apply limit", sshclient.MaxApplyBytes)}
			plan.Valid = false
			return
		}
		applyPlan.PayloadBytes = len(data)
		applyPlan.PayloadSHA256 = sshclient.SHA256Hex(data)
	} else {
		plan.ConfigCheck = dryRunStatus{Status: "error", ErrorKind: "local_io", Message: fmt.Sprintf("read --from=%s: %v", config.LocalPath, err)}
		plan.Valid = false
		return
	}
	plan.Apply = applyPlan
	plan.UsesSudo = config.ApplyUseSudo
	plan.SafetyCheck = dryRunStatus{Status: "passed"}
}

func modeUsesSSHConnection(config *sshclient.Config) bool {
	if config.Mode == "ssh" || config.Mode == "sftp" || config.Mode == "transfer" || config.Mode == "inspect" || config.Mode == "sql" || config.Mode == "apply" || config.Mode == "login" {
		return true
	}
	return config.Mode == "host" && (config.HostAction == "test" || config.HostAction == "test-all")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func printDryRunPlan(plan dryRunPlan) {
	fmt.Println("Dry run: no connection, execution, secret lookup, or state mutation performed.")
	fmt.Printf("Mode: %s\n", plan.Mode)
	if plan.Action != "" {
		fmt.Printf("Action: %s\n", plan.Action)
	}
	if plan.HostInput != "" {
		fmt.Printf("Host: %s", plan.HostInput)
		if plan.HostResolved != "" && plan.HostResolved != plan.HostInput {
			fmt.Printf(" -> %s", plan.HostResolved)
		}
		fmt.Println()
	}
	if plan.Mode != "transfer" && (plan.User != "" || plan.Port != "") {
		fmt.Printf("Target: %s@%s:%s\n", firstNonEmpty(plan.User, "-"), firstNonEmpty(plan.HostResolved, "-"), firstNonEmpty(plan.Port, "-"))
	}
	if plan.Command != "" {
		fmt.Printf("Command: %s\n", plan.Command)
	}
	if plan.SQL != nil {
		fmt.Printf("SQL: engine=%s db=%s class=%s verb=%s", plan.SQL.Engine, plan.SQL.Database, firstNonEmpty(plan.SQL.Class, "-"), firstNonEmpty(plan.SQL.Verb, "-"))
		if plan.SQL.Table != "" {
			fmt.Printf(" table=%s", plan.SQL.Table)
		}
		fmt.Printf(" where=%t\n", plan.SQL.HasWhere)
		if plan.SQL.Docker != "" {
			fmt.Printf("SQL docker: clients run inside container %s\n", plan.SQL.Docker)
		}
		if plan.SQL.CredSource != "" {
			fmt.Printf("SQL credentials: resolved remotely from %s (cache: %s)\n", plan.SQL.CredSource, plan.SQL.CredCache)
		}
		fmt.Printf("SQL policy: %s\n", statusText(plan.SQL.PolicyCheck))
		if plan.SQL.BackupKind != "" {
			fmt.Printf("SQL backup: %s (%s)\n", plan.SQL.BackupKind, plan.SQL.BackupReason)
		}
		if plan.SQL.ExplainCommand != "" {
			fmt.Printf("SQL explain command: %s\n", plan.SQL.ExplainCommand)
		}
		if plan.SQL.ExecuteCommand != "" {
			fmt.Printf("SQL execute command: %s\n", plan.SQL.ExecuteCommand)
		}
	}
	if plan.SftpAction != "" {
		fmt.Printf("SFTP: %s local=%q remote=%q\n", plan.SftpAction, plan.LocalPath, plan.RemotePath)
	}
	if plan.TransferSource != "" || plan.TransferDest != "" {
		fmt.Printf("Transfer: %s → %s\n", plan.TransferSource, plan.TransferDest)
	}
	if plan.PluginID != "" {
		fmt.Printf("Plugin: %s", plan.PluginID)
		if plan.PluginDigest != "" {
			fmt.Printf(" digest=%s trusted=%t", plan.PluginDigest, plan.PluginTrusted)
		}
		fmt.Println()
		if plan.PluginRunner != "" {
			fmt.Printf("Plugin contract: runner=%s privilege=%s platforms=%v effects=%v\n", plan.PluginRunner, plan.PluginPrivilege, plan.PluginPlatforms, plan.PluginEffects)
		}
	}
	fmt.Printf("Config check: %s\n", statusText(plan.ConfigCheck))
	fmt.Printf("Safety check: %s\n", statusText(plan.SafetyCheck))
	fmt.Printf("Uses sudo: %t", plan.UsesSudo)
	if plan.SudoKey != "" {
		fmt.Printf(" (key: %s)", plan.SudoKey)
	}
	fmt.Println()
	fmt.Printf("Would connect: %t\n", plan.WouldConnect)
	fmt.Printf("Would execute: %t\n", plan.WouldExecute)
	fmt.Printf("Would read secret: %t\n", plan.WouldReadSecret)
	if plan.SecretBackend != "" {
		fmt.Printf("Secret backend: %s", plan.SecretBackend)
		if plan.SecretUnlock != "" {
			fmt.Printf(" (unlock: %s)", plan.SecretUnlock)
		}
		fmt.Println()
	}
	fmt.Printf("Would write local state: %t\n", plan.WouldWriteLocalState)
	fmt.Printf("Would mutate remote: %t\n", plan.WouldMutateRemote)
	fmt.Printf("Would write remote state: %t\n", plan.WouldWriteRemoteState)
}

func statusText(status dryRunStatus) string {
	if status.Message == "" {
		return status.Status
	}
	return fmt.Sprintf("%s (%s)", status.Status, status.Message)
}
