package app

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/sqlsafe"
	"github.com/talkincode/sshx/internal/sshclient"
)

// parseTimeout parses a command timeout. It accepts a Go duration string
// (e.g. "30s", "2m") or a bare integer interpreted as seconds.
func parseTimeout(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty timeout")
	}
	if d, err := time.ParseDuration(value); err == nil {
		if d < 0 {
			return 0, fmt.Errorf("negative timeout: %s", value)
		}
		return d, nil
	}
	if secs, err := strconv.Atoi(value); err == nil {
		if secs < 0 {
			return 0, fmt.Errorf("negative timeout: %s", value)
		}
		return time.Duration(secs) * time.Second, nil
	}
	return 0, fmt.Errorf("invalid timeout %q (use e.g. 30s, 2m, or 30)", value)
}

// splitHostPath splits a "host:path" transfer spec at the first colon.
// If there is no colon, the whole value is treated as a host with an empty path.
func splitHostPath(spec string) (host, path string) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return spec, ""
}

// ParseArgs parses command-line arguments and returns a Config.
func ParseArgs(args []string) *sshclient.Config {
	config := &sshclient.Config{
		Mode:         "ssh",
		SafetyCheck:  true,
		Force:        false,
		UseKeyAuth:   true,
		AuditEnabled: true,
		RunTags:      map[string]string{},
	}

	if password := os.Getenv("SSH_PASSWORD"); password != "" {
		config.Password = password
	}
	if keyPath := os.Getenv("SSH_KEY_PATH"); keyPath != "" {
		config.KeyPath = keyPath
	}
	if disableKey := os.Getenv("SSH_DISABLE_KEY"); strings.EqualFold(disableKey, "true") || disableKey == "1" {
		config.UseKeyAuth = false
		config.KeyPath = ""
	}
	if knownHosts := os.Getenv("SSH_KNOWN_HOSTS"); knownHosts != "" {
		config.KnownHostsPath = knownHosts
	}
	if auditOutput := os.Getenv("SSHX_AUDIT_OUTPUT"); auditOutput != "" {
		config.AuditOutput = auditOutput
	}
	if noAudit := os.Getenv("SSHX_NO_AUDIT"); strings.EqualFold(noAudit, "true") || noAudit == "1" {
		config.AuditEnabled = false
	}
	// High-risk trust relaxations must be explicit CLI/request fields. Inherited
	// environment values and repository-local .env files must not authorize them.
	warnDeprecatedTrustEnv("SSH_ACCEPT_UNKNOWN_HOST")
	warnDeprecatedTrustEnv("SSH_INSECURE_HOST_KEY")
	warnDeprecatedTrustEnv("SSH_NO_SAFETY_CHECK")
	warnDeprecatedTrustEnv("SSH_FORCE")

	if timeoutStr := os.Getenv("SSH_TIMEOUT"); timeoutStr != "" {
		if d, err := parseTimeout(timeoutStr); err == nil {
			config.Timeout = d
		} else {
			config.Timeout = -1
		}
	}

	sudoKey := os.Getenv("SSH_SUDO_KEY")
	if sudoKey == "" {
		sudoKey = sshclient.DefaultSudoKey
	}
	config.SudoKey = sudoKey
	if sshPasswordKey := os.Getenv("SSH_PASSWORD_KEY"); sshPasswordKey != "" {
		config.SSHPasswordKey = sshPasswordKey
	}

	if len(args) > 1 {
		switch args[1] {
		case "plugin":
			parsePluginArgs(config, args[2:])
			return config
		case "skill":
			parseSkillArgs(config, args[2:])
			return config
		case "mcp":
			parseMCPArgs(config, args[2:])
			return config
		case "inspect":
			parseInspectArgs(config, args[2:])
			return config
		case "run":
			parseRunArgs(config, args[2:])
			return config
		case "sql":
			parseSQLArgs(config, args[2:])
			return config
		case "apply":
			parseApplyArgs(config, args[2:])
			return config
		}
	}

	commandParts := []string{}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if config.Mode == "ssh" && arg == "--" {
			commandParts = append(commandParts, args[i+1:]...)
			break
		}

		switch {
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="):
			config.Host = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case strings.HasPrefix(arg, "-pk="), strings.HasPrefix(arg, "--password-key="):
			config.SudoKey = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-key", arg == "--password-only":
			config.UseKeyAuth = false
			config.KeyPath = ""
		case arg == "--key-auth":
			config.UseKeyAuth = true
		case arg == "--force", arg == "-f":
			config.Force = true
		case strings.HasPrefix(arg, "--bypass-reason="):
			config.BypassReason = strings.SplitN(arg, "=", 2)[1]
		case arg == "--accept-unknown-host":
			config.AcceptUnknownHost = true
		case arg == "--insecure-hostkey":
			config.AllowInsecureHostKey = true
		case arg == "--strict-host-key":
			config.AllowInsecureHostKey = false
		case strings.HasPrefix(arg, "--known-hosts="):
			config.KnownHostsPath = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-safety-check":
			config.SafetyCheck = false
		case arg == "--dry-run":
			config.DryRun = true
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		case arg == "--json":
			config.JSONOutput = true
		case arg == "--pty":
			config.UsePTY = true
		case strings.HasPrefix(arg, "--timeout="):
			raw := strings.SplitN(arg, "=", 2)[1]
			if d, err := parseTimeout(raw); err == nil {
				config.Timeout = d
			} else {
				config.Timeout = -1
			}
		case arg == "--sftp":
			config.Mode = "sftp"
		case strings.HasPrefix(arg, "--upload="):
			config.Mode = "sftp"
			config.SftpAction = "upload"
			config.LocalPath = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--download="):
			config.Mode = "sftp"
			config.SftpAction = "download"
			config.RemotePath = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--transfer="):
			config.Mode = "transfer"
			config.TransferSrcHost, config.TransferSrcPath = splitHostPath(strings.SplitN(arg, "=", 2)[1])
		case strings.HasPrefix(arg, "--to="):
			switch {
			case config.Mode == "transfer":
				config.TransferDstHost, config.TransferDstPath = splitHostPath(strings.SplitN(arg, "=", 2)[1])
			case config.SftpAction == "upload":
				config.RemotePath = strings.SplitN(arg, "=", 2)[1]
			case config.SftpAction == "download":
				config.LocalPath = strings.SplitN(arg, "=", 2)[1]
			}
		case strings.HasPrefix(arg, "--list="), strings.HasPrefix(arg, "--ls="):
			config.Mode = "sftp"
			config.SftpAction = "list"
			config.RemotePath = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--mkdir="):
			config.Mode = "sftp"
			config.SftpAction = "mkdir"
			config.RemotePath = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--rm="):
			config.Mode = "sftp"
			config.SftpAction = "remove"
			config.RemotePath = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--password-set="):
			config.Mode = "password"
			config.PasswordAction = "set"
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) > 1 {
				keyValue := strings.SplitN(parts[1], ":", 2)
				config.PasswordKey = keyValue[0]
				if len(keyValue) > 1 {
					config.PasswordValue = keyValue[1]
				}
			}
		case strings.HasPrefix(arg, "--password-get="):
			config.Mode = "password"
			config.PasswordAction = "get"
			config.PasswordKey = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--password-delete="), strings.HasPrefix(arg, "--password-del="):
			config.Mode = "password"
			config.PasswordAction = "delete"
			config.PasswordKey = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--password-check="), strings.HasPrefix(arg, "--password-exists="):
			config.Mode = "password"
			config.PasswordAction = "check"
			config.PasswordKey = strings.SplitN(arg, "=", 2)[1]
		case arg == "--password-list" || arg == "--password-ls":
			config.Mode = "password"
			config.PasswordAction = "list"
		case arg == "--host-add":
			config.Mode = "host"
			config.HostAction = "add"
		case arg == "--host-import":
			config.Mode = "host"
			config.HostAction = "import"
		case strings.HasPrefix(arg, "--host-import="):
			config.Mode = "host"
			config.HostAction = "import"
			config.HostImportNames = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--ssh-config="):
			config.SSHConfigPath = strings.SplitN(arg, "=", 2)[1]
		case arg == "--host-update":
			config.Mode = "host"
			config.HostAction = "update"
		case arg == "--host-list" || arg == "--host-ls":
			config.Mode = "host"
			config.HostAction = "list"
		case strings.HasPrefix(arg, "--host-test="):
			config.Mode = "host"
			config.HostAction = "test"
			config.HostName = strings.SplitN(arg, "=", 2)[1]
		case arg == "--host-test-all":
			config.Mode = "host"
			config.HostAction = "test-all"
		case strings.HasPrefix(arg, "--host-remove="), strings.HasPrefix(arg, "--host-rm="):
			config.Mode = "host"
			config.HostAction = "remove"
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) > 1 {
				config.HostName = parts[1]
			}
		case strings.HasPrefix(arg, "--host-name="):
			config.HostName = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--host-desc="):
			config.HostDescription = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--host-type="):
			config.HostType = strings.SplitN(arg, "=", 2)[1]
		case arg == "--help":
			PrintUsage()
			os.Exit(0)
		default:
			if config.Mode == "ssh" {
				commandParts = append(commandParts, args[i:]...)
				i = len(args)
			}
		}
	}

	if config.Mode == "ssh" {
		if len(commandParts) > 0 {
			config.Command = strings.Join(commandParts, " ")
		}
	}

	return config
}

func parseSkillArgs(config *sshclient.Config, args []string) {
	config.Mode = "skill"
	// SSH_FORCE controls remote command safety and must never authorize
	// overwriting a local Agent trust asset. Only an explicit --force below may.
	config.Force = false
	if len(args) == 0 {
		return
	}
	config.SkillAction = args[0]
	for _, arg := range args[1:] {
		switch {
		case arg == "--json":
			config.JSONOutput = true
		case arg == "--force", arg == "-f":
			config.Force = true
		case strings.HasPrefix(arg, "--dir="):
			config.SkillDir = strings.SplitN(arg, "=", 2)[1]
			if config.SkillDir == "" {
				config.ArgumentError = "--dir must not be empty"
			}
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		case !strings.HasPrefix(arg, "-"):
			config.ArgumentError = fmt.Sprintf("unexpected skill argument %q", arg)
		default:
			config.ArgumentError = fmt.Sprintf("unknown skill option %q", arg)
		}
	}
}

func parsePluginArgs(config *sshclient.Config, args []string) {
	config.Mode = "plugin"
	if len(args) == 0 {
		return
	}
	config.PluginAction = args[0]
	for _, arg := range args[1:] {
		switch {
		case arg == "--json":
			config.JSONOutput = true
		case arg == "--dry-run":
			config.DryRun = true
		case arg == "--replace":
			config.PluginReplace = true
		case strings.HasPrefix(arg, "--runner="):
			config.PluginRunner = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--platform="):
			config.PluginPlatform = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--privilege="):
			config.PluginPrivilege = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--template="):
			config.PluginTemplate = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--fixture="):
			config.PluginFixture = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		case !strings.HasPrefix(arg, "-") && config.PluginID == "":
			config.PluginID = arg
		case !strings.HasPrefix(arg, "-"):
			config.ArgumentError = fmt.Sprintf("unexpected plugin argument %q", arg)
		default:
			config.ArgumentError = fmt.Sprintf("unknown plugin option %q", arg)
		}
	}
}

// warnDeprecatedTrustEnv emits a diagnostic when a high-risk env switch is set
// without applying it. Explicit CLI flags remain the only authorization path.
func warnDeprecatedTrustEnv(name string) {
	val := os.Getenv(name)
	if val == "" {
		return
	}
	if strings.EqualFold(val, "true") || val == "1" {
		fmt.Fprintf(os.Stderr, "sshx: ignoring deprecated trust env %s=%q; use an explicit CLI flag/request field instead\n", name, val)
	}
}

func parseRunArgs(config *sshclient.Config, args []string) {
	config.Mode = "run"
	config.FailureMode = "continue"
	config.RunConcurrency = 4
	commandParts := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			commandParts = append(commandParts, args[i+1:]...)
			break
		}
		switch {
		case strings.HasPrefix(arg, "--target="):
			name := strings.TrimSpace(strings.SplitN(arg, "=", 2)[1])
			if name != "" {
				config.RunTargets = append(config.RunTargets, name)
			}
		case strings.HasPrefix(arg, "--targets="):
			raw := strings.SplitN(arg, "=", 2)[1]
			for _, part := range strings.Split(raw, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					config.RunTargets = append(config.RunTargets, part)
				}
			}
		case strings.HasPrefix(arg, "--group="):
			g := strings.TrimSpace(strings.SplitN(arg, "=", 2)[1])
			if g != "" {
				config.RunGroups = append(config.RunGroups, g)
			}
		case strings.HasPrefix(arg, "--tag="):
			raw := strings.SplitN(arg, "=", 2)[1]
			kv := strings.SplitN(raw, "=", 2)
			if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" {
				config.ArgumentError = fmt.Sprintf("invalid --tag value %q (want key=value)", raw)
				continue
			}
			if config.RunTags == nil {
				config.RunTags = map[string]string{}
			}
			config.RunTags[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		case arg == "--all-hosts":
			config.RunAllHosts = true
		case strings.HasPrefix(arg, "--address="):
			config.RunAddress = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="):
			// Compatibility alias for a single strict target name.
			name := strings.TrimSpace(strings.SplitN(arg, "=", 2)[1])
			if name != "" {
				config.RunTargets = append(config.RunTargets, name)
			}
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case strings.HasPrefix(arg, "-pk="), strings.HasPrefix(arg, "--password-key="), strings.HasPrefix(arg, "--sudo-password-key="):
			config.SudoKey = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--ssh-password-key="):
			config.SSHPasswordKey = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-key", arg == "--password-only":
			config.UseKeyAuth = false
			config.KeyPath = ""
		case arg == "--key-auth":
			config.UseKeyAuth = true
		case arg == "--force", arg == "-f":
			config.Force = true
		case arg == "--no-safety-check":
			config.SafetyCheck = false
		case strings.HasPrefix(arg, "--bypass-reason="):
			config.BypassReason = strings.SplitN(arg, "=", 2)[1]
		case arg == "--accept-unknown-host":
			config.AcceptUnknownHost = true
		case arg == "--insecure-hostkey":
			config.AllowInsecureHostKey = true
		case arg == "--strict-host-key":
			config.AllowInsecureHostKey = false
		case strings.HasPrefix(arg, "--known-hosts="):
			config.KnownHostsPath = strings.SplitN(arg, "=", 2)[1]
		case arg == "--dry-run":
			config.DryRun = true
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		case arg == "--json":
			config.JSONOutput = true
		case arg == "--jsonl":
			config.JSONLOutput = true
			config.JSONOutput = true
		case strings.HasPrefix(arg, "--timeout="):
			raw := strings.SplitN(arg, "=", 2)[1]
			if d, err := parseTimeout(raw); err == nil {
				config.Timeout = d
			} else {
				config.Timeout = -1
			}
		case strings.HasPrefix(arg, "--concurrency="):
			raw := strings.SplitN(arg, "=", 2)[1]
			n, err := strconv.Atoi(raw)
			if err != nil || n <= 0 {
				config.ArgumentError = fmt.Sprintf("invalid --concurrency value %q", raw)
			} else {
				config.RunConcurrency = n
			}
		case strings.HasPrefix(arg, "--failure-mode="):
			config.FailureMode = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--intent="):
			config.RunIntent = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--request-id="):
			config.RequestID = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--script-file="):
			config.ScriptFile = strings.SplitN(arg, "=", 2)[1]
			config.RunActionKind = "script"
		case arg == "--script-stdin":
			config.ScriptStdin = true
			config.RunActionKind = "script"
		case arg == "--sudo":
			config.RunUseSudo = true
		case strings.HasPrefix(arg, "--max-output-bytes="):
			raw := strings.SplitN(arg, "=", 2)[1]
			n, err := strconv.Atoi(raw)
			if err != nil || n <= 0 {
				config.ArgumentError = fmt.Sprintf("invalid --max-output-bytes value %q", raw)
			} else {
				config.MaxOutputBytes = n
			}
		case strings.HasPrefix(arg, "--max-payload-bytes="):
			raw := strings.SplitN(arg, "=", 2)[1]
			n, err := strconv.Atoi(raw)
			if err != nil || n <= 0 {
				config.ArgumentError = fmt.Sprintf("invalid --max-payload-bytes value %q", raw)
			} else {
				config.MaxPayloadBytes = n
			}
		case strings.HasPrefix(arg, "--host-group="):
			// Host management convenience while adding hosts is separate; ignore here.
			config.ArgumentError = fmt.Sprintf("unknown run option %q (did you mean --group=)", arg)
		case !strings.HasPrefix(arg, "-"):
			commandParts = append(commandParts, args[i:]...)
			i = len(args)
		default:
			config.ArgumentError = fmt.Sprintf("unknown run option %q", arg)
		}
	}
	if len(commandParts) > 0 {
		config.Command = strings.Join(commandParts, " ")
		if config.RunActionKind == "" {
			config.RunActionKind = "command"
		}
	}
}

// parseSQLArgs parses the `sshx sql` guarded SQL execution subcommand. The
// SQL statement is the positional argument (or everything after `--`).
func parseSQLArgs(config *sshclient.Config, args []string) {
	config.Mode = "sql"
	config.SQLEngine = sqlsafe.EnginePostgres
	sqlParts := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			sqlParts = append(sqlParts, args[i+1:]...)
			break
		}
		switch {
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="):
			config.Host = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case strings.HasPrefix(arg, "-pk="), strings.HasPrefix(arg, "--password-key="):
			config.SudoKey = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--ssh-password-key="):
			config.SSHPasswordKey = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-key", arg == "--password-only":
			config.UseKeyAuth = false
			config.KeyPath = ""
		case arg == "--key-auth":
			config.UseKeyAuth = true
		case arg == "--accept-unknown-host":
			config.AcceptUnknownHost = true
		case arg == "--insecure-hostkey":
			config.AllowInsecureHostKey = true
		case arg == "--strict-host-key":
			config.AllowInsecureHostKey = false
		case strings.HasPrefix(arg, "--known-hosts="):
			config.KnownHostsPath = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--engine="):
			config.SQLEngine = sqlsafe.NormalizeEngine(strings.SplitN(arg, "=", 2)[1])
		case strings.HasPrefix(arg, "--db="), strings.HasPrefix(arg, "--database="):
			config.SQLDatabase = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--db-file="):
			config.SQLFile = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--db-user="):
			config.SQLUser = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--db-host="):
			config.SQLHost = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--db-port="):
			config.SQLPort = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--db-password-key="):
			config.SQLPasswordKey = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--row-threshold="):
			raw := strings.SplitN(arg, "=", 2)[1]
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || n <= 0 {
				config.ArgumentError = fmt.Sprintf("invalid --row-threshold value %q", raw)
			} else {
				config.SQLRowThreshold = n
			}
		case arg == "--allow-full-table":
			config.SQLAllowFullTable = true
		case arg == "--no-backup":
			config.SQLNoBackup = true
		case arg == "--explain":
			config.SQLExplainOnly = true
		case strings.HasPrefix(arg, "--backup-dir="):
			config.SQLBackupDir = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--docker="):
			config.SQLDockerContainer = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--db-cred-from="):
			config.SQLCredFrom = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--cred-cache="):
			raw := strings.SplitN(arg, "=", 2)[1]
			if raw == "off" {
				config.SQLCredCacheTTL = 0
			} else if d, err := parseTimeout(raw); err == nil && d > 0 {
				config.SQLCredCacheTTL = d
			} else {
				config.ArgumentError = fmt.Sprintf("invalid --cred-cache value %q (use off or a duration like 15m)", raw)
			}
		case arg == "--cred-refresh":
			config.SQLCredRefresh = true
		case arg == "--force", arg == "-f":
			config.Force = true
		case arg == "--dry-run":
			config.DryRun = true
		case arg == "--json":
			config.JSONOutput = true
		case strings.HasPrefix(arg, "--timeout="):
			raw := strings.SplitN(arg, "=", 2)[1]
			if d, err := parseTimeout(raw); err == nil {
				config.Timeout = d
			} else {
				config.Timeout = -1
			}
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		case !strings.HasPrefix(arg, "-"):
			sqlParts = append(sqlParts, args[i:]...)
			i = len(args)
		default:
			config.ArgumentError = fmt.Sprintf("unknown sql option %q", arg)
		}
	}
	config.SQLStatement = strings.TrimSpace(strings.Join(sqlParts, " "))

	// Password auth implies TCP: peer/ident auth on the local socket ignores
	// PGPASSWORD, so default the database host to loopback in that case.
	// Docker mode is exempt: inside the container the local socket works and
	// PGPASSWORD is forwarded through docker exec when needed.
	if config.SQLPasswordKey != "" && config.SQLHost == "" && config.SQLDockerContainer == "" {
		config.SQLHost = "127.0.0.1"
	}
	// Remote credential resolution defaults to a short-lived local cache so
	// repeated statements don't re-read the production environment.
	if config.SQLCredFrom != "" && config.SQLCredCacheTTL == 0 && !sqlCredCacheExplicit(args) {
		config.SQLCredCacheTTL = DefaultCredCacheTTL
	}
}

// parseApplyArgs parses the `sshx apply` guarded file-mutation subcommand.
func parseApplyArgs(config *sshclient.Config, args []string) {
	config.Mode = "apply"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			config.ArgumentError = "apply does not take a positional command; use --from= and --path="
			return
		}
		switch {
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="), strings.HasPrefix(arg, "--target="):
			config.Host = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case strings.HasPrefix(arg, "-pk="), strings.HasPrefix(arg, "--password-key="):
			config.SudoKey = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--ssh-password-key="):
			config.SSHPasswordKey = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-key", arg == "--password-only":
			config.UseKeyAuth = false
			config.KeyPath = ""
		case arg == "--key-auth":
			config.UseKeyAuth = true
		case arg == "--accept-unknown-host":
			config.AcceptUnknownHost = true
		case arg == "--insecure-hostkey":
			config.AllowInsecureHostKey = true
		case arg == "--strict-host-key":
			config.AllowInsecureHostKey = false
		case strings.HasPrefix(arg, "--known-hosts="):
			config.KnownHostsPath = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--path="):
			config.RemotePath = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--from="):
			config.LocalPath = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--expect-sha256="):
			config.ApplyExpectSHA256 = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--backup-dir="):
			config.ApplyBackupDir = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-backup":
			config.ApplyNoBackup = true
		case arg == "--sudo":
			config.ApplyUseSudo = true
		case arg == "--force", arg == "-f":
			config.Force = true
		case strings.HasPrefix(arg, "--bypass-reason="):
			config.BypassReason = strings.SplitN(arg, "=", 2)[1]
		case arg == "--dry-run":
			config.DryRun = true
		case arg == "--json":
			config.JSONOutput = true
		case strings.HasPrefix(arg, "--timeout="):
			raw := strings.SplitN(arg, "=", 2)[1]
			if d, err := parseTimeout(raw); err == nil {
				config.Timeout = d
			} else {
				config.Timeout = -1
			}
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		default:
			config.ArgumentError = fmt.Sprintf("unknown apply option %q", arg)
		}
	}
}

// sqlCredCacheExplicit reports whether the operator explicitly set
// --cred-cache (including --cred-cache=off, which must stay off).
func sqlCredCacheExplicit(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if strings.HasPrefix(arg, "--cred-cache=") {
			return true
		}
	}
	return false
}

func parseInspectArgs(config *sshclient.Config, args []string) {
	config.Mode = "inspect"
	config.InspectCacheMode = "off"
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="):
			config.Host = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case strings.HasPrefix(arg, "-pk="), strings.HasPrefix(arg, "--password-key="):
			config.SudoKey = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-key", arg == "--password-only":
			config.UseKeyAuth = false
			config.KeyPath = ""
		case arg == "--key-auth":
			config.UseKeyAuth = true
		case arg == "--accept-unknown-host":
			config.AcceptUnknownHost = true
		case arg == "--insecure-hostkey":
			config.AllowInsecureHostKey = true
		case arg == "--strict-host-key":
			config.AllowInsecureHostKey = false
		case strings.HasPrefix(arg, "--known-hosts="):
			config.KnownHostsPath = strings.SplitN(arg, "=", 2)[1]
		case arg == "--json":
			config.JSONOutput = true
		case arg == "--dry-run":
			config.DryRun = true
		case arg == "--refresh":
			config.InspectRefresh = true
		case arg == "--allow-stale":
			config.InspectAllowStale = true
		case arg == "--sudo":
			config.InspectUseSudo = true
		case strings.HasPrefix(arg, "--cache="):
			config.InspectCacheMode = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--max-age="):
			raw := strings.SplitN(arg, "=", 2)[1]
			if duration, err := parseTimeout(raw); err == nil {
				config.InspectMaxAge = duration
			} else {
				config.InspectMaxAge = -1
			}
		case strings.HasPrefix(arg, "--timeout="):
			raw := strings.SplitN(arg, "=", 2)[1]
			if duration, err := parseTimeout(raw); err == nil {
				config.Timeout = duration
			} else {
				config.Timeout = -1
			}
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		case !strings.HasPrefix(arg, "-") && config.InspectCapability == "":
			config.InspectCapability = arg
		case !strings.HasPrefix(arg, "-"):
			config.ArgumentError = fmt.Sprintf("unexpected inspection argument %q", arg)
		default:
			config.ArgumentError = fmt.Sprintf("unknown inspection option %q", arg)
		}
	}
}
