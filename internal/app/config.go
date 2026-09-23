package app

import (
	"fmt"
	"io"
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

// applyBindFlag records --bind=VALUE, including an explicit empty value that
// must override a named host's persisted bind.
func applyBindFlag(config *sshclient.Config, arg string) bool {
	if !strings.HasPrefix(arg, "--bind=") {
		return false
	}
	config.Bind = strings.SplitN(arg, "=", 2)[1]
	config.BindSet = true
	return true
}

func applyViaFlag(config *sshclient.Config, arg string) bool {
	if !strings.HasPrefix(arg, "--via=") {
		return false
	}
	config.Via = strings.SplitN(arg, "=", 2)[1]
	config.ViaSet = true
	return true
}

// applySudoKeyFlag records -pk/--password-key/--sudo-password-key, including
// an explicit empty value that must not be confused with the runtime default.
func applySudoKeyFlag(config *sshclient.Config, arg string) bool {
	switch {
	case strings.HasPrefix(arg, "-pk="), strings.HasPrefix(arg, "--password-key="), strings.HasPrefix(arg, "--sudo-password-key="):
		config.SudoKey = strings.SplitN(arg, "=", 2)[1]
		config.SudoKeySet = true
		return true
	default:
		return false
	}
}

// sudoKeyChosen reports whether the caller chose the sudo keyring reference:
// -pk/--password-key/--sudo-password-key, or a non-default SSH_SUDO_KEY. The
// built-in default ("master") is not a choice, so a host's configured
// sudo_password_key applies until the caller overrides it.
func sudoKeyChosen(config *sshclient.Config) bool {
	return config.SudoKeySet || config.SudoKey != sshclient.DefaultSudoKey
}

// sudoKeyChoice returns the caller's explicit sudo key, or "" when the key is
// still the built-in default.
func sudoKeyChoice(config *sshclient.Config) string {
	if sudoKeyChosen(config) {
		return config.SudoKey
	}
	return ""
}

func applyLifecycleFlag(config *sshclient.Config, arg string) bool {
	key, value, found := strings.Cut(arg, "=")
	if !found {
		return false
	}
	switch key {
	case "--expect-plan":
		config.ExpectPlan = value
		if value == "" {
			config.ArgumentError = "--expect-plan requires a digest"
		}
	case "--host-timeout", "--global-timeout":
		duration, err := parseTimeout(value)
		if err != nil {
			config.ArgumentError = fmt.Sprintf("invalid %s: %v", key, err)
		} else if key == "--host-timeout" {
			config.HostTimeout = duration
		} else {
			config.GlobalTimeout = duration
		}
	default:
		return false
	}
	return true
}

// scanVerbFlags scans sshx's own options in a verb invocation before the
// payload starts. It stops at the `--` separator and, for verbs whose first
// positional token begins a remote payload (compatibility mode, run, sql, ros),
// at that token: from there on every argument belongs to the payload, including
// tokens that look like sshx flags (see AGENT.md "Boundary Contracts").
//
// It returns the arguments with the notice flags removed, plus the requested
// --help / --json / --quiet state. --quiet is stripped because the CLI answers
// it before any parser runs; --help and --json stay in the list, so a global
// usage request still reaches the compatibility-mode parser and every parser
// keeps owning --json.
func scanVerbFlags(verb string, args []string) (rest []string, help, jsonOutput, quiet bool) {
	stopAtPayload := verb == "" || verb == "run" || verb == "sql" || verb == "ros"
	rest = make([]string, 0, len(args))
	for i, arg := range args {
		if arg == "--" || stopAtPayload && !strings.HasPrefix(arg, "-") {
			rest = append(rest, args[i:]...)
			break
		}
		switch arg {
		case "--help":
			help = true
			rest = append(rest, arg)
		case "--quiet", "--no-notices":
			quiet = true
		default:
			if arg == "--json" {
				jsonOutput = true
			}
			rest = append(rest, arg)
		}
	}
	return rest, help, jsonOutput, quiet
}

// knownVerb reports whether the first argument selects a subcommand parser
// rather than compatibility mode.
func knownVerb(verb string) string {
	if containsString(helpVerbs, verb) {
		return verb
	}
	return ""
}

// compatOptionNames are the sshx-owned options accepted in compatibility mode
// before the remote command starts. It feeds the "did you mean" suggestion for
// an unrecognized option; TestCompatOptionNamesAreRecognized fails when an entry
// is not actually parsed, so the list cannot drift into fiction.
var compatOptionNames = []string{
	"-h", "--host", "-p", "--port", "-u", "--user", "-i", "--key",
	"-pk", "--password-key", "--sudo-password-key", "--ssh-password-key",
	"--no-key", "--password-only", "--key-auth", "--force", "-f",
	"--bypass-reason", "--accept-unknown-host", "--insecure-hostkey",
	"--strict-host-key", "--known-hosts", "--no-safety-check", "--dry-run",
	"--audit-output", "--no-audit", "--json", "--pty", "--timeout",
	"--expect-plan", "--host-timeout", "--global-timeout", "--bind", "--via",
	"--sftp", "--upload", "--download", "--transfer", "--to", "--list", "--ls",
	"--mkdir", "--rm", "--password-set", "--password-get", "--password-delete",
	"--password-del", "--password-check", "--password-exists", "--password-list",
	"--password-ls", "--host-add", "--host-import", "--ssh-config",
	"--host-update", "--host-list", "--host-ls", "--host-test", "--host-test-all",
	"--host-remove", "--host-rm", "--host-name", "--host-desc", "--host-type",
}

// compatOptionHints explains the options callers most often guess at. They are
// not aliases: the upload/download surface is --upload=<local> or
// --download=<remote> plus --to=<destination>, and the guessed --local/--remote
// pair is silently useless, so name the real surface instead of only the typo.
var compatOptionHints = map[string]string{
	"--local":  "use --upload=<local-file> --to=<remote-path> (or --download=<remote-file> --to=<local-path>)",
	"--remote": "use --download=<remote-file> --to=<local-path> (or --upload=<local-file> --to=<remote-path>)",
}

// unknownCompatOption describes an option-shaped token that compatibility mode
// does not recognize. Before this rule the token was forwarded as part of the
// remote command, so a misspelled option ran something the caller never asked
// for and the resulting failure named the wrong cause.
func unknownCompatOption(token string) string {
	name := token
	if index := strings.Index(name, "="); index >= 0 {
		name = name[:index]
	}
	if hint, ok := compatOptionHints[name]; ok {
		return fmt.Sprintf("unknown option %q: %s", token, hint)
	}
	if suggestion := closestCompatOption(name); suggestion != "" {
		return fmt.Sprintf("unknown option %q (did you mean %q?); sshx options come before the remote command, and a command that starts with \"-\" must follow --", token, suggestion)
	}
	return fmt.Sprintf("unknown option %q; sshx options come before the remote command, and a command that starts with \"-\" must follow --", token)
}

// closestCompatOption returns the compatibility option nearest to an
// unrecognized one, or "" when nothing is close enough to suggest.
func closestCompatOption(name string) string {
	return closestOptionName(name, compatOptionNames)
}

// closestOptionName returns the known option nearest to an unrecognized token.
// Short names are specific, so they tolerate only one wrong character while
// longer names tolerate two, and one-character options are never suggested:
// each of them is one edit away from every other.
func closestOptionName(name string, candidates []string) string {
	long := strings.HasPrefix(name, "--")
	best, bestDistance := "", 3
	for _, candidate := range candidates {
		if strings.HasPrefix(candidate, "--") != long {
			continue
		}
		bare := strings.TrimLeft(candidate, "-")
		if len(bare) < 2 {
			continue
		}
		limit := 2
		if len(bare) <= 3 {
			limit = 1
		}
		if distance := levenshtein(name, candidate); distance <= limit && distance < bestDistance {
			best, bestDistance = candidate, distance
		}
	}
	return best
}

// levenshtein returns the edit distance between two option names.
func levenshtein(a, b string) int {
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			substitution := previous[j-1]
			if a[i-1] != b[j-1] {
				substitution++
			}
			current[j] = min(previous[j]+1, current[j-1]+1, substitution)
		}
		previous, current = current, previous
	}
	return previous[len(b)]
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

	// sshx's own flags come before the payload, so scan them once here: --quiet
	// must be known before the first notice is emitted, and --help must answer
	// before any parser can reject it as an unknown option. Compatibility mode
	// starts at the first argument (an sshx option or the remote command); a
	// subcommand starts after its verb.
	verb := ""
	scanFrom := 1
	if len(args) > 1 {
		verb = args[1]
		if knownVerb(verb) != "" {
			scanFrom = 2
		}
	}
	verbArgs := []string(nil)
	var help, jsonOutput bool
	if len(args) > scanFrom {
		verbArgs, help, jsonOutput, config.Quiet = scanVerbFlags(knownVerb(verb), args[scanFrom:])
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
	warnDeprecatedTrustEnv(config, "SSH_ACCEPT_UNKNOWN_HOST")
	warnDeprecatedTrustEnv(config, "SSH_INSECURE_HOST_KEY")
	warnDeprecatedTrustEnv(config, "SSH_NO_SAFETY_CHECK")
	warnDeprecatedTrustEnv(config, "SSH_FORCE")

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
		if help {
			if verb = knownVerb(verb); verb != "" {
				config.HelpVerb = verb
				config.JSONOutput = jsonOutput
			} else {
				config.ShowUsage = true
			}
			return config
		}
		switch verb {
		case "plugin":
			parsePluginArgs(config, verbArgs)
			return config
		case "skill":
			parseSkillArgs(config, verbArgs)
			return config
		case "mcp":
			parseMCPArgs(config, verbArgs)
			return config
		case "inspect":
			parseInspectArgs(config, verbArgs)
			return config
		case "run":
			parseRunArgs(config, verbArgs)
			return config
		case "sql":
			parseSQLArgs(config, verbArgs)
			return config
		case "apply":
			parseApplyArgs(config, verbArgs)
			return config
		case "text":
			parseTextArgs(config, verbArgs)
			return config
		case "audit":
			parseAuditArgs(config, verbArgs)
			return config
		case "login":
			parseLoginArgs(config, verbArgs)
			return config
		case "ros":
			parseROSArgs(config, verbArgs)
			return config
		}
		// Compatibility mode: the scanned list already carries the first
		// argument unless it was an sshx notice flag.
		args = append([]string{args[0]}, verbArgs...)
	}

	commandParts := []string{}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if config.Mode == "ssh" && arg == "--" {
			commandParts = append(commandParts, args[i+1:]...)
			break
		}

		switch {
		case applyLifecycleFlag(config, arg):
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="):
			config.Host = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case applySudoKeyFlag(config, arg):
		case strings.HasPrefix(arg, "--ssh-password-key="):
			config.SSHPasswordKey = strings.SplitN(arg, "=", 2)[1]
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
		case applyBindFlag(config, arg):
		case applyViaFlag(config, arg):
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
			// Unreachable through ParseArgs (the pre-scan answers --help in option
			// position), kept for callers that build a compatibility argument list.
			config.ShowUsage = true
			return config
		case strings.HasPrefix(arg, "-"):
			// Option position: everything here must be an sshx option. Forwarding
			// an unrecognized token as a command made typos execute with defaults
			// and produced an error that named the wrong cause.
			config.ArgumentError = unknownCompatOption(arg)
			return config
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
		case arg == "--trust":
			config.PluginTrust = true
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
		case !strings.HasPrefix(arg, "-") && config.PluginID == "" && config.PluginSource == "":
			// The install positional names the source directory; every other
			// action takes a plugin id.
			if config.PluginAction == "install" {
				config.PluginSource = arg
			} else {
				config.PluginID = arg
			}
		case !strings.HasPrefix(arg, "-"):
			config.ArgumentError = fmt.Sprintf("unexpected plugin argument %q", arg)
		default:
			config.ArgumentError = fmt.Sprintf("unknown plugin option %q", arg)
		}
	}
}

// warnDeprecatedTrustEnv emits a diagnostic when a high-risk env switch is set
// without applying it. Explicit CLI flags remain the only authorization path.
func warnDeprecatedTrustEnv(config *sshclient.Config, name string) {
	val := os.Getenv(name)
	if val == "" || config != nil && config.Quiet {
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
		case applyLifecycleFlag(config, arg):
		case arg == "--fail-fast":
			config.FailureMode = "fail_fast"
		case strings.HasPrefix(arg, "--max-failures="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "--max-failures="))
			if err != nil || n <= 0 {
				config.ArgumentError = "--max-failures requires a positive integer"
			} else {
				config.MaxFailures = n
			}
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
		case applySudoKeyFlag(config, arg):
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
		case applyBindFlag(config, arg):
		case applyViaFlag(config, arg):
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
		case strings.HasPrefix(arg, "--shell="):
			config.ScriptShell = strings.SplitN(arg, "=", 2)[1]
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

// sqlOptionNames are the options accepted by `sshx sql` before the statement
// starts. It feeds the "did you mean" suggestion for an unrecognized option;
// TestSQLOptionNamesAreRecognized fails when an entry is not actually parsed.
var sqlOptionNames = []string{
	"-h", "--host", "-p", "--port", "-u", "--user", "-i", "--key", "-pk",
	"--password-key", "--sudo-password-key", "--ssh-password-key", "--no-key",
	"--password-only", "--key-auth", "--accept-unknown-host", "--insecure-hostkey",
	"--strict-host-key", "--known-hosts", "--engine", "--db", "--database",
	"--db-file", "--db-user", "--db-host", "--db-port", "--db-password-key",
	"--statement-file", "--row-threshold", "--allow-full-table", "--no-backup",
	"--explain", "--backup-dir", "--docker", "--db-cred-from", "--cred-cache",
	"--cred-refresh", "--sudo", "--force", "-f", "--dry-run", "--json",
	"--timeout", "--bind", "--via", "--audit-output", "--no-audit",
	"--bypass-reason", "--expect-plan", "--host-timeout", "--global-timeout",
}

// sqlStatementToken reports whether an argument can only be statement text
// rather than an sshx option. SQL files, migrations, and dumps conventionally
// open with a comment header ("-- ..."), which is exactly a token that starts
// with "--" but cannot be an option because its name part contains whitespace.
func sqlStatementToken(arg string) bool {
	if !strings.HasPrefix(arg, "--") {
		return false
	}
	name, _, _ := strings.Cut(arg, "=")
	return strings.ContainsAny(name, " \t\r\n")
}

// unknownSQLOption describes an option-shaped SQL token. A statement that opens
// with a comment can look like an option, so the message names every way to pass
// a statement that begins with "-".
func unknownSQLOption(token string) string {
	name, _, _ := strings.Cut(token, "=")
	if suggestion := closestSQLOption(name); suggestion != "" {
		return fmt.Sprintf("unknown sql option %q (did you mean %q?); a statement is accepted as a positional argument, after --, via --statement-file=PATH, or on stdin", token, suggestion)
	}
	return fmt.Sprintf("unknown sql option %q; a statement is accepted as a positional argument, after --, via --statement-file=PATH, or on stdin", token)
}

// closestSQLOption returns the known sql option nearest to an unrecognized one.
func closestSQLOption(name string) string {
	return closestOptionName(name, sqlOptionNames)
}

// maxSQLStatementBytes bounds a statement read from a file or stdin so a stray
// stream cannot be buffered into memory.
const maxSQLStatementBytes = 1 << 20

// readSQLStatement loads one statement from a local file or, when stdin is
// piped rather than a terminal, from stdin. An empty pipe returns "" so the
// caller keeps its "statement is required" diagnostic.
func readSQLStatement(path string) (string, error) {
	if path != "" {
		data, err := os.ReadFile(path) // #nosec G304 -- caller-selected local statement file.
		if err != nil {
			return "", fmt.Errorf("read --statement-file: %w", err)
		}
		if len(data) > maxSQLStatementBytes {
			return "", fmt.Errorf("--statement-file %s exceeds %d bytes", path, maxSQLStatementBytes)
		}
		return string(data), nil
	}
	info, err := os.Stdin.Stat()
	if err != nil {
		return "", nil
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return "", nil
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxSQLStatementBytes+1))
	if err != nil {
		return "", fmt.Errorf("read SQL statement from stdin: %w", err)
	}
	if len(data) > maxSQLStatementBytes {
		return "", fmt.Errorf("SQL statement on stdin exceeds %d bytes", maxSQLStatementBytes)
	}
	return string(data), nil
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
		case applyLifecycleFlag(config, arg):
		case strings.HasPrefix(arg, "--bypass-reason="):
			config.BypassReason = strings.TrimPrefix(arg, "--bypass-reason=")
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="):
			config.Host = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case applySudoKeyFlag(config, arg):
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
		case strings.HasPrefix(arg, "--statement-file="):
			config.SQLStatementFile = strings.SplitN(arg, "=", 2)[1]
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
		case arg == "--sudo":
			config.SQLUseSudo = true
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
		case applyBindFlag(config, arg):
		case applyViaFlag(config, arg):
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		case strings.HasPrefix(arg, "--") && sqlStatementToken(arg):
			// A comment-leading statement is statement text, not an option.
			sqlParts = append(sqlParts, args[i:]...)
			i = len(args)
		case !strings.HasPrefix(arg, "-"):
			sqlParts = append(sqlParts, args[i:]...)
			i = len(args)
		default:
			config.ArgumentError = unknownSQLOption(arg)
		}
	}
	config.SQLStatement = strings.TrimSpace(strings.Join(sqlParts, " "))
	switch {
	case config.ArgumentError != "":
	case config.SQLStatement != "" && config.SQLStatementFile != "":
		config.ArgumentError = "--statement-file cannot be combined with a positional SQL statement"
	case config.SQLStatementFile != "":
		statement, readErr := readSQLStatement(config.SQLStatementFile)
		if readErr != nil {
			config.ArgumentError = readErr.Error()
		} else {
			config.SQLStatement = strings.TrimSpace(statement)
		}
	case config.SQLStatement == "":
		statement, readErr := readSQLStatement("")
		if readErr != nil {
			config.ArgumentError = readErr.Error()
		} else {
			config.SQLStatement = strings.TrimSpace(statement)
		}
	}

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
		case applyLifecycleFlag(config, arg):
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="), strings.HasPrefix(arg, "--target="):
			config.Host = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case applySudoKeyFlag(config, arg):
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
		case applyBindFlag(config, arg):
		case applyViaFlag(config, arg):
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		default:
			config.ArgumentError = fmt.Sprintf("unknown apply option %q", arg)
		}
	}
}

func parseTextArgs(config *sshclient.Config, args []string) {
	config.Mode = "text"
	config.TextRedact = true
	for _, arg := range args {
		switch {
		case applyLifecycleFlag(config, arg):
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="), strings.HasPrefix(arg, "--target="):
			config.Host = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case applySudoKeyFlag(config, arg):
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
		case strings.HasPrefix(arg, "--journal="):
			config.TextJournal = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--since="):
			config.TextSince = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--until="):
			config.TextUntil = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--preset="):
			config.TextPresets = append(config.TextPresets, strings.SplitN(arg, "=", 2)[1])
		case strings.HasPrefix(arg, "--pattern="):
			config.TextPattern = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--context="):
			n, err := strconv.Atoi(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				config.ArgumentError = fmt.Sprintf("invalid --context: %v", err)
			} else {
				config.TextContext = n
			}
		case strings.HasPrefix(arg, "--around-line="):
			n, err := strconv.Atoi(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				config.ArgumentError = fmt.Sprintf("invalid --around-line: %v", err)
			} else {
				config.TextAroundLine = n
			}
		case strings.HasPrefix(arg, "--offset="):
			n, err := strconv.Atoi(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				config.ArgumentError = fmt.Sprintf("invalid --offset: %v", err)
			} else {
				config.TextOffset = n
			}
		case strings.HasPrefix(arg, "--limit="):
			n, err := strconv.Atoi(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				config.ArgumentError = fmt.Sprintf("invalid --limit: %v", err)
			} else {
				config.TextLimit = n
			}
		case strings.HasPrefix(arg, "--tail="):
			n, err := strconv.Atoi(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				config.ArgumentError = fmt.Sprintf("invalid --tail: %v", err)
			} else {
				config.TextTail = n
			}
		case strings.HasPrefix(arg, "--scan="):
			config.TextScan = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--max-hits="):
			n, err := strconv.Atoi(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				config.ArgumentError = fmt.Sprintf("invalid --max-hits: %v", err)
			} else {
				config.TextMaxHits = n
			}
		case strings.HasPrefix(arg, "--max-bytes="):
			n, err := parseByteCount(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				config.ArgumentError = fmt.Sprintf("invalid --max-bytes: %v", err)
			} else {
				config.TextMaxBytes = int(n)
			}
		case strings.HasPrefix(arg, "--max-scan-bytes="):
			n, err := parseByteCount(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				config.ArgumentError = fmt.Sprintf("invalid --max-scan-bytes: %v", err)
			} else {
				config.TextMaxScanBytes = n
			}
		case arg == "--sudo":
			config.TextUseSudo = true
		case arg == "--no-redact":
			config.TextRedact = false
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
		case applyBindFlag(config, arg):
		case applyViaFlag(config, arg):
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		case arg == "--command", strings.HasPrefix(arg, "--command="):
			config.ArgumentError = "sshx text does not accept --command; use --path or --journal"
		default:
			config.ArgumentError = fmt.Sprintf("unknown text option %q", arg)
		}
	}
}

func parseByteCount(raw string) (int64, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(value, "k"):
		mult = 1024
		value = strings.TrimSuffix(value, "k")
	case strings.HasSuffix(value, "m"):
		mult = 1024 * 1024
		value = strings.TrimSuffix(value, "m")
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("negative size")
	}
	return n * mult, nil
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
		case applyLifecycleFlag(config, arg):
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="):
			config.Host = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case applySudoKeyFlag(config, arg):
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
		case applyBindFlag(config, arg):
		case applyViaFlag(config, arg):
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

func parseAuditArgs(config *sshclient.Config, args []string) {
	config.Mode = "audit"
	config.AuditEnabled = false
	if len(args) == 0 {
		config.ArgumentError = "audit action is required: query or export"
		return
	}
	config.AuditAction = args[0]
	for _, arg := range args[1:] {
		switch {
		case strings.HasPrefix(arg, "--execution-id="):
			config.AuditExecutionID = strings.TrimPrefix(arg, "--execution-id=")
		case arg == "--json":
			config.JSONOutput = true
		case arg == "--bypass-only":
			config.AuditBypassOnly = true
		case strings.HasPrefix(arg, "--since="):
			config.AuditSince = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--until="):
			config.AuditUntil = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--target="):
			config.AuditFilterHost = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--action="):
			config.AuditFilterAct = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--run-id="):
			config.AuditRunID = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--error-kind="):
			config.AuditErrorKind = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--to="):
			config.AuditExportPath = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		case !strings.HasPrefix(arg, "-"):
			config.ArgumentError = fmt.Sprintf("unexpected audit argument %q", arg)
		default:
			config.ArgumentError = fmt.Sprintf("unknown audit option %q", arg)
		}
	}
}

// parseROSArgs parses the `sshx ros` MikroTik RouterOS subcommand.
func parseROSArgs(config *sshclient.Config, args []string) {
	config.Mode = "ros"
	var tokens []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			tokens = append(tokens, args[i+1:]...)
			break
		}
		switch {
		case applyLifecycleFlag(config, arg):
		case strings.HasPrefix(arg, "--bypass-reason="):
			config.BypassReason = strings.TrimPrefix(arg, "--bypass-reason=")
		case strings.HasPrefix(arg, "-h="), strings.HasPrefix(arg, "--host="):
			config.Host = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-p="), strings.HasPrefix(arg, "--port="):
			config.Port = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-u="), strings.HasPrefix(arg, "--user="):
			config.User = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "-i="), strings.HasPrefix(arg, "--key="):
			config.KeyPath = strings.SplitN(arg, "=", 2)[1]
			config.UseKeyAuth = true
		case applySudoKeyFlag(config, arg):
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
		case applyBindFlag(config, arg):
		case strings.HasPrefix(arg, "--timeout="):
			raw := strings.SplitN(arg, "=", 2)[1]
			if d, err := parseTimeout(raw); err == nil {
				config.Timeout = d
			} else {
				config.Timeout = -1
			}
		case arg == "--dry-run":
			config.DryRun = true
		case arg == "--json":
			config.JSONOutput = true
		case arg == "--allow-write":
			config.ROSAllowWrite = true
		case arg == "--force", arg == "-f":
			config.Force = true
		case arg == "--raw":
			config.ROSRaw = true
		case strings.HasPrefix(arg, "--routeros-version="), strings.HasPrefix(arg, "--ros-version="): //nolint:misspell // domain name for MikroTik RouterOS
			config.ROSRouterOSVersion = strings.SplitN(arg, "=", 2)[1]
		case strings.HasPrefix(arg, "--source="):
			config.ROSSource = strings.TrimPrefix(strings.SplitN(arg, "=", 2)[1], "@")
		case arg == "--cleanup":
			config.ROSCleanup = true
		case arg == "--compact":
			config.ROSCompact = true
		case strings.HasPrefix(arg, "--name="):
			config.ROSBackupName = strings.SplitN(arg, "=", 2)[1]
		case arg == "--include-remote":
			config.ROSIncludeRemote = true
		case strings.HasPrefix(arg, "--audit-output="):
			config.AuditOutput = strings.SplitN(arg, "=", 2)[1]
		case arg == "--no-audit":
			config.AuditEnabled = false
		default:
			tokens = append(tokens, arg)
		}
	}
	config.ROSTokens = tokens
	if config.User == "" {
		config.User = "admin"
	}
}
