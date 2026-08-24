package app

import (
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
	"golang.org/x/crypto/ssh"
)

func HandleLogin(config *sshclient.Config, audit *auditRecorder) (err error) {
	if cfgErr := validateLoginConfig(config); cfgErr != nil {
		return failLogin(config, audit, sshclient.AuthMethodUnknown, "config", cfgErr)
	}
	if !sshclient.InteractiveLoginSupported() {
		return failLogin(config, audit, sshclient.AuthMethodUnknown, "config",
			fmt.Errorf("%w: interactive login is unavailable on %s", sshclient.ErrLoginUnsupported, runtime.GOOS))
	}
	if !sshclient.StdinIsTerminal() {
		return failLogin(config, audit, sshclient.AuthMethodUnknown, "config", sshclient.ErrLoginNotTTY)
	}

	if !config.LoginLiteralHost && config.Host != "" && !isIPAddress(config.Host) {
		if resolveErr := resolveHostFromSettings(config); resolveErr != nil {
			logger.GetLogger().Info("Note: Could not find host '%s' in settings, using as hostname directly", config.Host)
		}
	}
	fillLoginSSHPassword(config)

	if config.LoginUseSudo {
		password, pwdErr := sshclient.GetSudoPassword(config.SudoKey)
		if pwdErr != nil {
			return failLogin(config, audit, sshclient.AuthMethodUnknown, "secret",
				fmt.Errorf("resolve sudo password key %q: %w", config.SudoKey, pwdErr))
		}
		config.SudoPassword = password
	}

	client, cliErr := sshclient.NewSSHClient(config)
	if cliErr != nil {
		return failLogin(config, audit, sshclient.AuthMethodUnknown, "config",
			fmt.Errorf("failed to create SSH client: %w", cliErr))
	}
	defer errutil.HandleCloseError(&err, client)
	if connErr := client.ConnectDirect(); connErr != nil {
		return failLogin(config, audit, sshclient.AuthMethodUnknown, classifyError(connErr),
			fmt.Errorf("failed to connect: %w", connErr))
	}
	if audit != nil {
		audit.event.AuthMethod = string(client.AuthMethodUsed())
	}

	start := time.Now()
	waitErr := client.Login()
	return finishLogin(config, audit, client.AuthMethodUsed(), time.Since(start), waitErr)
}

func validateLoginConfig(config *sshclient.Config) error {
	if config.ArgumentError != "" {
		return fmt.Errorf("%w: %s", execution.ErrConfig, config.ArgumentError)
	}
	if config.Host == "" {
		return fmt.Errorf("%w: host is required (use sshx login <name>, -h=<host>, or --address=<host>)", execution.ErrConfig)
	}
	if config.JSONOutput && !config.DryRun {
		return fmt.Errorf("%w: login --json requires --dry-run", execution.ErrConfig)
	}
	return nil
}

func fillLoginSSHPassword(config *sshclient.Config) {
	if config.Password != "" || config.SSHPasswordKey == "" {
		return
	}
	password, pwdErr := sshclient.GetSudoPassword(config.SSHPasswordKey)
	if pwdErr != nil {
		logger.GetLogger().Warning("failed to get SSH password from keyring (%s): %v", config.SSHPasswordKey, pwdErr)
		return
	}
	config.Password = password
}

func failLogin(config *sshclient.Config, audit *auditRecorder, auth sshclient.AuthMethod, kind string, err error) error {
	if audit != nil {
		audit.recordFailure(config, auth, kind, err)
	}
	return err
}

func finishLogin(config *sshclient.Config, audit *auditRecorder, auth sshclient.AuthMethod, dur time.Duration, waitErr error) error {
	if waitErr == nil {
		if audit != nil {
			audit.recordCommandResult(config, auth, sshclient.ExecResult{ExitCode: 0}, dur, "", nil)
		}
		return nil
	}

	var exitErr *ssh.ExitError
	if errors.As(waitErr, &exitErr) {
		code := exitErr.ExitStatus()
		if audit != nil {
			audit.recordCommandResult(config, auth, sshclient.ExecResult{ExitCode: code}, dur, "", nil)
		}
		return &ExitError{Code: code}
	}

	kind := classifyError(waitErr)
	if errors.Is(waitErr, sshclient.ErrLoginNotTTY) || errors.Is(waitErr, sshclient.ErrLoginUnsupported) {
		kind = "config"
	}
	if audit != nil {
		audit.recordFailure(config, auth, kind, waitErr)
	}
	return waitErr
}

func parseLoginArgs(config *sshclient.Config, args []string) {
	config.Mode = "login"
	config.Timeout = 0
	var positional string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			config.ArgumentError = "login does not take a remote command; omit -- and any command text"
			return
		}
		switch {
		case stringsHasPrefixAny(arg, "-h=", "--host=", "--target="):
			if err := setLoginHost(config, stringsSplitValue(arg), false); err != nil {
				config.ArgumentError = err.Error()
				return
			}
		case stringsHasPrefixAny(arg, "--address="):
			if err := setLoginHost(config, stringsSplitValue(arg), true); err != nil {
				config.ArgumentError = err.Error()
				return
			}
		case stringsHasPrefixAny(arg, "-p=", "--port="):
			config.Port = stringsSplitValue(arg)
		case stringsHasPrefixAny(arg, "-u=", "--user="):
			config.User = stringsSplitValue(arg)
		case stringsHasPrefixAny(arg, "-i=", "--key="):
			config.KeyPath = stringsSplitValue(arg)
			config.UseKeyAuth = true
		case stringsHasPrefixAny(arg, "-pk=", "--password-key=", "--sudo-password-key="):
			config.SudoKey = stringsSplitValue(arg)
		case stringsHasPrefixAny(arg, "--ssh-password-key="):
			config.SSHPasswordKey = stringsSplitValue(arg)
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
		case stringsHasPrefixAny(arg, "--known-hosts="):
			config.KnownHostsPath = stringsSplitValue(arg)
		case arg == "--sudo":
			config.LoginUseSudo = true
		case arg == "--dry-run":
			config.DryRun = true
		case arg == "--json":
			config.JSONOutput = true
		case stringsHasPrefixAny(arg, "--audit-output="):
			config.AuditOutput = stringsSplitValue(arg)
		case arg == "--no-audit":
			config.AuditEnabled = false
		case arg == "--pty", arg == "--jsonl", arg == "--force", arg == "-f", arg == "--no-safety-check":
			config.ArgumentError = fmt.Sprintf("login does not accept %s", arg)
			return
		case stringsHasPrefixAny(arg, "--timeout="):
			config.ArgumentError = "login does not accept --timeout (interactive sessions are unbounded)"
			return
		case stringsHasPrefixAny(arg, "--group=", "--tag=", "--targets=", "--all-hosts", "--concurrency=", "--failure-mode="):
			config.ArgumentError = "login does not support multi-host selectors"
			return
		case !hasDashPrefix(arg):
			if positional != "" {
				config.ArgumentError = fmt.Sprintf("unexpected login argument %q", arg)
				return
			}
			positional = arg
			if err := setLoginHost(config, arg, false); err != nil {
				config.ArgumentError = err.Error()
				return
			}
		default:
			config.ArgumentError = fmt.Sprintf("unknown login option %q", arg)
			return
		}
	}
	if config.JSONOutput && !config.DryRun {
		config.ArgumentError = "login --json requires --dry-run"
	}
}

func setLoginHost(config *sshclient.Config, host string, literal bool) error {
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if config.Host != "" && config.Host != host {
		return fmt.Errorf("login accepts exactly one host")
	}
	if config.LoginLiteralHost && !literal {
		return fmt.Errorf("--address cannot combine with --target or -h")
	}
	if literal && config.Host != "" && !config.LoginLiteralHost {
		return fmt.Errorf("--address cannot combine with --target or -h")
	}
	config.Host = host
	if literal {
		config.LoginLiteralHost = true
	}
	return nil
}

func stringsHasPrefixAny(arg string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if len(arg) >= len(prefix) && arg[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func stringsSplitValue(arg string) string {
	for i := 0; i < len(arg); i++ {
		if arg[i] == '=' {
			return arg[i+1:]
		}
	}
	return ""
}

func hasDashPrefix(arg string) bool {
	return len(arg) > 0 && arg[0] == '-'
}
