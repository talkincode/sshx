package app

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

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

// ParseArgs parses command-line arguments and returns a Config.
func ParseArgs(args []string) *sshclient.Config {
	config := &sshclient.Config{
		Mode:        "ssh",
		SafetyCheck: true,
		Force:       false,
		UseKeyAuth:  true,
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
	if acceptUnknown := os.Getenv("SSH_ACCEPT_UNKNOWN_HOST"); strings.EqualFold(acceptUnknown, "true") || acceptUnknown == "1" {
		config.AcceptUnknownHost = true
	}
	if insecure := os.Getenv("SSH_INSECURE_HOST_KEY"); strings.EqualFold(insecure, "true") || insecure == "1" {
		config.AllowInsecureHostKey = true
	}

	if os.Getenv("SSH_NO_SAFETY_CHECK") == "true" {
		config.SafetyCheck = false
	}
	if os.Getenv("SSH_FORCE") == "true" {
		config.Force = true
	}
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

	for i := 1; i < len(args); i++ {
		arg := args[i]
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
		case strings.HasPrefix(arg, "--to="):
			switch config.SftpAction {
			case "upload":
				config.RemotePath = strings.SplitN(arg, "=", 2)[1]
			case "download":
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
		}
	}

	if config.Mode == "ssh" {
		actualCmd := []string{}
		for i := 1; i < len(args); i++ {
			arg := args[i]
			if strings.HasPrefix(arg, "-") {
				continue
			}
			actualCmd = append(actualCmd, arg)
		}

		if len(actualCmd) > 0 {
			config.Command = strings.Join(actualCmd, " ")
		}
	}

	return config
}
