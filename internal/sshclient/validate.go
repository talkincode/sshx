package sshclient

import (
	"fmt"
	"strings"

	"github.com/talkincode/sshx/pkg/logger"
	"github.com/zalando/go-keyring"
)

const KeyringServiceName = "sshx"

// CommandBlockedError is returned by ValidateCommand when a command matches a
// known destructive pattern. Its message is unchanged from the previous plain
// error so existing output and substring checks keep working, while callers can
// now detect a safety block via errors.As.
type CommandBlockedError struct {
	Command string
	Reason  string
}

func (e *CommandBlockedError) Error() string {
	return fmt.Sprintf("⚠️  Dangerous command blocked\nCommand: %s\nReason: %s\nIf you are sure, use --force or -f flag", e.Command, e.Reason)
}

// ValidateCommand performs a best-effort safety check against a small set of
// well-known destructive commands (for example "rm -rf /" or a fork bomb).
//
// It is a guardrail to catch accidental mistakes, NOT a security boundary: the
// substring/keyword matching is trivially bypassed (casing, quoting, shell
// variables, alternate paths), so it must never be relied upon to sandbox
// untrusted input.
func ValidateCommand(command string) error {
	cmd := strings.TrimSpace(command)
	cmdLower := strings.ToLower(cmd)

	dangerousExactPatterns := []struct {
		pattern string
		reason  string
	}{
		{" rm -rf / ", "Delete root directory"},
		{" rm -rf /$", "Delete root directory"},
		{" rm -rf /;", "Delete root directory"},
		{" rm -rf /&", "Delete root directory"},
		{" rm -rf /|", "Delete root directory"},
		{"rm -rf / ", "Delete root directory"},
		{"rm -rf /$", "Delete root directory"},
		{"rm -rf /;", "Delete root directory"},
		{"rm -rf /*", "Delete all files in root directory"},
		{"rm -rf ~", "Delete user home directory"},
		{"rm -rf ~/", "Delete user home directory"},
		{"rm -rf $home", "Delete $HOME directory"},
		{":(){:|:&};:", "Fork bomb"},
		{"> /etc/passwd", "Overwrite system password file"},
		{"> /etc/shadow", "Overwrite system shadow file"},
		{"dd if=/dev/zero", "Dangerous dd operation"},
		{"dd if=/dev/urandom", "Dangerous dd operation"},
	}

	for _, pattern := range dangerousExactPatterns {
		cmdWithSpaces := " " + cmdLower + " "
		patternLower := strings.ToLower(pattern.pattern)

		if strings.HasSuffix(pattern.pattern, "$") {
			patternLower = strings.TrimSuffix(patternLower, "$")
			if strings.HasSuffix(cmdLower, patternLower) {
				return &CommandBlockedError{Command: cmd, Reason: pattern.reason}
			}
		} else if strings.Contains(cmdWithSpaces, patternLower) {
			return &CommandBlockedError{Command: cmd, Reason: pattern.reason}
		}
	}

	dangerousPatterns := []struct {
		keywords []string
		reason   string
	}{
		{[]string{"mkfs."}, "Format filesystem"},
		{[]string{"mkfs", "ext4"}, "Format filesystem"},
		{[]string{"mkfs", "ext3"}, "Format filesystem"},
		{[]string{"mkfs", "xfs"}, "Format filesystem"},
		{[]string{"fdisk", "/dev/"}, "Disk partition operation"},
		{[]string{"parted", "/dev/"}, "Disk partition operation"},
		{[]string{"mkswap", "/dev/"}, "Create swap partition"},
		{[]string{"shutdown"}, "System shutdown operation"},
		{[]string{"halt"}, "System halt operation"},
		{[]string{"poweroff"}, "System poweroff operation"},
		{[]string{"reboot"}, "System reboot operation"},
		{[]string{"init 0"}, "System shutdown (init 0)"},
		{[]string{"init 6"}, "System reboot (init 6)"},
		{[]string{"systemctl", "halt"}, "System halt operation"},
		{[]string{"systemctl", "poweroff"}, "System poweroff operation"},
		{[]string{"systemctl", "reboot"}, "System reboot operation"},
		{[]string{"curl", "| sh"}, "Download and execute script from network"},
		{[]string{"curl", "| bash"}, "Download and execute script from network"},
		{[]string{"curl", "|sh"}, "Download and execute script from network"},
		{[]string{"curl", "|bash"}, "Download and execute script from network"},
		{[]string{"wget", "| sh"}, "Download and execute script from network"},
		{[]string{"wget", "| bash"}, "Download and execute script from network"},
		{[]string{"wget", "|sh"}, "Download and execute script from network"},
		{[]string{"wget", "|bash"}, "Download and execute script from network"},
		{[]string{"chmod", "777", "/ "}, "Set root directory permissions to 777"},
		{[]string{"chmod", "777", "/$"}, "Set root directory permissions to 777"},
		{[]string{"chmod", "-r", "777", "/ "}, "Recursively set root directory permissions to 777"},
		{[]string{"chmod", "-r", "777", "/$"}, "Recursively set root directory permissions to 777"},
		{[]string{"iptables", "-f"}, "Flush firewall rules"},
		{[]string{"iptables", "-x"}, "Delete firewall chain"},
	}

	for _, pattern := range dangerousPatterns {
		allMatch := true
		for _, keyword := range pattern.keywords {
			keywordLower := strings.ToLower(keyword)
			if strings.HasSuffix(keyword, "$") {
				keywordLower = strings.TrimSuffix(keywordLower, "$")
				if !strings.HasSuffix(cmdLower, keywordLower) {
					allMatch = false
					break
				}
			} else if !strings.Contains(cmdLower, keywordLower) {
				allMatch = false
				break
			}
		}
		if allMatch {
			return &CommandBlockedError{Command: cmd, Reason: pattern.reason}
		}
	}

	return nil
}

// CommandUsesSudo reports whether the command invokes sudo as a distinct
// command token. This avoids false positives from substrings such as "pseudo"
// that merely contain the letters "sudo".
func CommandUsesSudo(command string) bool {
	for _, field := range strings.Fields(command) {
		if field == "sudo" {
			return true
		}
	}
	return false
}

// GetSudoPassword reads sudo password from system keyring (cross-platform support)
// macOS: Keychain, Linux: Secret Service (gnome-keyring/kwallet), Windows: Credential Manager
func GetSudoPassword(key string) (string, error) {
	serviceName := KeyringServiceName

	password, err := keyring.Get(serviceName, key)
	if err != nil {
		if err == keyring.ErrNotFound {
			return "", fmt.Errorf("sudo password not found in keyring for key: %s\n"+
				"Add it using one of:\n"+
				"  macOS:   security add-generic-password -s %s -a %s -w <password>\n"+
				"  Linux:   secret-tool store --label='Sudo Password' service %s username %s\n"+
				"  Windows: Use 'Credential Manager' in Control Panel",
				key, serviceName, key, serviceName, key)
		}
		return "", fmt.Errorf("failed to get sudo password from keyring: %w", err)
	}

	if password == "" {
		return "", fmt.Errorf("empty sudo password in keyring for key: %s", key)
	}

	logger.GetLogger().Success("Sudo password loaded from system keyring for key: %s", key)
	return password, nil
}
