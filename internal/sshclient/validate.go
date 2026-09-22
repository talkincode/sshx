package sshclient

import (
	"errors"
	"fmt"
	"strings"

	"github.com/talkincode/sshx/internal/keyringstore"
	"github.com/talkincode/sshx/pkg/logger"
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
// well-known destructive operations (for example "rm -rf /" or a fork bomb).
//
// Matching happens on the token in *command position* after shell segmentation,
// not on the raw command string. That distinction matters: `last reboot -F`,
// `journalctl | grep -iE 'fail|halt'`, and `iptables-save | grep -F ...` are
// read-only and must not be blocked just because they contain a dangerous word.
//
// It is a guardrail to catch accidental mistakes, NOT a security boundary: the
// matching is trivially bypassed (obfuscation, indirection, generated command
// strings), so it must never be relied upon to sandbox untrusted input.
func ValidateCommand(command string) error {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return nil
	}

	// Fork bombs survive no useful tokenization, so match the literal shape
	// after stripping whitespace.
	if isForkBomb(cmd) {
		return &CommandBlockedError{Command: cmd, Reason: "Fork bomb"}
	}

	if reason, found := detectDestructiveCommand(cmd, 0); found {
		return &CommandBlockedError{Command: cmd, Reason: reason}
	}

	if engine, client, found := detectGuardedDBClient(cmd, 0); found {
		hint := `sshx sql -h=<host> --db=<name> [--docker=<container>] "<SQL>"`
		if client == "sqlite3" {
			hint = `sshx sql -h=<host> --engine=sqlite --db-file=<abs-path> "<SQL>"`
		}
		return &CommandBlockedError{
			Command: cmd,
			Reason: fmt.Sprintf("Direct %s client execution (%q) bypasses the guarded SQL pipeline. "+
				"Use: %s (adds classification, backups, and audit)", engine, client, hint),
		}
	}

	return nil
}

// CommandIsDestructive reuses the admission parser without conflating a
// direct-database-client routing restriction with a destructive operation.
func CommandIsDestructive(command string) bool {
	if isForkBomb(command) {
		return true
	}
	_, found := detectDestructiveCommand(strings.TrimSpace(command), 0)
	return found
}

// isForkBomb matches the classic `:(){:|:&};:` shape regardless of spacing.
func isForkBomb(cmd string) bool {
	var b strings.Builder
	for _, r := range cmd {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return strings.Contains(b.String(), ":(){:|:&};:")
}

// CommandUsesSudo reports whether sshx can safely treat the command as a sudo
// command for password auto-fill. Only a leading sudo command is supported,
// because that is the only form sudoStdinCommand can rewrite without guessing at
// shell syntax.
func CommandUsesSudo(command string) bool {
	_, ok := leadingSudoRemainder(command)
	return ok
}

func leadingSudoRemainder(command string) (string, bool) {
	trimmed := strings.TrimLeft(command, " \t\r\n")
	if trimmed == "sudo" {
		return "", true
	}
	if !strings.HasPrefix(trimmed, "sudo") {
		return "", false
	}
	rest := trimmed[len("sudo"):]
	if rest == "" || !isCommandWhitespace(rest[0]) {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

func isCommandWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}

// NonLeadingSudoHint reports a `sudo` invocation in command position that sshx
// cannot feed a password to, because auto-fill only rewrites a leading `sudo`
// token (see sudoStdinCommand). `cd /data/app && sudo docker compose up -d`
// therefore runs verbatim and sudo prompts for a password it can never read
// over a non-interactive session.
//
// The returned hint tells the operator how to restructure the command. The
// auto-fill scope itself is unchanged: sshx still fills only the leading form.
func NonLeadingSudoHint(command string) (string, bool) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return "", false
	}
	if _, ok := leadingSudoRemainder(trimmed); ok {
		return "", false
	}
	if !sudoInCommandPosition(trimmed, 0) {
		return "", false
	}
	return "sudo is not the first token, so sshx cannot auto-fill a stored sudo password " +
		"(auto-fill only rewrites a leading `sudo`). Run the privileged part as " +
		"`sudo sh -c \"<full command>\"`, or move `sudo` to the front.", true
}

// sudoInCommandPosition reports whether any shell segment executes sudo as its
// command, recursing into `sh -c '<script>'` payloads.
func sudoInCommandPosition(command string, depth int) bool {
	if depth > maxDestructiveDepth {
		return false
	}
	for _, seg := range splitShellSegments(command) {
		if sudoAtCommandPosition(seg) {
			return true
		}
		if _, args, kind := commandInPosition(seg); kind == positionShellScript && len(args) == 1 {
			if sudoInCommandPosition(args[0], depth+1) {
				return true
			}
		}
	}
	return false
}

// sudoAtCommandPosition walks environment assignments and command wrappers of a
// single simple command and reports whether one of them is sudo. The walk stops
// at the first token that is neither, so `sudo` used as an argument (`echo sudo`)
// or inside a container (`docker exec c sudo id`) does not match, while
// `nohup sudo …` and `FOO=1 sudo …` do.
func sudoAtCommandPosition(tokens []string) bool {
	i := 0
	for i < len(tokens) {
		tok := tokens[i]
		if isEnvAssignment(tok) {
			i++
			continue
		}
		name := strings.ToLower(commandBasename(tok))
		if name == "sudo" {
			return true
		}
		valueFlags, ok := commandWrappers[name]
		if !ok {
			return false
		}
		i++
		i = skipFlags(tokens, i, valueFlags)
		if name == "timeout" && i < len(tokens) && looksLikeDuration(tokens[i]) {
			i++
		}
	}
	return false
}

// sudoPromptFailures are the remote messages that mean sudo refused to run
// because it could not read a password.
var sudoPromptFailures = []string{
	"sudo: a password is required",
	"sudo: no password was provided",
	"sudo: a terminal is required to read the password",
	"sudo: no tty present and no askpass program specified",
	"sudo: unable to read password",
	"sudo: sorry, you must have a tty to run sudo",
}

// SudoPasswordPromptFailure reports whether remote output shows sudo refusing to
// run for want of a password read.
func SudoPasswordPromptFailure(output string) bool {
	lowered := strings.ToLower(output)
	for _, marker := range sudoPromptFailures {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}

// GetSudoPassword reads a sudo password from the configured secret backend
// (OS keyring by default, or the explicit local vault).
func GetSudoPassword(key string) (string, error) {
	serviceName := KeyringServiceName
	backend, backendErr := keyringstore.Backend()
	label := "system keyring"
	if backend == keyringstore.BackendVault {
		label = "local vault"
	}

	password, err := keyringstore.Get(serviceName, key)
	if err != nil {
		if errors.Is(err, keyringstore.ErrNotFound) {
			if backend == keyringstore.BackendVault {
				return "", fmt.Errorf("sudo password not found in local vault for key: %s\n"+
					"Add it using:\n  SSHX_SECRET_BACKEND=local-vault sshx --password-set=%s",
					key, key)
			}
			return "", fmt.Errorf("sudo password not found in keyring for key: %s\n"+
				"Add it using one of:\n"+
				"  macOS:   security add-generic-password -s %s -a %s -w <password>\n"+
				"  Linux:   secret-tool store --label='Sudo Password' service %s username %s\n"+
				"  Windows: Use 'Credential Manager' in Control Panel",
				key, serviceName, key, serviceName, key)
		}
		if backendErr != nil {
			return "", fmt.Errorf("failed to get sudo password: %w", backendErr)
		}
		return "", fmt.Errorf("failed to get sudo password from %s: %w", label, err)
	}

	if password == "" {
		return "", fmt.Errorf("empty sudo password in %s for key: %s", label, key)
	}

	logger.GetLogger().Success("Sudo password loaded from %s for key: %s", label, key)
	return password, nil
}
