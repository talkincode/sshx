package ros

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxScriptSourceBytes is the maximum allowed size for uploaded script source files (256 KB).
const MaxScriptSourceBytes = 256 * 1024

// dangerousPatterns contains known destructive RouterOS operations that must be guarded.
var dangerousPatterns = []struct {
	pattern string
	reason  string
}{
	{"reset-configuration", "wipes complete router configuration"},
	{"system/reboot", "reboots the remote router"},
	{"system reboot", "reboots the remote router"},
	{"system/shutdown", "shuts down the remote router"},
	{"system shutdown", "shuts down the remote router"},
	{"disk format", "formats router storage partition"},
	{"disk/format", "formats router storage partition"},
	{"system/package/uninstall", "uninstalls router system package"},
	{"system package uninstall", "uninstalls router system package"},
}

// ValidateSafety checks whether a RouterOS command is dangerous or requires mutation confirmation.
func ValidateSafety(req *ROSRequest, allowWrite bool, force bool) *ROSErr {
	cmdStr := strings.ToLower(BuildRouterOSCommand(req))

	// Check for dangerous destructive commands
	for _, dp := range dangerousPatterns {
		if strings.Contains(cmdStr, dp.pattern) {
			if !force {
				return NewDangerousCommandError(
					cmdStr,
					dp.reason,
					"use --force to bypass safety guardrail",
				)
			}
		}
	}

	// Raw mutative commands require --allow-write or --force
	if req.Mapping != nil && req.Mapping.IsRaw() && !ReadOnly(req) {
		if !allowWrite && !force {
			return &ROSErr{
				ErrorCode: ErrCodeUsageError,
				Message:   "raw RouterOS commands that may mutate state require --allow-write",
				Hint:      "use raw /.../print for read-only commands, or add --allow-write for explicit raw writes",
				ExitCode:  2,
				Context: ROSContext{
					Command: req.RawCommand,
				},
			}
		}
	}

	return nil
}

var simplePrint = regexp.MustCompile(`^/(?:[a-zA-Z0-9_.-]+[ /])+print(?:[ \t]+(?:detail|terse|without-paging|count-only|as-value))*$`)

// ReadOnly recognizes individual print commands and simple batches of literal
// print commands. Unknown syntax and nested evaluation require write admission.
var printFile = regexp.MustCompile(`(?i)(?:^|[ \t])file[ \t]*=`)

func ReadOnly(req *ROSRequest) bool {
	if req.Mapping == nil {
		return false
	}
	command := BuildRouterOSCommand(req)
	if !strings.ContainsAny(command, ";\r\n[]") {
		return req.Mapping.ActionKind == ActionPrint && !printFile.MatchString(command)
	}
	for _, part := range strings.Split(command, ";") {
		if !simplePrint.MatchString(strings.Trim(part, " \t")) {
			return false
		}
	}
	return true
}

// CommandDiagnostic recognizes device diagnostics, not arbitrary occurrences of
// the word error in user data. SSH exit status alone is insufficient on RouterOS.
func CommandDiagnostic(output string) bool {
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		for _, prefix := range []string{"input does not match any value", "expected end of command", "syntax error", "bad command name", "no such item", "not enough permissions", "failure:", "invalid value for argument"} {
			if strings.HasPrefix(line, prefix) {
				return true
			}
		}
	}
	return false
}

// ValidateScriptSource checks size and UTF-8 validity of script contents.
func ValidateScriptSource(content []byte, sourcePath string) *ROSErr {
	if len(content) > MaxScriptSourceBytes {
		return &ROSErr{
			ErrorCode: ErrCodeFileTooLarge,
			Message:   fmt.Sprintf("script source %s exceeds %d bytes (got %d)", sourcePath, MaxScriptSourceBytes, len(content)),
			Hint:      "reduce script size or split into multiple scripts",
			ExitCode:  2,
		}
	}

	if !utf8.Valid(content) {
		return &ROSErr{
			ErrorCode: ErrCodeUsageError,
			Message:   fmt.Sprintf("script source %s must be UTF-8 text", sourcePath),
			Hint:      "save the .rsc file as UTF-8 text",
			ExitCode:  2,
		}
	}

	return nil
}
