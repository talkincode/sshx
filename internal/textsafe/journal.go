package textsafe

import (
	"fmt"
	"strings"
	"unicode"
)

const maxTimeBoundLen = 128

// ValidateJournalUnit accepts systemd unit names sshx is willing to put on argv.
func ValidateJournalUnit(unit string) error {
	if unit == "" {
		return fmt.Errorf("journal unit is required")
	}
	if len(unit) > 256 {
		return fmt.Errorf("journal unit is too long")
	}
	if unit[0] == '-' || unit[0] == '.' {
		return fmt.Errorf("journal unit must start with an alphanumeric character")
	}
	for _, r := range unit {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case '.', '_', ':', '@', '+', '-':
			continue
		default:
			return fmt.Errorf("journal unit contains invalid character %q", r)
		}
	}
	return nil
}

// ValidateTimeBound allows journalctl-style since/until values without shell metacharacters.
func ValidateTimeBound(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > maxTimeBoundLen {
		return fmt.Errorf("value is too long")
	}
	if strings.ContainsAny(value, "$;`|&<>(){}[]\\\"\n\r\t") {
		return fmt.Errorf("contains shell metacharacters")
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return fmt.Errorf("contains control characters")
		}
	}
	return nil
}

// JournalCommand builds an sshx-owned journalctl argv string. unit/since/until
// must already have passed validation.
func JournalCommand(req Request, sudo bool) string {
	args := []string{
		"journalctl",
		"--no-pager",
		"--output=short-iso",
		"--utc",
		"--unit=" + posixQuote(req.JournalUnit),
		"-n", fmt.Sprintf("%d", req.JournalLines),
	}
	if req.Since != "" {
		args = append(args, "--since="+posixQuote(req.Since))
	}
	if req.Until != "" {
		args = append(args, "--until="+posixQuote(req.Until))
	}
	cmd := strings.Join(args, " ")
	if sudo {
		return "sudo -S -p '' " + cmd
	}
	return cmd
}

// FileReadCommand is the sshx-owned privileged file reader. Path must already
// be a clean absolute path.
func FileReadCommand(path string, fromEnd bool, maxBytes int64, sudo bool) string {
	tool := "head"
	if fromEnd {
		tool = "tail"
	}
	cmd := tool + " -c " + fmt.Sprintf("%d", maxBytes) + " -- " + posixQuote(path)
	if sudo {
		return "sudo -S -p '' " + cmd
	}
	return cmd
}

func posixQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
