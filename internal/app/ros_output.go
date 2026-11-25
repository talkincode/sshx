package app

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	// The console can fold a container argument across several display lines.
	// Treat an indented hexadecimal continuation as part of the same token.
	foldedReverseToken = regexp.MustCompile(`(?i)(--[ \t]*(?:\r?\n[ \t]+)?reverse-[ \t]*(?:\r?\n[ \t]+)?token(?:=|[ \t]+|\r?\n[ \t]+))(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[a-f0-9]+(?:\r?\n[ \t]+[a-f0-9]+\b)+|[^\s'"&;]+)`)
	rosSecretKey       = regexp.MustCompile(`(?i)(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|preshared[_-]?key|authorization)$`)
	rosColonSecret     = regexp.MustCompile(`(?im)^([ \t]*[a-z0-9_-]*(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|preshared[_-]?key|authorization):[ \t]*)[^\r\n]+`)
	rosKeyAssignment   = regexp.MustCompile(`(?i)\b((?:private|preshared)[_-]?key=)(?:"(?:\\.|[^"\\])*"|[^\s;]+)`)
)

func redactROSOutput(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var data any
		decoder := json.NewDecoder(strings.NewReader(trimmed))
		decoder.UseNumber()
		if json.Valid([]byte(trimmed)) && decoder.Decode(&data) == nil {
			scrubbed, changed := redactROSValue(data)
			if !changed {
				return value
			}
			if safe, err := json.Marshal(scrubbed); err == nil {
				return strings.Replace(value, trimmed, string(safe), 1)
			}
		}
	}
	return redactROSText(value)
}

func redactROSText(value string) string {
	joined := auditContinuationRE.ReplaceAllString(value, "")
	safe := foldedReverseToken.ReplaceAllString(joined, "--reverse-token <redacted>")
	safe = rosColonSecret.ReplaceAllString(safe, "${1}<redacted>")
	safe = rosKeyAssignment.ReplaceAllString(safe, "${1}<redacted>")
	safe = redactSensitiveText(safe)
	if safe == joined {
		return value
	}
	return safe
}

func redactROSValue(data any) (any, bool) {
	changed := false
	switch value := data.(type) {
	case map[string]any:
		for key, item := range value {
			if rosSecretKey.MatchString(key) {
				value[key] = "<redacted>"
				changed = true
			} else if safe, modified := redactROSValue(item); modified {
				value[key], changed = safe, true
			}
		}
	case []any:
		for i, item := range value {
			if safe, modified := redactROSValue(item); modified {
				value[i], changed = safe, true
			}
		}
	case string:
		safe := redactROSText(value)
		return safe, safe != value
	}
	return data, changed
}
