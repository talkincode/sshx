package plugin

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var sensitiveValuePattern = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|authorization|cookie|credentials?|private[_-]?key|api[_-]?key|access[_-]?key)(\s*[=:]\s*)[^\s,;]+`)

func RedactResult(result Result, policy RedactionPolicy) (Result, []string) {
	deny := map[string]bool{}
	for _, field := range append(defaultDenyFields(), policy.DenyFields...) {
		deny[normalizeField(field)] = true
	}
	redacted := []string{}
	result.Facts = redactMap(result.Facts, "facts", deny, &redacted)
	for index := range result.Evidence {
		clean := redactString(result.Evidence[index].Source)
		if clean != result.Evidence[index].Source {
			redacted = append(redacted, fmt.Sprintf("evidence[%d].source", index))
			result.Evidence[index].Source = clean
		}
	}
	for index := range result.Errors {
		clean := redactString(result.Errors[index].Message)
		if clean != result.Errors[index].Message {
			redacted = append(redacted, fmt.Sprintf("errors[%d].message", index))
			result.Errors[index].Message = clean
		}
	}
	sort.Strings(redacted)
	return result, uniqueStrings(redacted)
}

func redactMap(value map[string]any, path string, deny map[string]bool, redacted *[]string) map[string]any {
	clean := make(map[string]any, len(value))
	for key, item := range value {
		childPath := path + "." + key
		if isDeniedField(key, deny) {
			*redacted = append(*redacted, childPath)
			continue
		}
		clean[key] = redactValue(item, childPath, deny, redacted)
	}
	return clean
}

func redactValue(value any, path string, deny map[string]bool, redacted *[]string) any {
	switch typed := value.(type) {
	case map[string]any:
		return redactMap(typed, path, deny, redacted)
	case []any:
		items := make([]any, len(typed))
		for index, item := range typed {
			items[index] = redactValue(item, fmt.Sprintf("%s[%d]", path, index), deny, redacted)
		}
		return items
	case string:
		clean := redactString(typed)
		if clean != typed {
			*redacted = append(*redacted, path)
		}
		return clean
	default:
		return value
	}
}

func isDeniedField(field string, deny map[string]bool) bool {
	normalized := normalizeField(field)
	if deny[normalized] {
		return true
	}
	for _, marker := range []string{"password", "passwd", "token", "secret", "authorization", "cookie", "privatekey", "credentials"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func normalizeField(field string) string {
	value := strings.ToLower(strings.TrimSpace(field))
	replacer := strings.NewReplacer("_", "", "-", "", ".", "", " ", "")
	return replacer.Replace(value)
}

func redactString(value string) string {
	return sensitiveValuePattern.ReplaceAllString(value, "$1$2<redacted>")
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := values[:0]
	for index, value := range values {
		if index == 0 || value != values[index-1] {
			result = append(result, value)
		}
	}
	return result
}
