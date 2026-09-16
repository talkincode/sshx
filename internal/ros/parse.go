package ros

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var (
	// Matches colon-separated single-record outputs (e.g. `/system resource print`)
	colonRecordRegex = regexp.MustCompile(`^\s*([a-zA-Z0-9_\-\.]+)\s*:\s*(.*?)\s*$`)

	// Matches starting item index and optional flags, e.g. " 0   ;;; defconf" or " 1 D address=..." or " 0 name=..."
	itemStartRegex = regexp.MustCompile(`^\s*(\d+)\s*([A-Z*]*)\s*(.*)$`)

	// Matches comments in detail output: ";;; comment text"
	commentRegex = regexp.MustCompile(`^;;;\s*(.*)$`)

	// Tokenizes key=value or key="quoted value" pairs
	kvPairRegex = regexp.MustCompile(`([a-zA-Z0-9_\-\.]+)=("(?:[^"\\]|\\.)*"|\S+)`)
)

// ParseRouterOSOutput attempts to parse RouterOS output into structured JSON-compatible data.
// If the output cannot be parsed into structured records, it returns nil and the original string.
func ParseRouterOSOutput(output string) (any, bool) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return []map[string]any{}, true
	}

	// 1. If it's already JSON (e.g. from ROS v7 :serialize to=json)
	if (strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) ||
		(strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) {
		var val any
		if err := json.Unmarshal([]byte(trimmed), &val); err == nil {
			return val, true
		}
	}

	lines := strings.Split(output, "\n")

	// 2. Try single-record key: value format
	if record, ok := tryParseColonRecord(lines); ok {
		return record, true
	}

	// 3. Try multi-item detail/terse format
	if items, ok := tryParseItemRecords(lines); ok && len(items) > 0 {
		return items, true
	}

	return nil, false
}

// tryParseColonRecord checks if all non-empty lines are `key: value` format.
func tryParseColonRecord(lines []string) (map[string]any, bool) {
	record := make(map[string]any)
	matchedLines := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Skip header flags like "Flags: X - disabled..."
		if strings.HasPrefix(trimmed, "Flags:") {
			continue
		}
		matches := colonRecordRegex.FindStringSubmatch(line)
		if len(matches) != 3 {
			return nil, false
		}
		key := strings.TrimSpace(matches[1])
		val := strings.TrimSpace(matches[2])
		record[key] = coerceValue(val)
		matchedLines++
	}

	if matchedLines == 0 {
		return nil, false
	}
	return record, true
}

// tryParseItemRecords parses RouterOS `print detail` or `print terse` outputs.
func tryParseItemRecords(lines []string) ([]map[string]any, bool) {
	var items []map[string]any
	var currentItem map[string]any

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Skip legend header
		if strings.HasPrefix(trimmed, "Flags:") {
			continue
		}

		// Check if line starts with a new item number: " 0   ...", " 1 D ..."
		sub := itemStartRegex.FindStringSubmatch(line)
		// To be a valid item start, the line shouldn't be indented by many spaces and must match a digit index
		if len(sub) == 4 && len(line) > 0 && (line[0] != '\t' && (len(line) < 4 || line[:4] != "    ")) {
			// Finish previous item
			if currentItem != nil {
				items = append(items, currentItem)
			}
			currentItem = make(map[string]any)
			indexStr := sub[1]
			flags := strings.TrimSpace(sub[2])
			rest := strings.TrimSpace(sub[3])

			if idx, err := strconv.Atoi(indexStr); err == nil {
				currentItem[".id"] = idx
			} else {
				currentItem[".id"] = indexStr
			}
			if flags != "" {
				currentItem["flags"] = flags
			}

			// Check if rest contains a comment
			if commentMatches := commentRegex.FindStringSubmatch(rest); len(commentMatches) == 2 {
				currentItem["comment"] = strings.TrimSpace(commentMatches[1])
			} else if rest != "" {
				extractKVPairs(rest, currentItem)
			}
			continue
		}

		// Continuation of current item
		if currentItem != nil {
			if commentMatches := commentRegex.FindStringSubmatch(trimmed); len(commentMatches) == 2 {
				currentItem["comment"] = strings.TrimSpace(commentMatches[1])
			} else {
				extractKVPairs(trimmed, currentItem)
			}
		}
	}

	if currentItem != nil {
		items = append(items, currentItem)
	}

	if len(items) > 0 {
		return items, true
	}
	return nil, false
}

// extractKVPairs extracts key=value or key="val" from a line.
func extractKVPairs(line string, target map[string]any) {
	matches := kvPairRegex.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) == 3 {
			key := m[1]
			val := m[2]
			if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") && len(val) >= 2 {
				val = val[1 : len(val)-1]
			}
			target[key] = coerceValue(val)
		}
	}
}

// coerceValue converts string primitives like true/false or numbers when appropriate.
func coerceValue(val string) any {
	if strings.EqualFold(val, "yes") || strings.EqualFold(val, "true") {
		return true
	}
	if strings.EqualFold(val, "no") || strings.EqualFold(val, "false") {
		return false
	}
	if n, err := strconv.ParseInt(val, 10, 64); err == nil {
		return n
	}
	return val
}
