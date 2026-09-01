package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/sshclient"
)

const auditQuerySchemaVersion = "sshx.audit.query.v1"

type auditQueryJSON struct {
	SchemaVersion string            `json:"schema_version"`
	Success       bool              `json:"success"`
	Action        string            `json:"action"`
	Count         int               `json:"count"`
	Path          string            `json:"path,omitempty"`
	Events        []json.RawMessage `json:"events"`
	ErrorKind     string            `json:"error_kind,omitempty"`
	Error         string            `json:"error,omitempty"`
}

type auditQueryFilter struct {
	since      time.Time
	until      time.Time
	hasSince   bool
	hasUntil   bool
	target     string
	action     string
	runID      string
	errorKind  string
	bypassOnly bool
}

// HandleAudit runs the read-only audit query/export surface. It never writes
// an audit event of its own.
func HandleAudit(config *sshclient.Config) error {
	if config.ArgumentError != "" {
		return reportAuditError(config, fmt.Errorf("%s", config.ArgumentError))
	}
	switch config.AuditAction {
	case "query":
		return handleAuditQuery(config)
	case "export":
		return handleAuditExport(config)
	default:
		return reportAuditError(config, fmt.Errorf("unknown audit action %q (use: query, export)", config.AuditAction))
	}
}

func reportAuditError(config *sshclient.Config, err error) error {
	if config != nil && config.JSONOutput {
		if emitErr := encodeJSON(auditQueryJSON{
			SchemaVersion: auditQuerySchemaVersion,
			Success:       false,
			Action:        config.AuditAction,
			Events:        []json.RawMessage{},
			ErrorKind:     "config",
			Error:         err.Error(),
		}); emitErr != nil {
			return emitErr
		}
		return ErrReported
	}
	return err
}

func handleAuditQuery(config *sshclient.Config) error {
	events, err := loadMatchingAuditEvents(config)
	if err != nil {
		return reportAuditError(config, err)
	}
	if config.JSONOutput {
		return encodeJSON(auditQueryJSON{
			SchemaVersion: auditQuerySchemaVersion,
			Success:       true,
			Action:        "query",
			Count:         len(events),
			Events:        events,
		})
	}
	printAuditTable(events)
	return nil
}

func handleAuditExport(config *sshclient.Config) error {
	if strings.TrimSpace(config.AuditExportPath) == "" {
		return reportAuditError(config, fmt.Errorf("export requires --to=<path>"))
	}
	events, err := loadMatchingAuditEvents(config)
	if err != nil {
		return reportAuditError(config, err)
	}
	if err := writeAuditExport(config.AuditExportPath, events); err != nil {
		return reportAuditError(config, err)
	}
	if config.JSONOutput {
		return encodeJSON(auditQueryJSON{
			SchemaVersion: auditQuerySchemaVersion,
			Success:       true,
			Action:        "export",
			Count:         len(events),
			Path:          config.AuditExportPath,
			Events:        events,
		})
	}
	fmt.Printf("Exported %d audit event(s) to %s\n", len(events), config.AuditExportPath)
	return nil
}

func loadMatchingAuditEvents(config *sshclient.Config) ([]json.RawMessage, error) {
	filter, err := buildAuditQueryFilter(config)
	if err != nil {
		return nil, err
	}
	dir, err := auditOutputDir(config)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []json.RawMessage{}, nil
		}
		return nil, fmt.Errorf("read audit directory %s: %w", dir, err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "sshx-") && strings.HasSuffix(name, ".jsonl") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	matched := make([]json.RawMessage, 0)
	for _, name := range names {
		path := filepath.Join(dir, name)
		fileEvents, readErr := readAuditJSONL(path, filter)
		if readErr != nil {
			return nil, readErr
		}
		matched = append(matched, fileEvents...)
	}
	return matched, nil
}

func buildAuditQueryFilter(config *sshclient.Config) (auditQueryFilter, error) {
	filter := auditQueryFilter{
		target:     strings.TrimSpace(config.AuditFilterHost),
		action:     strings.TrimSpace(config.AuditFilterAct),
		runID:      strings.TrimSpace(config.AuditRunID),
		errorKind:  strings.TrimSpace(config.AuditErrorKind),
		bypassOnly: config.AuditBypassOnly,
	}
	if strings.TrimSpace(config.AuditSince) != "" {
		ts, err := parseAuditTime(config.AuditSince, false)
		if err != nil {
			return filter, fmt.Errorf("invalid --since: %w", err)
		}
		filter.since = ts
		filter.hasSince = true
	}
	if strings.TrimSpace(config.AuditUntil) != "" {
		ts, err := parseAuditTime(config.AuditUntil, true)
		if err != nil {
			return filter, fmt.Errorf("invalid --until: %w", err)
		}
		filter.until = ts
		filter.hasUntil = true
	}
	return filter, nil
}

func parseAuditTime(raw string, endOfDay bool) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		if endOfDay {
			return t.Add(24*time.Hour - time.Nanosecond), nil
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("use RFC3339 or YYYY-MM-DD, got %q", raw)
}

func readAuditJSONL(path string, filter auditQueryFilter) ([]json.RawMessage, error) {
	file, err := os.Open(path) // #nosec G304 -- audit path is the local sshx audit directory.
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	defer func() { _ = file.Close() }() //nolint:errcheck

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	matched := make([]json.RawMessage, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		raw := json.RawMessage(line)
		if !auditEventMatches(raw, filter) {
			continue
		}
		matched = append(matched, append(json.RawMessage(nil), raw...))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read audit log %s: %w", path, err)
	}
	return matched, nil
}

func auditEventMatches(raw json.RawMessage, filter auditQueryFilter) bool {
	var event map[string]any
	if err := json.Unmarshal(raw, &event); err != nil {
		return false
	}
	if filter.hasSince || filter.hasUntil {
		ts, ok := parseEventTimestamp(event["timestamp"])
		if !ok {
			return false
		}
		if filter.hasSince && ts.Before(filter.since) {
			return false
		}
		if filter.hasUntil && ts.After(filter.until) {
			return false
		}
	}
	if filter.target != "" && !auditStringFieldEquals(event, filter.target, "host_input", "host_resolved", "host_name") {
		return false
	}
	if filter.action != "" && !auditStringFieldEquals(event, filter.action, "action", "mode") {
		return false
	}
	if filter.runID != "" && !auditStringFieldEquals(event, filter.runID, "run_id", "event_id") {
		return false
	}
	if filter.errorKind != "" {
		kind := ""
		if outcome, ok := event["outcome"].(map[string]any); ok {
			if value, isString := outcome["error_kind"].(string); isString {
				kind = value
			}
		}
		if !strings.EqualFold(kind, filter.errorKind) {
			return false
		}
	}
	if filter.bypassOnly {
		reason := mapString(event, "bypass_reason")
		force := mapBool(event, "force")
		if strings.TrimSpace(reason) == "" && !force {
			return false
		}
	}
	return true
}

func mapString(event map[string]any, key string) string {
	if value, ok := event[key].(string); ok {
		return value
	}
	return ""
}

func mapBool(event map[string]any, key string) bool {
	if value, ok := event[key].(bool); ok {
		return value
	}
	return false
}

func parseEventTimestamp(value any) (time.Time, bool) {
	s, ok := value.(string)
	if !ok || s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func auditStringFieldEquals(event map[string]any, want string, fields ...string) bool {
	for _, field := range fields {
		got := mapString(event, field)
		if got != "" && strings.EqualFold(got, want) {
			return true
		}
	}
	return false
}

func writeAuditExport(path string, events []json.RawMessage) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create export directory: %w", err)
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- export path is an explicit CLI argument.
	if err != nil {
		return fmt.Errorf("create export file: %w", err)
	}
	defer func() { _ = file.Close() }() //nolint:errcheck
	return writeAuditJSONL(file, events)
}

func writeAuditJSONL(w io.Writer, events []json.RawMessage) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, event := range events {
		if err := enc.Encode(event); err != nil {
			return fmt.Errorf("write export event: %w", err)
		}
	}
	return nil
}

func printAuditTable(events []json.RawMessage) {
	if len(events) == 0 {
		fmt.Println("No matching audit events.")
		return
	}
	fmt.Printf("=== Audit events (%d) ===\n", len(events))
	for i, raw := range events {
		var event map[string]any
		if err := json.Unmarshal(raw, &event); err != nil {
			fmt.Printf("[%d] (unreadable event)\n", i+1)
			continue
		}
		ts := mapString(event, "timestamp")
		mode := mapString(event, "mode")
		action := mapString(event, "action")
		host := mapString(event, "host_input")
		if host == "" {
			host = mapString(event, "host_resolved")
		}
		status := ""
		kind := ""
		if outcome, ok := event["outcome"].(map[string]any); ok {
			status = mapString(outcome, "status")
			kind = mapString(outcome, "error_kind")
		}
		fmt.Printf("[%d] %s  mode=%s action=%s host=%s status=%s", i+1, ts, mode, action, host, status)
		if kind != "" {
			fmt.Printf(" error_kind=%s", kind)
		}
		fmt.Println()
	}
}
