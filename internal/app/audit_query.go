package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

const (
	auditQuerySchemaVersion = "sshx.audit.query.v1"
	maxAuditRecordBytes     = 4 * 1024 * 1024
)

type auditQueryJSON struct {
	SchemaVersion  string              `json:"schema_version"`
	Success        bool                `json:"success"`
	Action         string              `json:"action"`
	Count          int                 `json:"count"`
	Path           string              `json:"path,omitempty"`
	Events         []json.RawMessage   `json:"events"`
	ErrorKind      string              `json:"error_kind,omitempty"`
	Error          string              `json:"error,omitempty"`
	ErrorDetails   *auditQueryError    `json:"error_details,omitempty"`
	SkippedRecords int                 `json:"skipped_records,omitempty"`
	Warnings       []auditQueryWarning `json:"warnings,omitempty"`
}

type auditQueryError struct {
	Kind string `json:"kind"`
}

type auditQueryWarning struct {
	Path      string `json:"path"`
	Line      int    `json:"line,omitempty"`
	ErrorKind string `json:"error_kind"`
	Message   string `json:"message"`
}

type auditQueryRecords struct {
	events         []json.RawMessage
	skippedRecords int
	warnings       []auditQueryWarning
}

type auditQueryFilter struct {
	since       time.Time
	until       time.Time
	hasSince    bool
	hasUntil    bool
	target      string
	action      string
	runID       string
	executionID string
	errorKind   string
	bypassOnly  bool
}

// HandleAudit runs the read-only audit query/export surface. It never writes
// an audit event of its own.
func HandleAudit(config *sshclient.Config) error {
	if config.ArgumentError != "" {
		return reportAuditError(config, fmt.Errorf("%w: %s", execution.ErrConfig, config.ArgumentError))
	}
	switch config.AuditAction {
	case "query":
		return handleAuditQuery(config)
	case "export":
		return handleAuditExport(config)
	default:
		return reportAuditError(config, fmt.Errorf("%w: unknown audit action %q (use: query, export)", execution.ErrConfig, config.AuditAction))
	}
}

func reportAuditError(config *sshclient.Config, err error) error {
	return reportAuditQueryError(config, auditQueryRecords{}, err)
}

func reportAuditQueryError(config *sshclient.Config, records auditQueryRecords, err error) error {
	if config != nil && config.JSONOutput {
		result := auditQueryResult(config.AuditAction, records)
		if config.AuditAction == "export" {
			result.Path = config.AuditExportPath
		}
		result.Success = false
		// The v1 flat projection historically used config for every query
		// failure. Preserve it while exposing the owned I/O boundary's kind.
		result.ErrorKind = "config"
		result.Error = redactError(err)
		kind := "config"
		if errors.Is(err, execution.ErrLocalIO) {
			kind = execution.ErrorKindLocalIO
		}
		result.ErrorDetails = &auditQueryError{Kind: kind}
		if emitErr := encodeJSON(result); emitErr != nil {
			return errors.Join(err, auditIOError("write audit query response", "", emitErr))
		}
		return ErrReported
	}
	warningErr := printAuditWarnings(records.warnings)
	if len(records.events) > 0 {
		return errors.Join(err, warningErr, printAuditTable(records.events))
	}
	return errors.Join(err, warningErr)
}

func auditQueryResult(action string, records auditQueryRecords) auditQueryJSON {
	if records.events == nil {
		records.events = []json.RawMessage{}
	}
	return auditQueryJSON{
		SchemaVersion: auditQuerySchemaVersion, Success: true, Action: action,
		Count: len(records.events), Events: records.events,
		SkippedRecords: records.skippedRecords, Warnings: records.warnings,
	}
}

func handleAuditQuery(config *sshclient.Config) error {
	records, err := loadMatchingAuditEvents(config)
	if err != nil {
		return reportAuditQueryError(config, records, err)
	}
	if config.JSONOutput {
		return auditIOError("write audit query response", "", encodeJSON(auditQueryResult("query", records)))
	}
	return errors.Join(printAuditWarnings(records.warnings), printAuditTable(records.events))
}

func handleAuditExport(config *sshclient.Config) error {
	if strings.TrimSpace(config.AuditExportPath) == "" {
		return reportAuditError(config, fmt.Errorf("%w: export requires --to=<path>", execution.ErrConfig))
	}
	records, err := loadMatchingAuditEvents(config)
	if err != nil {
		return reportAuditQueryError(config, records, err)
	}
	if exportErr := writeAuditExport(config.AuditExportPath, records.events); exportErr != nil {
		return reportAuditQueryError(config, records, exportErr)
	}
	if config.JSONOutput {
		result := auditQueryResult("export", records)
		result.Path = config.AuditExportPath
		return auditIOError("write audit export response", "", encodeJSON(result))
	}
	warningErr := printAuditWarnings(records.warnings)
	_, err = fmt.Printf("Exported %d audit event(s) to %s\n", len(records.events), config.AuditExportPath)
	return errors.Join(warningErr, auditIOError("write audit export response", "", err))
}

func loadMatchingAuditEvents(config *sshclient.Config) (auditQueryRecords, error) {
	records := auditQueryRecords{events: make([]json.RawMessage, 0)}
	filter, err := buildAuditQueryFilter(config)
	if err != nil {
		return records, err
	}
	dir, err := auditOutputDir(config)
	if err != nil {
		return records, auditIOError("resolve audit directory", "", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return records, nil
		}
		return records, auditIOError("read audit directory", dir, err)
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
	var readErrors []error
	for _, name := range names {
		path := filepath.Join(dir, name)
		fileRecords, readErr := readAuditJSONL(path, filter)
		records.events = append(records.events, fileRecords.events...)
		records.skippedRecords += fileRecords.skippedRecords
		records.warnings = append(records.warnings, fileRecords.warnings...)
		if readErr != nil {
			readErrors = append(readErrors, readErr)
		}
	}
	return records, errors.Join(readErrors...)
}

func buildAuditQueryFilter(config *sshclient.Config) (auditQueryFilter, error) {
	filter := auditQueryFilter{
		target:      strings.TrimSpace(config.AuditFilterHost),
		action:      strings.TrimSpace(config.AuditFilterAct),
		runID:       strings.TrimSpace(config.AuditRunID),
		executionID: strings.TrimSpace(config.AuditExecutionID),
		errorKind:   strings.TrimSpace(config.AuditErrorKind),
		bypassOnly:  config.AuditBypassOnly,
	}
	if strings.TrimSpace(config.AuditSince) != "" {
		ts, err := parseAuditTime(config.AuditSince, false)
		if err != nil {
			return filter, fmt.Errorf("%w: invalid --since: %w", execution.ErrConfig, err)
		}
		filter.since = ts
		filter.hasSince = true
	}
	if strings.TrimSpace(config.AuditUntil) != "" {
		ts, err := parseAuditTime(config.AuditUntil, true)
		if err != nil {
			return filter, fmt.Errorf("%w: invalid --until: %w", execution.ErrConfig, err)
		}
		filter.until = ts
		filter.hasUntil = true
	}
	if filter.hasSince && filter.hasUntil && filter.until.Before(filter.since) {
		return filter, fmt.Errorf("%w: --until must not precede --since", execution.ErrConfig)
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

func readAuditJSONL(path string, filter auditQueryFilter) (records auditQueryRecords, err error) {
	records.events = make([]json.RawMessage, 0)
	file, err := os.Open(path) // #nosec G304 -- audit path is the local sshx audit directory.
	if err != nil {
		return records, auditIOError("open audit log", path, err)
	}
	defer func() {
		err = errors.Join(err, auditIOError("close audit log", path, file.Close()))
	}()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxAuditRecordBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		raw := json.RawMessage(line)
		event, decodeErr := decodeAuditEvent(raw)
		if decodeErr != nil {
			records.skippedRecords++
			records.warnings = append(records.warnings, auditQueryWarning{
				Path: path, Line: lineNumber, ErrorKind: "audit_record_invalid",
				Message: "skipped malformed or incomplete JSON object",
			})
			continue
		}
		if !auditFieldsMatch(event, filter) {
			continue
		}
		records.events = append(records.events, append(json.RawMessage(nil), raw...))
	}
	if scanErr := scanner.Err(); scanErr != nil {
		records.warnings = append(records.warnings, auditQueryWarning{
			Path: path, Line: lineNumber + 1, ErrorKind: execution.ErrorKindLocalIO,
			Message: "audit log scan failed; remaining records could not be read",
		})
		return records, auditIOError("read audit log", path, scanErr)
	}
	return records, nil
}

func auditEventMatches(raw json.RawMessage, filter auditQueryFilter) bool {
	event, err := decodeAuditEvent(raw)
	return err == nil && auditFieldsMatch(event, filter)
}

func decodeAuditEvent(raw json.RawMessage) (map[string]any, error) {
	if !json.Valid(raw) {
		return nil, errors.New("invalid audit JSON")
	}
	var event map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return nil, err
	}
	if event == nil {
		return nil, errors.New("audit record must be an object")
	}
	return event, nil
}

func auditFieldsMatch(event map[string]any, filter auditQueryFilter) bool {
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
	if filter.executionID != "" && !auditStringFieldEquals(event, filter.executionID, "execution_id", "parent_execution_id") {
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
			return auditIOError("create export directory", dir, err)
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- export path is an explicit CLI argument.
	if err != nil {
		return auditIOError("create export file", path, err)
	}
	writeErr := writeAuditJSONL(file, events)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	return auditIOError("persist audit export", path, errors.Join(writeErr, file.Close()))
}

func writeAuditJSONL(w io.Writer, events []json.RawMessage) error {
	for _, event := range events {
		if !json.Valid(event) {
			return auditIOError("encode export event", "", errors.New("invalid JSON record"))
		}
		line := append(append([]byte(nil), event...), '\n')
		n, err := w.Write(line)
		if err == nil && n != len(line) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return auditIOError("write export event", "", err)
		}
	}
	return nil
}

func auditIOError(op, path string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s %s: %w", execution.ErrLocalIO, op, path, err)
}

func printAuditWarnings(warnings []auditQueryWarning) error {
	for _, warning := range warnings {
		if _, err := fmt.Fprintf(os.Stderr, "audit warning: %s:%d: %s\n", warning.Path, warning.Line, warning.Message); err != nil {
			return auditIOError("write audit warning", "", err)
		}
	}
	return nil
}

func printAuditTable(events []json.RawMessage) error {
	var output strings.Builder
	if len(events) == 0 {
		output.WriteString("No matching audit events.\n")
	} else {
		fmt.Fprintf(&output, "=== Audit events (%d) ===\n", len(events)) //nolint:errcheck // strings.Builder cannot fail.
	}
	for i, raw := range events {
		event, err := decodeAuditEvent(raw)
		if err != nil {
			return auditIOError("decode audit table event", "", err)
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
		fmt.Fprintf(&output, "[%d] %s  mode=%s action=%s host=%s status=%s", i+1, ts, mode, action, host, status) //nolint:errcheck // strings.Builder cannot fail.
		if kind != "" {
			fmt.Fprintf(&output, " error_kind=%s", kind) //nolint:errcheck // strings.Builder cannot fail.
		}
		output.WriteByte('\n') //nolint:errcheck // strings.Builder cannot fail.
	}
	_, err := io.WriteString(os.Stdout, output.String())
	return auditIOError("write audit table", "", err)
}
