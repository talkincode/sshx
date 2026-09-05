package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

func writeAuditFixture(t *testing.T, dir string, lines ...string) {
	t.Helper()
	auditDir := filepath.Join(dir, ".sshx", "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(auditDir, "sshx-2026-09-01.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func TestAuditQueryFiltersAndEmptyJSON(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	writeAuditFixture(t, home,
		`{"schema_version":"sshx.audit.v1","event_id":"e1","timestamp":"2026-09-01T01:00:00Z","mode":"ssh","action":"command","host_input":"lab","run_id":"run-1","force":false,"outcome":{"status":"success"}}`,
		`{"schema_version":"sshx.audit.v1","event_id":"e2","timestamp":"2026-09-01T02:00:00Z","mode":"run","action":"command","host_input":"prod","run_id":"run-2","force":true,"bypass_reason":"window","outcome":{"status":"failure","error_kind":"blocked"}}`,
	)

	out := string(captureStdout(t, func() {
		if err := HandleAudit(ParseArgs([]string{"sshx", "audit", "query", "--json"})); err != nil {
			t.Errorf("query all: %v", err)
		}
	}))
	var all auditQueryJSON
	if err := json.Unmarshal([]byte(out), &all); err != nil {
		t.Fatalf("query json: %v (%s)", err, out)
	}
	if !all.Success || all.Count != 2 || all.SchemaVersion != auditQuerySchemaVersion {
		t.Fatalf("all = %+v", all)
	}

	out = string(captureStdout(t, func() {
		if err := HandleAudit(ParseArgs([]string{"sshx", "audit", "query", "--run-id=run-2", "--json"})); err != nil {
			t.Errorf("query run-id: %v", err)
		}
	}))
	var byRun auditQueryJSON
	if err := json.Unmarshal([]byte(out), &byRun); err != nil {
		t.Fatalf("run-id json: %v (%s)", err, out)
	}
	if byRun.Count != 1 {
		t.Fatalf("run-id count = %d", byRun.Count)
	}

	out = string(captureStdout(t, func() {
		if err := HandleAudit(ParseArgs([]string{"sshx", "audit", "query", "--error-kind=blocked", "--json"})); err != nil {
			t.Errorf("query error-kind: %v", err)
		}
	}))
	var byKind auditQueryJSON
	if err := json.Unmarshal([]byte(out), &byKind); err != nil {
		t.Fatalf("kind json: %v (%s)", err, out)
	}
	if byKind.Count != 1 {
		t.Fatalf("error-kind count = %d", byKind.Count)
	}

	out = string(captureStdout(t, func() {
		if err := HandleAudit(ParseArgs([]string{"sshx", "audit", "query", "--bypass-only", "--json"})); err != nil {
			t.Errorf("query bypass: %v", err)
		}
	}))
	var bypass auditQueryJSON
	if err := json.Unmarshal([]byte(out), &bypass); err != nil {
		t.Fatalf("bypass json: %v (%s)", err, out)
	}
	if bypass.Count != 1 {
		t.Fatalf("bypass count = %d", bypass.Count)
	}

	out = string(captureStdout(t, func() {
		if err := HandleAudit(ParseArgs([]string{"sshx", "audit", "query", "--target=missing", "--json"})); err != nil {
			t.Errorf("empty query: %v", err)
		}
	}))
	var empty auditQueryJSON
	if err := json.Unmarshal([]byte(out), &empty); err != nil {
		t.Fatalf("empty json: %v (%s)", err, out)
	}
	if !empty.Success || empty.Count != 0 || empty.Events == nil {
		t.Fatalf("empty = %+v", empty)
	}

	exportPath := filepath.Join(home, "handoff.jsonl")
	out = string(captureStdout(t, func() {
		if err := HandleAudit(ParseArgs([]string{"sshx", "audit", "export", "--to=" + exportPath, "--run-id=run-1", "--json"})); err != nil {
			t.Errorf("export: %v", err)
		}
	}))
	var exported auditQueryJSON
	if err := json.Unmarshal([]byte(out), &exported); err != nil {
		t.Fatalf("export json: %v (%s)", err, out)
	}
	if !exported.Success || exported.Count != 1 || exported.Path != exportPath {
		t.Fatalf("export = %+v", exported)
	}
	data, err := os.ReadFile(exportPath) // #nosec G304 -- test fixture path.
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if !strings.Contains(string(data), `"run_id":"run-1"`) {
		t.Fatalf("export file = %s", data)
	}
}

func TestParseAuditTime(t *testing.T) {
	ts, err := parseAuditTime("2026-09-01", false)
	if err != nil || !ts.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("date = %v err=%v", ts, err)
	}
	end, err := parseAuditTime("2026-09-01", true)
	if err != nil || !end.After(ts) {
		t.Fatalf("end of day = %v err=%v", end, err)
	}
}

func TestAuditQueryCorruptRecordsRetainOriginalFields(t *testing.T) {
	dir := t.TempDir()
	first := ` {"event_id":"old","run_id":"legacy","extra":{"large":9007199254740993,"future":1e1000},"timestamp":"2026-09-01T00:00:00Z"} `
	second := `{"event_id":"new","execution_id":"exec-2","future_field":[true,{"literal":"<already-redacted>"}]}`
	path := filepath.Join(dir, "sshx-2026-09-01.jsonl")
	fixture := first + "\nnot-json SECRET_LOG_SENTINEL\nnull\n[]\n" + second + "\n\n" + `{"event_id":"partial"`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &sshclient.Config{AuditAction: "query", AuditOutput: dir, JSONOutput: true}
	records, err := loadMatchingAuditEvents(config)
	if err != nil {
		t.Fatal(err)
	}
	if records.skippedRecords != 4 || len(records.warnings) != 4 || len(records.events) != 2 {
		t.Fatalf("unexpected read diagnostics: %+v", records)
	}
	if string(records.events[0]) != first || string(records.events[1]) != second {
		t.Fatalf("raw records were changed: %s", records.events)
	}
	for i, line := range []int{2, 3, 4, 7} {
		if records.warnings[i].Line != line || records.warnings[i].Path != path {
			t.Fatalf("warning %d = %+v", i, records.warnings[i])
		}
	}
	out := captureStdout(t, func() {
		if queryErr := HandleAudit(config); queryErr != nil {
			t.Errorf("query: %v", queryErr)
		}
	})
	var result auditQueryJSON
	if decodeErr := json.Unmarshal(out, &result); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if !result.Success || result.Count != 2 || result.SkippedRecords != 4 || len(result.Warnings) != 4 {
		t.Fatalf("query result = %+v", result)
	}
	if bytes.Contains(out, []byte("SECRET_LOG_SENTINEL")) {
		t.Fatal("warning leaked malformed log content")
	}
	exportPath := filepath.Join(t.TempDir(), "export.jsonl")
	if exportErr := writeAuditExport(exportPath, records.events); exportErr != nil {
		t.Fatal(exportErr)
	}
	exported, err := os.ReadFile(exportPath) // #nosec G304 -- test-owned export path.
	if err != nil {
		t.Fatal(err)
	}
	if string(exported) != first+"\n"+second+"\n" {
		t.Fatalf("export did not retain original records: %s", exported)
	}
}

func TestAuditQueryExecutionCorrelationAndLegacyRunID(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	writeAuditFixture(t, home,
		`{"event_id":"old-event","run_id":"old-run"}`,
		`{"event_id":"parent","execution_id":"execution-1","run_id":"run-1"}`,
		`{"event_id":"child","execution_id":"target-1","parent_execution_id":"execution-1","run_id":"run-1"}`,
		`{"event_id":"other","execution_id":"execution-2","run_id":"run-2"}`,
	)
	tests := []struct {
		name  string
		flags []string
		count int
	}{
		{"parent and target", []string{"--execution-id=execution-1"}, 2},
		{"target only", []string{"--execution-id=target-1"}, 1},
		{"legacy run", []string{"--run-id=old-run"}, 1},
		{"legacy event fallback", []string{"--run-id=old-event"}, 1},
		{"matching intersection", []string{"--execution-id=execution-1", "--run-id=run-1"}, 2},
		{"empty intersection", []string{"--execution-id=execution-1", "--run-id=run-2"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"sshx", "audit", "query", "--json"}, tt.flags...)
			out := captureStdout(t, func() {
				if err := HandleAudit(ParseArgs(args)); err != nil {
					t.Errorf("query: %v", err)
				}
			})
			var result auditQueryJSON
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatal(err)
			}
			if !result.Success || result.Count != tt.count {
				t.Fatalf("query result = %+v", result)
			}
		})
	}
}

func TestAuditQueryOversizedScanReturnsPartialFailure(t *testing.T) {
	dir := t.TempDir()
	first := `{"event_id":"before-large"}`
	oversized := `{"payload":"` + strings.Repeat("x", maxAuditRecordBytes) + `"}`
	if err := os.WriteFile(filepath.Join(dir, "sshx-2026-09-01.jsonl"), []byte(first+"\n"+oversized+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshx-2026-09-02.jsonl"), []byte(`{"event_id":"next-file"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &sshclient.Config{AuditAction: "query", AuditOutput: dir, JSONOutput: true}
	records, err := loadMatchingAuditEvents(config)
	if !errors.Is(err, execution.ErrLocalIO) {
		t.Fatalf("scan error = %v, want local I/O", err)
	}
	if len(records.events) != 2 || len(records.warnings) != 1 || records.warnings[0].Line != 2 {
		t.Fatalf("partial records = %+v", records)
	}
	out := captureStdout(t, func() {
		if queryErr := HandleAudit(config); !errors.Is(queryErr, ErrReported) {
			t.Errorf("query error = %v", queryErr)
		}
	})
	var result auditQueryJSON
	if decodeErr := json.Unmarshal(out, &result); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if result.Success || result.Count != 2 || result.ErrorKind != "config" ||
		result.ErrorDetails == nil || result.ErrorDetails.Kind != execution.ErrorKindLocalIO {
		t.Fatalf("partial failure = %+v", result)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("missing scan warning: %+v", result)
	}
}

func TestAuditQueryReadAndExportFailuresAreTyped(t *testing.T) {
	dir := t.TempDir()
	_, err := readAuditJSONL(filepath.Join(dir, "missing.jsonl"), auditQueryFilter{})
	if !errors.Is(err, execution.ErrLocalIO) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open error lost its causes: %v", err)
	}
	file := filepath.Join(dir, "not-a-directory")
	if writeErr := os.WriteFile(file, []byte("not a directory"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	_, err = loadMatchingAuditEvents(&sshclient.Config{AuditOutput: file})
	if !errors.Is(err, execution.ErrLocalIO) {
		t.Fatalf("read directory error = %v", err)
	}
	auditDir := t.TempDir()
	if writeErr := os.WriteFile(filepath.Join(auditDir, "sshx-2026-09-01.jsonl"), []byte(`{"event_id":"retained"}`+"\n"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	config := &sshclient.Config{AuditAction: "export", AuditOutput: auditDir, AuditExportPath: dir, JSONOutput: true}
	out := captureStdout(t, func() {
		if exportErr := HandleAudit(config); !errors.Is(exportErr, ErrReported) {
			t.Errorf("export error = %v", exportErr)
		}
	})
	var result auditQueryJSON
	if decodeErr := json.Unmarshal(out, &result); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if result.Success || result.Count != 1 || result.Path != dir || result.ErrorDetails == nil ||
		result.ErrorDetails.Kind != execution.ErrorKindLocalIO {
		t.Fatalf("export failure = %+v", result)
	}
}

type auditTestWriter struct {
	err   error
	short bool
}

func (w auditTestWriter) Write(data []byte) (int, error) {
	if w.short {
		return len(data) - 1, nil
	}
	return 0, w.err
}

func TestAuditExportWriteFailures(t *testing.T) {
	failure := errors.New("writer failed")
	events := []json.RawMessage{json.RawMessage(`{"event_id":"one"}`)}
	for _, tt := range []struct {
		name   string
		writer io.Writer
		cause  error
	}{
		{"write error", auditTestWriter{err: failure}, failure},
		{"short write", auditTestWriter{short: true}, io.ErrShortWrite},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := writeAuditJSONL(tt.writer, events)
			if !errors.Is(err, execution.ErrLocalIO) || !errors.Is(err, tt.cause) {
				t.Fatalf("write error lost its kind or cause: %v", err)
			}
		})
	}
}

func TestAuditQueryInvalidTimeRange(t *testing.T) {
	_, err := buildAuditQueryFilter(&sshclient.Config{AuditSince: "2026-09-02", AuditUntil: "2026-09-01"})
	if err == nil {
		t.Fatal("reversed range must fail")
	}
}

func TestAuditQueryResponseWriteFailure(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		name := "human"
		if jsonOutput {
			name = "json"
		}
		t.Run(name, func(t *testing.T) {
			file, err := os.Create(filepath.Join(t.TempDir(), "closed-output"))
			if err != nil {
				t.Fatal(err)
			}
			if closeErr := file.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			original := os.Stdout
			os.Stdout = file
			defer func() { os.Stdout = original }()
			err = HandleAudit(&sshclient.Config{
				AuditAction: "query", AuditOutput: t.TempDir(), JSONOutput: jsonOutput,
			})
			if !errors.Is(err, execution.ErrLocalIO) || !errors.Is(err, os.ErrClosed) {
				t.Fatalf("output error lost its kind or cause: %v", err)
			}
		})
	}
}
