package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
