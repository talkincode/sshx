package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestRun_BlockedCommandWritesRedactedAuditEvent(t *testing.T) {
	setTestHome(t, t.TempDir())
	auditDir := t.TempDir()
	command := "sudo rm -rf / password=orange --token purple" //nolint:gosec // test verifies redaction of credential-like arguments.

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	runErr := Run([]string{"sshx", "-h=192.0.2.1", "--audit-output=" + auditDir, "--json", command})

	if closeErr := w.Close(); closeErr != nil {
		t.Logf("failed to close pipe writer: %v", closeErr)
	}
	os.Stdout = old
	if _, copyErr := io.Copy(io.Discard, r); copyErr != nil {
		t.Logf("failed to drain stdout: %v", copyErr)
	}

	if !errors.Is(runErr, ErrReported) {
		t.Fatalf("expected ErrReported, got %v", runErr)
	}

	event := readSingleAuditEvent(t, auditDir)
	if event["schema_version"] != auditSchemaVersion {
		t.Fatalf("expected schema %q, got %v", auditSchemaVersion, event["schema_version"])
	}
	if event["mode"] != "ssh" {
		t.Errorf("expected ssh mode, got %v", event["mode"])
	}
	if event["action"] != "command" {
		t.Errorf("expected command action, got %v", event["action"])
	}
	if event["host_input"] != "192.0.2.1" {
		t.Errorf("expected host input, got %v", event["host_input"])
	}
	if event["uses_sudo"] != true {
		t.Errorf("expected uses_sudo=true, got %v", event["uses_sudo"])
	}
	if event["would_read_secret"] != false {
		t.Errorf("blocked command must not audit a secret read, got %v", event["would_read_secret"])
	}
	if event["would_mutate_remote"] != false {
		t.Errorf("blocked command must not audit remote mutation, got %v", event["would_mutate_remote"])
	}

	auditedCommand, ok := event["command"].(string)
	if !ok {
		t.Fatalf("expected command string, got %T", event["command"])
	}
	if strings.Contains(auditedCommand, "orange") || strings.Contains(auditedCommand, "purple") {
		t.Fatalf("audit command was not redacted: %q", auditedCommand)
	}
	if !strings.Contains(auditedCommand, "password=<redacted>") || !strings.Contains(auditedCommand, "--token <redacted>") {
		t.Errorf("audit command did not include expected redaction markers: %q", auditedCommand)
	}

	outcome, ok := event["outcome"].(map[string]any)
	if !ok {
		t.Fatalf("expected outcome object, got %T", event["outcome"])
	}
	if outcome["status"] != "failure" {
		t.Errorf("expected failure outcome, got %v", outcome["status"])
	}
	if outcome["error_kind"] != "blocked" {
		t.Errorf("expected blocked error kind, got %v", outcome["error_kind"])
	}
	message, ok := outcome["message"].(string)
	if !ok {
		t.Fatalf("expected outcome message string, got %T", outcome["message"])
	}
	if strings.Contains(message, "orange") || strings.Contains(message, "purple") {
		t.Fatalf("audit error message was not redacted: %q", message)
	}

	redaction, ok := event["redaction"].(map[string]any)
	if !ok {
		t.Fatalf("expected redaction object, got %T", event["redaction"])
	}
	if redaction["secrets_redacted"] != true || redaction["stdout_omitted"] != true || redaction["stderr_omitted"] != true {
		t.Errorf("unexpected redaction metadata: %v", redaction)
	}
	if _, exists := event["stdout"]; exists {
		t.Error("audit event must not include stdout")
	}
	if _, exists := event["stderr"]; exists {
		t.Error("audit event must not include stderr")
	}
}

//nolint:gosec // test inputs intentionally contain credential-like command arguments.
func TestRedactSensitiveTextCoversQuotedAndUnquotedValues(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		forbidden []string
	}{
		{
			name:      "quoted assignment with spaces",
			input:     `deploy password="alpha bravo" tail`,
			want:      `deploy password=<redacted> tail`,
			forbidden: []string{"alpha", "bravo"},
		},
		{
			name:      "single quoted assignment with spaces",
			input:     `deploy token='charlie delta' tail`,
			want:      `deploy token=<redacted> tail`,
			forbidden: []string{"charlie", "delta"},
		},
		{
			name:      "quoted flag with spaces",
			input:     `curl --token "echo foxtrot" done`,
			want:      `curl --token <redacted> done`,
			forbidden: []string{"echo", "foxtrot"},
		},
		{
			name:      "quoted equals flag with spaces",
			input:     `curl --api-key="golf hotel" done`,
			want:      `curl --api-key=<redacted> done`,
			forbidden: []string{"golf", "hotel"},
		},
		{
			name:      "unquoted assignment",
			input:     `deploy access_key=india tail`,
			want:      `deploy access_key=<redacted> tail`,
			forbidden: []string{"india"},
		},
		{
			name:      "unquoted flag",
			input:     `curl --secret juliet done`,
			want:      `curl --secret <redacted> done`,
			forbidden: []string{"juliet"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactSensitiveText(tt.input)
			if got != tt.want {
				t.Fatalf("redactSensitiveText() = %q, want %q", got, tt.want)
			}
			for _, forbidden := range tt.forbidden {
				if strings.Contains(got, forbidden) {
					t.Fatalf("redactSensitiveText() leaked %q in %q", forbidden, got)
				}
			}
		})
	}
}

func TestSQLAuditUsesRedactedStatementAndDigest(t *testing.T) {
	statement := "UPDATE users SET password = 'super-secret', pin=1234 WHERE id=42"
	config := &sshclient.Config{
		Mode:         "sql",
		SQLEngine:    "postgres",
		SQLDatabase:  "app",
		SQLStatement: statement,
		AuditEnabled: true,
	}
	recorder := newAuditRecorder(config)
	if recorder == nil {
		t.Fatal("expected audit recorder")
	}
	recorder.refresh(config)
	if strings.Contains(recorder.event.SQLStatement, "super-secret") ||
		strings.Contains(recorder.event.SQLStatement, "1234") {
		t.Fatalf("SQL audit statement leaked literals: %q", recorder.event.SQLStatement)
	}
	if recorder.event.SQLStatementHash != sqlStatementDigest(statement) ||
		len(recorder.event.SQLStatementHash) != 64 {
		t.Fatalf("unexpected statement digest %q", recorder.event.SQLStatementHash)
	}
}

func TestRun_DryRunDoesNotWriteAuditEvent(t *testing.T) {
	setTestHome(t, t.TempDir())
	auditDir := filepath.Join(t.TempDir(), "audit")
	result := runDryRunJSON(t, []string{"sshx", "-h=192.0.2.1", "--audit-output=" + auditDir, "--dry-run", "--json", "uptime"})

	if result["dry_run"] != true {
		t.Fatalf("expected dry_run=true, got %v", result["dry_run"])
	}
	if _, err := os.Stat(auditDir); !os.IsNotExist(err) {
		t.Fatalf("dry-run should not create audit directory, stat err=%v", err)
	}
}

func TestAuditRecorderRefreshRecordsExecutionContract(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := &sshclient.Config{
		AuditEnabled:      true,
		Host:              "prod-web",
		Port:              "2222",
		User:              "root",
		Mode:              "ssh",
		Command:           `sudo deploy --token "alpha bravo"`,
		UseKeyAuth:        true,
		KeyPath:           "/keys/prod.pem",
		SudoKey:           "prod-sudo",
		Timeout:           45 * time.Second,
		JSONOutput:        true,
		SafetyCheck:       true,
		AcceptUnknownHost: true,
		KnownHostsPath:    "/tmp/known_hosts",
	}
	recorder := newAuditRecorder(config)
	if recorder == nil {
		t.Fatal("expected audit recorder")
	}

	config.Host = "10.0.0.5"
	recorder.refresh(config)
	event := recorder.event

	if event.HostInput != "prod-web" || event.HostResolved != "10.0.0.5" || event.HostResolvedBy != "settings" {
		t.Fatalf("unexpected host resolution fields: input=%q resolved=%q by=%q", event.HostInput, event.HostResolved, event.HostResolvedBy)
	}
	if event.Command != "sudo deploy --token <redacted>" {
		t.Fatalf("expected redacted command, got %q", event.Command)
	}
	if event.Action != "command" || event.Mode != "ssh" {
		t.Fatalf("unexpected mode/action: %s/%s", event.Mode, event.Action)
	}
	if !event.UsesSudo || !event.WouldReadSecret || !event.WouldMutateRemote || !event.MayMutateKnownHosts {
		t.Fatalf("unexpected audit effects: sudo=%v read_secret=%v mutate_remote=%v known_hosts=%v",
			event.UsesSudo, event.WouldReadSecret, event.WouldMutateRemote, event.MayMutateKnownHosts)
	}
	if event.KeyPath != "/keys/prod.pem" || event.SudoKey != "prod-sudo" || event.Timeout != "45s" {
		t.Fatalf("unexpected key/sudo/timeout metadata: key=%q sudo=%q timeout=%q", event.KeyPath, event.SudoKey, event.Timeout)
	}
	if !event.JSONOutput || !event.SafetyCheckEnabled || !event.AcceptUnknownHost || event.KnownHostsPath != "/tmp/known_hosts" {
		t.Fatalf("unexpected execution flags: json=%v safety=%v accept=%v known_hosts=%q",
			event.JSONOutput, event.SafetyCheckEnabled, event.AcceptUnknownHost, event.KnownHostsPath)
	}
}

func TestAuditEffectFlagsByModeAndAction(t *testing.T) {
	tests := []struct {
		name                    string
		config                  sshclient.Config
		wantReadSecret          bool
		wantWriteLocalState     bool
		wantMutateRemote        bool
		wantMayMutateKnownHosts bool
	}{
		{
			name: "ssh sudo command reads secret mutates remote and may trust host",
			config: sshclient.Config{
				Mode:              "ssh",
				Command:           "sudo systemctl restart nginx",
				SudoKey:           "prod",
				AcceptUnknownHost: true,
			},
			wantReadSecret:          true,
			wantMutateRemote:        true,
			wantMayMutateKnownHosts: true,
		},
		{
			name:                "password set writes only local state",
			config:              sshclient.Config{Mode: "password", PasswordAction: "set"},
			wantWriteLocalState: true,
		},
		{
			name:                "password delete reads and writes local state",
			config:              sshclient.Config{Mode: "password", PasswordAction: "delete"},
			wantReadSecret:      true,
			wantWriteLocalState: true,
		},
		{
			name:                "host add writes only local state",
			config:              sshclient.Config{Mode: "host", HostAction: "add"},
			wantWriteLocalState: true,
		},
		{
			name:                "skill install writes only local state",
			config:              sshclient.Config{Mode: "skill", SkillAction: "install"},
			wantWriteLocalState: true,
		},
		{
			name:                    "host test reads secret mutates remote and may trust host",
			config:                  sshclient.Config{Mode: "host", HostAction: "test", AcceptUnknownHost: true},
			wantReadSecret:          true,
			wantMutateRemote:        true,
			wantMayMutateKnownHosts: true,
		},
		{
			name:             "sftp upload mutates remote",
			config:           sshclient.Config{Mode: "sftp", SftpAction: "upload"},
			wantMutateRemote: true,
		},
		{
			name:   "sftp download does not mutate remote",
			config: sshclient.Config{Mode: "sftp", SftpAction: "download"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := auditWouldReadSecret(&tt.config); got != tt.wantReadSecret {
				t.Errorf("auditWouldReadSecret() = %v, want %v", got, tt.wantReadSecret)
			}
			if got := auditWouldWriteLocalState(&tt.config); got != tt.wantWriteLocalState {
				t.Errorf("auditWouldWriteLocalState() = %v, want %v", got, tt.wantWriteLocalState)
			}
			if got := auditWouldMutateRemote(&tt.config); got != tt.wantMutateRemote {
				t.Errorf("auditWouldMutateRemote() = %v, want %v", got, tt.wantMutateRemote)
			}
			recorder := &auditRecorder{started: time.Now()}
			recorder.refresh(&tt.config)
			if recorder.event.MayMutateKnownHosts != tt.wantMayMutateKnownHosts {
				t.Errorf("MayMutateKnownHosts = %v, want %v", recorder.event.MayMutateKnownHosts, tt.wantMayMutateKnownHosts)
			}
		})
	}
}

func TestWriteAuditEventUsesJSONLWithPrivatePermissions(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	config := &sshclient.Config{AuditEnabled: true}
	event := auditEvent{
		SchemaVersion: auditSchemaVersion,
		EventID:       "test-event",
		Timestamp:     "2026-06-20T00:00:00Z",
		Mode:          "ssh",
		Action:        "command",
		Outcome:       auditStatus{Status: "success"},
		Redaction:     auditRedaction{SecretsRedacted: true, StdoutOmitted: true, StderrOmitted: true},
	}

	if err := writeAuditEvent(config, event, mustParseDate(t, "2026-06-20")); err != nil {
		t.Fatalf("writeAuditEvent() error = %v", err)
	}

	auditPath := filepath.Join(home, SettingsDir, auditDirName, "sshx-2026-06-20.jsonl")
	info, err := os.Stat(auditPath)
	if err != nil {
		t.Fatalf("expected audit file at %s: %v", auditPath, err)
	}
	// Windows has no POSIX permission bits; Go reports 0666/0777 there.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("expected audit file mode 0600, got %v", info.Mode().Perm())
	}

	data, err := os.ReadFile(auditPath) //nolint:gosec // test reads a controlled temp file.
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}
	if lines := bytes.Count(data, []byte("\n")); lines != 1 {
		t.Fatalf("expected one JSONL line, got %d in %q", lines, string(data))
	}
}

func readSingleAuditEvent(t *testing.T, auditDir string) map[string]any {
	t.Helper()

	entries, err := os.ReadDir(auditDir)
	if err != nil {
		t.Fatalf("failed to read audit directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one audit file, got %d", len(entries))
	}
	data, err := os.ReadFile(filepath.Join(auditDir, entries[0].Name())) //nolint:gosec // test reads a controlled temp file.
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("expected one audit event, got %d", len(lines))
	}
	var event map[string]any
	if err := json.Unmarshal(lines[0], &event); err != nil {
		t.Fatalf("failed to decode audit event %q: %v", string(lines[0]), err)
	}
	return event
}

func mustParseDate(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		t.Fatalf("failed to parse date: %v", err)
	}
	return parsed
}

func TestAuditRecorderPreservesFinalizedEvidenceAndWritesOnce(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := &sshclient.Config{
		AuditEnabled: true, AuditOutput: t.TempDir(),
		Mode: "sql", Host: "db.example", SQLEngine: "postgres", SQLStatement: "SELECT 1",
		PlanHash: "sha256:admitted", ExecutionID: "invocation", Risk: "read",
	}
	recorder := newAuditRecorder(config)
	recorder.recordSQLOutcome(config, sshclient.AuthMethodKey, sqlAuditMeta{
		Class: "read", Mutates: false, Phase: "execute",
	}, 0, "", nil)
	if !recorder.completed || recorder.persisted || recorder.persistenceErr != nil {
		t.Fatal("recording execution facts must not attempt persistence")
	}
	executed := true
	recorder.event.Metadata = execution.Metadata{
		PlanHash: "sha256:admitted", ExecutionID: "invocation", ParentExecutionID: "parent",
		ExecutionFingerprint: "sha256:finalized", Risk: execution.Risk("read"),
		StartedAt: "2026-09-01T00:00:00Z", FinishedAt: "2026-09-01T00:00:01Z",
		ChangeState: "unchanged", Executed: &executed, Verified: true, Verification: "passed",
		Postconditions: []execution.Condition{{Kind: "rows", Observed: "1", Status: "passed"}},
	}
	recorder.event.PeerAddress = "192.0.2.3:22"
	recorder.event.HostKeyFingerprint = "SHA256:observed"
	before := recorder.event
	config.Host = "mutated.example"
	config.PlanHash = "sha256:mutated"
	config.SQLStatement = "DELETE FROM users"
	recorder.refresh(config)
	if !reflect.DeepEqual(before, recorder.event) {
		t.Fatalf("refresh changed finalized evidence:\nbefore=%+v\nafter=%+v", before, recorder.event)
	}
	for range 2 {
		if err := recorder.finish(config, nil); err != nil {
			t.Fatal(err)
		}
		if !recorder.persisted || recorder.persistenceErr != nil {
			t.Fatal("successful finalization must retain persistence status")
		}
	}
	event := readSingleAuditEvent(t, config.AuditOutput)
	if event["would_mutate_remote"] != false || event["execution_id"] != "invocation" ||
		event["parent_execution_id"] != "parent" || event["execution_fingerprint"] != "sha256:finalized" ||
		event["host_resolved"] != "db.example" || event["plan_hash"] != "sha256:admitted" ||
		event["change_state"] != "unchanged" || event["verified"] != true {
		t.Fatalf("persisted evidence was changed: %+v", event)
	}
}

func TestAuditRecorderRetainsObservedPluginAndPeer(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := &sshclient.Config{
		AuditEnabled: true, Mode: "inspect", InspectCapability: "system",
		InspectUseSudo: true, HostKeyFingerprint: "SHA256:configured",
	}
	recorder := newAuditRecorder(config)
	recorder.event.PluginDigest = "sha256:executed-plugin"
	recorder.event.PluginTrusted = true
	recorder.event.PeerAddress = "192.0.2.4:2222"
	recorder.event.HostKeyFingerprint = "SHA256:observed"
	recorder.event.CacheHit = true
	recorder.event.ObservationStatus = "ok"
	recorder.event.DeadlineScope = "host"
	recorder.event.StopReason = "max_failures"
	recorder.refresh(config)
	if recorder.event.PluginDigest != "sha256:executed-plugin" || !recorder.event.PluginTrusted ||
		recorder.event.PeerAddress != "192.0.2.4:2222" || recorder.event.HostKeyFingerprint != "SHA256:observed" ||
		!recorder.event.CacheHit || recorder.event.ObservationStatus != "ok" ||
		recorder.event.DeadlineScope != "host" || recorder.event.StopReason != "max_failures" {
		t.Fatalf("refresh overwrote observed facts: %+v", recorder.event)
	}
	recorder.recordPeer(nil)
}

func TestAuditCredentialRolesAndKnownSecretRedaction(t *testing.T) {
	setTestHome(t, t.TempDir())
	const sshSecret = "SSH_SENTINEL_6be64352"     // #nosec G101 -- redaction test sentinel, not a credential.
	const sudoSecret = "SUDO_SENTINEL_71fc2e28"   // #nosec G101 -- redaction test sentinel, not a credential.
	const valueSecret = "VALUE_SENTINEL_9a54d286" // gitleaks:allow -- synthetic redaction test sentinel.
	config := &sshclient.Config{
		AuditEnabled: true, AuditOutput: t.TempDir(), Mode: "sql",
		Host: "database", User: "ssh-principal", SQLUser: "database-principal",
		SQLHost: "localhost", SQLPort: "5432", SQLPasswordKey: "database-role",
		SSHPasswordKey: "ssh-role", SudoKey: "sudo-role", SQLUseSudo: true,
		Password: sshSecret, SudoPassword: sudoSecret, PasswordValue: valueSecret,
		Command:      "echo " + sshSecret + " " + sudoSecret + " " + valueSecret,
		SQLStatement: "SELECT '" + sshSecret + "', '" + sudoSecret + "'",
		BypassReason: "reason " + sudoSecret,
	}
	recorder := newAuditRecorder(config)
	failure := errors.New("remote refused " + sshSecret + " " + sudoSecret + " " + valueSecret)
	recorder.recordCommandResult(config, sshclient.AuthMethodPassword, sshclient.ExecResult{
		ExitCode: -1, Stdout: sshSecret, Stderr: sudoSecret,
	}, time.Second, "auth", failure)
	if err := recorder.finish(config, failure); err != nil {
		t.Fatal(err)
	}
	event := readSingleAuditEvent(t, config.AuditOutput)
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{sshSecret, sudoSecret, valueSecret} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("audit leaked a known secret: %s", data)
		}
	}
	if event["ssh_password_key"] != "ssh-role" || event["sudo_key"] != "sudo-role" ||
		event["sql_password_key"] != "database-role" || event["sql_user"] != "database-principal" ||
		event["user"] != "ssh-principal" {
		t.Fatalf("credential role identities missing: %+v", event)
	}
	for _, key := range []string{"password", "sudo_password", "password_value", "stdout", "stderr"} {
		if _, exists := event[key]; exists {
			t.Fatalf("private field %s was persisted", key)
		}
	}
}

func TestAuditCancellationPreservesObservedCompletionAndCause(t *testing.T) {
	setTestHome(t, t.TempDir())
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			config := &sshclient.Config{AuditEnabled: true, AuditOutput: t.TempDir(), Mode: "ssh"}
			recorder := newAuditRecorder(config)
			recorder.event.Completion = "partial"
			recorder.event.DeadlineScope = "global"
			recorder.recordCommandResult(config, sshclient.AuthMethodKey, sshclient.ExecResult{
				ExitCode: -1, Started: true,
			}, time.Second, classifyError(cause), cause)
			if recorder.event.CancellationCause == "" || recorder.event.Completion != "partial" ||
				recorder.event.DeadlineScope != "global" {
				t.Fatalf("missing cancellation evidence: %+v", recorder.event)
			}
			before := recorder.event.CancellationCause
			recorder.recordCancellation(config, errors.New("different failure"))
			if recorder.event.CancellationCause != before {
				t.Fatal("observed cancellation cause changed")
			}
		})
	}
}

func TestAuditApplyFailurePreservesPartialMutation(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := &sshclient.Config{AuditEnabled: true, Mode: "apply"}
	recorder := newAuditRecorder(config)
	recorder.recordApplyOutcome(config, sshclient.AuthMethodKey, &sshclient.ApplyOutcome{
		BeforeSHA256: "before", AfterSHA256: "after", BackupPath: "/backup/original", Changed: true,
	}, []byte("payload"), "verify", -1, "verification_failed", errors.New("readback failed"))
	recorder.refresh(config)
	recorder.recordFailure(config, sshclient.AuthMethodUnknown, "connect", errors.New("cleanup disconnected"))
	if !recorder.event.ApplyChanged || !recorder.event.WouldMutateRemote ||
		recorder.event.ApplyBackupPath != "/backup/original" ||
		recorder.event.ApplyBeforeHash != "before" || recorder.event.ApplyAfterHash != "after" ||
		recorder.event.Outcome.ErrorKind != "verification_failed" {
		t.Fatalf("partial apply evidence lost: %+v", recorder.event)
	}
}

func TestAuditEventMatchingRejectsNonObjectsAndPreservesLegacyFields(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`null`), json.RawMessage(`[]`), json.RawMessage(`{"unfinished":`),
	} {
		if auditEventMatches(raw, auditQueryFilter{}) {
			t.Fatalf("non-object or malformed record matched: %s", raw)
		}
	}
	if !auditEventMatches(json.RawMessage(`{"event_id":"old","future":1e1000}`), auditQueryFilter{runID: "old"}) {
		t.Fatal("valid legacy record with unknown field must match")
	}
}

func TestAuditAppendFailureIsTypedAndDoesNotChangeOutcome(t *testing.T) {
	setTestHome(t, t.TempDir())
	output := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(output, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &sshclient.Config{AuditEnabled: true, AuditOutput: output, Mode: "ssh"}
	recorder := newAuditRecorder(config)
	recorder.recordCommandResult(config, sshclient.AuthMethodKey, sshclient.ExecResult{ExitCode: 0}, time.Second, "", nil)
	first := recorder.finish(config, nil)
	if !errors.Is(first, execution.ErrLocalIO) {
		t.Fatalf("append error = %v", first)
	}
	if recorder.persisted || recorder.persistenceErr != first {
		t.Fatal("failed persistence must retain its error without claiming success")
	}
	config.AuditOutput = t.TempDir()
	if recorder.finish(config, nil) != first {
		t.Fatal("second finalization must retain the original persistence error")
	}
	entries, err := os.ReadDir(config.AuditOutput)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed finalization must not retry persistence: entries=%v err=%v", entries, err)
	}
	if recorder.event.Outcome.Status != "success" {
		t.Fatalf("audit persistence changed execution outcome: %+v", recorder.event.Outcome)
	}
	data, err := os.ReadFile(output) // #nosec G304 -- test-owned output path.
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("append failure changed existing file: data=%q err=%v", data, err)
	}
}

func TestAuditCompletedRunOutcomeIsNotReclassified(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := &sshclient.Config{
		AuditEnabled: true, AuditOutput: t.TempDir(), Mode: "run",
		Host: "prod-web", HostName: "production", User: "operator",
		SSHPasswordKey: "ssh-role", SudoKey: "sudo-role",
	}
	recorder := newAuditRecorder(config)
	recorder.event.RunID = "run-existing"
	recorder.event.Metadata = execution.Metadata{
		ExecutionID: "invocation", ExecutionFingerprint: "parent-fingerprint",
		TargetFingerprints: []string{"target-fingerprint"},
	}
	recorder.event.Outcome = auditStatus{Status: "failed", ErrorKind: "aggregate"}
	recorder.completed = true
	config.Host, config.HostName, config.User = "mutated-host", "mutated-name", "mutated-user"
	config.SSHPasswordKey, config.SudoKey = "mutated-ssh-role", "mutated-sudo-role"
	if err := recorder.finish(config, ErrReported); err != nil {
		t.Fatal(err)
	}
	event := readSingleAuditEvent(t, config.AuditOutput)
	if event["run_id"] != "run-existing" || event["execution_id"] != "invocation" {
		t.Fatalf("run correlation lost: %+v", event)
	}
	if event["host_input"] != "prod-web" || event["host_name"] != "production" ||
		event["user"] != "operator" || event["ssh_password_key"] != "ssh-role" ||
		event["sudo_key"] != "sudo-role" {
		t.Fatalf("initial alias or credential-role snapshot changed: %+v", event)
	}
	targetFingerprints, ok := event["target_fingerprints"].([]any)
	if event["execution_fingerprint"] != "parent-fingerprint" || !ok ||
		len(targetFingerprints) != 1 || targetFingerprints[0] != "target-fingerprint" {
		t.Fatalf("parent and target fingerprints changed: %+v", event)
	}
	outcome, ok := event["outcome"].(map[string]any)
	if !ok || outcome["status"] != "failed" || outcome["error_kind"] != "aggregate" {
		t.Fatalf("completed run outcome overwritten: %+v", event)
	}
}
