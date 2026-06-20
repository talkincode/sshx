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

	"github.com/talkincode/sshx/internal/sshclient"
)

func TestRun_BlockedCommandWritesRedactedAuditEvent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
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

func TestRun_DryRunDoesNotWriteAuditEvent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
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
	t.Setenv("HOME", t.TempDir())
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
	t.Setenv("HOME", home)
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
	if info.Mode().Perm() != 0o600 {
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
