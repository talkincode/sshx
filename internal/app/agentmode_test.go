package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/talkincode/sshx/internal/sshclient"
)

func TestParseTimeout(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{"duration seconds", "30s", 30 * time.Second, false},
		{"duration minutes", "2m", 2 * time.Minute, false},
		{"bare seconds", "45", 45 * time.Second, false},
		{"zero", "0", 0, false},
		{"empty", "", 0, true},
		{"negative duration", "-5s", 0, true},
		{"negative bare", "-5", 0, true},
		{"garbage", "abc", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTimeout(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("parseTimeout(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestParseArgs_AgentFlags(t *testing.T) {
	config := ParseArgs([]string{"sshx", "-h=host", "--json", "--timeout=30s", "uptime"})
	if !config.JSONOutput {
		t.Error("expected JSONOutput to be true")
	}
	if config.UsePTY {
		t.Error("expected UsePTY to be false")
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", config.Timeout)
	}
	if config.Command != "uptime" {
		t.Errorf("expected command uptime, got %q", config.Command)
	}
}

func TestParseArgs_PTYFlag(t *testing.T) {
	config := ParseArgs([]string{"sshx", "-h=host", "--pty", "top"})
	if !config.UsePTY {
		t.Error("expected UsePTY to be true")
	}
	if config.JSONOutput {
		t.Error("expected JSONOutput to be false")
	}
}

func TestParseArgs_InvalidTimeoutSentinel(t *testing.T) {
	config := ParseArgs([]string{"sshx", "-h=host", "--timeout=banana", "uptime"})
	if config.Timeout != -1 {
		t.Errorf("expected invalid timeout to set sentinel -1, got %v", config.Timeout)
	}
}

func TestParseArgs_TimeoutEnv(t *testing.T) {
	t.Setenv("SSH_TIMEOUT", "15s")
	config := ParseArgs([]string{"sshx", "-h=host", "uptime"})
	if config.Timeout != 15*time.Second {
		t.Errorf("expected timeout from env 15s, got %v", config.Timeout)
	}

	t.Setenv("SSH_TIMEOUT", "nonsense")
	config = ParseArgs([]string{"sshx", "-h=host", "uptime"})
	if config.Timeout != -1 {
		t.Errorf("expected invalid env timeout to set sentinel -1, got %v", config.Timeout)
	}
}

func TestExitErrorMessage(t *testing.T) {
	err := &ExitError{Code: 7}
	if err.Error() != "command exited with status 7" {
		t.Errorf("unexpected ExitError message: %q", err.Error())
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"timeout", sshclient.ErrCommandTimeout, "timeout"},
		{"no exit status", sshclient.ErrNoExitStatus, "exit_missing"},
		{"blocked", &sshclient.CommandBlockedError{Command: "rm -rf /", Reason: "danger"}, "blocked"},
		{"host key", errors.New("host key mismatch: not in known_hosts"), "host_key"},
		{"auth", errors.New("ssh: handshake failed: unable to authenticate"), "auth"},
		{"connect", errors.New("failed to connect to host: connection refused"), "connect"},
		{"generic", errors.New("something odd happened"), "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyError(tt.err); got != tt.want {
				t.Errorf("classifyError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

// TestRun_BlockedCommandShortCircuits verifies a dangerous command is rejected
// before any network work, so it reports error_kind "blocked" (not "connect")
// even though the host is never reachable.
func TestRun_BlockedCommandShortCircuits(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	// 192.0.2.1 is RFC 5737 TEST-NET-1: if validation did not short-circuit,
	// the dial would block instead of returning instantly.
	runErr := Run([]string{"sshx", "-h=192.0.2.1", "--json", "rm -rf /"})

	if closeErr := w.Close(); closeErr != nil {
		t.Logf("failed to close pipe writer: %v", closeErr)
	}
	os.Stdout = old
	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Logf("failed to copy pipe output: %v", copyErr)
	}

	if !errors.Is(runErr, ErrReported) {
		t.Fatalf("expected ErrReported, got %v", runErr)
	}
	var result map[string]any
	if jErr := json.Unmarshal(buf.Bytes(), &result); jErr != nil {
		t.Fatalf("invalid JSON output %q: %v", buf.String(), jErr)
	}
	if result["error_kind"] != "blocked" {
		t.Errorf("expected error_kind=blocked, got %v (full: %s)", result["error_kind"], buf.String())
	}
	if code, ok := result["exit_code"].(float64); !ok || code != -1 {
		t.Errorf("expected exit_code=-1, got %v", result["exit_code"])
	}
	if result["success"] != false {
		t.Errorf("expected success=false, got %v", result["success"])
	}
}

func TestRun_DryRunJSONDoesNotConnect(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	result := runDryRunJSON(t, []string{"sshx", "-h=192.0.2.1", "--dry-run", "--json", "uptime"})

	if result["dry_run"] != true {
		t.Fatalf("expected dry_run=true, got %v", result["dry_run"])
	}
	if result["mode"] != "ssh" {
		t.Errorf("expected mode=ssh, got %v", result["mode"])
	}
	if result["host_resolved"] != "192.0.2.1" {
		t.Errorf("expected direct host resolution, got %v", result["host_resolved"])
	}
	if result["would_connect"] != true {
		t.Errorf("expected would_connect=true for valid command plan, got %v", result["would_connect"])
	}
	if result["would_execute"] != true {
		t.Errorf("expected would_execute=true for valid command plan, got %v", result["would_execute"])
	}
	if result["would_read_secret"] != false {
		t.Errorf("expected no secret lookup for non-sudo command, got %v", result["would_read_secret"])
	}
}

func TestRun_DryRunReportsBlockedCommand(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	result := runDryRunJSON(t, []string{"sshx", "-h=192.0.2.1", "--dry-run", "--json", "sudo rm -rf /"})

	if result["valid"] != false {
		t.Fatalf("expected valid=false for blocked command, got %v", result["valid"])
	}
	safety, ok := result["safety_check"].(map[string]any)
	if !ok {
		t.Fatalf("expected safety_check object, got %T", result["safety_check"])
	}
	if safety["status"] != "blocked" {
		t.Errorf("expected safety status blocked, got %v", safety["status"])
	}
	if safety["error_kind"] != "blocked" {
		t.Errorf("expected error_kind blocked, got %v", safety["error_kind"])
	}
	if result["would_connect"] != false {
		t.Errorf("blocked dry-run must not plan a connection, got %v", result["would_connect"])
	}
	if result["uses_sudo"] != true {
		t.Errorf("expected blocked sudo command to report uses_sudo=true, got %v", result["uses_sudo"])
	}
	if result["would_read_secret"] != false {
		t.Errorf("blocked dry-run must not plan a secret read, got %v", result["would_read_secret"])
	}
}

func TestRun_DryRunMissingHostDoesNotPlanConnection(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	result := runDryRunJSON(t, []string{"sshx", "--dry-run", "--json", "uptime"})

	if result["valid"] != false {
		t.Fatalf("expected valid=false for missing host, got %v", result["valid"])
	}
	resolution, ok := result["host_resolution"].(map[string]any)
	if !ok {
		t.Fatalf("expected host_resolution object, got %T", result["host_resolution"])
	}
	if resolution["status"] != "missing" {
		t.Errorf("expected host resolution status missing, got %v", resolution["status"])
	}
	if result["would_connect"] != false {
		t.Errorf("missing host dry-run must not plan a connection, got %v", result["would_connect"])
	}
	if result["would_execute"] != false {
		t.Errorf("missing host dry-run must not plan execution, got %v", result["would_execute"])
	}
}

func TestRun_DryRunResolvesNamedHostAndSudoKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	passwordKeyName := "prod-web-sudo" //nolint:gosec // G101: keyring key name used in a test, not secret material.
	err := SaveSettings(&Settings{
		Key: "/keys/default.pem",
		Hosts: []HostConfig{
			{
				Name:        "prod-web",
				Host:        "10.0.0.5",
				Port:        "2222",
				User:        "root",
				Key:         "/keys/prod-web.pem",
				PasswordKey: passwordKeyName,
			},
		},
	})
	if err != nil {
		t.Fatalf("SaveSettings() error = %v", err)
	}

	result := runDryRunJSON(t, []string{"sshx", "-h=prod-web", "--dry-run", "--json", "sudo systemctl status nginx"})

	if result["host_input"] != "prod-web" {
		t.Errorf("expected host_input prod-web, got %v", result["host_input"])
	}
	if result["host_resolved"] != "10.0.0.5" {
		t.Errorf("expected resolved host 10.0.0.5, got %v", result["host_resolved"])
	}
	if result["port"] != "2222" {
		t.Errorf("expected port 2222, got %v", result["port"])
	}
	if result["user"] != "root" {
		t.Errorf("expected user root, got %v", result["user"])
	}
	if result["key_path"] != "/keys/prod-web.pem" {
		t.Errorf("expected host key path, got %v", result["key_path"])
	}
	if result["uses_sudo"] != true {
		t.Errorf("expected uses_sudo=true, got %v", result["uses_sudo"])
	}
	if result["sudo_key"] != passwordKeyName {
		t.Errorf("expected per-host sudo key, got %v", result["sudo_key"])
	}
	if result["would_read_secret"] != true {
		t.Errorf("expected sudo keyring lookup in real run, got %v", result["would_read_secret"])
	}
}

func TestRun_DryRunHostTestUsesConfiguredKeyAndPasswordKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	passwordKeyName := "prod-web-password" //nolint:gosec // G101: keyring key name used in a test, not secret material.
	err := SaveSettings(&Settings{
		Key: "/keys/default.pem",
		Hosts: []HostConfig{
			{
				Name:        "prod-web",
				Host:        "10.0.0.5",
				Port:        "2222",
				User:        "root",
				Key:         "/keys/prod-web.pem",
				PasswordKey: passwordKeyName,
			},
		},
	})
	if err != nil {
		t.Fatalf("SaveSettings() error = %v", err)
	}

	result := runDryRunJSON(t, []string{"sshx", "--host-test=prod-web", "--dry-run", "--json"})

	if result["mode"] != "host" {
		t.Errorf("expected host mode, got %v", result["mode"])
	}
	if result["action"] != "test" {
		t.Errorf("expected test action, got %v", result["action"])
	}
	if result["host_resolved"] != "10.0.0.5" {
		t.Errorf("expected resolved host 10.0.0.5, got %v", result["host_resolved"])
	}
	if result["key_path"] != "/keys/prod-web.pem" {
		t.Errorf("expected configured host key path, got %v", result["key_path"])
	}
	if result["sudo_key"] != passwordKeyName {
		t.Errorf("expected configured password key, got %v", result["sudo_key"])
	}
	if result["would_connect"] != true {
		t.Errorf("expected real host test would connect, got %v", result["would_connect"])
	}
	if result["would_read_secret"] != true {
		t.Errorf("expected real host test would read configured password key, got %v", result["would_read_secret"])
	}
}

func runDryRunJSON(t *testing.T, args []string) map[string]any {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	runErr := Run(args)

	if closeErr := w.Close(); closeErr != nil {
		t.Logf("failed to close pipe writer: %v", closeErr)
	}
	os.Stdout = old
	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Logf("failed to copy pipe output: %v", copyErr)
	}

	if runErr != nil {
		t.Fatalf("Run() error = %v, output=%s", runErr, buf.String())
	}
	var result map[string]any
	if jErr := json.Unmarshal(buf.Bytes(), &result); jErr != nil {
		t.Fatalf("invalid JSON output %q: %v", buf.String(), jErr)
	}
	return result
}
