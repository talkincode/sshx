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
