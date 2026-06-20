package app

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestPrintUsage(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stdout = w

	// Call PrintUsage
	PrintUsage()

	// Restore stdout
	if closeErr := w.Close(); closeErr != nil {
		t.Logf("Failed to close pipe writer: %v", closeErr)
	}
	os.Stdout = old

	// Read captured output
	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Logf("Failed to copy pipe output: %v", copyErr)
	}
	output := buf.String()

	// Verify output contains key sections
	expectedSections := []string{
		"SSH & SFTP Remote Tool",
		"Usage:",
		"SSH Options:",
		"Sudo Auto-fill:",
		"Dry-run Plan Preview:",
		"Safety Options:",
		"SFTP Options:",
		"Password Management",
		"Environment Variables",
		"SSH Examples:",
		"SFTP Examples:",
		"Password Management Examples:",
	}

	for _, section := range expectedSections {
		if !strings.Contains(output, section) {
			t.Errorf("Expected output to contain section: %s", section)
		}
	}

	// Verify important commands are documented
	importantCommands := []string{
		"sshx -h=",
		"--upload=",
		"--download=",
		"--password-set=",
		"--password-get=",
		"--dry-run",
		"--force",
		"--no-safety-check",
	}

	for _, cmd := range importantCommands {
		if !strings.Contains(output, cmd) {
			t.Errorf("Expected output to contain command: %s", cmd)
		}
	}

	// Verify platform mentions
	platforms := []string{"macOS", "Linux", "Windows"}
	for _, platform := range platforms {
		if !strings.Contains(output, platform) {
			t.Errorf("Expected output to mention platform: %s", platform)
		}
	}

	// Verify safety warnings
	safetyKeywords := []string{
		"rm -rf /",
		"BLOCKED",
		"safety check",
		"remote command starts with sudo",
		"Non-leading sudo is not auto-filled",
		"Dry-run never connects",
	}

	for _, keyword := range safetyKeywords {
		if !strings.Contains(output, keyword) {
			t.Errorf("Expected output to contain safety keyword: %s", keyword)
		}
	}

	// Verify output is not empty
	if len(output) < 100 {
		t.Errorf("Expected longer usage output, got %d characters", len(output))
	}
}

func TestPrintUsage_OutputFormat(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stdout = w

	PrintUsage()

	if closeErr := w.Close(); closeErr != nil {
		t.Logf("Failed to close pipe writer: %v", closeErr)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Logf("Failed to copy pipe output: %v", copyErr)
	}
	output := buf.String()

	// Verify output starts with newline (for proper formatting)
	if !strings.HasPrefix(output, "\n") {
		t.Error("Expected output to start with newline for formatting")
	}

	// Verify there are multiple lines
	lines := strings.Split(output, "\n")
	if len(lines) < 50 {
		t.Errorf("Expected at least 50 lines of usage text, got %d", len(lines))
	}
}

func TestPrintUsage_Examples(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stdout = w

	PrintUsage()

	if closeErr := w.Close(); closeErr != nil {
		t.Logf("Failed to close pipe writer: %v", closeErr)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Logf("Failed to copy pipe output: %v", copyErr)
	}
	output := buf.String()

	// Verify practical examples exist
	examples := []string{
		`sshx -h=192.168.1.100 "uptime"`,
		`sshx -h=192.168.1.100 "sudo systemctl status docker"`,
		`sshx --password-set=master`,
		`--upload=local.txt --to=/tmp/remote.txt`,
		`--download=/var/log/app.log`,
	}

	for _, example := range examples {
		if !strings.Contains(output, example) {
			t.Errorf("Expected output to contain example: %s", example)
		}
	}
}
