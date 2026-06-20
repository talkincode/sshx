package app

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestRun_NoArgs(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stdout = w

	args := []string{"sshx"}
	err = Run(args)

	if closeErr := w.Close(); closeErr != nil {
		t.Logf("Failed to close pipe writer: %v", closeErr)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Logf("Failed to copy pipe output: %v", copyErr)
	}

	// Should return ErrUsage
	if !errors.Is(err, ErrUsage) {
		t.Errorf("Expected ErrUsage, got %v", err)
	}

	// Should have printed usage
	output := buf.String()
	if !strings.Contains(output, "Usage:") {
		t.Error("Expected usage to be printed")
	}
}

func TestRun_HelpFlag(t *testing.T) {
	// This would trigger os.Exit(0) in ParseArgs
	// We can't easily test this without mocking os.Exit
	// In practice, this is better tested as an integration test
	t.Skip("--help flag calls os.Exit, requires integration test")
}

func TestRun_PasswordMode(t *testing.T) {
	// These tests would require actual keyring access
	// Better tested as integration tests
	t.Skip("Password mode requires keyring integration testing")
}

func TestRun_SSHMode(t *testing.T) {
	// SSH mode requires actual SSH connection
	// Better tested as integration tests
	t.Skip("SSH mode requires SSH server integration testing")
}

func TestRun_SFTPMode(t *testing.T) {
	// SFTP mode requires actual SSH/SFTP connection
	// Better tested as integration tests
	t.Skip("SFTP mode requires SSH/SFTP server integration testing")
}

func TestErrUsage(t *testing.T) {
	// Verify ErrUsage is a proper error
	if ErrUsage == nil {
		t.Error("ErrUsage should not be nil")
	}

	if ErrUsage.Error() != "usage displayed" {
		t.Errorf("Expected 'usage displayed', got '%s'", ErrUsage.Error())
	}

	// Verify it can be used with errors.Is
	err := ErrUsage
	if !errors.Is(err, ErrUsage) {
		t.Error("errors.Is should work with ErrUsage")
	}
}

// Mock tests for demonstrating the testing approach
// In a real scenario, you'd want to refactor Run() to accept dependencies
// that can be mocked (like SSH client factory, etc.)

func TestRun_ArgumentParsing(t *testing.T) {
	// This test verifies that Run() calls ParseArgs correctly
	// by checking the behavior with various arguments

	tests := []struct {
		name        string
		args        []string
		shouldError bool
		errorIs     error
	}{
		{
			name:        "no arguments",
			args:        []string{"sshx"},
			shouldError: true,
			errorIs:     ErrUsage,
		},
		{
			name:        "single argument",
			args:        []string{"sshx", "command"},
			shouldError: true, // Will fail due to missing host, but won't be ErrUsage
			errorIs:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			// Suppress output
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("Failed to create pipe: %v", err)
			}
			os.Stdout = w
			os.Stderr = w

			err = Run(tt.args)

			if closeErr := w.Close(); closeErr != nil {
				t.Logf("Failed to close pipe writer: %v", closeErr)
			}
			os.Stdout = oldStdout
			os.Stderr = oldStderr

			// Drain pipe
			if _, copyErr := io.Copy(io.Discard, r); copyErr != nil {
				t.Logf("Failed to drain pipe: %v", copyErr)
			}

			if tt.shouldError && err == nil {
				t.Error("Expected error but got nil")
			}

			if tt.errorIs != nil && !errors.Is(err, tt.errorIs) {
				t.Errorf("Expected error %v, got %v", tt.errorIs, err)
			}
		})
	}
}

// Integration test examples (these would need actual setup):
//
// func TestRun_SSHCommand_Integration(t *testing.T) {
//     if testing.Short() {
//         t.Skip("Skipping integration test")
//     }
//     // Set up test SSH server
//     // Run actual SSH command
//     // Verify output
// }
//
// func TestRun_SFTPUpload_Integration(t *testing.T) {
//     if testing.Short() {
//         t.Skip("Skipping integration test")
//     }
//     // Set up test SFTP server
//     // Upload file
//     // Verify file exists on server
// }
//
// func TestRun_PasswordManagement_Integration(t *testing.T) {
//     if testing.Short() {
//         t.Skip("Skipping integration test")
//     }
//     // Test password set/get/delete with actual keyring
// }

// Example of how to refactor for better testability:
//
// type AppDependencies struct {
//     SSHClientFactory func(*sshclient.Config) (*sshclient.SSHClient, error)
//     PasswordManager  PasswordManager
//     UsagePrinter     func()
// }
//
// func RunWithDeps(args []string, deps AppDependencies) error {
//     // Use deps instead of direct calls
//     // This allows mocking for unit tests
// }
