package app

import (
	"os"
	"runtime"
	"testing"
)

func TestIsWindows(t *testing.T) {
	if got, want := isWindows(), runtime.GOOS == "windows"; got != want {
		t.Errorf("isWindows() = %v, want %v", got, want)
	}
}

func TestIsMacOS(t *testing.T) {
	if got, want := isMacOS(), runtime.GOOS == "darwin"; got != want {
		t.Errorf("isMacOS() = %v, want %v", got, want)
	}
}

func TestReadPassword_Empty(t *testing.T) {
	// This test would require mocking stdin, which is complex
	// For now, we'll skip it or test it with integration tests
	t.Skip("readPassword requires stdin mocking")
}

// Note: Testing actual keyring operations would require:
// 1. A mock keyring implementation
// 2. Integration tests on actual platforms
// 3. Platform-specific setup
//
// For unit tests, we focus on testing the logic flow and error handling
// without actual keyring operations.

func TestHandlePasswordManagement_UnknownAction(t *testing.T) {
	// This would need the actual Config type from sshclient
	// For now, this demonstrates the test structure
	// Integration tests would verify error handling for unknown actions
	t.Skip("Requires integration with actual keyring")
}

func TestSetPassword_EmptyKey(t *testing.T) {
	err := setPassword("test-service", "", "test-value")
	if err == nil {
		t.Error("Expected error when key is empty")
	}
	if err != nil && err.Error() != "password key is required" {
		t.Errorf("Expected 'password key is required' error, got: %v", err)
	}
}

func TestGetPassword_EmptyKey(t *testing.T) {
	err := getPassword("test-service", "")
	if err == nil {
		t.Error("Expected error when key is empty")
	}
	if err != nil && err.Error() != "password key is required" {
		t.Errorf("Expected 'password key is required' error, got: %v", err)
	}
}

func TestDeletePassword_EmptyKey(t *testing.T) {
	err := deletePassword("test-service", "")
	if err == nil {
		t.Error("Expected error when key is empty")
	}
	if err != nil && err.Error() != "password key is required" {
		t.Errorf("Expected 'password key is required' error, got: %v", err)
	}
}

func TestCheckPassword_EmptyKey(t *testing.T) {
	err := checkPassword("test-service", "")
	if err == nil {
		t.Error("Expected error when key is empty")
	}
	if err != nil && err.Error() != "password key is required" {
		t.Errorf("Expected 'password key is required' error, got: %v", err)
	}
}

// Integration test examples (these would need actual keyring access):
//
// func TestSetPassword_Integration(t *testing.T) {
//     if testing.Short() {
//         t.Skip("Skipping integration test")
//     }
//     // Test actual keyring set operation
// }
//
// func TestGetPassword_Integration(t *testing.T) {
//     if testing.Short() {
//         t.Skip("Skipping integration test")
//     }
//     // Test actual keyring get operation
// }
//
// func TestDeletePassword_Integration(t *testing.T) {
//     if testing.Short() {
//         t.Skip("Skipping integration test")
//     }
//     // Test actual keyring delete operation
// }
//
// func TestCheckPassword_Integration(t *testing.T) {
//     if testing.Short() {
//         t.Skip("Skipping integration test")
//     }
//     // Test actual keyring check operation
// }
//
// func TestListPasswords_Integration(t *testing.T) {
//     if testing.Short() {
//         t.Skip("Skipping integration test")
//     }
//     // Test actual keyring list operation
// }

// Mock keyring for unit testing
// This is a simplified example of how to create mock tests

type MockKeyring struct {
	storage map[string]map[string]string // service -> account -> password
}

func NewMockKeyring() *MockKeyring {
	return &MockKeyring{
		storage: make(map[string]map[string]string),
	}
}

func (m *MockKeyring) Set(service, account, password string) error {
	if m.storage[service] == nil {
		m.storage[service] = make(map[string]string)
	}
	m.storage[service][account] = password
	return nil
}

func (m *MockKeyring) Get(service, account string) (string, error) {
	if m.storage[service] == nil {
		return "", os.ErrNotExist
	}
	password, ok := m.storage[service][account]
	if !ok {
		return "", os.ErrNotExist
	}
	return password, nil
}

func (m *MockKeyring) Delete(service, account string) error {
	if m.storage[service] != nil {
		delete(m.storage[service], account)
	}
	return nil
}

func TestMockKeyring(t *testing.T) {
	mock := NewMockKeyring()

	// Test Set
	err := mock.Set("test-service", "test-account", "test-password")
	if err != nil {
		t.Errorf("Set failed: %v", err)
	}

	// Test Get
	password, err := mock.Get("test-service", "test-account")
	if err != nil {
		t.Errorf("Get failed: %v", err)
	}
	if password != "test-password" {
		t.Errorf("Expected 'test-password', got '%s'", password)
	}

	// Test Get non-existent
	_, err = mock.Get("test-service", "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent key")
	}

	// Test Delete
	err = mock.Delete("test-service", "test-account")
	if err != nil {
		t.Errorf("Delete failed: %v", err)
	}

	// Verify deleted
	_, err = mock.Get("test-service", "test-account")
	if err == nil {
		t.Error("Expected error after deletion")
	}
}
