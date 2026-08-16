//go:build sshx_e2e

package keyringstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func withKeyringFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nested", "keyring.json")
	t.Setenv("SSHX_E2E_KEYRING_FILE", path)
	return path
}

func TestE2EBackendRoundtrip(t *testing.T) {
	path := withKeyringFile(t)

	if err := Set("svc", "acct", "value-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := Get("svc", "acct")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "value-1" {
		t.Fatalf("Get returned %q, want %q", got, "value-1")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat keyring file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("keyring file permissions = %o, want 600", perm)
		}
	}

	if err := Delete("svc", "acct"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get("svc", "acct"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete returned %v, want ErrNotFound", err)
	}
}

func TestE2EBackendMissingEntry(t *testing.T) {
	withKeyringFile(t)

	if _, err := Get("svc", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get returned %v, want ErrNotFound", err)
	}
	if err := Delete("svc", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete returned %v, want ErrNotFound", err)
	}
}

func TestE2EBackendRequiresEnv(t *testing.T) {
	t.Setenv("SSHX_E2E_KEYRING_FILE", "")

	if err := Set("svc", "acct", "v"); err == nil {
		t.Fatal("Set succeeded without SSHX_E2E_KEYRING_FILE, want error")
	}
	if _, err := Get("svc", "acct"); err == nil {
		t.Fatal("Get succeeded without SSHX_E2E_KEYRING_FILE, want error")
	}
}

func TestE2EBackendRejectsCorruptFile(t *testing.T) {
	path := withKeyringFile(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	if _, err := Get("svc", "acct"); err == nil {
		t.Fatal("Get succeeded on corrupt keyring file, want error")
	}
}
