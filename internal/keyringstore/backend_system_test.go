//go:build !sshx_e2e

package keyringstore

import (
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestSystemBackendRoundtrip exercises Set/Get/Delete against the in-memory
// mock provider so the test never touches a real OS keyring.
func TestSystemBackendRoundtrip(t *testing.T) {
	t.Setenv("SSHX_SECRET_BACKEND", "keyring")
	keyring.MockInit()

	const (
		service = "sshx-test-service"
		account = "sshx-test-account"
		secret  = "s3cret-value"
	)

	if err := Set(service, account, secret); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := Get(service, account)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != secret {
		t.Fatalf("Get returned %q, want %q", got, secret)
	}

	if err := Delete(service, account); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := Get(service, account); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete returned %v, want ErrNotFound", err)
	}
}

// TestSystemBackendMissingKey verifies the package-level ErrNotFound maps to
// the provider's not-found error for keys that were never stored.
func TestSystemBackendMissingKey(t *testing.T) {
	t.Setenv("SSHX_SECRET_BACKEND", "keyring")
	keyring.MockInit()

	if _, err := Get("sshx-test-service", "never-stored"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get returned %v, want ErrNotFound", err)
	}
	if err := Delete("sshx-test-service", "never-stored"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete returned %v, want ErrNotFound", err)
	}
}
