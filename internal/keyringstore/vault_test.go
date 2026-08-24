package keyringstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func withVaultEnv(t *testing.T, passphrase string) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("SSHX_HOME", root)
	t.Setenv(EnvBackend, BackendVault)
	t.Setenv(EnvVaultPassphrase, passphrase)
	t.Setenv(EnvVaultKeyFile, "")
	return root
}

func TestVaultRoundtripAndOwnerOnlyFile(t *testing.T) {
	root := withVaultEnv(t, "correct-horse-battery")
	const (
		service = "sshx"
		account = "prod-web"
		secret  = "sudo-secret-value" // #nosec G101 -- isolated unit-test fixture
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

	path := filepath.Join(root, "vault")
	data, err := os.ReadFile(path) // #nosec G304 -- path is the test vault under TempDir
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	if bytes.Contains(data, []byte(secret)) {
		t.Fatal("vault file contained the plaintext secret")
	}
	if !bytes.HasPrefix(data, []byte(vaultMagic)) {
		t.Fatalf("vault magic = %q, want %s", data[:min(len(data), 8)], vaultMagic)
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat vault: %v", statErr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("vault permissions = %o, want 600", perm)
		}
	}

	accounts, err := Accounts(service)
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if len(accounts) != 1 || accounts[0] != account {
		t.Fatalf("Accounts = %v, want [%s]", accounts, account)
	}

	if err := Delete(service, account); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get(service, account); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete returned %v, want ErrNotFound", err)
	}
}

func TestVaultWrongPassphraseFailsClosed(t *testing.T) {
	withVaultEnv(t, "alpha-passphrase")
	if err := Set("sshx", "k", "secret-one"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Setenv(EnvVaultPassphrase, "other-passphrase")
	if _, err := Get("sshx", "k"); err == nil {
		t.Fatal("Get succeeded with the wrong passphrase")
	}
	if err := Set("sshx", "other", "secret-two"); err == nil {
		t.Fatal("Set succeeded with the wrong passphrase")
	}
	t.Setenv(EnvVaultPassphrase, "alpha-passphrase")
	got, err := Get("sshx", "k")
	if err != nil {
		t.Fatalf("Get after restoring passphrase: %v", err)
	}
	if got != "secret-one" {
		t.Fatalf("Get returned %q, want secret-one (failed write must not destroy the vault)", got)
	}
}

func TestVaultMissingPassphraseFailsClosed(t *testing.T) {
	withVaultEnv(t, "present")
	os.Unsetenv(EnvVaultPassphrase) //nolint:errcheck // test clears the unlock factor
	t.Setenv(EnvVaultKeyFile, "")
	if err := Set("sshx", "k", "v"); err == nil {
		t.Fatal("Set succeeded without an unlock factor")
	}
}

func TestVaultDoesNotFallbackToKeyring(t *testing.T) {
	root := withVaultEnv(t, "vault-only")
	if err := Set("sshx", "k", "vault-secret"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Setenv(EnvBackend, BackendKeyring)
	if _, err := Get("sshx", "k"); err == nil {
		t.Fatal("keyring Get succeeded for a vault-only secret; backend must not silently fall back")
	}
	if _, err := os.Stat(filepath.Join(root, "vault")); err != nil {
		t.Fatalf("vault file should remain: %v", err)
	}
}

func TestUnknownBackendFailsClosed(t *testing.T) {
	t.Setenv(EnvBackend, "hashicorp")
	if err := Set("sshx", "k", "v"); err == nil {
		t.Fatal("Set succeeded with an unknown backend")
	}
	if _, err := Get("sshx", "k"); err == nil {
		t.Fatal("Get succeeded with an unknown backend")
	}
	status := Inspect()
	if status.Backend != "invalid" {
		t.Fatalf("Inspect backend = %q, want invalid", status.Backend)
	}
	if CanReveal() {
		t.Fatal("CanReveal must be false for an invalid backend")
	}
}

func TestVaultWriteOnlyRevealDenied(t *testing.T) {
	withVaultEnv(t, "phrase")
	if CanReveal() {
		t.Fatal("local vault must not allow CLI reveal")
	}
	t.Setenv(EnvBackend, BackendKeyring)
	if !CanReveal() {
		t.Fatal("keyring backend should allow CLI reveal")
	}
}

func TestVaultRejectsWorldReadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on Windows")
	}
	root := withVaultEnv(t, "phrase")
	if err := Set("sshx", "k", "secret-value"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	path := filepath.Join(root, "vault")
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- deliberately creates an unsafe fixture
		t.Fatalf("chmod: %v", err)
	}
	if _, err := Get("sshx", "k"); err == nil {
		t.Fatal("Get succeeded on a world-readable vault file")
	}
}

func TestVaultKeyFileUnlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX key-file mode checks are the contract under test")
	}
	root := withVaultEnv(t, "")
	keyFile := filepath.Join(t.TempDir(), "vault.key")
	if err := os.WriteFile(keyFile, []byte("file-passphrase\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	t.Setenv(EnvVaultPassphrase, "")
	os.Unsetenv(EnvVaultPassphrase) //nolint:errcheck // keyfile is the only unlock factor
	t.Setenv(EnvVaultKeyFile, keyFile)
	t.Setenv("SSHX_HOME", root)

	if err := Set("sshx", "k", "from-keyfile"); err != nil {
		t.Fatalf("Set via key file: %v", err)
	}
	got, err := Get("sshx", "k")
	if err != nil {
		t.Fatalf("Get via key file: %v", err)
	}
	if got != "from-keyfile" {
		t.Fatalf("Get returned %q", got)
	}
	if Inspect().Unlock != UnlockKeyFile {
		t.Fatalf("Unlock = %q, want %s", Inspect().Unlock, UnlockKeyFile)
	}

	if err := os.Chmod(keyFile, 0o644); err != nil { // #nosec G302 -- deliberately creates an unsafe fixture
		t.Fatalf("chmod key file: %v", err)
	}
	if _, err := Get("sshx", "k"); err == nil {
		t.Fatal("Get succeeded with a world-readable vault key file")
	}
}

func TestVaultCorruptFileFailsClosed(t *testing.T) {
	root := withVaultEnv(t, "phrase")
	path := filepath.Join(root, "vault")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("SSHXVL01not-a-real-vault"), 0o600); err != nil {
		t.Fatalf("write corrupt vault: %v", err)
	}
	if _, err := Get("sshx", "k"); err == nil {
		t.Fatal("Get succeeded on a corrupt vault")
	}
}

func TestDefaultBackendIsKeyring(t *testing.T) {
	t.Setenv(EnvBackend, "")
	name, err := Backend()
	if err != nil {
		t.Fatalf("Backend: %v", err)
	}
	if name != BackendKeyring {
		t.Fatalf("Backend = %q, want %s", name, BackendKeyring)
	}
	if Inspect().Unlock != UnlockNone {
		t.Fatalf("keyring unlock = %q, want %s", Inspect().Unlock, UnlockNone)
	}
}

func TestVaultAliasName(t *testing.T) {
	t.Setenv(EnvBackend, "vault")
	name, err := Backend()
	if err != nil {
		t.Fatalf("Backend: %v", err)
	}
	if name != BackendVault {
		t.Fatalf("Backend = %q, want %s", name, BackendVault)
	}
}

func TestFailedVaultWriteKeepsPreviousSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission recovery fixture is POSIX-specific")
	}
	root := withVaultEnv(t, "phrase")
	if err := Set("sshx", "keep", "original"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := os.Chmod(root, 0o555); err != nil { // #nosec G302 -- directory fixture, not a secret file
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(root, 0o700) //nolint:errcheck,gosec // restore so TempDir cleanup can remove the tree
	})
	if err := Set("sshx", "keep", "replacement"); err == nil {
		t.Fatal("Set succeeded on a read-only vault directory")
	}
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- restore directory permissions
		t.Fatalf("restore dir perms: %v", err)
	}
	got, err := Get("sshx", "keep")
	if err != nil {
		t.Fatalf("Get after failed write: %v", err)
	}
	if got != "original" {
		t.Fatalf("Get returned %q, want original", got)
	}
}

func TestVaultEmptyPassphraseRejected(t *testing.T) {
	withVaultEnv(t, "")
	if err := Set("sshx", "k", "v"); err == nil {
		t.Fatal("Set succeeded with an empty passphrase")
	}
}

func TestVaultInspectUnlockKinds(t *testing.T) {
	withVaultEnv(t, "phrase")
	if got := Inspect().Unlock; got != UnlockEnv {
		t.Fatalf("Unlock = %q, want %s", got, UnlockEnv)
	}
	os.Unsetenv(EnvVaultPassphrase) //nolint:errcheck // missing unlock
	t.Setenv(EnvVaultKeyFile, "")
	t.Setenv(EnvBackend, BackendVault)
	if got := Inspect().Unlock; got != UnlockMissing {
		t.Fatalf("Unlock = %q, want %s", got, UnlockMissing)
	}
}

func TestVaultDoesNotCreateFileOnDefaultBackend(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SSHX_HOME", root)
	t.Setenv(EnvBackend, BackendKeyring)
	t.Setenv(EnvVaultPassphrase, "unused")
	_, err := os.Stat(filepath.Join(root, "vault"))
	if err == nil {
		t.Fatal("vault file exists before any vault operation")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("stat vault: %v", err)
	}
}
