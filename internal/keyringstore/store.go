package keyringstore

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	// EnvBackend selects the secret persistence backend. Unset defaults to the
	// OS keyring. There is no silent fallback: an explicit local-vault choice
	// never degrades to the keyring, and a keyring failure never creates a vault.
	EnvBackend = "SSHX_SECRET_BACKEND"
	// EnvVaultPassphrase unlocks the local vault for unattended use.
	// #nosec G101 -- environment variable name, not a credential.
	EnvVaultPassphrase = "SSHX_VAULT_PASSPHRASE" //nolint:gosec
	// EnvVaultKeyFile is a 0600 file whose contents are the vault passphrase.
	// When set, it takes precedence over EnvVaultPassphrase.
	EnvVaultKeyFile = "SSHX_VAULT_KEY_FILE"

	BackendKeyring = "keyring"
	BackendVault   = "local-vault"

	UnlockNone    = "none"
	UnlockEnv     = "env"
	UnlockKeyFile = "keyfile"
	UnlockMissing = "missing"
)

// ErrNotFound reports that a key has no value in the selected backend.
var ErrNotFound = errors.New("secret not found")

// ErrListUnsupported reports that the selected backend cannot enumerate keys.
var ErrListUnsupported = errors.New("secret backend cannot list keys")

// ErrRevealDenied reports that the selected backend never emits secret values
// on the CLI display path. Internal Get still works for stdin injection.
var ErrRevealDenied = errors.New("local vault is write-only")

// Status is the non-secret view of the configured backend. Unlock names the
// configured factor, not whether a passphrase is currently valid.
type Status struct {
	Backend string
	Unlock  string
}

// Backend returns the canonical backend name or an error for unknown values.
func Backend() (string, error) {
	raw := strings.TrimSpace(os.Getenv(EnvBackend))
	switch strings.ToLower(raw) {
	case "", BackendKeyring:
		return BackendKeyring, nil
	case BackendVault, "vault":
		return BackendVault, nil
	default:
		return "", fmt.Errorf("unknown %s %q (use %s or %s)", EnvBackend, raw, BackendKeyring, BackendVault)
	}
}

// Inspect reports the configured backend without reading secrets.
func Inspect() Status {
	name, err := Backend()
	if err != nil {
		return Status{Backend: "invalid", Unlock: UnlockNone}
	}
	status := Status{Backend: name, Unlock: UnlockNone}
	if name == BackendVault {
		status.Unlock = vaultUnlockKind()
	}
	return status
}

// CanReveal reports whether CLI --password-get may emit a secret value.
// The local vault is write-only; the OS keyring (and its E2E stand-in) may
// emit on a pipe for human capture.
func CanReveal() bool {
	name, err := Backend()
	return err == nil && name == BackendKeyring
}

// Set stores a secret in the selected backend.
func Set(service, account, password string) error {
	backend, err := Backend()
	if err != nil {
		return err
	}
	if backend == BackendVault {
		return vaultSet(service, account, password)
	}
	return keyringSet(service, account, password)
}

// Get returns a secret from the selected backend. Callers must not print the
// value on an Agent-facing surface when CanReveal is false.
func Get(service, account string) (string, error) {
	backend, err := Backend()
	if err != nil {
		return "", err
	}
	if backend == BackendVault {
		return vaultGet(service, account)
	}
	return keyringGet(service, account)
}

// Delete removes a secret from the selected backend.
func Delete(service, account string) error {
	backend, err := Backend()
	if err != nil {
		return err
	}
	if backend == BackendVault {
		return vaultDelete(service, account)
	}
	return keyringDelete(service, account)
}

// Accounts lists account names stored under service. The OS keyring backend
// cannot enumerate keys and returns ErrListUnsupported.
func Accounts(service string) ([]string, error) {
	backend, err := Backend()
	if err != nil {
		return nil, err
	}
	if backend == BackendVault {
		return vaultAccounts(service)
	}
	return keyringAccounts(service)
}
