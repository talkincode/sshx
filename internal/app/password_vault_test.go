package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/talkincode/sshx/internal/keyringstore"
	"github.com/talkincode/sshx/internal/sshclient"
)

func withAppVault(t *testing.T) {
	t.Helper()
	t.Setenv("SSHX_HOME", t.TempDir())
	t.Setenv(keyringstore.EnvBackend, keyringstore.BackendVault)
	t.Setenv(keyringstore.EnvVaultPassphrase, "app-vault-passphrase")
	t.Setenv(keyringstore.EnvVaultKeyFile, "")
}

func TestGetPassword_VaultIsWriteOnly(t *testing.T) {
	withAppVault(t)
	const key = "prod-web"
	if err := setPassword(sshclient.KeyringServiceName, key, "never-print-this-secret"); err != nil {
		t.Fatalf("setPassword: %v", err)
	}
	err := getPassword(sshclient.KeyringServiceName, key)
	if err == nil {
		t.Fatal("getPassword succeeded against local vault")
	}
	if !errors.Is(err, keyringstore.ErrRevealDenied) {
		t.Fatalf("getPassword error = %v, want ErrRevealDenied", err)
	}
	if strings.Contains(err.Error(), "never-print-this-secret") {
		t.Fatalf("error leaked the secret: %v", err)
	}
}

func TestCheckPassword_VaultExistsWithoutRevealing(t *testing.T) {
	withAppVault(t)
	if err := setPassword(sshclient.KeyringServiceName, "prod-web", "vault-secret"); err != nil {
		t.Fatalf("setPassword: %v", err)
	}
	if err := checkPassword(sshclient.KeyringServiceName, "prod-web"); err != nil {
		t.Fatalf("checkPassword: %v", err)
	}
}

func TestDryRunPasswordGet_VaultWriteOnly(t *testing.T) {
	withAppVault(t)
	config := ParseArgs([]string{"sshx", "--password-get=prod-web", "--dry-run", "--json"})
	plan := buildDryRunPlan(config)
	if plan.Valid {
		t.Fatal("dry-run --password-get against local vault should be invalid")
	}
	if plan.SecretBackend != keyringstore.BackendVault {
		t.Fatalf("SecretBackend = %q, want %s", plan.SecretBackend, keyringstore.BackendVault)
	}
	if plan.ConfigCheck.ErrorKind != "config" {
		t.Fatalf("ConfigCheck = %+v", plan.ConfigCheck)
	}
	if plan.WouldReadSecret {
		t.Fatal("write-only get must not claim it would read a secret")
	}
}

func TestDryRunSudo_ReportsLocalVaultWithoutReading(t *testing.T) {
	withAppVault(t)
	config := ParseArgs([]string{"sshx", "-h=10.0.0.1", "--dry-run", "--json", "sudo whoami"})
	plan := buildDryRunPlan(config)
	if !plan.Valid {
		t.Fatalf("sudo dry-run should remain valid: %+v", plan.ConfigCheck)
	}
	if plan.SecretBackend != keyringstore.BackendVault {
		t.Fatalf("SecretBackend = %q", plan.SecretBackend)
	}
	if plan.SecretUnlock != keyringstore.UnlockEnv {
		t.Fatalf("SecretUnlock = %q", plan.SecretUnlock)
	}
	if !plan.WouldReadSecret {
		t.Fatal("sudo dry-run should still declare would_read_secret")
	}
	entries, err := os.ReadDir(os.Getenv("SSHX_HOME"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() == "vault" {
			t.Fatal("dry-run created a vault file")
		}
	}
}

func TestUnknownSecretBackend_DryRunFailsClosed(t *testing.T) {
	t.Setenv(keyringstore.EnvBackend, "consul")
	config := ParseArgs([]string{"sshx", "-h=10.0.0.1", "--dry-run", "--json", "uptime"})
	plan := buildDryRunPlan(config)
	if plan.Valid {
		t.Fatal("dry-run with an unknown secret backend should be invalid")
	}
	if plan.SecretBackend != "invalid" {
		t.Fatalf("SecretBackend = %q, want invalid", plan.SecretBackend)
	}
}

func TestSetPassword_DoesNotCreateVaultOnKeyringBackend(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SSHX_HOME", home)
	t.Setenv(keyringstore.EnvBackend, keyringstore.BackendKeyring)
	_, err := os.Stat(filepath.Join(home, "vault"))
	if !os.IsNotExist(err) && err != nil {
		t.Fatalf("stat: %v", err)
	}
}
