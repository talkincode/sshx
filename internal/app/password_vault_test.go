package app

import (
	"encoding/json"
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
	if err := setPassword(nil, sshclient.KeyringServiceName, key, "never-print-this-secret"); err != nil {
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
	if err := setPassword(nil, sshclient.KeyringServiceName, "prod-web", "vault-secret"); err != nil {
		t.Fatalf("setPassword: %v", err)
	}
	if err := checkPassword(nil, sshclient.KeyringServiceName, "prod-web"); err != nil {
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

func TestCheckPassword_MissingKeyFailsAndJSON(t *testing.T) {
	withAppVault(t)
	err := checkPassword(nil, sshclient.KeyringServiceName, "missing")
	if err == nil {
		t.Fatal("missing key must not succeed")
	}
	if !errors.Is(err, errPasswordNotFound) {
		t.Fatalf("error = %v, want errPasswordNotFound", err)
	}

	cfg := ParseArgs([]string{"sshx", "--password-check=missing", "--json"})
	var jsonErr error
	out := string(captureStdout(t, func() {
		jsonErr = checkPassword(cfg, sshclient.KeyringServiceName, "missing")
	}))
	if !errors.Is(jsonErr, ErrReported) {
		t.Fatalf("json missing check error = %v, want ErrReported", jsonErr)
	}
	if strings.Contains(out, "NOT stored") || strings.Contains(out, "Password not found") {
		t.Fatalf("json stdout leaked human text: %s", out)
	}
	var doc secretsJSONResult
	if unmarshalErr := json.Unmarshal([]byte(out), &doc); unmarshalErr != nil {
		t.Fatalf("json: %v (%s)", unmarshalErr, out)
	}
	if doc.SchemaVersion != secretsSchemaVersion || doc.Success || doc.Exists == nil || *doc.Exists || doc.Action != "check" {
		t.Fatalf("doc = %+v", doc)
	}
	if doc.ErrorKind != "not_found" {
		t.Fatalf("error_kind = %q", doc.ErrorKind)
	}
}

func TestPasswordSetListCheckJSON(t *testing.T) {
	withAppVault(t)
	cfg := ParseArgs([]string{"sshx", "--password-set=lab", "--json"})
	var setErr error
	out := string(captureStdout(t, func() {
		setErr = setPassword(cfg, sshclient.KeyringServiceName, "lab", "vault-lab-pass")
	}))
	if setErr != nil {
		t.Fatalf("set: %v", setErr)
	}
	if strings.Contains(out, "Enter password") || strings.Contains(out, "vault-lab-pass") {
		t.Fatalf("set json leaked prompt or secret: %s", out)
	}
	var setDoc secretsJSONResult
	if unmarshalErr := json.Unmarshal([]byte(out), &setDoc); unmarshalErr != nil {
		t.Fatalf("set json: %v (%s)", unmarshalErr, out)
	}
	if !setDoc.Success || setDoc.Action != "set" || setDoc.Key != "lab" {
		t.Fatalf("set doc = %+v", setDoc)
	}

	listCfg := ParseArgs([]string{"sshx", "--password-list", "--json"})
	var listErr error
	out = string(captureStdout(t, func() { listErr = listPasswords(listCfg) }))
	if listErr != nil {
		t.Fatalf("list: %v", listErr)
	}
	var listDoc secretsJSONResult
	if unmarshalErr := json.Unmarshal([]byte(out), &listDoc); unmarshalErr != nil {
		t.Fatalf("list json: %v (%s)", unmarshalErr, out)
	}
	if !listDoc.Success || listDoc.ListComplete == nil || !*listDoc.ListComplete {
		t.Fatalf("list doc = %+v", listDoc)
	}
	found := false
	for _, key := range listDoc.Keys {
		if key == "lab" {
			found = true
		}
	}
	if !found {
		t.Fatalf("list keys = %v, want lab", listDoc.Keys)
	}

	checkCfg := ParseArgs([]string{"sshx", "--password-check=lab", "--json"})
	var checkErr error
	out = string(captureStdout(t, func() {
		checkErr = checkPassword(checkCfg, sshclient.KeyringServiceName, "lab")
	}))
	if checkErr != nil {
		t.Fatalf("check: %v", checkErr)
	}
	var checkDoc secretsJSONResult
	if unmarshalErr := json.Unmarshal([]byte(out), &checkDoc); unmarshalErr != nil {
		t.Fatalf("check json: %v (%s)", unmarshalErr, out)
	}
	if !checkDoc.Success || checkDoc.Exists == nil || !*checkDoc.Exists {
		t.Fatalf("check doc = %+v", checkDoc)
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
