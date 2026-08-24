package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func vaultEnv(passphrase string) map[string]string {
	return map[string]string{
		"SSHX_SECRET_BACKEND":   "local-vault",
		"SSHX_VAULT_PASSPHRASE": passphrase,
		"SSH_PASSWORD":          operatorPassword,
	}
}

func TestLocalVaultWriteOnlySetCheckAndSudoInjection(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	key := "vault-sudo"
	env := vaultEnv("e2e-vault-passphrase")

	set := runSSHX(t, home, []string{"--password-set=" + key + ":" + operatorPassword, "--no-audit"}, env)
	require.Equal(t, 0, set.exitCode, set.stderr)
	assert.NotContains(t, set.stdout, operatorPassword)
	assert.NotContains(t, set.stderr, operatorPassword)

	vaultPath := filepath.Join(home, ".sshx", "vault")
	data, err := os.ReadFile(vaultPath) // #nosec G304 -- isolated E2E vault under TempDir
	require.NoError(t, err)
	assert.NotContains(t, string(data), operatorPassword)
	assert.True(t, strings.HasPrefix(string(data), "SSHXVL01"))
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(vaultPath)
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	check := runSSHX(t, home, []string{"--password-check=" + key, "--no-audit"}, env)
	require.Equal(t, 0, check.exitCode, check.stderr)
	assert.NotContains(t, check.stdout, operatorPassword)

	get := runSSHX(t, home, []string{"--password-get=" + key, "--no-audit"}, env)
	assert.NotEqual(t, 0, get.exitCode)
	assert.NotContains(t, get.stdout, operatorPassword)
	assert.NotContains(t, get.stderr, operatorPassword)
	assert.Contains(t, get.stderr+get.stdout, "write-only")

	list := runSSHX(t, home, []string{"--password-list", "--no-audit"}, env)
	require.Equal(t, 0, list.exitCode, list.stderr)
	assert.Contains(t, list.stdout, key)
	assert.NotContains(t, list.stdout, operatorPassword)

	plan := runSSHX(t, home, []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--dry-run",
		"--json",
		"-pk=" + key,
		"sudo whoami",
	}, env)
	require.Equal(t, 0, plan.exitCode, plan.stderr)
	var dry struct {
		Valid         bool   `json:"valid"`
		SecretBackend string `json:"secret_backend"`
		SecretUnlock  string `json:"secret_unlock"`
		WouldRead     bool   `json:"would_read_secret"`
	}
	require.NoError(t, json.Unmarshal([]byte(plan.stdout), &dry))
	assert.True(t, dry.Valid)
	assert.Equal(t, "local-vault", dry.SecretBackend)
	assert.Equal(t, "env", dry.SecretUnlock)
	assert.True(t, dry.WouldRead)
	assert.NotContains(t, plan.stdout, operatorPassword)

	sudo := runSSHX(t, home, []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--json",
		"-pk=" + key,
		"sudo whoami",
	}, env)
	require.Equal(t, 0, sudo.exitCode, "stderr=%s stdout=%s", sudo.stderr, sudo.stdout)
	var payload commandResult
	require.NoError(t, json.Unmarshal([]byte(sudo.stdout), &payload))
	assert.Equal(t, "sudo-ok\n", payload.Stdout)
	assert.NotContains(t, sudo.stdout, operatorPassword)
	assert.NotContains(t, sudo.stderr, operatorPassword)
}

func TestLocalVaultPasswordGetDryRunIsInvalid(t *testing.T) {
	home := t.TempDir()
	env := vaultEnv("e2e-vault-passphrase")
	result := runSSHX(t, home, []string{"--password-get=prod-web", "--dry-run", "--json"}, env)
	require.Equal(t, 0, result.exitCode, result.stderr)
	var plan struct {
		Valid         bool   `json:"valid"`
		SecretBackend string `json:"secret_backend"`
		WouldRead     bool   `json:"would_read_secret"`
		ConfigCheck   struct {
			Status    string `json:"status"`
			ErrorKind string `json:"error_kind"`
		} `json:"config_check"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &plan))
	assert.False(t, plan.Valid)
	assert.Equal(t, "local-vault", plan.SecretBackend)
	assert.Equal(t, "config", plan.ConfigCheck.ErrorKind)
	assert.False(t, plan.WouldRead)
}

func TestLocalVaultWrongPassphraseKeepsSecret(t *testing.T) {
	home := t.TempDir()
	key := "keep-me"
	env := vaultEnv("original-pass")
	set := runSSHX(t, home, []string{"--password-set=" + key + ":" + operatorPassword, "--no-audit"}, env)
	require.Equal(t, 0, set.exitCode, set.stderr)

	wrong := vaultEnv("other-pass")
	check := runSSHX(t, home, []string{"--password-check=" + key, "--no-audit"}, wrong)
	assert.NotEqual(t, 0, check.exitCode)
	assert.NotContains(t, check.stdout, operatorPassword)
	assert.NotContains(t, check.stderr, operatorPassword)

	ok := runSSHX(t, home, []string{"--password-check=" + key, "--no-audit"}, env)
	require.Equal(t, 0, ok.exitCode, ok.stderr)
}

func TestLocalVaultRejectsWorldReadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX vault file modes are the permission contract")
	}
	home := t.TempDir()
	key := "perm-key"
	env := vaultEnv("e2e-vault-passphrase")
	set := runSSHX(t, home, []string{"--password-set=" + key + ":" + operatorPassword, "--no-audit"}, env)
	require.Equal(t, 0, set.exitCode, set.stderr)

	vaultPath := filepath.Join(home, ".sshx", "vault")
	require.NoError(t, os.Chmod(vaultPath, 0o644)) // #nosec G302 -- deliberately creates an unsafe fixture
	check := runSSHX(t, home, []string{"--password-check=" + key, "--no-audit"}, env)
	assert.NotEqual(t, 0, check.exitCode, check.stdout+"\n"+check.stderr)
	assert.NotContains(t, check.stdout, operatorPassword)
}

func TestLocalVaultFailedWritePreservesPreviousSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission recovery fixture is POSIX-specific")
	}
	home := t.TempDir()
	key := "keep"
	env := vaultEnv("e2e-vault-passphrase")
	set := runSSHX(t, home, []string{"--password-set=" + key + ":" + operatorPassword, "--no-audit"}, env)
	require.Equal(t, 0, set.exitCode, set.stderr)

	runtimeDir := filepath.Join(home, ".sshx")
	vaultPath := filepath.Join(runtimeDir, "vault")
	before, err := os.ReadFile(vaultPath) // #nosec G304 -- isolated E2E vault under TempDir
	require.NoError(t, err)
	require.NoError(t, os.Chmod(runtimeDir, 0o555)) // #nosec G302 -- directory fixture, not a secret file
	t.Cleanup(func() {
		_ = os.Chmod(runtimeDir, 0o700) //nolint:errcheck,gosec // restore so TempDir cleanup can remove the tree
	})
	second := runSSHX(t, home, []string{"--password-set=" + key + ":replacement-secret", "--no-audit"}, env)
	assert.NotEqual(t, 0, second.exitCode)
	assert.NotContains(t, second.stdout, "replacement-secret")
	require.NoError(t, os.Chmod(runtimeDir, 0o700)) // #nosec G302 -- restore directory permissions
	after, err := os.ReadFile(vaultPath)            // #nosec G304 -- isolated E2E vault under TempDir
	require.NoError(t, err)
	assert.Equal(t, before, after)

	check := runSSHX(t, home, []string{"--password-check=" + key, "--no-audit"}, env)
	require.Equal(t, 0, check.exitCode, check.stderr)
}

func TestLocalVaultAuditRecordsBackendWithoutSecret(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	key := "audit-vault"
	env := vaultEnv("e2e-vault-passphrase")
	env["SSHX_NO_AUDIT"] = "false"
	env["SSHX_AUDIT_OUTPUT"] = filepath.Join(home, "audit-out")

	set := runSSHX(t, home, []string{"--password-set=" + key + ":" + operatorPassword}, env)
	require.Equal(t, 0, set.exitCode, set.stderr)

	sudo := runSSHX(t, home, []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--json",
		"-pk=" + key,
		"sudo whoami",
	}, env)
	require.Equal(t, 0, sudo.exitCode, sudo.stderr)

	entries, err := os.ReadDir(env["SSHX_AUDIT_OUTPUT"])
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	body, err := os.ReadFile(filepath.Join(env["SSHX_AUDIT_OUTPUT"], entries[0].Name())) // #nosec G304 -- isolated E2E audit dir
	require.NoError(t, err)
	assert.NotContains(t, string(body), operatorPassword)
	assert.Contains(t, string(body), `"secret_backend":"local-vault"`)
}

func TestDefaultBackendDoesNotCreateVaultFile(t *testing.T) {
	home := t.TempDir()
	result := runSSHX(t, home, []string{"--dry-run", "--json", "-h=127.0.0.1", "uptime"}, nil)
	require.Equal(t, 0, result.exitCode, result.stderr)
	var plan struct {
		SecretBackend string `json:"secret_backend"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &plan))
	assert.Equal(t, "keyring", plan.SecretBackend)
	_, err := os.Stat(filepath.Join(home, ".sshx", "vault"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}
