package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestIsolatedEnvironmentCaseInsensitiveHomeAndOverrides(t *testing.T) {
	inherited := []string{
		"HOME=/inherited", "Home=/duplicate", "UserProfile=C:\\inherited",
		"ssh_password=inherited-secret", "sShX_hOmE=inherited-state",
		"sshx_e2e_keyring_file=inherited-keyring", "Path=old", "SYSTEMROOT=C:\\Windows",
	}
	env := isolatedEnvironmentFrom(inherited, "isolated home", map[string]string{"path": "new", "ssh_password": "fixture"})
	values := map[string]string{}
	for _, item := range env {
		name, value, ok := strings.Cut(item, "=")
		require.True(t, ok)
		name = strings.ToUpper(name)
		_, duplicate := values[name]
		require.False(t, duplicate, "case-insensitive duplicate %s", name)
		values[name] = value
	}
	assert.Equal(t, "isolated home", values["HOME"])
	assert.Equal(t, "isolated home", values["USERPROFILE"])
	assert.Equal(t, "fixture", values["SSH_PASSWORD"])
	assert.Equal(t, "new", values["PATH"])
	assert.Equal(t, `C:\Windows`, values["SYSTEMROOT"])
	assert.NotContains(t, values, "SSHX_HOME")
	assert.NotContains(t, values, "SSHX_E2E_KEYRING_FILE")
}

func TestPortableCLIHomePluginAndVaultIsolation(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home with spaces 目录")
	require.NoError(t, os.Mkdir(home, 0o700))
	installed := runSSHX(t, home, []string{"skill", "install", "--json"}, nil)
	require.Equal(t, 0, installed.exitCode, installed.stdout+installed.stderr)
	var skill skillInstallResult
	require.NoError(t, json.Unmarshal([]byte(installed.stdout), &skill))
	assert.Equal(t, filepath.Join(home, ".agents", "skills", "sshx", "SKILL.md"), skill.Path)
	current := runSSHX(t, home, []string{"skill", "install", "--json"}, nil)
	require.Equal(t, 0, current.exitCode, current.stdout+current.stderr)
	require.NoError(t, json.Unmarshal([]byte(current.stdout), &skill))
	assert.Equal(t, "current", skill.Status)

	for _, args := range [][]string{
		{"plugin", "create", "portable.inspect", "--json"},
		{"plugin", "validate", "portable.inspect", "--json"},
		{"plugin", "test", "portable.inspect", "--fixture=complete", "--json"},
		{"plugin", "trust", "portable.inspect", "--json"},
	} {
		result := runSSHX(t, home, args, nil)
		require.Equal(t, 0, result.exitCode, "%v: %s%s", args, result.stdout, result.stderr)
		require.True(t, json.Valid([]byte(result.stdout)), "stdout must contain only a JSON document")
	}
	require.FileExists(t, filepath.Join(home, ".sshx", "plugin-lock.json"))
	env := map[string]string{"SSHX_SECRET_BACKEND": "local-vault", "SSHX_VAULT_PASSPHRASE": "portable-vault-pass"}
	set := runSSHX(t, home, []string{"--password-set=portable-key:portable-secret"}, env)
	require.Equal(t, 0, set.exitCode, set.stdout+set.stderr)
	path := filepath.Join(home, ".sshx", "vault")
	before, err := os.ReadFile(path) // #nosec G304 -- isolated CLI vault fixture.
	require.NoError(t, err)
	assert.NotContains(t, string(before), "portable-secret")
	env["SSHX_VAULT_PASSPHRASE"] = "wrong-pass"
	denied := runSSHX(t, home, []string{"--password-set=portable-key:replacement"}, env)
	assert.Equal(t, 255, denied.exitCode)
	after, err := os.ReadFile(path) // #nosec G304 -- isolated CLI vault fixture.
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestReliabilityMalformedSettingsPreventAliasFallbackOrConnect(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	for _, malformed := range []string{"{", `{"hosts":[`, `{"hosts":"wrong"}`, `{"hosts":[]}{"hosts":[]}`} {
		t.Run(malformed, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".sshx", "settings.json")
			require.NoError(t, os.Mkdir(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, []byte(malformed), 0o600))
			// A resolvable alias must not silently become a DNS target after an
			// inventory parse failure. Explicit literal addresses need no lookup.
			for _, args := range [][]string{
				{"-h=localhost", "-p=" + server.port, "-u=operator", "--no-key", "--json", "probe"},
				{"run", "--hosts=localhost", "-p=" + server.port, "-u=operator", "--no-key", "--dry-run", "--json", "probe"},
			} {
				before := server.connections.Load()
				result := runSSHX(t, home, args, map[string]string{"SSH_PASSWORD": operatorPassword})
				assert.Equal(t, 255, result.exitCode, result.stdout+result.stderr)
				assert.Equal(t, before, server.connections.Load(), "corrupt settings must fail before dialing")
				after, err := os.ReadFile(path) // #nosec G304 -- isolated malformed settings fixture.
				require.NoError(t, err)
				assert.Equal(t, malformed, string(after))
			}
		})
	}
}

func TestReliabilityAuthenticationMatrix(t *testing.T) {
	authorized, authorizedPath := newClientKey(t)
	_, rejectedPath := newClientKey(t)
	hostSigner := newHostSigner(t)
	server := startSSHServer(t, serverOptions{authorizedKey: authorized.PublicKey(), hostSigner: hostSigner})
	fixtures := t.TempDir()
	malformedPath := filepath.Join(fixtures, "malformed-key")
	require.NoError(t, os.WriteFile(malformedPath, []byte("not a private key"), 0o600))
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "encrypted-fixture", []byte("not-supplied"))
	require.NoError(t, err)
	encryptedPath := filepath.Join(fixtures, "encrypted-key")
	require.NoError(t, os.WriteFile(encryptedPath, pem.EncodeToMemory(block), 0o600))

	cases := []struct {
		name, key, password, auth string
	}{
		{"key wins over supplied wrong password", authorizedPath, "wrong", "key"},
		{"rejected key explicit fallback", rejectedPath, operatorPassword, "password-fallback"},
		{"rejected key no fallback", rejectedPath, "", ""},
		{"rejected key wrong fallback", rejectedPath, "wrong", ""},
		{"missing key no fallback", filepath.Join(fixtures, "missing"), "", ""},
		{"missing key explicit password", filepath.Join(fixtures, "missing"), operatorPassword, "password"},
		{"malformed key no fallback", malformedPath, "", ""},
		{"malformed key explicit password", malformedPath, operatorPassword, "password"},
		{"encrypted key no passphrase", encryptedPath, "", ""},
		{"encrypted key explicit password", encryptedPath, operatorPassword, "password"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			trust := writeKnownHost(t, home, server, hostSigner.PublicKey())
			result := runSSHX(t, home, []string{
				"-h=" + server.host, "-p=" + server.port, "-u=operator", "-i=" + test.key,
				"--known-hosts=" + trust, "--json", "probe",
			}, map[string]string{"SSH_PASSWORD": test.password})
			if test.auth == "" {
				assertSSHXFailure(t, result, "auth")
				return
			}
			require.Equal(t, 0, result.exitCode, result.stdout+result.stderr)
			var payload commandResult
			require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload))
			assert.Equal(t, test.auth, payload.AuthMethod)
			assert.Equal(t, "probe-ok\n", payload.Stdout)
		})
	}
}

func TestReliabilityPrivateShellCredentialsRejectPublicFixtures(t *testing.T) {
	var calls atomic.Int64
	options := privateShellServerOptions(t, func(channel ssh.Channel, _ string, role string) {
		calls.Add(1)
		_, _ = channel.Write([]byte(role + "\n")) //nolint:errcheck // inert authenticated handler fixture.
		sendExitStatus(channel, 0)
	})
	server := startSSHServer(t, options)
	home := t.TempDir()
	for _, account := range []struct {
		user, publicPassword, privatePassword string
	}{
		{"operator", operatorPassword, options.operatorPassword},
		{"reader", readerPassword, options.readerPassword},
	} {
		t.Run(account.user, func(t *testing.T) {
			base := []string{
				"-h=" + server.host, "-p=" + server.port, "-u=" + account.user,
				"--no-key", "--accept-unknown-host", "--json", "probe",
			}
			before := calls.Load()
			denied := runSSHX(t, home, base, map[string]string{"SSH_PASSWORD": account.publicPassword})
			assertSSHXFailure(t, denied, "auth")
			assert.Equal(t, before, calls.Load(), "public fixture password must not reach private handler")
			allowed := runSSHX(t, home, base, map[string]string{"SSH_PASSWORD": account.privatePassword})
			require.Equal(t, 0, allowed.exitCode, allowed.stdout+allowed.stderr)
			assert.Equal(t, before+1, calls.Load())
			var result commandResult
			require.NoError(t, json.Unmarshal([]byte(allowed.stdout), &result))
			assert.Equal(t, account.user+"\n", result.Stdout)
			assert.NotContains(t, allowed.stdout+allowed.stderr, account.privatePassword)
		})
	}
}

func TestReliabilityHostTrustMatrix(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	for _, test := range []struct {
		name, content, flag string
		success             bool
	}{
		{"unknown strict", "", "", false},
		{"unknown accepted", "", "--accept-unknown-host", true},
		{"malformed strict", "not a known-host record\n", "", false},
		{"malformed accept is not repair", "not a known-host record\n", "--accept-unknown-host", false},
		{"malformed explicit insecure", "not a known-host record\n", "--insecure-hostkey", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "known_hosts")
			require.NoError(t, os.WriteFile(path, []byte(test.content), 0o600))
			args := []string{"-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--known-hosts=" + path, "--json"}
			if test.flag != "" {
				args = append(args, test.flag)
			}
			result := runSSHX(t, home, append(args, "probe"), map[string]string{"SSH_PASSWORD": operatorPassword})
			if test.success {
				require.Equal(t, 0, result.exitCode, result.stdout+result.stderr)
			} else {
				assertSSHXFailure(t, result, "host_key")
			}
			after, err := os.ReadFile(path) // #nosec G304 -- isolated trust fixture.
			require.NoError(t, err)
			if test.flag != "--accept-unknown-host" || !test.success {
				assert.Equal(t, test.content, string(after), "failed/insecure trust checks must not rewrite trust")
			} else {
				assert.Contains(t, string(after), server.host)
			}
		})
	}
	t.Run("changed key never accepted by TOFU", func(t *testing.T) {
		home := t.TempDir()
		path := writeKnownHost(t, home, server, newHostSigner(t).PublicKey())
		before, err := os.ReadFile(path) // #nosec G304 -- isolated trust fixture.
		require.NoError(t, err)
		result := runSSHX(t, home, []string{
			"-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key",
			"--known-hosts=" + path, "--accept-unknown-host", "--json", "probe",
		}, map[string]string{"SSH_PASSWORD": operatorPassword})
		assertSSHXFailure(t, result, "host_key")
		after, err := os.ReadFile(path) // #nosec G304 -- isolated trust fixture.
		require.NoError(t, err)
		assert.Equal(t, before, after)
	})
	t.Run("unwritable trust preserves original", func(t *testing.T) {
		home := t.TempDir()
		path := filepath.Join(home, "readonly_known_hosts")
		require.NoError(t, os.WriteFile(path, nil, 0o400))
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) }) //nolint:errcheck // restore test fixture for cleanup.
		if runtime.GOOS != "windows" {
			file, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- permission probe on an isolated trust fixture.
			if err == nil {
				require.NoError(t, file.Close())
				t.Skip("current UID bypasses POSIX read-only permissions")
			}
			require.ErrorIs(t, err, os.ErrPermission)
		}
		result := runSSHX(t, home, []string{
			"-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key",
			"--known-hosts=" + path, "--accept-unknown-host", "--json", "probe",
		}, map[string]string{"SSH_PASSWORD": operatorPassword})
		assertSSHXFailure(t, result, "host_key")
		after, err := os.ReadFile(path) // #nosec G304 -- isolated read-only trust fixture.
		require.NoError(t, err)
		assert.Empty(t, after)
	})
}

func writeKnownHost(t *testing.T, home string, server *testSSHServer, key ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(home, "known_hosts")
	line := knownhosts.Line([]string{net.JoinHostPort(server.host, server.port)}, key) + "\n"
	require.NoError(t, os.WriteFile(path, []byte(line), 0o600))
	return path
}
