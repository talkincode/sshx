package e2e

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Explicit opt-in: users/sudoers belong to a disposable CI runner, provisioned
// by ci.yml. This test never edits the caller's accounts or credential stores.
func TestNativeSudoInputBoundary(t *testing.T) {
	if os.Getenv("SSHX_E2E_NATIVE_SUDO") != "1" {
		t.Skip("requires disposable native sudo fixture")
	}
	require.Equal(t, "linux", runtime.GOOS, "native fixture is Linux-only")
	for _, role := range []string{"password", "nopasswd", "cached", "root", "wrong-password"} {
		t.Run(role, func(t *testing.T) {
			user := "sshx-sudo-" + role
			if role == "wrong-password" {
				user = "sshx-sudo-password"
			}
			if role == "root" {
				user = "root"
			}
			require.NoError(t, exec.Command("id", user).Run(), "provision the isolated sudo fixture first") // #nosec G204 -- fixed fixture account list
			if role == "cached" {
				warm := exec.Command("sudo", "-n", "-u", user, "sudo", "-S", "-p", "", "-v") // #nosec G204 -- explicit disposable sudo fixture
				warm.Stdin = bytes.NewBufferString(operatorPassword + "\n")
				output, err := warm.CombinedOutput()
				require.NoError(t, err, string(output))
			}
			server := startSSHServer(t, serverOptions{execHandler: func(ch ssh.Channel, command, _ string) {
				cmd := exec.Command("sudo", "-n", "-u", user, "/bin/sh", "-c", command) // #nosec G204 -- explicit disposable sudo fixture.
				cmd.Stdin = ch
				cmd.Stdout = ch
				cmd.Stderr = ch.Stderr()
				code := uint32(0)
				if err := cmd.Run(); err != nil {
					code = 1
					var exit *exec.ExitError
					if errors.As(err, &exit) {
						code = uint32(exit.ExitCode())
					}
				} // #nosec G115 -- process exit status
				sendExitStatus(ch, code)
			}})
			home := t.TempDir()
			env := map[string]string{"SSHX_E2E_KEYRING_FILE": filepath.Join(home, "keyring.json"), "SSH_PASSWORD": operatorPassword}
			secret := operatorPassword
			if role == "wrong-password" {
				secret = "wrong-fixture-password"
			}
			set := runSSHXWithTestKeyring(t, home, []string{"--password-set=fixture:" + secret, "--no-audit"}, env)
			require.Equal(t, 0, set.exitCode, set.stderr)
			source := filepath.Join(home, "script.sh")
			require.NoError(t, os.WriteFile(source, []byte("#!/bin/sh\nprintf 'native-payload-ok\\n'\n"), 0600))
			result := runSSHXWithTestKeyring(t, home, []string{"run", "--address=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--accept-unknown-host", "--bypass-reason=isolated-native-fixture", "-pk=fixture", "--sudo", "--script-file=" + source, "--timeout=5s", "--json"}, env)
			if role == "wrong-password" {
				assert.NotEqual(t, 0, result.exitCode)
				assert.NotContains(t, result.stdout, `"stdout":"native-payload-ok`)
			} else {
				require.Equal(t, 0, result.exitCode, "stdout=%s stderr=%s", result.stdout, result.stderr)
				assert.Contains(t, result.stdout, "native-payload-ok")
			}
			assert.NotContains(t, result.stdout, secret)
			assert.NotContains(t, result.stderr, secret)
		})
	}
}
