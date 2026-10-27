package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Exercise the compiled CLI against real shells. Unlike the historical SSH
// fixture, sudo is allowed not to consume stdin (NOPASSWD/cached/root).
func TestSudoInputBoundary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX sudo/shell input boundary")
	}
	for _, mode := range []string{"password", "cached"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			require.NoError(t, os.Mkdir(bin, 0700))
			shim := `#!/bin/sh
prompt=
while [ "$#" -gt 0 ]; do
 case "$1" in
  -S) shift;;
  -p) prompt=$2; shift 2;;
  --) shift; break;;
  *) break;;
 esac
done
if [ "$FIXTURE_MODE" = password ]; then
 printf '%s' "$prompt" >&2
 IFS= read -r password || exit 1
 [ "$password" = SSHX_PRIVATE_CANARY ] || exit 1
fi
exec "$@"
`
			require.NoError(t, os.WriteFile(filepath.Join(bin, "sudo"), []byte(shim), 0700)) // #nosec G306 -- executable isolated fixture
			server := startSSHServer(t, serverOptions{root: root, execHandler: func(ch ssh.Channel, command, _ string) {
				cmd := exec.Command("/bin/sh", "-c", command) // #nosec G204 -- isolated fixture commands only.
				cmd.Dir = root
				cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "FIXTURE_MODE=" + mode}
				cmd.Stdin = ch
				cmd.Stdout = ch
				cmd.Stderr = ch.Stderr()
				code := uint32(0)
				if err := cmd.Run(); err != nil {
					code = 1
				}
				sendExitStatus(ch, code)
			}})
			home := t.TempDir()
			env := map[string]string{"SSHX_E2E_KEYRING_FILE": filepath.Join(home, "keyring.json"), "SSH_PASSWORD": operatorPassword}
			set := runSSHXWithTestKeyring(t, home, []string{"--password-set=fixture:SSHX_PRIVATE_CANARY", "--no-audit"}, env)
			require.Equal(t, 0, set.exitCode, set.stderr)
			script := filepath.Join(home, "script.sh")
			require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nprintf 'payload-ok\\n'\n"), 0600))
			args := []string{"run", "--address=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--accept-unknown-host", "--bypass-reason=isolated-fixture", "-pk=fixture", "--sudo", "--script-file=" + script, "--timeout=3s", "--json"}
			result := runSSHXWithTestKeyring(t, home, args, env)
			require.Equal(t, 0, result.exitCode, "stdout=%s stderr=%s", result.stdout, result.stderr)
			assert.Contains(t, result.stdout, "payload-ok")
			assert.NotContains(t, result.stdout, "SSHX_PRIVATE_CANARY")
			assert.NotContains(t, result.stderr, "SSHX_PRIVATE_CANARY")
			// A stdin-reading child must receive EOF, not an unsolicited credential.
			result = runSSHXWithTestKeyring(t, home, []string{"-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "-pk=fixture", "--timeout=3s", "--json", "sudo cat"}, env)
			require.Equal(t, 0, result.exitCode, "stdout=%s stderr=%s", result.stdout, result.stderr)
			assert.NotContains(t, result.stdout, "SSHX_PRIVATE_CANARY")
		})
	}
}
