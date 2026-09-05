package plugin

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWindowsPluginRejectsDrivePathsAndJunctions(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{`C:\outside`, `C:relative`, `\\server\share\outside`, `..\outside`} {
		if _, err := safeChild(root, path); err == nil {
			t.Fatalf("accepted Windows escape %q", path)
		}
	}
	target := filepath.Join(root, "outside")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "linked")
	output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput() // #nosec G204 -- isolated junction fixture paths.
	if err != nil {
		t.Fatalf("create isolated junction: %v: %s", err, output)
	}
	if _, err := safeChild(root, filepath.Join("linked", "collector.sh")); err == nil {
		t.Fatal("plugin path crossed a Windows junction")
	}
}

func TestWindowsPluginTrustReplacementRecovery(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SSHX_HOME", root)
	if _, err := Create(CreateOptions{ID: "portable"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Trust("portable"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, LockFile)
	before, err := os.ReadFile(path) // #nosec G304 -- isolated plugin trust file.
	if err != nil {
		t.Fatal(err)
	}
	if chmodErr := os.Chmod(path, 0o400); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) }) //nolint:errcheck // restore isolated read-only fixture.
	if _, trustErr := Trust("portable"); trustErr == nil {
		t.Fatal("trust replacement succeeded over a read-only Windows lock file")
	}
	after, err := os.ReadFile(path) // #nosec G304 -- isolated plugin trust file.
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed trust write did not preserve lock: %v", err)
	}
	if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	trusted, err := Trust("portable")
	if err != nil || !trusted.Trusted {
		t.Fatalf("trust recovery = %#v, %v", trusted, err)
	}
}
