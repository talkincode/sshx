package skillinstall

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsSkillPathsAndReplacementRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills with space 目录", "sshx")
	oldContent := []byte("---\nname: sshx\ndescription: old\n---\n# Old\n")
	newContent := []byte("---\nname: sshx\ndescription: new\n---\n# New\n")
	first, err := installContent(Options{Dir: dir}, oldContent)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(first.Path) || filepath.VolumeName(first.Path) == "" {
		t.Fatalf("Windows installed path is not drive-qualified: %q", first.Path)
	}
	metadata := filepath.Join(dir, metadataFileName)
	beforeMetadata, err := os.ReadFile(metadata) // #nosec G304 -- isolated skill metadata.
	if err != nil {
		t.Fatal(err)
	}
	if chmodErr := os.Chmod(first.Path, 0o400); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	t.Cleanup(func() { _ = os.Chmod(first.Path, 0o644) }) //nolint:errcheck,gosec // restore isolated read-only fixture.
	if _, installErr := installContent(Options{Dir: dir}, newContent); installErr == nil {
		t.Fatal("replacement unexpectedly succeeded over Windows read-only destination")
	}
	unchanged, err := os.ReadFile(first.Path) // #nosec G304 -- isolated skill installation.
	if err != nil || !bytes.Equal(unchanged, oldContent) {
		t.Fatalf("failed replacement modified skill: %q, %v", unchanged, err)
	}
	afterMetadata, err := os.ReadFile(metadata) // #nosec G304 -- isolated skill metadata.
	if err != nil || !bytes.Equal(afterMetadata, beforeMetadata) {
		t.Fatalf("failed replacement modified metadata: %q, %v", afterMetadata, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("failed replacement leaked staging file: %s", entry.Name())
		}
	}
	if chmodErr := os.Chmod(first.Path, 0o644); chmodErr != nil { // #nosec G302 -- restore fixture attribute.
		t.Fatal(chmodErr)
	}
	recovered, err := installContent(Options{Dir: dir}, newContent)
	if err != nil || recovered.Status != "updated" {
		t.Fatalf("retry after restoring write access: %#v, %v", recovered, err)
	}
	current, err := installContent(Options{Dir: dir}, newContent)
	if err != nil || current.Status != "current" {
		t.Fatalf("Windows reinstall must not continually repair POSIX modes: %#v, %v", current, err)
	}
}

func TestWindowsSkillRejectsJunctionAndUNCRoot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction")
	output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput() // #nosec G204 -- isolated junction fixture paths.
	if err != nil {
		t.Fatalf("create junction in isolated test directory: %v: %s", err, output)
	}
	if _, installErr := Install(Options{Dir: junction}); !errors.Is(installErr, ErrUnsafeTarget) {
		t.Fatalf("junction installation = %v, want ErrUnsafeTarget", installErr)
	}
	if _, resolveErr := ResolveDir(`\\server\share\`); !errors.Is(resolveErr, ErrUnsafeTarget) {
		t.Fatalf("UNC share root = %v, want ErrUnsafeTarget", resolveErr)
	}
}
