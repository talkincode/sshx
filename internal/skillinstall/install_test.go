package skillinstall

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestInstallLifecyclePreservesConflictsUntilForced(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills", "sshx")

	installed, err := Install(Options{Dir: dir})
	if err != nil {
		t.Fatalf("install skill: %v", err)
	}
	if installed.Status != "installed" || installed.Source != "embedded" || installed.SHA256 == "" {
		t.Fatalf("unexpected initial result: %#v", installed)
	}
	content, err := os.ReadFile(installed.Path)
	if err != nil {
		t.Fatalf("read installed skill: %v", err)
	}
	if validationErr := validate(content); validationErr != nil {
		t.Fatalf("installed invalid skill: %v", validationErr)
	}
	current, err := Install(Options{Dir: dir})
	if err != nil {
		t.Fatalf("reinstall current skill: %v", err)
	}
	if current.Status != "current" {
		t.Fatalf("reinstall status = %q, want current", current.Status)
	}
	custom := []byte("custom local skill\n")
	if writeErr := os.WriteFile(installed.Path, custom, 0o600); writeErr != nil {
		t.Fatalf("write custom skill: %v", writeErr)
	}
	if _, conflictErr := Install(Options{Dir: dir}); !errors.Is(conflictErr, ErrConflict) {
		t.Fatalf("conflicting install error = %v, want ErrConflict", conflictErr)
	}
	preserved, err := os.ReadFile(installed.Path)
	if err != nil {
		t.Fatalf("read preserved skill: %v", err)
	}
	if string(preserved) != string(custom) {
		t.Fatalf("conflicting install modified existing content: %q", preserved)
	}

	updated, err := Install(Options{Dir: dir, Force: true})
	if err != nil {
		t.Fatalf("force update skill: %v", err)
	}
	if updated.Status != "updated" {
		t.Fatalf("force update status = %q, want updated", updated.Status)
	}
	restored, err := os.ReadFile(installed.Path)
	if err != nil {
		t.Fatalf("read restored skill: %v", err)
	}
	if err := validate(restored); err != nil {
		t.Fatalf("force update did not restore bundled skill: %v", err)
	}
}

func TestInstallPOSIXPermissionsAndRepair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode enforcement is not a Windows ACL capability; see Windows replacement tests")
	}
	dir := filepath.Join(t.TempDir(), "sshx")
	installed, err := Install(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{installed.Path, filepath.Join(dir, metadataFileName)} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode = %o, want 644", path, info.Mode().Perm())
		}
	}
	if chmodErr := os.Chmod(installed.Path, 0o666); chmodErr != nil { // #nosec G302 -- deliberately exercises permission repair.
		t.Fatal(chmodErr)
	}
	repaired, err := Install(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if repaired.Status != "repaired" {
		t.Fatalf("permission repair status = %q, want repaired", repaired.Status)
	}
	info, err := os.Stat(installed.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("repaired skill mode = %o, want 644", info.Mode().Perm())
	}
}

func TestManagedPreviousVersionUpdatesWithoutForce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills", "sshx")
	oldContent := []byte("---\nname: sshx\ndescription: old\n---\n# Old\n")
	newContent := []byte("---\nname: sshx\ndescription: new\n---\n# New\n")

	oldResult, err := installContent(Options{Dir: dir}, oldContent)
	if err != nil {
		t.Fatalf("install old managed skill: %v", err)
	}
	if oldResult.Status != "installed" {
		t.Fatalf("old install status = %q, want installed", oldResult.Status)
	}

	newResult, err := installContent(Options{Dir: dir}, newContent)
	if err != nil {
		t.Fatalf("update managed skill: %v", err)
	}
	if newResult.Status != "updated" {
		t.Fatalf("managed update status = %q, want updated", newResult.Status)
	}
	installed, err := os.ReadFile(filepath.Join(dir, skillFileName)) // #nosec G304 -- isolated managed test path.
	if err != nil {
		t.Fatalf("read updated skill: %v", err)
	}
	if string(installed) != string(newContent) {
		t.Fatalf("managed update content = %q, want %q", installed, newContent)
	}
	metadata, exists, err := readMetadata(filepath.Join(dir, metadataFileName))
	if err != nil || !exists {
		t.Fatalf("read updated metadata: exists=%v err=%v", exists, err)
	}
	if metadata.SHA256 != digest(newContent) {
		t.Fatalf("unexpected updated metadata: %#v", metadata)
	}
}

func TestInstallRejectsSymlinkedTargetDirectoryAndFile(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatalf("create real directory: %v", err)
	}
	symlinkDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		if runtime.GOOS == "windows" && (errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.Errno(1314))) {
			t.Skipf("Windows symlink privilege unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := Install(Options{Dir: symlinkDir, Force: true}); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("symlink directory error = %v, want ErrUnsafeTarget", err)
	}
	if _, err := os.Stat(filepath.Join(realDir, skillFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink directory install escaped target: %v", err)
	}

	targetDir := filepath.Join(root, "target")
	if err := os.Mkdir(targetDir, 0o750); err != nil {
		t.Fatalf("create target directory: %v", err)
	}
	outside := filepath.Join(root, "outside.md")
	if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(targetDir, skillFileName)); err != nil {
		t.Fatalf("create target symlink: %v", err)
	}
	if _, err := Install(Options{Dir: targetDir, Force: true}); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("symlink file error = %v, want ErrUnsafeTarget", err)
	}
	outsideContent, err := os.ReadFile(outside) // #nosec G304 -- outside is an isolated test fixture path.
	if err != nil {
		t.Fatalf("read outside file: %v", err)
	}
	if string(outsideContent) != "outside\n" {
		t.Fatalf("outside file was modified: %q", outsideContent)
	}

	managedDir := filepath.Join(root, "managed")
	if _, installErr := Install(Options{Dir: managedDir}); installErr != nil {
		t.Fatalf("install managed skill fixture: %v", installErr)
	}
	metadataPath := filepath.Join(managedDir, metadataFileName)
	if removeErr := os.Remove(metadataPath); removeErr != nil {
		t.Fatalf("remove managed metadata fixture: %v", removeErr)
	}
	outsideMetadata := filepath.Join(root, "outside-metadata.json")
	if writeErr := os.WriteFile(outsideMetadata, []byte("outside metadata\n"), 0o600); writeErr != nil {
		t.Fatalf("write outside metadata: %v", writeErr)
	}
	if symlinkErr := os.Symlink(outsideMetadata, metadataPath); symlinkErr != nil {
		t.Fatalf("create metadata symlink: %v", symlinkErr)
	}
	if _, installErr := Install(Options{Dir: managedDir, Force: true}); !errors.Is(installErr, ErrUnsafeTarget) {
		t.Fatalf("metadata symlink error = %v, want ErrUnsafeTarget", installErr)
	}
	outsideMetadataContent, err := os.ReadFile(outsideMetadata) // #nosec G304 -- isolated test fixture path.
	if err != nil {
		t.Fatalf("read outside metadata: %v", err)
	}
	if string(outsideMetadataContent) != "outside metadata\n" {
		t.Fatalf("outside metadata was modified: %q", outsideMetadataContent)
	}
}

func TestResolveDirDefaultAndHomeExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}

	defaultDir, err := ResolveDir("")
	if err != nil {
		t.Fatalf("resolve default directory: %v", err)
	}
	if defaultDir != filepath.Join(home, ".agents", "skills", "sshx") {
		t.Fatalf("default directory = %q", defaultDir)
	}

	explicit, err := ResolveDir("~/explicit")
	if err != nil {
		t.Fatalf("resolve explicit directory: %v", err)
	}
	if explicit != filepath.Join(home, "explicit") {
		t.Fatalf("explicit directory = %q", explicit)
	}
	for _, path := range []string{"~", `~\explicit`, filepath.Join(home, "space 目录", "sshx")} {
		got, resolveErr := ResolveDir(path)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		want := path
		switch path {
		case "~":
			want = home
		case `~\explicit`:
			want = filepath.Join(home, "explicit")
		}
		if got != want {
			t.Fatalf("ResolveDir(%q) = %q, want %q", path, got, want)
		}
	}
	root := filepath.VolumeName(home) + string(filepath.Separator)
	if _, err := ResolveDir(root); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("filesystem root %q: %v", root, err)
	}
}

func TestValidateRejectsMalformedContent(t *testing.T) {
	for _, content := range [][]byte{
		nil,
		[]byte("name: sshx\n"),
		[]byte("---\nname: sshx\n"),
		[]byte("---\nname: other\n---\nbody\n"),
	} {
		if err := validate(content); err == nil {
			t.Fatalf("validate(%q) unexpectedly succeeded", content)
		}
	}
}
