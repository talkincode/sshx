package plugin

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// installSourcePath stages one scaffolded plugin as an external source directory
// with caller-owned permissions: install sanitizes modes instead of inheriting
// them, so the source deliberately keeps a permissive layout. The scaffold is
// built in a scratch runtime root, then copied out, because a source is by
// definition not part of the plugin root.
func installSourcePath(t *testing.T, id string) string {
	t.Helper()
	runtimeRoot := os.Getenv("SSHX_HOME")
	scratch := t.TempDir()
	t.Setenv("SSHX_HOME", scratch)
	created, err := Create(CreateOptions{ID: id, Template: "generic"})
	if err != nil {
		t.Fatalf("Create(%q) error = %v", id, err)
	}
	t.Setenv("SSHX_HOME", runtimeRoot)
	source := filepath.Join(t.TempDir(), id)
	if copyErr := copyDirForTest(created.Resolved.Path, source); copyErr != nil {
		t.Fatalf("stage source: %v", copyErr)
	}
	return source
}

func copyDirForTest(from, to string) error {
	if err := os.MkdirAll(to, 0o750); err != nil { // #nosec G301 -- fixture stages a caller-owned source layout.
		return err
	}
	sourceRoot, err := os.OpenRoot(from)
	if err != nil {
		return err
	}
	defer func() { _ = sourceRoot.Close() }() //nolint:errcheck // fixture handle cleanup
	stageRoot, err := os.OpenRoot(to)
	if err != nil {
		return err
	}
	defer func() { _ = stageRoot.Close() }() //nolint:errcheck // fixture handle cleanup
	return fs.WalkDir(sourceRoot.FS(), ".", func(relative string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if entry.IsDir() {
			return stageRoot.Mkdir(relative, 0o750)
		}
		data, readErr := sourceRoot.ReadFile(relative)
		if readErr != nil {
			return readErr
		}
		return stageRoot.WriteFile(relative, data, 0o600) // #nosec G306 -- fixture copy of its own scaffold.
	})
}

func TestInstallPublishesValidatedPluginWithRestrictiveModes(t *testing.T) {
	t.Setenv("SSHX_HOME", t.TempDir())
	source := installSourcePath(t, "installed.inspect")

	installed, err := Install(InstallOptions{Source: source})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if installed.Resolved.Trusted {
		t.Fatal("installed plugin must stay untrusted until it is explicitly trusted")
	}
	if installed.BackupPath != "" {
		t.Fatalf("fresh install must not back anything up, got %q", installed.BackupPath)
	}
	if installed.Resolved.Manifest.ID != "installed.inspect" {
		t.Fatalf("installed id = %q", installed.Resolved.Manifest.ID)
	}
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "installed.inspect"); installed.Resolved.Path != want {
		t.Fatalf("installed path = %q, want %q", installed.Resolved.Path, want)
	}
	for _, relative := range installed.Files {
		info, statErr := os.Stat(filepath.Join(installed.Resolved.Path, relative))
		if statErr != nil {
			t.Fatalf("stat %s: %v", relative, statErr)
		}
		wantMode := os.FileMode(0o600)
		if relative == "collectors/linux.sh" {
			wantMode = 0o700
		}
		if runtime.GOOS == "windows" {
			continue // synthetic mode bits on Windows are not ACL evidence
		}
		if info.Mode().Perm() != wantMode {
			t.Fatalf("%s mode = %04o, want %04o", relative, info.Mode().Perm(), wantMode)
		}
	}
	// The published plugin is immediately usable through the normal loader.
	if _, resolveErr := Resolve("installed.inspect"); resolveErr != nil {
		t.Fatalf("Resolve(installed) error = %v", resolveErr)
	}
}

func TestInstallReplacesWithBackupAndTrustsInOneStep(t *testing.T) {
	t.Setenv("SSHX_HOME", t.TempDir())
	source := installSourcePath(t, "installed.inspect")

	if _, err := Install(InstallOptions{Source: source}); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(InstallOptions{Source: source}); err == nil {
		t.Fatal("second install succeeded without --replace")
	}
	replaced, err := Install(InstallOptions{Source: source, Replace: true, Trust: true})
	if err != nil {
		t.Fatalf("Install(replace, trust) error = %v", err)
	}
	if replaced.BackupPath == "" {
		t.Fatal("replace must preserve the previous plugin as a backup")
	}
	if _, statErr := os.Stat(filepath.Join(replaced.BackupPath, ManifestFile)); statErr != nil {
		t.Fatalf("backup missing manifest: %v", statErr)
	}
	if !replaced.Resolved.Trusted {
		t.Fatal("--trust must record the published digest in the same step")
	}
	// The trust lock stores the published digest, not the source's bytes.
	listed, err := List()
	if err != nil {
		t.Fatal(err)
	}
	for _, summary := range listed {
		if summary.ID != "installed.inspect" {
			continue
		}
		if !summary.Trusted || summary.Digest != replaced.Resolved.Digest {
			t.Fatalf("listing = %#v", summary)
		}
	}
}

func TestInstallRefusesSymlinksNonDirectoriesAndReservedIDs(t *testing.T) {
	t.Setenv("SSHX_HOME", t.TempDir())
	source := installSourcePath(t, "installed.inspect")
	if symlinkErr := os.Symlink(filepath.Join(source, ManifestFile), filepath.Join(source, "linked.json")); symlinkErr != nil {
		t.Skipf("symlinks unsupported here: %v", symlinkErr)
	}
	if _, err := Install(InstallOptions{Source: source}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink source error = %v", err)
	}
	if _, err := Install(InstallOptions{Source: filepath.Join(source, ManifestFile)}); err == nil {
		t.Fatal("installing a file instead of a directory must fail")
	}
	if _, err := Install(InstallOptions{Source: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing source must fail")
	}
	reserved := installSourcePath(t, "installed.inspect")
	manifestPath := filepath.Join(reserved, ManifestFile)
	data, readErr := os.ReadFile(manifestPath) // #nosec G304 -- fixture reads its own staged manifest.
	if readErr != nil {
		t.Fatal(readErr)
	}
	reservedManifest := strings.Replace(string(data), `"installed.inspect"`, `"network.dns"`, 1)
	if writeErr := os.WriteFile(manifestPath, []byte(reservedManifest), 0o600); writeErr != nil { // #nosec G304,G703 -- fixture rewrites its own staged manifest.
		t.Fatal(writeErr)
	}
	if _, err := Install(InstallOptions{Source: reserved}); err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Fatalf("built-in id error = %v", err)
	}
}

// A source that cannot be validated must never reach the published plugin: the
// validation happens on a staged copy before the installed directory is touched.
func TestInstallKeepsPublishedPluginWhenSourceIsInvalid(t *testing.T) {
	t.Setenv("SSHX_HOME", t.TempDir())
	source := installSourcePath(t, "installed.inspect")
	published, err := Install(InstallOptions{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	broken := installSourcePath(t, "installed.inspect")
	collector := filepath.Join(broken, "collectors", "linux.sh")
	if removeErr := os.Remove(collector); removeErr != nil {
		t.Fatal(removeErr)
	}
	if _, err := Install(InstallOptions{Source: broken, Replace: true}); err == nil || !strings.Contains(err.Error(), "validate source plugin") {
		t.Fatalf("invalid source error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(published.Resolved.Path, "collectors", "linux.sh")); statErr != nil {
		t.Fatalf("published plugin was disturbed by a failed install: %v", statErr)
	}
	if _, resolveErr := Resolve("installed.inspect"); resolveErr != nil {
		t.Fatalf("published plugin no longer resolves: %v", resolveErr)
	}
}

// A missing plugin names the directory that was searched, so a caller does not
// have to derive the plugin root from the source or the documentation.
func TestResolveMissingPluginNamesTheSearchedDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SSHX_HOME", root)
	_, err := Resolve("missing.plugin")
	if err == nil {
		t.Fatal("missing plugin resolved")
	}
	if !strings.Contains(err.Error(), filepath.Join(root, "plugins")) {
		t.Fatalf("error does not name the plugin root: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error does not report a miss: %v", err)
	}
}

// A killed install can leave a staging directory behind. It is not a plugin, and
// a dot-prefixed name can never be a valid plugin id, so the inventory must not
// report it as an INVALID entry that hides the real local plugins (issue #88).
func TestListSkipsInterruptedInstallStaging(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SSHX_HOME", root)
	source := installSourcePath(t, "installed.inspect")
	published, err := Install(InstallOptions{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	pluginsRoot, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(pluginsRoot, ".install-installed.inspect-123456")
	if mkdirErr := os.MkdirAll(leftover, 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	listed, err := List()
	if err != nil {
		t.Fatal(err)
	}
	for _, summary := range listed {
		if strings.HasPrefix(summary.ID, ".install-") {
			t.Fatalf("staging directory reported as a plugin: %#v", summary)
		}
	}
	found := false
	for _, summary := range listed {
		if summary.ID == "installed.inspect" {
			found = true
			if !summary.Valid || summary.Path != published.Resolved.Path {
				t.Fatalf("published plugin listing = %#v", summary)
			}
		}
	}
	if !found {
		t.Fatalf("published plugin missing from %#v", listed)
	}
}

// A failed publication must not leave the plugin missing: the previous plugin is
// restored when the staged move fails and the restore can run, and it is kept at
// its backup path when the restore cannot (AGENT.md §9 recovery evidence).
func TestPublishStagedDirRestoresOrKeepsThePreviousPlugin(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	backup := filepath.Join(dir, "backup")
	writeBackup := func(t *testing.T) {
		t.Helper()
		require.NoError(t, os.MkdirAll(backup, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(backup, ManifestFile), []byte("previous\n"), 0o600))
	}

	// The staged move fails (the staging directory was lost) while the previous
	// plugin is still recoverable: it must come back instead of staying missing.
	writeBackup(t)
	kept, publishErr := publishStagedDir(filepath.Join(dir, "lost-stage"), target, backup)
	require.Error(t, publishErr)
	require.Contains(t, publishErr.Error(), "previous plugin restored")
	require.Empty(t, kept, "a restored plugin no longer needs its backup path")
	restored, readErr := os.ReadFile(filepath.Join(target, ManifestFile)) // #nosec G304 -- fixture path inside the owned test directory.
	require.NoError(t, readErr, "the previous plugin must be back in place")
	require.Equal(t, []byte("previous\n"), restored)
	require.NoFileExists(t, backup, "the restore consumes the backup")

	// The rename fails because the target cannot be replaced and the restore
	// cannot run either: the failure must name where the previous plugin is kept,
	// and that recovery copy must survive.
	writeBackup(t)
	stage := filepath.Join(dir, "stage")
	require.NoError(t, os.MkdirAll(stage, 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(target, "child"), 0o700))
	kept, publishErr = publishStagedDir(stage, target, backup)
	require.Error(t, publishErr)
	require.Contains(t, publishErr.Error(), "previous plugin kept at "+backup)
	require.Equal(t, backup, kept)
	_, statErr := os.Stat(filepath.Join(backup, ManifestFile))
	require.NoError(t, statErr, "the recovery copy must survive a failed publication")

	// Without a backup there is nothing to restore, and the error stays plain.
	kept, publishErr = publishStagedDir(stage, target, "")
	require.Error(t, publishErr)
	require.NotContains(t, publishErr.Error(), "kept at")
	require.Empty(t, kept)
}
