package sshclient

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestApplyCleanupDoesNotDependOnPathRm reproduces the reported leak where a host
// resolves rm through a wrapper earlier in PATH that moves files to the Trash
// instead of unlinking them: every apply left a byte-identical copy of the
// applied payload in the target user's Trash while the privileged report still
// claimed a clean run, because remove_owned() deleted sshx-owned artifacts with
// a bare `rm -f`.
//
// buildApplySudoScript is the only apply script builder in this package. The SFTP
// apply path (applySFTPFile) removes its temporaries over SFTP rather than through
// a remote shell, so it has no PATH-dependent cleanup to cover here.
func TestApplyCleanupDoesNotDependOnPathRm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the privileged remote script requires a POSIX shell")
	}
	requireAbsoluteRemover(t)

	t.Run("published", func(t *testing.T) {
		fixture := newApplyCleanupFixture(t)
		result := fixture.run(t, fixture.env())
		outcome, applyErr := parseApplyScriptReport(result)
		requireApplyOutcome(t, "published", result, outcome, applyErr)
		require.NoError(t, applyErr, "%s", result.Stderr)
		require.True(t, outcome.Verified)
		require.NoFileExists(t, fixture.staging, "the staging payload must be removed")
		fixture.requireNoOwnedTemp(t)
		fixture.requireNoTrashLeak(t)
		require.NotEmpty(t, outcome.BackupPath)
		require.FileExists(t, outcome.BackupPath, "a verified backup must be preserved")
	})

	t.Run("temp candidate", func(t *testing.T) {
		fixture := newApplyCleanupFixture(t)
		fixture.shadow(t, "chmod", "case \"$2\" in *.sshx.*) exit 9;; esac\nexec '"+realCommand(t, "chmod")+"' \"$@\"\n")
		result := fixture.run(t, fixture.env())
		outcome, applyErr := parseApplyScriptReport(result)
		requireApplyOutcome(t, "temp candidate", result, outcome, applyErr)
		require.Error(t, applyErr, "%s", result.Stderr)
		require.NotZero(t, result.ExitCode, "%s", result.Stderr)
		require.NoFileExists(t, fixture.tempCandidate(), "the publication temp candidate must be removed")
		require.NoFileExists(t, fixture.staging, "the staging payload must be removed")
		fixture.requireNoOwnedTemp(t)
		fixture.requireNoTrashLeak(t)
		require.Empty(t, outcome.CleanupPending, "a successful cleanup must not be reported as pending")
		require.NotEmpty(t, outcome.BackupPath)
		require.FileExists(t, outcome.BackupPath, "a verified backup must be preserved")
	})

	t.Run("unverified backup", func(t *testing.T) {
		fixture := newApplyCleanupFixture(t)
		fixture.shadow(t, "chmod", "case \"$2\" in '"+fixture.backupDir+"'/*) exit 9;; esac\nexec '"+realCommand(t, "chmod")+"' \"$@\"\n")
		result := fixture.run(t, fixture.env())
		outcome, applyErr := parseApplyScriptReport(result)
		requireApplyOutcome(t, "unverified backup", result, outcome, applyErr)
		require.Error(t, applyErr, "%s", result.Stderr)
		require.NotZero(t, result.ExitCode, "%s", result.Stderr)
		require.NotEmpty(t, outcome.BackupPath)
		require.NoFileExists(t, outcome.BackupPath, "an unverified backup must be removed")
		entries, listErr := os.ReadDir(fixture.backupDir)
		require.NoError(t, listErr)
		require.Empty(t, entries)
		require.NoFileExists(t, fixture.staging, "the staging payload must be removed")
		fixture.requireNoOwnedTemp(t)
		fixture.requireNoTrashLeak(t)
		require.Empty(t, outcome.CleanupPending, "a successful cleanup must not be reported as pending")
	})

	t.Run("unremovable artifact", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: directory permissions do not prevent removal")
		}
		fixture := newApplyCleanupFixture(t)
		stagingDir := filepath.Dir(fixture.staging)
		require.NoError(t, os.Chmod(stagingDir, 0o500)) // #nosec G302 -- directory fixture, not a secret file.
		t.Cleanup(func() {
			_ = os.Chmod(stagingDir, 0o700) //nolint:errcheck,gosec // restore so t.TempDir cleanup can remove the tree.
		})
		result := fixture.run(t, fixture.env())
		outcome, applyErr := parseApplyScriptReport(result)
		requireApplyOutcome(t, "unremovable artifact", result, outcome, applyErr)
		require.Equal(t, 4, result.ExitCode, "%s", result.Stderr)
		require.ErrorContains(t, applyErr, "artifact cleanup failed")
		require.Equal(t, []string{fixture.staging}, outcome.CleanupPending,
			"an artifact that cannot be removed must be reported instead of hidden")
		require.FileExists(t, fixture.staging, "a failed removal must leave the artifact in place")
		// The payload itself was published and verified; the invocation still fails
		// because an owned artifact leaked.
		published, readErr := os.ReadFile(fixture.target) // #nosec G304 -- path is confined to the owned test fixture.
		require.NoError(t, readErr)
		require.Equal(t, fixture.payload, published)
		require.True(t, outcome.Verified)
		fixture.requireNoTrashLeak(t)
	})
}

// applyCleanupFixture is an apply fixture whose PATH resolves rm to a wrapper that
// moves every argument into a fake Trash directory and never unlinks anything.
type applyCleanupFixture struct {
	dir       string
	binDir    string
	trashDir  string
	staging   string
	target    string
	backupDir string
	before    []byte
	payload   []byte
}

func newApplyCleanupFixture(t *testing.T) *applyCleanupFixture {
	t.Helper()
	fixture := &applyCleanupFixture{
		dir:     t.TempDir(),
		before:  []byte("before\n"),
		payload: []byte("after\n"),
	}
	fixture.binDir = filepath.Join(fixture.dir, "bin")
	fixture.trashDir = filepath.Join(fixture.dir, "trash")
	fixture.staging = filepath.Join(fixture.dir, "staging", "stage.new")
	fixture.target = filepath.Join(fixture.dir, "app.conf")
	fixture.backupDir = filepath.Join(fixture.dir, "backups")
	for _, dir := range []string{fixture.binDir, fixture.trashDir, filepath.Dir(fixture.staging)} {
		require.NoError(t, os.MkdirAll(dir, 0o700))
	}
	require.NoError(t, os.WriteFile(fixture.target, fixture.before, 0o640)) // #nosec G306 -- fixture mirrors a group-readable config file.
	require.NoError(t, os.WriteFile(fixture.staging, fixture.payload, 0o600))
	fixture.shadow(t, "rm", "mkdir -p '"+fixture.trashDir+"'\n"+
		"for argument in \"$@\"; do\n"+
		"  case \"$argument\" in -*) continue ;; esac\n"+
		"  if [ -e \"$argument\" ] || [ -L \"$argument\" ]; then mv \"$argument\" \""+fixture.trashDir+"/${argument##*/}.new\" || exit 1; fi\n"+
		"done\n"+
		"exit 0\n")
	// The fixture only proves anything while the wrapper really is the rm the
	// generated script resolves through PATH.
	require.Equal(t, filepath.Join(fixture.binDir, "rm"), fixture.resolvedRm(t))
	return fixture
}

// shadow installs an executable stand-in for one command ahead of PATH.
func (f *applyCleanupFixture) shadow(t *testing.T, name, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(f.binDir, name), []byte("#!/bin/sh\n"+body), 0o700)) // #nosec G306 -- owned executable fault fixture.
}

// env is the environment the generated script runs with: the shadowing directory
// first, exactly like a host whose PATH prefers a wrapper over /bin/rm.
func (f *applyCleanupFixture) env() []string {
	return append(os.Environ(), "PATH="+f.binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func (f *applyCleanupFixture) resolvedRm(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("sh", "-c", "command -v rm") // #nosec G204 -- fixed command string, no caller input.
	cmd.Env = applyScriptEnv(f.env())
	out, err := cmd.Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

func (f *applyCleanupFixture) run(t *testing.T, env []string) ExecResult {
	t.Helper()
	req := ApplyRequest{RemotePath: f.target, Payload: f.payload, Backup: true, ExpectSHA256: SHA256Hex(f.before)}
	script, err := buildApplySudoScript(req, f.staging, f.backupDir)
	require.NoError(t, err)
	return runApplyScriptFixture(t, script, env)
}

// tempCandidate mirrors the script's same-directory publication temp.
func (f *applyCleanupFixture) tempCandidate() string {
	return filepath.Join(f.dir, "."+filepath.Base(f.target)+".sshx."+filepath.Base(f.staging)+".tmp")
}

func (f *applyCleanupFixture) requireNoOwnedTemp(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(f.dir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.NotContains(t, entry.Name(), ".sshx.", "owned temp must be cleaned")
	}
}

// requireNoTrashLeak is the regression assertion: cleanup must not resolve rm
// through PATH, so the wrapper must never be handed an owned artifact.
func (f *applyCleanupFixture) requireNoTrashLeak(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(f.trashDir)
	require.NoError(t, err)
	leaked := make([]string, 0, len(entries))
	for _, entry := range entries {
		leaked = append(leaked, entry.Name())
	}
	require.Empty(t, leaked, "cleanup resolved rm through PATH and moved owned artifacts to the Trash: %v", leaked)
}

// realCommand resolves a command without the fixture's shadowing directory.
func realCommand(t *testing.T, name string) string {
	t.Helper()
	resolved, err := exec.LookPath(name)
	require.NoError(t, err)
	return resolved
}

// requireAbsoluteRemover skips when this host offers neither the absolute rm
// candidates nor unlink that the generated script relies on: without either, a
// PATH-independent cleanup cannot be exercised at all.
func requireAbsoluteRemover(t *testing.T) {
	t.Helper()
	for _, candidate := range []string{"/bin/rm", "/usr/bin/rm", "/usr/local/bin/rm"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return
		}
	}
	if _, err := exec.LookPath("unlink"); err == nil {
		return
	}
	t.Skip("no absolute rm and no unlink on this host: PATH-independent cleanup cannot be exercised")
}
