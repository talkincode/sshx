package e2e

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type skillInstallResult struct {
	Success   bool   `json:"success"`
	Action    string `json:"action"`
	Status    string `json:"status"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Source    string `json:"source"`
	ErrorKind string `json:"error_kind"`
	Error     string `json:"error"`
}

func TestCLISkillInstallIsStandaloneIdempotentAndConflictSafe(t *testing.T) {
	home := t.TempDir()
	targetDir := filepath.Join(home, ".agents", "skills", "sshx")

	installed := runSSHX(t, home, []string{"skill", "install", "--json"}, nil)
	require.Equal(t, 0, installed.exitCode, installed.stderr)
	var installedPayload skillInstallResult
	require.NoError(t, json.Unmarshal([]byte(installed.stdout), &installedPayload))
	assert.True(t, installedPayload.Success)
	assert.Equal(t, "install", installedPayload.Action)
	assert.Equal(t, "installed", installedPayload.Status)
	assert.Equal(t, "embedded", installedPayload.Source)
	assert.NotEmpty(t, installedPayload.SHA256)
	assert.Equal(t, filepath.Join(targetDir, "SKILL.md"), installedPayload.Path)

	want, err := os.ReadFile(filepath.Join(repositoryRoot(), "skills", "sshx", "SKILL.md"))
	require.NoError(t, err)
	got, err := os.ReadFile(installedPayload.Path)
	require.NoError(t, err)
	assert.Equal(t, want, got, "compiled binary must install the canonical repository skill")
	metadataInfo, err := os.Stat(filepath.Join(targetDir, ".sshx-managed.json"))
	require.NoError(t, err)
	t.Run("POSIX metadata mode", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows synthetic mode bits are not POSIX permission evidence")
		}
		assert.Equal(t, os.FileMode(0o644), metadataInfo.Mode().Perm())
	})

	current := runSSHX(t, home, []string{"skill", "install", "--json"}, nil)
	require.Equal(t, 0, current.exitCode, current.stderr)
	var currentPayload skillInstallResult
	require.NoError(t, json.Unmarshal([]byte(current.stdout), &currentPayload))
	assert.Equal(t, "current", currentPayload.Status)

	custom := []byte("custom local skill\n")
	require.NoError(t, os.WriteFile(installedPayload.Path, custom, 0o600))
	conflict := runSSHX(t, home, []string{"skill", "install", "--json"}, map[string]string{"SSH_FORCE": "true"})
	require.Equal(t, 255, conflict.exitCode, conflict.stderr)
	var conflictPayload skillInstallResult
	require.NoError(t, json.Unmarshal([]byte(conflict.stdout), &conflictPayload))
	assert.False(t, conflictPayload.Success)
	assert.Equal(t, "conflict", conflictPayload.ErrorKind)
	preserved, err := os.ReadFile(installedPayload.Path)
	require.NoError(t, err)
	assert.Equal(t, custom, preserved, "a conflicting skill must remain untouched without --force")

	updated := runSSHX(t, home, []string{
		"skill", "install", "--dir=" + targetDir, "--force", "--json",
	}, nil)
	require.Equal(t, 0, updated.exitCode, updated.stderr)
	var updatedPayload skillInstallResult
	require.NoError(t, json.Unmarshal([]byte(updated.stdout), &updatedPayload))
	assert.Equal(t, "updated", updatedPayload.Status)
	restored, err := os.ReadFile(installedPayload.Path)
	require.NoError(t, err)
	assert.Equal(t, want, restored)
}

func TestCLISkillInstallRejectsSymlinkedDirectoryWithoutEscaping(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	require.NoError(t, os.Mkdir(outside, 0o750))
	linked := filepath.Join(root, "linked")
	symlinkErr := os.Symlink(outside, linked)
	if runtime.GOOS == "windows" && (errors.Is(symlinkErr, os.ErrPermission) || errors.Is(symlinkErr, syscall.Errno(1314))) {
		t.Skipf("Windows symlink privilege unavailable: %v", symlinkErr)
	}
	require.NoError(t, symlinkErr)

	result := runSSHX(t, home, []string{
		"skill", "install", "--dir=" + linked, "--force", "--json",
	}, nil)
	require.Equal(t, 255, result.exitCode, result.stderr)
	var payload skillInstallResult
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload))
	assert.Equal(t, "unsafe_target", payload.ErrorKind)
	_, err := os.Stat(filepath.Join(outside, "SKILL.md"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}
