// Package skillinstall installs the Agent skill embedded in the sshx binary.
package skillinstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/talkincode/sshx/skills"
)

const (
	defaultSkillsDir = ".agents/skills/sshx"
	skillFileName    = "SKILL.md"
	metadataFileName = ".sshx-managed.json"
	metadataSchema   = "sshx.skill-install.v1"
	maxSkillSize     = 1 << 20
	maxMetadataSize  = 4096
)

var (
	// ErrConflict means an existing skill differs from the bundled version.
	ErrConflict = errors.New("installed skill differs from bundled skill")
	// ErrUnsafeTarget means the destination would cross a symlink or overwrite
	// a non-regular filesystem object.
	ErrUnsafeTarget = errors.New("unsafe skill installation target")
)

// Options controls one local skill installation.
type Options struct {
	Dir   string
	Force bool
}

// Result describes the installed artifact and whether it changed.
type Result struct {
	Status string `json:"status"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Source string `json:"source"`
}

type managedMetadata struct {
	SchemaVersion string `json:"schema_version"`
	SHA256        string `json:"sha256"`
}

// Install writes the canonical embedded Agent skill to the configured target.
// Existing differing content is preserved unless Force is explicit.
func Install(options Options) (Result, error) {
	return installContent(options, skills.SSHX())
}

func installContent(options Options, content []byte) (Result, error) {
	if err := validate(content); err != nil {
		return Result{}, fmt.Errorf("invalid bundled skill: %w", err)
	}

	dir, err := ResolveDir(options.Dir)
	if err != nil {
		return Result{}, err
	}
	if targetErr := ensureTargetDir(dir); targetErr != nil {
		return Result{}, targetErr
	}

	destination := filepath.Join(dir, skillFileName)
	metadataPath := filepath.Join(dir, metadataFileName)
	status, metadataCurrent, err := installationStatus(destination, metadataPath, content, options.Force)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		Status: status,
		Path:   destination,
		SHA256: digest(content),
		Source: "embedded",
	}
	if status == "current" {
		if metadataCurrent {
			return result, nil
		}
	} else if writeErr := writeAtomic(destination, content); writeErr != nil {
		return Result{}, fmt.Errorf("install skill at %s: %w", destination, writeErr)
	}
	metadata := managedMetadata{
		SchemaVersion: metadataSchema,
		SHA256:        result.SHA256,
	}
	encodedMetadata, err := json.Marshal(metadata)
	if err != nil {
		return Result{}, fmt.Errorf("encode skill metadata: %w", err)
	}
	encodedMetadata = append(encodedMetadata, '\n')
	if err := writeAtomic(metadataPath, encodedMetadata); err != nil {
		return Result{}, fmt.Errorf("record managed skill metadata at %s: %w", metadataPath, err)
	}
	return result, nil
}

// ResolveDir resolves the destination directory. An explicit value wins;
// otherwise the target is ~/.agents/skills/sshx.
func ResolveDir(explicit string) (string, error) {
	dir := explicit
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		dir = filepath.Join(home, filepath.FromSlash(defaultSkillsDir))
	} else {
		expanded, err := expandHome(dir)
		if err != nil {
			return "", err
		}
		dir = expanded
	}

	absolute, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", fmt.Errorf("resolve skill directory %q: %w", dir, err)
	}
	if absolute == filepath.VolumeName(absolute)+string(filepath.Separator) {
		return "", fmt.Errorf("%w: filesystem root is not a valid skill directory", ErrUnsafeTarget)
	}
	return absolute, nil
}

func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") && !strings.HasPrefix(path, `~\`) {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

func ensureTargetDir(dir string) error {
	info, err := os.Lstat(dir)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: %s must be a real directory", ErrUnsafeTarget, dir)
		}
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("inspect skill directory %s: %w", dir, err)
	}

	if mkdirErr := os.MkdirAll(dir, 0o755); mkdirErr != nil { // #nosec G301 -- Agent skills are public documentation, not secrets.
		return fmt.Errorf("create skill directory %s: %w", dir, mkdirErr)
	}
	info, err = os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("verify skill directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: %s must be a real directory", ErrUnsafeTarget, dir)
	}
	return nil
}

func installationStatus(destination, metadataPath string, content []byte, force bool) (string, bool, error) {
	metadata, metadataExists, err := readMetadata(metadataPath)
	if err != nil {
		return "", false, err
	}
	info, err := os.Lstat(destination)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "installed", false, nil
	case err != nil:
		return "", false, fmt.Errorf("inspect existing skill %s: %w", destination, err)
	case info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular():
		return "", false, fmt.Errorf("%w: %s must be a regular file", ErrUnsafeTarget, destination)
	}
	if info.Size() > maxSkillSize {
		if !force {
			return "", false, fmt.Errorf("%w at %s; existing file exceeds %d bytes and requires --force", ErrConflict, destination, maxSkillSize)
		}
		return "updated", false, nil
	}

	existing, err := os.ReadFile(destination) // #nosec G304 -- destination is the resolved, managed SKILL.md target.
	if err != nil {
		return "", false, fmt.Errorf("read existing skill %s: %w", destination, err)
	}
	existingDigest := digest(existing)
	desiredDigest := digest(content)
	metadataCurrent := metadataExists && metadata.SchemaVersion == metadataSchema && metadata.SHA256 == desiredDigest
	if bytes.Equal(existing, content) {
		// Windows mode bits do not represent POSIX owner/group permissions.
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
			return "repaired", metadataCurrent, nil
		}
		return "current", metadataCurrent, nil
	}
	if !force {
		managedPreviousVersion := metadataExists && metadata.SchemaVersion == metadataSchema && metadata.SHA256 == existingDigest
		if managedPreviousVersion {
			return "updated", false, nil
		}
		return "", false, fmt.Errorf("%w at %s; review it and rerun with --force to replace it", ErrConflict, destination)
	}
	return "updated", false, nil
}

func readMetadata(path string) (managedMetadata, bool, error) {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return managedMetadata{}, false, nil
	case err != nil:
		return managedMetadata{}, false, fmt.Errorf("inspect skill metadata %s: %w", path, err)
	case info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular():
		return managedMetadata{}, false, fmt.Errorf("%w: %s must be a regular file", ErrUnsafeTarget, path)
	case info.Size() > maxMetadataSize:
		return managedMetadata{}, true, nil
	}

	data, err := os.ReadFile(path) // #nosec G304 -- path is the managed metadata file beside SKILL.md.
	if err != nil {
		return managedMetadata{}, false, fmt.Errorf("read skill metadata %s: %w", path, err)
	}
	var metadata managedMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return managedMetadata{}, true, nil
	}
	return metadata, true, nil
}

func writeAtomic(destination string, content []byte) error {
	dir := filepath.Dir(destination)
	temporaryPrefix := "." + strings.TrimPrefix(filepath.Base(destination), ".") + ".tmp-*"
	temporary, err := os.CreateTemp(dir, temporaryPrefix)
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath) //nolint:errcheck // best-effort cleanup after a failed installation
		}
	}()

	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close() //nolint:errcheck // preserve the original permission error
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close() //nolint:errcheck // preserve the original write error
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close() //nolint:errcheck // preserve the original sync error
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func validate(content []byte) error {
	if len(content) == 0 {
		return fmt.Errorf("content is empty")
	}
	if len(content) > maxSkillSize {
		return fmt.Errorf("content exceeds %d bytes", maxSkillSize)
	}
	if !bytes.HasPrefix(content, []byte("---\n")) {
		return fmt.Errorf("missing YAML frontmatter")
	}
	end := bytes.Index(content[4:], []byte("\n---\n"))
	if end < 0 {
		return fmt.Errorf("unterminated YAML frontmatter")
	}
	frontmatter := string(content[4 : 4+end])
	for _, line := range strings.Split(frontmatter, "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(key) == "name" && strings.TrimSpace(value) == "sshx" {
			return nil
		}
	}
	return fmt.Errorf("frontmatter name must be sshx")
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
