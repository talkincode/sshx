package plugin

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// MaxInstallBytes bounds the total payload copied from an install source.
	MaxInstallBytes = 8 << 20
	// MaxInstallFiles bounds the number of entries copied from an install source.
	MaxInstallFiles = 128
)

// InstallOptions configures `sshx plugin install`.
type InstallOptions struct {
	Source  string // local directory that holds the plugin
	Replace bool   // preserve an existing plugin as a backup (--replace)
	Trust   bool   // trust the installed digest in the same step (--trust)
}

// InstallResult reports the published plugin.
type InstallResult struct {
	Resolved   *Resolved
	Files      []string
	BackupPath string
}

// Install publishes a local plugin directory into the runtime plugin root
// ($SSHX_HOME/plugins/<id>). The source is staged with sshx's own restrictive
// modes, validated through the same loader the executor uses, and only then
// published, so an invalid source can never replace an installed plugin. --trust
// records the published digest in the local trust lock in the same step.
//
// This is the audited alternative to hand-placing files under the plugin root:
// it is one CLI invocation, it refuses symlinks and non-regular files, and it is
// bounded by MaxInstallBytes/MaxInstallFiles.
func Install(options InstallOptions) (*InstallResult, error) {
	source, sourceErr := filepath.Abs(strings.TrimSpace(options.Source))
	if sourceErr != nil {
		return nil, fmt.Errorf("resolve install source: %w", sourceErr)
	}
	// The source itself must be a real directory: a symlinked source would make
	// "install this directory" mean "install whatever it points at".
	if linkInfo, linkErr := os.Lstat(source); linkErr != nil {
		if os.IsNotExist(linkErr) {
			return nil, fmt.Errorf("install source %s does not exist", source)
		}
		return nil, fmt.Errorf("inspect install source: %w", linkErr)
	} else if !linkInfo.IsDir() || linkInfo.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, fmt.Errorf("install source must be a real directory (not a symlink): %s", source)
	}

	// A rooted handle keeps every source read inside the source directory even if
	// the tree changes while it is being copied.
	sourceRoot, rootErr := os.OpenRoot(source)
	if rootErr != nil {
		if os.IsNotExist(rootErr) {
			return nil, fmt.Errorf("install source %s does not exist", source)
		}
		return nil, fmt.Errorf("inspect install source: %w", rootErr)
	}
	defer func() { _ = sourceRoot.Close() }() //nolint:errcheck // read-only handle cleanup
	if info, statErr := sourceRoot.Stat("."); statErr != nil {
		return nil, fmt.Errorf("inspect install source: %w", statErr)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("install source must be a real directory (not a symlink): %s", source)
	}

	// The source is caller-owned staging: its permissions are not a plugin
	// contract, because the staged copy below is written with sshx's own modes
	// and then validated. Only the manifest identity is read from the source.
	manifestInfo, manifestStatErr := sourceRoot.Lstat(ManifestFile)
	if manifestStatErr != nil {
		return nil, fmt.Errorf("read manifest: %w", manifestStatErr)
	}
	if !manifestInfo.Mode().IsRegular() || manifestInfo.Size() > MaxManifest {
		return nil, fmt.Errorf("read manifest: %s is not a regular file under %d bytes", ManifestFile, MaxManifest)
	}
	manifestBytes, readErr := sourceRoot.ReadFile(ManifestFile)
	if readErr != nil {
		return nil, fmt.Errorf("read manifest: %w", readErr)
	}
	var manifest Manifest
	if decodeErr := decodeStrictJSON(manifestBytes, &manifest); decodeErr != nil {
		return nil, fmt.Errorf("parse manifest: %w", decodeErr)
	}
	id := strings.TrimSpace(manifest.ID)
	if idErr := ValidateID(id); idErr != nil {
		return nil, idErr
	}
	if _, builtin := resolveBuiltin(id); builtin {
		return nil, fmt.Errorf("plugin id %q is reserved by a built-in capability", id)
	}

	root, rootErr := Root()
	if rootErr != nil {
		return nil, rootErr
	}
	if rootErr := ensurePrivateRoot(root); rootErr != nil {
		return nil, rootErr
	}

	tempDir, tempErr := os.MkdirTemp(root, ".install-"+id+"-*")
	if tempErr != nil {
		return nil, fmt.Errorf("stage plugin install: %w", tempErr)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tempDir) //nolint:errcheck // best-effort cleanup inside the constrained plugin root
		}
	}()
	// os.MkdirTemp already created the staging directory owner-only (0700).

	files, copyErr := copyPluginTree(sourceRoot, tempDir, manifest)
	if copyErr != nil {
		return nil, copyErr
	}
	if _, validateErr := loadFromPath(tempDir, id); validateErr != nil {
		return nil, fmt.Errorf("validate source plugin: %w", validateErr)
	}

	target := filepath.Join(root, id)
	var backupPath string
	if _, lstatErr := os.Lstat(target); lstatErr == nil {
		if !options.Replace {
			return nil, fmt.Errorf("plugin %q already exists; use --replace to preserve it as a backup", id)
		}
		var backupErr error
		backupPath, backupErr = backupExisting(target, id)
		if backupErr != nil {
			return nil, backupErr
		}
	} else if !os.IsNotExist(lstatErr) {
		return nil, fmt.Errorf("inspect existing plugin: %w", lstatErr)
	}
	published, renameErr := publishStagedDir(tempDir, target, backupPath)
	if renameErr != nil {
		return nil, renameErr
	}
	backupPath = published
	cleanup = false

	resolved, resolveErr := Resolve(id)
	if resolveErr != nil {
		return nil, fmt.Errorf("validate installed plugin: %w", resolveErr)
	}
	if options.Trust {
		resolved, resolveErr = trustResolved(resolved)
		if resolveErr != nil {
			return nil, resolveErr
		}
	}
	return &InstallResult{Resolved: resolved, Files: files, BackupPath: backupPath}, nil
}

// copyPluginTree stages one source plugin under the plugin root with sshx's own
// modes: directories 0700, files 0600, and the declared entrypoint 0700. Symlinks
// and non-regular files are refused so a source cannot pull content from outside
// the plugin directory, and both handles are rooted, so the copy stays inside the
// source and the staging directory even if the trees change mid-walk.
func copyPluginTree(sourceRoot *os.Root, tempDir string, manifest Manifest) ([]string, error) {
	stageRoot, rootErr := os.OpenRoot(tempDir)
	if rootErr != nil {
		return nil, fmt.Errorf("stage plugin install: %w", rootErr)
	}
	defer func() { _ = stageRoot.Close() }() //nolint:errcheck // staging handle cleanup

	entrypoint := filepath.ToSlash(filepath.Clean(manifest.Runner.Entrypoint))
	files := make([]string, 0, 8)
	var total int64
	walkErr := fs.WalkDir(sourceRoot.FS(), ".", func(relative string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			return fmt.Errorf("install source contains a symlink (%s); plugins hold plain files only", relative)
		case entry.IsDir():
			return stageRoot.Mkdir(relative, 0o700)
		case !entry.Type().IsRegular():
			return fmt.Errorf("install source contains a non-regular entry (%s)", relative)
		}
		if len(files) >= MaxInstallFiles {
			return fmt.Errorf("install source holds more than %d files", MaxInstallFiles)
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("read %s: %w", relative, infoErr)
		}
		if info.Size() > MaxInstallBytes {
			return fmt.Errorf("read %s: file exceeds %d-byte limit", relative, MaxInstallBytes)
		}
		data, readErr := sourceRoot.ReadFile(relative)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", relative, readErr)
		}
		total += int64(len(data))
		if total > MaxInstallBytes {
			return fmt.Errorf("install source exceeds %d bytes", MaxInstallBytes)
		}
		mode := os.FileMode(0o600)
		if relative == entrypoint {
			mode = 0o700
		}
		if writeErr := stageRoot.WriteFile(relative, data, mode); writeErr != nil {
			return fmt.Errorf("stage %s: %w", relative, writeErr)
		}
		files = append(files, relative)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Strings(files)
	return files, nil
}
