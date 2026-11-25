package sshclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
)

// FileOutcome describes one observed effect; digests are content evidence,
// whereas Size alone is never treated as content verification.
type FileOutcome struct {
	SourcePath         string  `json:"source_path,omitempty"`
	Path               string  `json:"path"`
	Type               string  `json:"type"`
	Size               int64   `json:"size"`
	Mode               string  `json:"mode,omitempty"`
	UID                *uint32 `json:"uid,omitempty"`
	GID                *uint32 `json:"gid,omitempty"`
	BytesTransferred   int64   `json:"bytes_transferred"`
	SHA256             string  `json:"sha256,omitempty"`
	SourceSHA256       string  `json:"source_sha256,omitempty"`
	Started            bool    `json:"started"`
	Published          bool    `json:"published"`
	Publication        string  `json:"publication,omitempty"`
	ChangeState        string  `json:"change_state"`
	Verified           bool    `json:"verified"`
	Verification       string  `json:"verification"`
	VerificationMethod string  `json:"verification_method,omitempty"`
	ModifiedAt         string  `json:"modified_at,omitempty"`
	BackupPath         string  `json:"backup_path,omitempty"`
	BackupPreserved    bool    `json:"backup_preserved,omitempty"`
	StagingPath        string  `json:"staging_path,omitempty"`
	CleanupError       string  `json:"cleanup_error,omitempty"`
	phase              string
	displayMode        string
}

// SFTPOutcome retains completed entries and partial-file evidence on failure.
// DirectoryAtomic is always false: a tree is a sequence of per-file operations.
type SFTPOutcome struct {
	Action          string `json:"action"`
	SourcePath      string `json:"source_path,omitempty"`
	DestinationPath string `json:"destination_path,omitempty"`
	Started         bool   `json:"started"`
	Phase           string `json:"phase"`
	Completion      string `json:"completion"`
	// Executed describes acknowledged destination effects (or listing reads),
	// not preparatory staging writes. Nil means an effect is unconfirmed.
	Executed           *bool         `json:"executed"`
	ChangeState        string        `json:"change_state"`
	Verified           bool          `json:"verified"`
	Verification       string        `json:"verification"`
	VerificationMethod string        `json:"verification_method"`
	BytesTransferred   int64         `json:"bytes_transferred"`
	Partial            bool          `json:"partial"`
	DirectoryAtomic    bool          `json:"directory_atomic"`
	Entries            []FileOutcome `json:"entries"`
	operationComplete  bool
	directory          bool
	readAttempted      bool
}

func finishSFTPOutcome(out *SFTPOutcome, err error) {
	out.ChangeState = "unchanged"
	out.Verified = out.operationComplete
	out.VerificationMethod = "content_and_metadata"
	switch out.Action {
	case "list", "ls":
		out.VerificationMethod = "metadata"
	case "mkdir":
		out.VerificationMethod = "exists_and_directory"
	case "remove", "rm":
		out.VerificationMethod = "absent"
	}
	acknowledged := (out.Action == "list" || out.Action == "ls") && out.Started
	uncertain, targetAcknowledged, verificationFailed := false, false, false
	if out.readAttempted && !out.Started {
		uncertain = true
	}
	out.BytesTransferred = 0
	for _, entry := range out.Entries {
		out.Started = out.Started || entry.Started
		out.BytesTransferred += entry.BytesTransferred
		if entry.ChangeState == "changed" {
			out.ChangeState = "changed"
			acknowledged = true
			if entry.Path == out.DestinationPath && (!entry.BackupPreserved || entry.Published) &&
				(!out.directory || out.Action == "mkdir" || out.Action == "remove" || out.Action == "rm") {
				targetAcknowledged = true
			}
		}
		if entry.ChangeState == "unknown" {
			uncertain = true
			if out.ChangeState != "changed" {
				out.ChangeState = "unknown"
			}
		}
		out.Verified = out.Verified && entry.Verified
		verificationFailed = verificationFailed || entry.Verification == "failed"
		if err != nil && !entry.Verified && entry.phase != "" {
			out.Phase = entry.phase
		}
	}
	out.Executed = &acknowledged
	if !acknowledged && uncertain {
		out.Executed = nil
	}
	switch {
	case out.Verified:
		out.Verification = "passed"
	case verificationFailed:
		out.Verification = "failed"
	case out.Started || uncertain:
		out.Verification = "unknown"
	default:
		out.Verification = "not_performed"
	}
	switch {
	case err == nil:
		out.Phase, out.Completion = "complete", "completed"
	case out.operationComplete || targetAcknowledged:
		out.Completion = "completed"
		if out.operationComplete {
			out.Phase = "collect"
		}
	case uncertain && !acknowledged:
		out.Completion = "unknown"
	case out.Started || acknowledged:
		out.Completion = "partial"
	default:
		out.Completion = "not_started"
	}
	out.Partial = err != nil && out.Started && !out.operationComplete
}

// ExecuteSftp is the human-output compatibility adapter.
func (c *SSHClient) ExecuteSftp() error {
	out, err := c.ExecuteSftpResult()
	if err != nil {
		return err
	}
	return RenderSFTPOutcome(out)
}

// RenderSFTPOutcome renders captured evidence without opening any transport.
func RenderSFTPOutcome(out *SFTPOutcome) error {
	return renderSFTPOutcome(os.Stdout, out)
}

func renderSFTPOutcome(w io.Writer, out *SFTPOutcome) error {
	if out == nil {
		return boundaryError("config", "render SFTP outcome", fmt.Errorf("missing outcome"))
	}
	if out.Action != "list" && out.Action != "ls" {
		if _, err := fmt.Fprintf(w, "SFTP %s: %s (%d bytes)\n", out.Action, out.Completion, out.BytesTransferred); err != nil {
			return boundaryError("local_io", "render SFTP outcome", err)
		}
		for _, entry := range out.Entries {
			if entry.BackupPreserved {
				if _, err := fmt.Fprintf(w, "Previous file preserved at %s\n", entry.BackupPath); err != nil {
					return boundaryError("local_io", "render SFTP outcome", err)
				}
			}
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "Directory listing: %s\n", out.DestinationPath); err != nil {
		return boundaryError("local_io", "render SFTP outcome", err)
	}
	if _, err := fmt.Fprintln(w, "\nPermissions  Size      Modified              Name\n-------------------------------------------------------"); err != nil {
		return boundaryError("local_io", "render SFTP outcome", err)
	}
	for _, file := range out.Entries {
		mode, modified := file.displayMode, file.ModifiedAt
		if mode == "" {
			mode = file.Mode
		}
		if timestamp, parseErr := time.Parse(time.RFC3339Nano, modified); parseErr == nil {
			modified = timestamp.Format("2006-01-02 15:04:05")
		}
		if _, err := fmt.Fprintf(w, "%-12s %10d  %-20s  %s\n", mode, file.Size, modified, path.Base(file.Path)); err != nil {
			return boundaryError("local_io", "render SFTP outcome", err)
		}
	}
	_, err := fmt.Fprintf(w, "\nTotal: %d items\n", len(out.Entries))
	return boundaryError("local_io", "render SFTP outcome", err)
}

// ExecuteSftpResult returns evidence without writing human output.
func (c *SSHClient) ExecuteSftpResult() (*SFTPOutcome, error) {
	return c.executeSftpResult(c.config)
}

// CopyFile reuses the same publication and recovery contract for domain adapters.
// It never mutates the connection's Config or creates a second transport.
func (c *SSHClient) CopyFile(action, localPath, remotePath string) (*SFTPOutcome, error) {
	config := *c.config
	config.SftpAction, config.LocalPath, config.RemotePath = action, localPath, remotePath
	config.PreparedPayload = nil
	return c.executeSftpResult(&config)
}

func (c *SSHClient) executeSftpResult(config *Config) (out *SFTPOutcome, err error) {
	out = &SFTPOutcome{Action: config.SftpAction, SourcePath: config.LocalPath, DestinationPath: config.RemotePath, Phase: "connect"}
	if out.Action == "download" {
		out.SourcePath, out.DestinationPath = config.RemotePath, config.LocalPath
	}
	defer func() {
		if err != nil {
			err = c.transportError("remote_io", "SFTP "+out.Action, err)
		}
		finishSFTPOutcome(out, err)
	}()
	switch out.Action {
	case "upload", "download", "list", "ls", "mkdir", "remove", "rm":
	default:
		out.Phase = "admission"
		return out, boundaryError("config", "SFTP action", fmt.Errorf("unknown SFTP action: %s", out.Action))
	}
	client, err := c.newSFTPClient()
	if err != nil {
		return out, err
	}
	defer closeSFTP(client, &err)
	ctx := c.transportContext()
	out.Phase = "execute"
	switch config.SftpAction {
	case "upload":
		entry := FileOutcome{SourcePath: config.LocalPath, Path: config.RemotePath, Type: "file", ChangeState: "unchanged", Verification: "not_performed"}
		defer func() { out.Entries = append(out.Entries, entry) }()
		var source io.Reader
		size := int64(len(config.PreparedPayload))
		if config.PreparedPayload != nil {
			source = bytes.NewReader(bytes.Clone(config.PreparedPayload))
		} else {
			file, openErr := os.Open(config.LocalPath) // #nosec G304 -- explicit local source
			if openErr != nil {
				return out, boundaryError("local_io", "open source", openErr)
			}
			defer closeLocal(file, &err)
			info, statErr := file.Stat()
			if statErr != nil {
				return out, boundaryError("local_io", "stat source", statErr)
			}
			if !info.Mode().IsRegular() {
				return out, boundaryError("local_io", "read source", fmt.Errorf("source is not a regular file"))
			}
			source, size = file, info.Size()
		}
		err = publishRemoteFileWithOptions(ctx, client, source, "local_io", size, nil, &entry,
			remotePublishOptions{allowNonAtomic: config.AllowNonAtomic, progress: config.TransferProgress})
	case "download":
		entry := FileOutcome{SourcePath: config.RemotePath, Path: config.LocalPath, Type: "file", ChangeState: "unchanged", Verification: "not_performed"}
		defer func() { out.Entries = append(out.Entries, entry) }()
		err = downloadStaged(ctx, client, &entry)
	case "list", "ls":
		remotePath := config.RemotePath
		if remotePath == "" {
			remotePath = "."
		}
		out.SourcePath, out.DestinationPath, out.readAttempted = remotePath, remotePath, true
		files, listErr := client.ReadDir(remotePath)
		for _, file := range files {
			out.Entries = append(out.Entries, metadataOutcome(remotePathJoin(remotePath, file.Name()), file))
		}
		out.Started = listErr == nil || len(files) > 0
		if listErr != nil {
			return out, listErr
		}
	case "mkdir":
		entry := FileOutcome{Path: config.RemotePath, Type: "directory", ChangeState: "unchanged", Verification: "not_performed"}
		defer func() { out.Entries = append(out.Entries, entry) }()
		err = ensureRemoteDirectory(ctx, client, &entry)
	case "remove", "rm":
		err = removeRemoteTree(ctx, client, config.RemotePath, out)
	}
	out.operationComplete = err == nil
	return out, err
}

func closeSFTP(client *sftp.Client, err *error) {
	if closeErr := client.Close(); closeErr != nil && *err == nil && !errors.Is(closeErr, io.EOF) {
		*err = boundaryError("remote_io", "close SFTP session", closeErr)
	}
}

func closeLocal(file *os.File, err *error) {
	if closeErr := file.Close(); closeErr != nil && *err == nil {
		*err = boundaryError("local_io", "close local file", closeErr)
	}
}

func metadataOutcome(name string, info os.FileInfo) FileOutcome {
	kind := "other"
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		kind = "symlink"
	case info.IsDir():
		kind = "directory"
	case info.Mode().IsRegular():
		kind = "file"
	}
	out := FileOutcome{
		Path: name, Type: kind, Size: info.Size(), Mode: fmt.Sprintf("%04o", info.Mode().Perm()),
		Started: true, ChangeState: "unchanged", Verified: true, Verification: "passed", VerificationMethod: "metadata",
		ModifiedAt: info.ModTime().Format(time.RFC3339Nano), displayMode: info.Mode().String(), phase: "collect",
	}
	setFileOwner(&out, info)
	return out
}

func fileOwner(info os.FileInfo) (uint32, uint32, bool) {
	stat, ok := info.Sys().(*sftp.FileStat)
	if !ok || stat == nil {
		return 0, 0, false
	}
	return stat.UID, stat.GID, true
}

func setFileOwner(entry *FileOutcome, info os.FileInfo) {
	uid, gid, ok := fileOwner(info)
	if !ok {
		entry.UID, entry.GID = nil, nil
		return
	}
	entry.UID, entry.GID = &uid, &gid
}

func stagingName(destination string) (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return "." + path.Base(destination) + ".sshx-copy-" + hex.EncodeToString(token[:]), nil
}

func publishRemoteFile(ctx context.Context, client *sftp.Client, source io.Reader, sourceKind string, expectedSize int64, requestedMode *os.FileMode, entry *FileOutcome) error {
	return publishRemoteFileWithOptions(ctx, client, source, sourceKind, expectedSize, requestedMode, entry, remotePublishOptions{})
}

type remotePublishOptions struct {
	allowNonAtomic bool
	progress       func(phase string, bytes, total int64)
}

func publishRemoteFileWithOptions(ctx context.Context, client *sftp.Client, source io.Reader, sourceKind string, expectedSize int64, requestedMode *os.FileMode, entry *FileOutcome, options remotePublishOptions) (err error) {
	entry.phase, entry.VerificationMethod = "execute", "sha256_and_metadata"
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if expectedSize < 0 || expectedSize == 1<<63-1 {
		return boundaryError(sourceKind, "copy source", fmt.Errorf("invalid source size"))
	}
	var mode os.FileMode
	var uid, gid uint32
	var haveOwner bool
	info, statErr := client.Lstat(entry.Path)
	exists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	if exists {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("destination is not a regular file: %s", entry.Path)
		}
		mode = info.Mode().Perm()
		uid, gid, haveOwner = fileOwner(info)
		if !haveOwner {
			return boundaryError("remote_io", "inspect destination ownership", fmt.Errorf("destination owner is unavailable; existing file preserved"))
		}
		entry.Size, entry.Mode = info.Size(), fmt.Sprintf("%04o", mode)
		setFileOwner(entry, info)
	}
	if requestedMode != nil {
		mode = requestedMode.Perm()
	}
	_, atomicReplace := client.HasExtension("posix-rename@openssh.com")
	nonAtomic := exists && !atomicReplace
	if nonAtomic && !options.allowNonAtomic {
		return boundaryError("remote_io", "publish file", fmt.Errorf("server lacks atomic replacement; existing destination preserved (use --allow-non-atomic for a replacement that keeps a backup)"))
	}
	name, err := stagingName(entry.Path)
	if err != nil {
		return err
	}
	stage := remotePathJoin(path.Dir(entry.Path), name)
	file, err := client.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	entry.Started, entry.StagingPath = true, stage
	closed, published := false, false
	defer func() {
		if !closed {
			_ = file.Close() //nolint:errcheck // primary failure retained
		}
		if !published {
			if cleanupErr := client.Remove(stage); cleanupErr != nil && !os.IsNotExist(cleanupErr) {
				entry.CleanupError = "staging cleanup not confirmed"
			} else {
				entry.StagingPath = ""
			}
		}
	}()
	initial, initialErr := file.Stat()
	if initialErr != nil {
		return boundaryError("remote_io", "inspect staging metadata", initialErr)
	}
	if !initial.Mode().IsRegular() {
		return boundaryError("remote_io", "inspect staging metadata", fmt.Errorf("staging path is not a regular file"))
	}
	if !exists && requestedMode == nil {
		// The server applies its umask/default creation policy to OpenFile.
		// Capture that policy before making the staging file private.
		mode = initial.Mode().Perm()
	}
	stageUID, stageGID, stageHasOwner := fileOwner(initial)
	if exists && !stageHasOwner {
		return boundaryError("remote_io", "inspect staging ownership", fmt.Errorf("staging owner is unavailable; existing file preserved"))
	}
	if !exists {
		uid, gid, haveOwner = stageUID, stageGID, stageHasOwner
	}
	if chmodErr := file.Chmod(0o600); chmodErr != nil {
		return chmodErr
	}
	digest := sha256.New()
	var target io.Writer = file
	if options.progress != nil {
		options.progress("upload", 0, expectedSize)
		target = &copyProgressWriter{writer: file, phase: "upload", total: expectedSize, progress: options.progress}
	}
	entry.BytesTransferred, err = copyBoundary(ctx, target, io.TeeReader(io.LimitReader(source, expectedSize+1), digest), sourceKind, "remote_io")
	entry.SourceSHA256 = hex.EncodeToString(digest.Sum(nil))
	if err != nil {
		return err
	}
	if entry.BytesTransferred != expectedSize {
		return boundaryError(sourceKind, "copy source", fmt.Errorf("source size changed during copy"))
	}
	if haveOwner && (stageUID != uid || stageGID != gid) {
		if chownErr := file.Chown(int(uid), int(gid)); chownErr != nil {
			return boundaryError("remote_io", "preserve destination ownership", chownErr)
		}
	}
	// Ownership changes can clear mode bits; restore permissions afterward.
	if chmodErr := file.Chmod(mode); chmodErr != nil {
		return chmodErr
	}
	staged, stagedErr := file.Stat()
	if stagedErr != nil {
		return boundaryError("remote_io", "verify staging metadata", stagedErr)
	}
	if !staged.Mode().IsRegular() || staged.Size() != entry.BytesTransferred || staged.Mode().Perm() != mode {
		return boundaryError("remote_io", "verify staging metadata", fmt.Errorf("staging metadata mismatch; destination not replaced"))
	}
	if haveOwner {
		actualUID, actualGID, ownerKnown := fileOwner(staged)
		if !ownerKnown || actualUID != uid || actualGID != gid {
			return boundaryError("remote_io", "preserve destination ownership", fmt.Errorf("staging ownership mismatch; destination not replaced"))
		}
	}
	err = file.Close()
	closed = true
	if err != nil {
		return err
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if nonAtomic {
		if preserveErr := preserveBeforeReplacement(ctx, client, stage, info, entry, options.progress); preserveErr != nil {
			return preserveErr
		}
	}
	if options.progress != nil {
		options.progress("publish", expectedSize, expectedSize)
	}
	if entry.ChangeState != "changed" {
		entry.ChangeState = "unknown"
	}
	if atomicReplace {
		entry.Publication = "posix_rename"
		err = client.PosixRename(stage, entry.Path)
	} else {
		if !nonAtomic {
			entry.Publication = "sftp_rename_no_replace"
		}
		err = client.Rename(stage, entry.Path)
	}
	if err != nil {
		if entry.BackupPreserved {
			return fmt.Errorf("publish replacement (previous file preserved at %s): %w", entry.BackupPath, err)
		}
		return err
	}
	published, entry.Published, entry.ChangeState, entry.StagingPath = true, true, "changed", ""
	entry.phase, entry.Verification = "collect", "unknown"
	info, err = client.Lstat(entry.Path)
	if err != nil {
		return boundaryError("verification_failed", "verify destination metadata", err)
	}
	entry.Size, entry.Mode = info.Size(), fmt.Sprintf("%04o", info.Mode().Perm())
	setFileOwner(entry, info)
	if !info.Mode().IsRegular() || info.Size() != entry.BytesTransferred || info.Mode().Perm() != mode {
		entry.Verification = "failed"
		return boundaryError("verification_failed", "verify destination metadata", fmt.Errorf("destination metadata mismatch"))
	}
	if haveOwner && (entry.UID == nil || entry.GID == nil || *entry.UID != uid || *entry.GID != gid) {
		entry.Verification = "failed"
		return boundaryError("verification_failed", "verify destination ownership", fmt.Errorf("destination ownership mismatch"))
	}
	entry.SHA256, err = verifyRemoteDigest(ctx, client, entry.Path, entry.BytesTransferred, entry.SourceSHA256, "verify", options.progress)
	if err != nil {
		if errors.Is(err, errSFTPDigestMismatch) {
			entry.Verification = "failed"
		}
		return boundaryError("verification_failed", "verify destination contents", err)
	}
	entry.Verified, entry.Verification = true, "passed"
	return nil
}

// Preserve the original under a sibling name before the non-atomic publish.
// An uncertain move is never replayed or automatically rolled back.
func preserveBeforeReplacement(ctx context.Context, client *sftp.Client, stage string, original os.FileInfo, entry *FileOutcome, progress func(string, int64, int64)) error {
	if _, err := verifyRemoteDigest(ctx, client, stage, entry.BytesTransferred, entry.SourceSHA256, "verify staging", progress); err != nil {
		return boundaryError("verification_failed", "verify staging before replacement", err)
	}
	current, err := client.Lstat(entry.Path)
	if err != nil {
		return boundaryError("remote_io", "recheck destination before replacement", err)
	}
	currentUID, currentGID, ownerKnown := fileOwner(current)
	originalUID, originalGID, _ := fileOwner(original)
	if current.Mode() != original.Mode() || current.Size() != original.Size() ||
		!current.ModTime().Equal(original.ModTime()) || !ownerKnown || currentUID != originalUID || currentGID != originalGID {
		return boundaryError("remote_io", "recheck destination before replacement", fmt.Errorf("destination changed during upload"))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entry.BackupPath = stage + ".previous"
	entry.Publication, entry.ChangeState = "sftp_rename_with_backup", "unknown"
	if err := client.Rename(entry.Path, entry.BackupPath); err != nil {
		return boundaryError("remote_io", "move destination to backup", err)
	}
	entry.BackupPreserved, entry.ChangeState = true, "changed"
	return ctx.Err()
}

var errSFTPDigestMismatch = errors.New("content digest mismatch")

func verifyRemoteDigest(ctx context.Context, client *sftp.Client, name string, size int64, expected, phase string, progress func(string, int64, int64)) (string, error) {
	file, err := client.Open(name)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	var target io.Writer = digest
	if progress != nil {
		progress(phase, 0, size)
		target = &copyProgressWriter{writer: digest, phase: phase, total: size, progress: progress}
	}
	n, readErr := copyBoundary(ctx, target, io.LimitReader(file, size+1), "remote_io", "remote_io")
	closeErr := file.Close()
	actual := hex.EncodeToString(digest.Sum(nil))
	if readErr != nil || closeErr != nil {
		return actual, errors.Join(readErr, closeErr)
	}
	if n != size || actual != expected {
		return actual, errSFTPDigestMismatch
	}
	return actual, nil
}

type copyProgressWriter struct {
	writer   io.Writer
	phase    string
	progress func(string, int64, int64)
	done     int64
	total    int64
}

func (w *copyProgressWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.done += int64(n)
	w.progress(w.phase, w.done, w.total)
	return n, err
}

func downloadStaged(ctx context.Context, client *sftp.Client, entry *FileOutcome) (err error) {
	entry.phase, entry.VerificationMethod = "execute", "sha256_and_metadata"
	remote, err := client.Open(entry.SourcePath)
	if err != nil {
		return err
	}
	defer func() { _ = remote.Close() }() //nolint:errcheck // read-only handle
	info, err := remote.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file")
	}
	if info.Size() < 0 || info.Size() == 1<<63-1 {
		return fmt.Errorf("invalid source size")
	}
	mode := os.FileMode(0o600)
	if existing, statErr := os.Lstat(entry.Path); statErr == nil {
		if !existing.Mode().IsRegular() {
			return boundaryError("local_io", "inspect destination", fmt.Errorf("destination is not a regular file"))
		}
		mode = existing.Mode().Perm()
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return boundaryError("local_io", "inspect destination", statErr)
	}
	local, err := os.CreateTemp(filepath.Dir(entry.Path), "."+filepath.Base(entry.Path)+".sshx-copy-*")
	if err != nil {
		return boundaryError("local_io", "stage destination", err)
	}
	stage := local.Name()
	entry.Started, entry.StagingPath = true, stage
	closed, published := false, false
	defer func() {
		if !closed {
			_ = local.Close() //nolint:errcheck // primary error retained
		}
		if !published {
			if cleanupErr := os.Remove(stage); cleanupErr != nil && !os.IsNotExist(cleanupErr) {
				entry.CleanupError = "staging cleanup not confirmed"
			} else {
				entry.StagingPath = ""
			}
		}
	}()
	digest := sha256.New()
	entry.BytesTransferred, err = copyBoundary(ctx, local, io.TeeReader(io.LimitReader(remote, info.Size()+1), digest), "remote_io", "local_io")
	entry.SourceSHA256 = hex.EncodeToString(digest.Sum(nil))
	if err != nil {
		return err
	}
	if entry.BytesTransferred != info.Size() {
		return boundaryError("remote_io", "copy source", fmt.Errorf("source size changed during copy"))
	}
	entry.phase, entry.Verification = "collect", "unknown"
	if _, seekErr := local.Seek(0, io.SeekStart); seekErr != nil {
		return boundaryError("local_io", "verify local file", seekErr)
	}
	actual := sha256.New()
	if _, copyErr := copyBoundary(ctx, actual, local, "local_io", "local_io"); copyErr != nil {
		return copyErr
	}
	entry.SHA256 = hex.EncodeToString(actual.Sum(nil))
	if entry.SHA256 != entry.SourceSHA256 {
		entry.Verification = "failed"
		return boundaryError("verification_failed", "verify local file", fmt.Errorf("destination digest mismatch"))
	}
	entry.phase = "execute"
	if chmodErr := local.Chmod(mode); chmodErr != nil {
		return boundaryError("local_io", "preserve destination permissions", chmodErr)
	}
	if syncErr := local.Sync(); syncErr != nil {
		return boundaryError("local_io", "sync destination", syncErr)
	}
	err = local.Close()
	closed = true
	if err != nil {
		return boundaryError("local_io", "close destination", err)
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	entry.Publication = "local_rename"
	if renameErr := os.Rename(stage, entry.Path); renameErr != nil {
		return boundaryError("local_io", "publish destination", renameErr)
	}
	published, entry.Published, entry.ChangeState, entry.StagingPath = true, true, "changed", ""
	entry.phase = "collect"
	after, err := os.Lstat(entry.Path)
	if err != nil {
		return boundaryError("verification_failed", "verify local metadata", err)
	}
	entry.Size, entry.Mode = after.Size(), fmt.Sprintf("%04o", after.Mode().Perm())
	if !after.Mode().IsRegular() || after.Size() != entry.BytesTransferred {
		entry.Verification = "failed"
		return boundaryError("verification_failed", "verify local metadata", fmt.Errorf("destination metadata mismatch"))
	}
	entry.Verified, entry.Verification = true, "passed"
	return nil
}

func ensureRemoteDirectory(ctx context.Context, client *sftp.Client, entry *FileOutcome) error {
	entry.phase, entry.VerificationMethod = "execute", "exists_and_directory"
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := client.Lstat(entry.Path)
	if err == nil && before.IsDir() {
		source := entry.SourcePath
		*entry = metadataOutcome(entry.Path, before)
		entry.SourcePath, entry.VerificationMethod = source, "exists_and_directory"
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		return fmt.Errorf("destination is not a directory")
	}
	entry.Started, entry.ChangeState = true, "unknown"
	if mkdirErr := client.MkdirAll(entry.Path); mkdirErr != nil {
		return mkdirErr
	}
	entry.ChangeState = "changed"
	entry.Published, entry.phase, entry.Verification = true, "collect", "unknown"
	info, err := client.Lstat(entry.Path)
	if err != nil {
		return boundaryError("verification_failed", "verify directory", err)
	}
	if !info.IsDir() {
		entry.Verification = "failed"
		return boundaryError("verification_failed", "verify directory", fmt.Errorf("path is not a directory"))
	}
	entry.Mode, entry.Size = fmt.Sprintf("%04o", info.Mode().Perm()), info.Size()
	entry.Verified, entry.Verification = true, "passed"
	return nil
}

func removeRemoteTree(ctx context.Context, client *sftp.Client, name string, out *SFTPOutcome) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := client.Lstat(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		files, readErr := client.ReadDir(name)
		if readErr != nil {
			return readErr
		}
		for _, file := range files {
			if removeErr := removeRemoteTree(ctx, client, remotePathJoin(name, file.Name()), out); removeErr != nil {
				return removeErr
			}
		}
	}
	entry := metadataOutcome(name, info)
	entry.ChangeState, entry.Verified, entry.Verification = "unchanged", false, "not_performed"
	entry.phase, entry.VerificationMethod = "execute", "absent"
	defer func() { out.Entries = append(out.Entries, entry) }()
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	entry.ChangeState = "unknown"
	if info.IsDir() {
		err = client.RemoveDirectory(name)
	} else {
		err = client.Remove(name)
	}
	if err != nil {
		return err
	}
	entry.ChangeState, entry.Published = "changed", true
	entry.phase, entry.Verification = "collect", "unknown"
	_, err = client.Lstat(name)
	if !os.IsNotExist(err) {
		if err == nil {
			entry.Verification = "failed"
			err = fmt.Errorf("removed path still exists")
		}
		return boundaryError("verification_failed", "verify removal", err)
	}
	entry.Verified, entry.Verification = true, "passed"
	return nil
}

type boundaryReader struct {
	ctx    context.Context
	reader io.Reader
	kind   string
}

func (r boundaryReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if err != nil && err != io.EOF {
		err = boundaryError(r.kind, "read copy source", err)
	}
	return n, err
}

type boundaryWriter struct {
	ctx    context.Context
	writer io.Writer
	kind   string
}

func (w boundaryWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := w.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, boundaryError(w.kind, "write copy destination", err)
}
func copyBoundary(ctx context.Context, dst io.Writer, src io.Reader, sourceKind, destinationKind string) (int64, error) {
	return io.CopyBuffer(boundaryWriter{ctx, dst, destinationKind}, boundaryReader{ctx, src, sourceKind}, make([]byte, sftpReadApertureBytes))
}

func remotePathJoin(elem ...string) string { return path.Join(elem...) }
