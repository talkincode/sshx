package sshclient

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/pkg/sftp"
)

const (
	// MaxApplyBytes bounds both the incoming payload and any existing remote
	// file that apply will read for hashing or backup.
	MaxApplyBytes = 10 << 20

	defaultApplyBackupDir = ".sshx/file-backups"
	applyStagingDir       = ".sshx/apply-staging"
)

var (
	// ErrPrecondition indicates the remote file hash did not match --expect-sha256.
	ErrPrecondition = errors.New("apply precondition failed")
	// ErrApplyBlocked indicates the target path is refused by apply policy.
	ErrApplyBlocked = errors.New("apply target blocked")
	// ErrApplyVerification indicates publication was attempted but required
	// readback did not establish that the target matches the payload.
	ErrApplyVerification = errors.New("apply verification failed")
)

// ApplyRequest is one guarded regular-file replacement.
type ApplyRequest struct {
	RemotePath   string
	Payload      []byte
	ExpectSHA256 string
	Backup       bool
	BackupDir    string
	Force        bool
	UseSudo      bool
}

// ApplyOutcome is the observed result of one apply.
type ApplyOutcome struct {
	Changed       bool
	Created       bool
	BeforeSHA256  string
	AfterSHA256   string
	BackupPath    string
	Mode          string
	PayloadSHA256 string
	ExpectSHA256  string
	// PreconditionSHA256 is the latest guard observation; BeforeSHA256 remains
	// the original snapshot used to verify the backup.
	PreconditionSHA256 string
	PreconditionStatus string
	ChangeState        string
	// Executed describes target publication, not preparatory backup writes.
	// Nil means publication may have occurred without acknowledgement.
	Executed       *bool
	Verified       bool
	Verification   string
	BackupVerified bool
	UID, GID       *uint32
	CleanupPending []string
	ReplaceMethod  string
}

type applyScriptReport struct {
	Status             string   `json:"status"`
	Changed            bool     `json:"changed"`
	Created            bool     `json:"created"`
	Before             string   `json:"before"`
	After              string   `json:"after"`
	Backup             string   `json:"backup"`
	Mode               string   `json:"mode"`
	Error              string   `json:"error"`
	Payload            string   `json:"payload"`
	ChangeState        string   `json:"change_state"`
	Executed           *bool    `json:"executed"`
	Verified           bool     `json:"verified"`
	Verification       string   `json:"verification"`
	BackupVerified     bool     `json:"backup_verified"`
	UID                *uint32  `json:"uid"`
	GID                *uint32  `json:"gid"`
	CleanupPending     []string `json:"cleanup_pending"`
	ReplaceMethod      string   `json:"replace_method"`
	PreconditionSHA256 string   `json:"precondition_sha256"`
	PreconditionStatus string   `json:"precondition_status"`
}

type applyCleanupError struct {
	path string
	err  error
}

func (e *applyCleanupError) Error() string {
	return fmt.Sprintf("cleanup owned apply artifact %s: %v", e.path, e.err)
}
func (e *applyCleanupError) Unwrap() error { return e.err }

func newApplyOutcome(req ApplyRequest) *ApplyOutcome {
	no := false
	return &ApplyOutcome{
		PayloadSHA256: SHA256Hex(req.Payload), ExpectSHA256: req.ExpectSHA256,
		ChangeState: "unchanged", Executed: &no, Verification: "not_performed", PreconditionStatus: "not_performed",
	}
}

// ValidateApplyPath rejects anything that is not a clean POSIX absolute file path.
func ValidateApplyPath(remotePath string) error {
	if err := validateAbsoluteRemotePath(remotePath); err != nil {
		return fmt.Errorf("%w: %v", ErrApplyBlocked, err)
	}
	if remotePath == "/" {
		return fmt.Errorf("%w: cannot apply to /", ErrApplyBlocked)
	}
	if strings.HasSuffix(remotePath, "/") {
		return fmt.Errorf("%w: remote path must name a file", ErrApplyBlocked)
	}
	base := path.Base(remotePath)
	if base == "." || base == ".." || strings.HasPrefix(base, ".") && strings.Contains(base, ".sshx.") {
		return fmt.Errorf("%w: refused remote file name %q", ErrApplyBlocked, base)
	}
	return nil
}

// ApplyPathBlocked reports whether the path is a critical identity file that
// requires an explicit force + bypass-reason pair.
func ApplyPathBlocked(remotePath string) bool {
	cleaned := path.Clean(remotePath)
	switch cleaned {
	case "/etc/passwd", "/etc/shadow", "/etc/master.passwd", "/etc/sudoers":
		return true
	}
	return cleaned == "/etc/sudoers.d" || strings.HasPrefix(cleaned, "/etc/sudoers.d/")
}

// NormalizeApplySHA256 lowercases a hex digest and verifies it is SHA-256.
func NormalizeApplySHA256(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "", nil
	}
	if len(value) != 64 {
		return "", fmt.Errorf("expected SHA-256 hex digest (64 chars)")
	}
	for _, r := range value {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return "", fmt.Errorf("expected SHA-256 hex digest")
		}
	}
	return value, nil
}

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ApplyRegularFile replaces one remote regular file. The SFTP path is used
// unless UseSudo is set, in which case the payload is staged over SFTP and a
// privileged stdin script performs backup + atomic install.
func (c *SSHClient) ApplyRegularFile(req ApplyRequest) (outcome *ApplyOutcome, err error) {
	outcome = newApplyOutcome(req)
	defer func() {
		if err != nil {
			var cleanup *applyCleanupError
			if outcome != nil && errors.As(err, &cleanup) && !slices.Contains(outcome.CleanupPending, cleanup.path) {
				outcome.CleanupPending = append(outcome.CleanupPending, cleanup.path)
			}
			kind := "remote_io"
			var typed interface{ ErrorKind() string }
			if errors.As(err, &typed) {
				kind = typed.ErrorKind()
			}
			switch {
			case errors.Is(err, ErrApplyVerification):
				kind = "verification_failed"
			case errors.Is(err, ErrPrecondition):
				kind = "precondition"
			case errors.Is(err, ErrApplyBlocked):
				kind = "blocked"
			}
			err = &BoundaryError{Kind: kind, Op: "apply", Err: err}
		}
	}()
	if pathErr := ValidateApplyPath(req.RemotePath); pathErr != nil {
		return outcome, pathErr
	}
	if len(req.Payload) > MaxApplyBytes {
		return outcome, fmt.Errorf("payload exceeds %d-byte apply limit", MaxApplyBytes)
	}
	expect, err := NormalizeApplySHA256(req.ExpectSHA256)
	if err != nil {
		return outcome, err
	}
	req.ExpectSHA256 = expect
	if req.UseSudo {
		return c.applyWithSudo(req)
	}
	return c.applyWithSFTP(req)
}

func (c *SSHClient) applyWithSFTP(req ApplyRequest) (outcome *ApplyOutcome, err error) {
	outcome = newApplyOutcome(req)
	client, clientErr := c.newSFTPClient()
	if clientErr != nil {
		return outcome, clientErr
	}
	defer func() { _ = client.Close() }() //nolint:errcheck // teardown cannot invalidate verified remote evidence
	outcome, err = c.applySFTPFile(client, req)
	if err != nil {
		var cleanup *applyCleanupError
		if errors.As(err, &cleanup) {
			outcome.CleanupPending = append(outcome.CleanupPending, cleanup.path)
		}
		if errors.Is(err, ErrApplyVerification) {
			err = errors.Join(err, c.transportContext().Err())
		} else {
			err = c.transportError("remote_io", "apply file", err)
		}
	}
	return outcome, err
}

func (c *SSHClient) applySFTPFile(client *sftp.Client, req ApplyRequest) (outcome *ApplyOutcome, err error) {
	outcome = newApplyOutcome(req)
	info, statErr := client.Lstat(req.RemotePath)
	created := false
	var before []byte
	var beforeMode os.FileMode
	var beforeUID, beforeGID uint32
	var haveOwner bool
	switch {
	case statErr == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return outcome, fmt.Errorf("%w: target must be a regular file", ErrApplyBlocked)
		}
		beforeMode = info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
		outcome.Mode = applyModeString(beforeMode)
		if stat, ok := info.Sys().(*sftp.FileStat); ok {
			beforeUID = stat.UID
			beforeGID = stat.GID
			haveOwner = true
			outcome.UID, outcome.GID = &beforeUID, &beforeGID
		}
		if info.Size() > MaxApplyBytes {
			return outcome, fmt.Errorf("existing file exceeds %d-byte apply limit", MaxApplyBytes)
		}
		before, err = readRemoteRegularFile(client, req.RemotePath, info.Size())
		if err != nil {
			return outcome, err
		}
	case os.IsNotExist(statErr):
		created = true
	default:
		return outcome, fmt.Errorf("remote file inspect failed: %w", statErr)
	}

	beforeHash := ""
	if !created {
		beforeHash = SHA256Hex(before)
	}
	payloadHash := SHA256Hex(req.Payload)
	outcome.BeforeSHA256 = beforeHash
	mode := os.FileMode(0o600)
	if !created {
		mode = beforeMode
	}
	outcome.Mode = applyModeString(mode)
	if preErr := observeApplyPrecondition(outcome, created, beforeHash, req); preErr != nil {
		return outcome, preErr
	}
	if !created && beforeHash == payloadHash {
		outcome.AfterSHA256, outcome.Verified, outcome.Verification = beforeHash, true, "passed"
		return outcome, nil
	}

	backupPath := ""
	if req.Backup && !created {
		backupPath, err = writeApplyBackup(c, client, req, path.Base(req.RemotePath), before, beforeHash)
		outcome.BackupPath = backupPath
		if err != nil {
			return outcome, err
		}
		saved, backupErr := readRemoteRegularFile(client, backupPath, int64(len(before)))
		if backupErr != nil {
			return outcome, fmt.Errorf("verify backup: %w", backupErr)
		}
		if SHA256Hex(saved) != beforeHash {
			return outcome, fmt.Errorf("backup hash mismatch")
		}
		outcome.BackupVerified = true
	}

	recheck := func() error {
		// SFTP has no compare-and-swap primitive: this narrows the race window,
		// but cannot exclude arbitrary writers between this read and rename.
		if req.ExpectSHA256 != "" && !req.Force {
			outcome.PreconditionStatus, outcome.PreconditionSHA256 = "unknown", ""
		}
		current, inspectErr := client.Lstat(req.RemotePath)
		if inspectErr != nil && !os.IsNotExist(inspectErr) {
			return fmt.Errorf("reinspect apply target: %w", inspectErr)
		}
		if inspectErr == nil && !current.Mode().IsRegular() {
			return fmt.Errorf("%w: target is no longer a regular file", ErrApplyBlocked)
		}
		if req.ExpectSHA256 == "" || req.Force {
			return nil
		}
		if os.IsNotExist(inspectErr) {
			return observeApplyPrecondition(outcome, true, "", req)
		}
		observed, readErr := readRemoteRegularFile(client, req.RemotePath, current.Size())
		if readErr != nil {
			return readErr
		}
		return observeApplyPrecondition(outcome, false, SHA256Hex(observed), req)
	}
	if replaceErr := atomicReplaceFile(client, req.RemotePath, req.Payload, mode, haveOwner && !created, beforeUID, beforeGID, outcome, recheck); replaceErr != nil {
		return outcome, replaceErr
	}
	outcome.Created = created
	after, afterErr := readRemoteRegularFile(client, req.RemotePath, int64(len(req.Payload)))
	if afterErr != nil {
		outcome.Verification = "failed"
		return outcome, fmt.Errorf("%w: %w", ErrApplyVerification, afterErr)
	}
	afterHash := SHA256Hex(after)
	outcome.AfterSHA256 = afterHash
	if afterHash != payloadHash {
		outcome.Verification = "failed"
		return outcome, fmt.Errorf("%w: remote file post-apply hash mismatch", ErrApplyVerification)
	}
	outcome.Verified, outcome.Verification = true, "passed"
	return outcome, nil
}

func checkApplyPrecondition(created bool, beforeHash string, req ApplyRequest) error {
	if req.Force {
		return nil
	}
	if req.ExpectSHA256 == "" {
		return nil
	}
	if created {
		return fmt.Errorf("%w: target does not exist (expected %s)", ErrPrecondition, req.ExpectSHA256)
	}
	if beforeHash != req.ExpectSHA256 {
		return fmt.Errorf("%w: have %s, expected %s", ErrPrecondition, beforeHash, req.ExpectSHA256)
	}
	return nil
}

func observeApplyPrecondition(outcome *ApplyOutcome, created bool, observed string, req ApplyRequest) error {
	if req.ExpectSHA256 == "" {
		return nil
	}
	outcome.PreconditionSHA256 = observed
	if req.Force {
		outcome.PreconditionStatus = "bypassed"
		return nil
	}
	if err := checkApplyPrecondition(created, observed, req); err != nil {
		outcome.PreconditionStatus = "failed"
		return err
	}
	outcome.PreconditionStatus = "passed"
	return nil
}

func applyModeString(mode os.FileMode) string {
	bits := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		bits |= 0o1000
	}
	return fmt.Sprintf("%04o", bits)
}

func writeApplyBackup(c *SSHClient, client *sftp.Client, req ApplyRequest, base string, data []byte, hash string) (string, error) {
	dir := strings.TrimSpace(req.BackupDir)
	if dir == "" {
		home, err := c.RemoteHome()
		if err != nil {
			return "", fmt.Errorf("resolve backup directory: %w", err)
		}
		dir = path.Join(home, defaultApplyBackupDir)
	}
	if err := validateAbsoluteRemotePath(dir); err != nil {
		return "", fmt.Errorf("backup directory: %w", err)
	}
	if err := mkdirAllPrivate(client, dir); err != nil {
		return "", err
	}
	short := hash
	if len(short) > 12 {
		short = short[:12]
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate backup name: %w", err)
	}
	name := fmt.Sprintf("%s.%s.%s.%s", base, time.Now().UTC().Format("20060102T150405Z"), short, hex.EncodeToString(random))
	backupPath := path.Join(dir, name)
	if err := writePrivateFile(client, backupPath, data); err != nil {
		return backupPath, fmt.Errorf("write backup: %w", err)
	}
	return backupPath, nil
}

func atomicReplaceFile(client *sftp.Client, dest string, data []byte, mode os.FileMode, chown bool, uid, gid uint32, outcome *ApplyOutcome, recheck func() error) (err error) {
	dir := path.Dir(dest)
	random := make([]byte, 12)
	if _, randErr := rand.Read(random); randErr != nil {
		return fmt.Errorf("generate apply temp name: %w", randErr)
	}
	tempPath := path.Join(dir, "."+path.Base(dest)+"."+hex.EncodeToString(random)+".sshx.tmp")
	file, err := client.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fmt.Errorf("remote file create apply temp file: %w", err)
	}
	cleanup := true
	defer func() {
		_ = file.Close() //nolint:errcheck // best-effort cleanup
		if cleanup {
			if cleanupErr := client.Remove(tempPath); cleanupErr != nil && !os.IsNotExist(cleanupErr) {
				outcome.CleanupPending = append(outcome.CleanupPending, tempPath)
				err = errors.Join(err, fmt.Errorf("cleanup apply temp: %w", cleanupErr))
			}
		}
	}()
	if chmodErr := file.Chmod(0o600); chmodErr != nil {
		return fmt.Errorf("remote file secure apply temp file: %w", chmodErr)
	}
	if n, writeErr := file.Write(data); writeErr != nil || n != len(data) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return fmt.Errorf("remote file write apply temp file: %w", writeErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		return fmt.Errorf("remote file close apply temp file: %w", closeErr)
	}
	if chown {
		tempInfo, statErr := client.Lstat(tempPath)
		if statErr != nil {
			return fmt.Errorf("remote file inspect apply temp file: %w", statErr)
		}
		stat, ok := tempInfo.Sys().(*sftp.FileStat)
		if !ok {
			return fmt.Errorf("remote file cannot inspect owner of apply temp file")
		}
		if stat.UID != uid || stat.GID != gid {
			if chownErr := client.Chown(tempPath, int(uid), int(gid)); chownErr != nil {
				return fmt.Errorf("remote file cannot preserve owner (retry with --sudo): %w", chownErr)
			}
		}
	}
	// chown can clear permission bits, so permissions are set afterward.
	if chmodErr := client.Chmod(tempPath, mode); chmodErr != nil {
		return fmt.Errorf("remote file chmod apply temp file: %w", chmodErr)
	}
	if recheckErr := recheck(); recheckErr != nil {
		return recheckErr
	}
	outcome.Executed, outcome.ChangeState, outcome.Verification = nil, "unknown", "unknown"
	outcome.ReplaceMethod, err = posixOrRename(client, tempPath, dest)
	if err != nil {
		var status *sftp.StatusError
		unsupported := errors.As(err, &status) && status.FxCode() == sftp.ErrSSHFxOpUnsupported
		if unsupported || os.IsPermission(err) || os.IsNotExist(err) || os.IsExist(err) {
			no := false
			outcome.Executed, outcome.ChangeState, outcome.Verification = &no, "unchanged", "not_performed"
			return fmt.Errorf("remote file replace target: %w", err)
		}
		return fmt.Errorf("%w: replacement acknowledgement missing: %w", ErrApplyVerification, err)
	}
	cleanup = false
	yes := true
	outcome.Executed, outcome.Changed, outcome.ChangeState = &yes, true, "changed"
	return nil
}

func posixOrRename(client *sftp.Client, oldpath, newpath string) (string, error) {
	err := client.PosixRename(oldpath, newpath)
	if err == nil {
		return "posix_rename", nil
	}
	var status *sftp.StatusError
	if !errors.As(err, &status) || status.FxCode() != sftp.ErrSSHFxOpUnsupported {
		return "posix_rename", err
	}
	return "sftp_rename", client.Rename(oldpath, newpath)
}

func readRemoteRegularFile(client *sftp.Client, remotePath string, size int64) ([]byte, error) {
	pathInfo, inspectErr := client.Lstat(remotePath)
	if inspectErr != nil {
		return nil, fmt.Errorf("remote file inspect target: %w", inspectErr)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: target must be a regular file", ErrApplyBlocked)
	}
	file, err := client.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("remote file open target: %w", err)
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // best-effort close
	if size > MaxApplyBytes {
		return nil, fmt.Errorf("existing file exceeds %d-byte apply limit", MaxApplyBytes)
	}
	info, statErr := file.Stat()
	if statErr != nil {
		return nil, fmt.Errorf("remote file stat target: %w", statErr)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: target must be a regular file", ErrApplyBlocked)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxApplyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("remote file read target: %w", err)
	}
	if int64(len(data)) > MaxApplyBytes {
		return nil, fmt.Errorf("existing file exceeds %d-byte apply limit", MaxApplyBytes)
	}
	return data, nil
}

func writePrivateFile(client *sftp.Client, remotePath string, data []byte) (err error) {
	file, err := client.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = file.Close() //nolint:errcheck // best-effort close
		if !complete {
			if cleanupErr := client.Remove(remotePath); cleanupErr != nil && !os.IsNotExist(cleanupErr) {
				err = errors.Join(err, &applyCleanupError{path: remotePath, err: cleanupErr})
			}
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if n, err := file.Write(data); err != nil || n != len(data) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func mkdirAllPrivate(client *sftp.Client, dir string) error {
	if err := validateAbsoluteRemotePath(dir); err != nil {
		return err
	}
	var missing []string
	current := dir
	for {
		info, err := client.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("backup path component is not a directory: %s", current)
			}
			break
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect backup directory %s: %w", current, err)
		}
		missing = append([]string{current}, missing...)
		parent := path.Dir(current)
		if parent == current {
			return fmt.Errorf("cannot create backup directory %s", dir)
		}
		current = parent
	}
	for _, item := range missing {
		if err := client.Mkdir(item); err != nil {
			return fmt.Errorf("create backup directory %s: %w", item, err)
		}
		if err := client.Chmod(item, 0o700); err != nil {
			return fmt.Errorf("secure backup directory %s: %w", item, err)
		}
	}
	return nil
}

func (c *SSHClient) applyWithSudo(req ApplyRequest) (outcome *ApplyOutcome, err error) {
	outcome = newApplyOutcome(req)
	if c.config.SudoPassword == "" {
		return outcome, fmt.Errorf("sudo apply requires a resolved sudo password")
	}
	home, err := c.RemoteHome()
	if err != nil {
		return outcome, err
	}
	stagingDir := path.Join(home, applyStagingDir)
	client, clientErr := c.newSFTPClient()
	if clientErr != nil {
		return outcome, clientErr
	}
	defer func() { _ = client.Close() }() //nolint:errcheck // best-effort close

	if mkdirErr := mkdirAllPrivate(client, stagingDir); mkdirErr != nil {
		return outcome, mkdirErr
	}
	random := make([]byte, 12)
	if _, randErr := rand.Read(random); randErr != nil {
		return outcome, fmt.Errorf("generate staging name: %w", randErr)
	}
	staging := path.Join(stagingDir, hex.EncodeToString(random)+".new")
	if stageErr := writePrivateFile(client, staging, req.Payload); stageErr != nil {
		return outcome, fmt.Errorf("stage payload: %w", stageErr)
	}
	defer func() {
		if cleanupErr := client.Remove(staging); cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			outcome.CleanupPending = append(outcome.CleanupPending, staging)
			err = errors.Join(err, fmt.Errorf("cleanup staged payload: %w", cleanupErr))
		}
	}()

	backupDir := strings.TrimSpace(req.BackupDir)
	if backupDir == "" {
		backupDir = path.Join(home, defaultApplyBackupDir)
	}
	script, err := buildApplySudoScript(req, staging, backupDir)
	if err != nil {
		return outcome, err
	}
	result, runErr := c.RunScript(script, true)
	outcome, reportErr := applySudoOutcome(req, result)
	return outcome, errors.Join(runErr, reportErr)
}

func applySudoOutcome(req ApplyRequest, result ExecResult) (*ApplyOutcome, error) {
	outcome := newApplyOutcome(req)
	observed, reportErr := parseApplyScriptReport(result)
	if observed != nil {
		outcome = observed
		outcome.ExpectSHA256 = req.ExpectSHA256
		if outcome.PayloadSHA256 != SHA256Hex(req.Payload) {
			outcome.Verified, outcome.Verification = false, "failed"
			reportErr = errors.Join(reportErr, fmt.Errorf("%w: privileged report payload differs", ErrApplyVerification))
			outcome.PayloadSHA256 = SHA256Hex(req.Payload)
		}
		if reportErr == nil && (req.Backup && outcome.Changed && !outcome.Created && !outcome.BackupVerified ||
			!req.Backup && outcome.BackupPath != "" ||
			!req.Force && req.ExpectSHA256 != "" && (outcome.PreconditionSHA256 != req.ExpectSHA256 || outcome.PreconditionStatus != "passed") ||
			req.Force && req.ExpectSHA256 != "" && outcome.PreconditionStatus != "bypassed") {
			outcome.Verified, outcome.Verification = false, "failed"
			reportErr = fmt.Errorf("%w: privileged report contradicts the admitted apply request", ErrApplyVerification)
		}
	} else if result.Started || result.StartAttempted {
		outcome.Executed, outcome.ChangeState, outcome.Verification = nil, "unknown", "unknown"
	}
	return outcome, reportErr
}

func buildApplySudoScript(req ApplyRequest, staging, backupDir string) ([]byte, error) {
	for _, value := range []string{req.RemotePath, staging, backupDir, req.ExpectSHA256} {
		if !shellSafeToken(value) {
			return nil, fmt.Errorf("%w: value is not safe to embed in the apply script", ErrApplyBlocked)
		}
	}
	wantBackup := "0"
	if req.Backup {
		wantBackup = "1"
	}
	force := "0"
	if req.Force {
		force = "1"
	}
	script := fmt.Sprintf(`#!/bin/sh
set -eu
umask 077
TARGET='%s'
STAGING='%s'
BACKUP_DIR='%s'
EXPECT='%s'
WANT_BACKUP='%s'
FORCE='%s'
PAYLOAD_SHA='%s'

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum "$1") || return
    digest=${digest%%%% *}
  elif command -v shasum >/dev/null 2>&1; then
    digest=$(shasum -a 256 "$1") || return
    digest=${digest%%%% *}
  else
    digest=$(openssl dgst -sha256 "$1") || return
    digest=${digest##* }
  fi
  [ "${#digest}" = 64 ] || return 1
  case "$digest" in *[!0-9a-f]*) return 1 ;; esac
  printf '%%s\n' "$digest"
}

file_mode() {
  if stat -c '%%a' "$1" >/dev/null 2>&1; then
    stat -c '%%a' "$1"
  else
    stat -f '%%OLp' "$1"
  fi
}

file_uid() {
  if stat -c '%%u' "$1" >/dev/null 2>&1; then
    stat -c '%%u' "$1"
  else
    stat -f '%%u' "$1"
  fi
}

file_gid() {
  if stat -c '%%g' "$1" >/dev/null 2>&1; then
    stat -c '%%g' "$1"
  else
    stat -f '%%g' "$1"
  fi
}

file_size() {
  if stat -c '%%s' "$1" >/dev/null 2>&1; then stat -c '%%s' "$1"
  else stat -f '%%z' "$1"; fi
}

status=remote_io
error="privileged file operation failed"
created=false
changed=false
before=""
after=""
backup=""
backup_verified=false
mode="0600"
uid=null
gid=null
executed=false
change_state=unchanged
verified=false
verification=not_performed
tmp=""
cleanup_pending=""
replace_method=""
precondition_status=not_performed
precondition_sha256=""
if [ -n "$EXPECT" ] && [ "$FORCE" = "1" ]; then precondition_status=bypassed; fi
report() {
  printf '{"status":"%%s","changed":%%s,"created":%%s,"before":"%%s","after":"%%s","backup":"%%s","mode":"%%s","payload":"%%s","executed":%%s,"change_state":"%%s","verified":%%s,"verification":"%%s","backup_verified":%%s,"uid":%%s,"gid":%%s,"cleanup_pending":[%%s],"error":"%%s","replace_method":"%%s","precondition_status":"%%s","precondition_sha256":"%%s"}\n' "$status" "$changed" "$created" "$before" "$after" "$backup" "$mode" "$PAYLOAD_SHA" "$executed" "$change_state" "$verified" "$verification" "$backup_verified" "$uid" "$gid" "$cleanup_pending" "$error" "$replace_method" "$precondition_status" "$precondition_sha256"
}
remove_owned() {
  if ! rm -f "$1"; then
    cleanup_pending="$cleanup_pending${cleanup_pending:+,}\"$1\""
    return 1
  fi
}
finish() {
  rc=$?
  trap - 0 HUP INT TERM
  if [ -n "$tmp" ]; then remove_owned "$tmp" || rc=4; fi
  if [ -n "$backup" ] && [ "$backup_verified" != true ]; then remove_owned "$backup" || rc=4; fi
  remove_owned "$STAGING" || rc=4
  if [ "$rc" != 0 ] && [ "$status" = ok ]; then status=remote_io; error="artifact cleanup failed"; fi
  report
  exit "$rc"
}
trap finish 0
trap 'exit 4' HUP INT TERM

if [ -L "$TARGET" ]; then
  status=blocked; error="target is a symlink"
  exit 2
fi
if [ -e "$TARGET" ] && [ ! -f "$TARGET" ]; then
  status=blocked; error="target is not a regular file"
  exit 2
fi
if [ -L "$STAGING" ] || [ ! -f "$STAGING" ] || [ "$(file_size "$STAGING")" -gt %d ]; then
  error="staged payload is missing or invalid"
  exit 4
fi
[ "$(hash_file "$STAGING")" = "$PAYLOAD_SHA" ] || exit 4

missing=true
if [ -f "$TARGET" ]; then
  missing=false
  [ "$(file_size "$TARGET")" -le %d ] || exit 4
  mode=$(file_mode "$TARGET")
  uid=$(file_uid "$TARGET")
  gid=$(file_gid "$TARGET")
  before=$(hash_file "$TARGET")
  if [ -n "$EXPECT" ]; then precondition_sha256="$before"; fi
  if [ "$FORCE" != "1" ] && [ -n "$EXPECT" ] && [ "$before" != "$EXPECT" ]; then
    precondition_status=failed; status=precondition; error="hash mismatch"
    exit 3
  fi
  if [ "$FORCE" != "1" ] && [ -n "$EXPECT" ]; then precondition_status=passed; fi
  if [ "$before" = "$PAYLOAD_SHA" ]; then
    status=ok; error=""; after="$before"; verified=true; verification=passed
    exit 0
  fi
else
  if [ "$FORCE" != "1" ] && [ -n "$EXPECT" ]; then
    precondition_status=failed; status=precondition; error="target does not exist"
    exit 3
  fi
fi
status=progress; report; status=remote_io

if [ "$WANT_BACKUP" = "1" ] && [ "$missing" = "false" ]; then
  mkdir -p "$BACKUP_DIR"
  [ ! -L "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ] || exit 4
  chmod 700 "$BACKUP_DIR"
  short=$(printf '%%s' "$before" | cut -c1-12)
  stamp=$(date -u +%%Y%%m%%dT%%H%%M%%SZ)
  candidate="$BACKUP_DIR/$(basename "$TARGET").$stamp.$short.$(basename "$STAGING")"
  (set -C; : > "$candidate") || exit 4
  backup="$candidate"
  cat "$TARGET" > "$backup"
  chmod 600 "$backup"
  [ "$(file_size "$backup")" -le %d ] && [ "$(hash_file "$backup")" = "$before" ] || exit 4
  backup_verified=true
  status=progress; report; status=remote_io
fi

dir=$(dirname "$TARGET")
candidate="$dir/.$(basename "$TARGET").sshx.$(basename "$STAGING").tmp"
(set -C; : > "$candidate") || exit 4
tmp="$candidate"
cat "$STAGING" > "$tmp"
if [ "$missing" = "false" ]; then
  chown "$uid:$gid" "$tmp"
fi
chmod "$mode" "$tmp"
[ "$(hash_file "$tmp")" = "$PAYLOAD_SHA" ] || exit 4
if [ "$FORCE" != "1" ] && [ -n "$EXPECT" ]; then precondition_status=unknown; precondition_sha256=""; fi
if [ -L "$TARGET" ] || { [ -e "$TARGET" ] && [ ! -f "$TARGET" ]; }; then
  status=blocked; error="target is no longer a regular file"; exit 2
fi
if [ "$FORCE" != "1" ] && [ -n "$EXPECT" ]; then
  if [ ! -f "$TARGET" ]; then
    precondition_status=failed; status=precondition; error="target disappeared before publication"; exit 3
  fi
  [ "$(file_size "$TARGET")" -le %d ] || exit 4
  precondition_sha256=$(hash_file "$TARGET")
  if [ "$precondition_sha256" != "$EXPECT" ]; then
    precondition_status=failed; status=precondition; error="target changed before publication"; exit 3
  fi
  precondition_status=passed
fi
executed=null; change_state=unknown; verification=unknown; replace_method=same_directory_mv
status=progress; report; status=verification_failed
mv -f "$tmp" "$TARGET"
tmp=""
executed=true; changed=true; change_state=changed; created="$missing"
status=progress; report; status=verification_failed; verification=failed
[ ! -L "$TARGET" ] && [ -f "$TARGET" ] && [ "$(file_size "$TARGET")" -le %d ] || exit 4
after=$(hash_file "$TARGET")
if [ "$after" != "$PAYLOAD_SHA" ]; then
  error="post-apply hash mismatch"
  exit 4
fi
status=ok; error=""; verified=true; verification=passed
`, req.RemotePath, staging, backupDir, req.ExpectSHA256, wantBackup, force, SHA256Hex(req.Payload), MaxApplyBytes, MaxApplyBytes, MaxApplyBytes, MaxApplyBytes, MaxApplyBytes)
	return []byte(script), nil
}

func parseApplyScriptReport(result ExecResult) (*ApplyOutcome, error) {
	report, decodeErr := decodeApplyScriptReport(result.Stdout)
	var outcome *ApplyOutcome
	if report.Payload != "" {
		outcome = &ApplyOutcome{
			Changed: report.Changed, Created: report.Created,
			BeforeSHA256: report.Before, AfterSHA256: report.After,
			BackupPath: report.Backup, Mode: report.Mode, PayloadSHA256: report.Payload,
			ChangeState: report.ChangeState, Executed: report.Executed,
			Verified: report.Verified, Verification: report.Verification,
			BackupVerified: report.BackupVerified, UID: report.UID, GID: report.GID,
			CleanupPending:     report.CleanupPending,
			ReplaceMethod:      report.ReplaceMethod,
			PreconditionSHA256: report.PreconditionSHA256,
			PreconditionStatus: report.PreconditionStatus,
		}
	}
	if decodeErr != nil || result.StdoutTruncated || result.ExitCode == 0 && report.Status != "ok" || report.Status == "ok" && result.ExitCode != 0 {
		if outcome != nil {
			outcome.Verified, outcome.Verification = false, "failed"
			if report.Status == "progress" && (outcome.Executed == nil || !*outcome.Executed) {
				outcome.Executed, outcome.ChangeState, outcome.Verification = nil, "unknown", "unknown"
			}
		}
		return outcome, fmt.Errorf("%w: invalid privileged report (exit %d): %v", ErrApplyVerification, result.ExitCode, decodeErr)
	}
	if report.Status == "ok" {
		return outcome, nil
	}
	switch report.Status {
	case "precondition":
		if report.PreconditionSHA256 != "" {
			return outcome, fmt.Errorf("%w: have %s: %s", ErrPrecondition, report.PreconditionSHA256, report.Error)
		}
		return outcome, fmt.Errorf("%w: %s", ErrPrecondition, emptyFallback(report.Error, "target mismatch"))
	case "blocked":
		return outcome, fmt.Errorf("%w: %s", ErrApplyBlocked, emptyFallback(report.Error, "target refused"))
	case "verification_failed":
		return outcome, fmt.Errorf("%w: %s", ErrApplyVerification, emptyFallback(report.Error, "postcondition unavailable"))
	case "progress":
		// The remote script can continue after its last received checkpoint.
		// An early checkpoint is not proof that publication never happened.
		if outcome.Executed == nil || !*outcome.Executed {
			outcome.Executed, outcome.ChangeState = nil, "unknown"
		}
		outcome.Verified, outcome.Verification = false, "unknown"
		return outcome, fmt.Errorf("%w: final privileged acknowledgement missing", ErrApplyVerification)
	default:
		return outcome, fmt.Errorf("remote file %s", emptyFallback(report.Error, "privileged apply failed"))
	}
}

func decodeApplyScriptReport(stdout string) (applyScriptReport, error) {
	var last applyScriptReport
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for i, line := range lines {
		report, err := decodeApplyScriptLine(line)
		if err != nil {
			return last, err
		}
		if i > 0 && (last.Status != "progress" || last.Payload != report.Payload ||
			last.Before != report.Before || last.Backup != "" && last.Backup != report.Backup ||
			last.Executed != nil && *last.Executed && (report.Executed == nil || !*report.Executed)) {
			return last, fmt.Errorf("inconsistent privileged apply progress")
		}
		last = report
	}
	return last, nil
}

func decodeApplyScriptLine(line string) (applyScriptReport, error) {
	var report applyScriptReport
	data := []byte(line)
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return report, fmt.Errorf("privileged apply report must be an object")
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		key, keyErr := dec.Token()
		if keyErr != nil {
			return report, keyErr
		}
		name, ok := key.(string)
		if !ok {
			return report, fmt.Errorf("invalid privileged report field")
		}
		if _, duplicate := fields[name]; duplicate {
			return report, fmt.Errorf("duplicate privileged report field %q", name)
		}
		var value json.RawMessage
		if valueErr := dec.Decode(&value); valueErr != nil {
			return report, valueErr
		}
		fields[name] = value
	}
	for _, required := range []string{"status", "changed", "created", "before", "after", "backup", "mode", "payload", "executed", "change_state", "verified", "verification", "backup_verified", "uid", "gid", "cleanup_pending", "error", "replace_method", "precondition_status", "precondition_sha256"} {
		value, ok := fields[required]
		if !ok || string(value) == "null" && required != "executed" && required != "uid" && required != "gid" && required != "cleanup_pending" {
			return report, fmt.Errorf("missing privileged report field %q", required)
		}
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		return applyScriptReport{}, fmt.Errorf("parse privileged apply result: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return applyScriptReport{}, fmt.Errorf("trailing privileged apply report data")
	}
	for _, hash := range []string{report.Before, report.After, report.Payload, report.PreconditionSHA256} {
		normalized, hashErr := NormalizeApplySHA256(hash)
		if hashErr != nil || normalized != hash {
			return applyScriptReport{}, fmt.Errorf("invalid privileged apply hash")
		}
	}
	if report.Payload == "" {
		return applyScriptReport{}, fmt.Errorf("missing privileged payload hash")
	}
	switch report.PreconditionStatus {
	case "passed":
		if report.PreconditionSHA256 == "" {
			return applyScriptReport{}, fmt.Errorf("missing privileged precondition observation")
		}
	case "not_performed", "unknown", "bypassed", "failed":
	default:
		return applyScriptReport{}, fmt.Errorf("invalid privileged precondition status")
	}
	if report.ReplaceMethod != "" && report.ReplaceMethod != "same_directory_mv" {
		return applyScriptReport{}, fmt.Errorf("invalid privileged replacement method")
	}
	if (report.Executed == nil || *report.Executed) && report.ReplaceMethod == "" {
		return applyScriptReport{}, fmt.Errorf("missing privileged replacement method")
	}
	if len(report.Mode) < 3 || len(report.Mode) > 4 || strings.Trim(report.Mode, "01234567") != "" {
		return applyScriptReport{}, fmt.Errorf("invalid privileged file mode")
	}
	for _, remotePath := range append([]string{report.Backup}, report.CleanupPending...) {
		if remotePath != "" && validateAbsoluteRemotePath(remotePath) != nil {
			return applyScriptReport{}, fmt.Errorf("invalid privileged artifact path")
		}
	}
	switch report.ChangeState {
	case "changed":
		if !report.Changed || report.Executed == nil || !*report.Executed {
			return applyScriptReport{}, fmt.Errorf("inconsistent privileged change evidence")
		}
	case "unchanged":
		if report.Changed || report.Executed == nil || *report.Executed {
			return applyScriptReport{}, fmt.Errorf("inconsistent privileged no-change evidence")
		}
	case "unknown":
		if report.Changed || report.Executed != nil {
			return applyScriptReport{}, fmt.Errorf("inconsistent privileged unknown evidence")
		}
	default:
		return applyScriptReport{}, fmt.Errorf("invalid privileged change state")
	}
	if report.BackupVerified && (report.Backup == "" || report.Before == "") ||
		report.Created && (report.Before != "" || !report.Changed) ||
		report.Changed && report.Before == "" && !report.Created ||
		(report.UID == nil) != (report.GID == nil) {
		return applyScriptReport{}, fmt.Errorf("inconsistent privileged file evidence")
	}
	switch report.Verification {
	case "passed":
		if !report.Verified || report.After != report.Payload || !report.Changed && report.Before != report.After {
			return applyScriptReport{}, fmt.Errorf("inconsistent privileged verification evidence")
		}
	case "failed", "unknown", "not_performed":
		if report.Verified {
			return applyScriptReport{}, fmt.Errorf("inconsistent privileged verification status")
		}
	default:
		return applyScriptReport{}, fmt.Errorf("invalid privileged verification status")
	}
	switch report.Status {
	case "ok":
		if !report.Verified || report.Error != "" || len(report.CleanupPending) != 0 ||
			report.PreconditionStatus == "failed" || report.PreconditionStatus == "unknown" {
			return applyScriptReport{}, fmt.Errorf("unverified privileged success report")
		}
	case "progress", "remote_io", "verification_failed":
	case "precondition", "blocked":
		if report.ChangeState != "unchanged" {
			return applyScriptReport{}, fmt.Errorf("privileged rejection after publication")
		}
	default:
		return applyScriptReport{}, fmt.Errorf("unknown privileged apply status")
	}
	return report, nil
}

func emptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func shellSafeToken(value string) bool {
	if value == "" {
		return true
	}
	if strings.ContainsAny(value, "'\n\r\x00$`\\\"!") {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
