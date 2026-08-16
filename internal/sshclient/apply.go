package sshclient

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/pkg/sftp"
	"github.com/talkincode/sshx/pkg/errutil"
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
	Changed      bool
	Created      bool
	BeforeSHA256 string
	AfterSHA256  string
	BackupPath   string
	Mode         string
}

type applyScriptReport struct {
	Status  string `json:"status"`
	Changed bool   `json:"changed"`
	Created bool   `json:"created"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Backup  string `json:"backup"`
	Mode    string `json:"mode"`
	Error   string `json:"error"`
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
func (c *SSHClient) ApplyRegularFile(req ApplyRequest) (*ApplyOutcome, error) {
	if err := ValidateApplyPath(req.RemotePath); err != nil {
		return nil, err
	}
	if len(req.Payload) > MaxApplyBytes {
		return nil, fmt.Errorf("payload exceeds %d-byte apply limit", MaxApplyBytes)
	}
	expect, err := NormalizeApplySHA256(req.ExpectSHA256)
	if err != nil {
		return nil, err
	}
	req.ExpectSHA256 = expect
	if req.UseSudo {
		return c.applyWithSudo(req)
	}
	return c.applyWithSFTP(req)
}

func (c *SSHClient) applyWithSFTP(req ApplyRequest) (outcome *ApplyOutcome, err error) {
	client, clientErr := sftp.NewClient(c.client)
	if clientErr != nil {
		return nil, fmt.Errorf("open SFTP session: %w", clientErr)
	}
	defer errutil.HandleCloseError(&err, client)

	info, statErr := client.Lstat(req.RemotePath)
	created := false
	var before []byte
	var beforeMode os.FileMode
	var beforeUID, beforeGID uint32
	var haveOwner bool
	switch {
	case statErr == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: target must be a regular file", ErrApplyBlocked)
		}
		if info.Size() > MaxApplyBytes {
			return nil, fmt.Errorf("existing file exceeds %d-byte apply limit", MaxApplyBytes)
		}
		before, err = readRemoteRegularFile(client, req.RemotePath, info.Size())
		if err != nil {
			return nil, err
		}
		beforeMode = info.Mode().Perm()
		if stat, ok := info.Sys().(*sftp.FileStat); ok {
			beforeUID = stat.UID
			beforeGID = stat.GID
			haveOwner = true
		}
	case os.IsNotExist(statErr):
		created = true
	default:
		return nil, fmt.Errorf("remote file inspect failed: %w", statErr)
	}

	beforeHash := ""
	if !created {
		beforeHash = SHA256Hex(before)
	}
	payloadHash := SHA256Hex(req.Payload)
	if preErr := checkApplyPrecondition(created, beforeHash, req); preErr != nil {
		return nil, preErr
	}
	if !created && beforeHash == payloadHash {
		return &ApplyOutcome{
			Changed:      false,
			Created:      false,
			BeforeSHA256: beforeHash,
			AfterSHA256:  beforeHash,
			Mode:         fmt.Sprintf("%04o", beforeMode),
		}, nil
	}

	backupPath := ""
	if req.Backup && !created {
		backupPath, err = writeApplyBackup(c, client, req, path.Base(req.RemotePath), before, beforeHash)
		if err != nil {
			return nil, err
		}
	}

	mode := os.FileMode(0o600)
	if !created {
		mode = beforeMode
	}
	if err := atomicReplaceFile(client, req.RemotePath, req.Payload, mode, haveOwner && !created, beforeUID, beforeGID); err != nil {
		return nil, err
	}
	after, afterErr := readRemoteRegularFile(client, req.RemotePath, int64(len(req.Payload)))
	if afterErr != nil {
		return nil, afterErr
	}
	afterHash := SHA256Hex(after)
	if afterHash != payloadHash {
		return nil, fmt.Errorf("remote file post-apply hash mismatch")
	}
	return &ApplyOutcome{
		Changed:      true,
		Created:      created,
		BeforeSHA256: beforeHash,
		AfterSHA256:  afterHash,
		BackupPath:   backupPath,
		Mode:         fmt.Sprintf("%04o", mode),
	}, nil
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
	name := fmt.Sprintf("%s.%s.%s", base, time.Now().UTC().Format("20060102T150405Z"), short)
	backupPath := path.Join(dir, name)
	if err := writePrivateFile(client, backupPath, data); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	return backupPath, nil
}

func atomicReplaceFile(client *sftp.Client, dest string, data []byte, mode os.FileMode, chown bool, uid, gid uint32) error {
	dir := path.Dir(dest)
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("generate apply temp name: %w", err)
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
			_ = client.Remove(tempPath) //nolint:errcheck // best-effort cleanup
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("remote file write apply temp file: %w", err)
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("remote file chmod apply temp file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("remote file close apply temp file: %w", err)
	}
	if chown {
		tempInfo, statErr := client.Lstat(tempPath)
		if statErr != nil {
			return fmt.Errorf("remote file inspect apply temp file: %w", statErr)
		}
		if stat, ok := tempInfo.Sys().(*sftp.FileStat); ok && (stat.UID != uid || stat.GID != gid) {
			if chownErr := client.Chown(tempPath, int(uid), int(gid)); chownErr != nil {
				return fmt.Errorf("remote file cannot preserve owner (retry with --sudo): %w", chownErr)
			}
		}
	}
	if err := posixOrRename(client, tempPath, dest); err != nil {
		return fmt.Errorf("remote file atomically replace target: %w", err)
	}
	cleanup = false
	return nil
}

func posixOrRename(client *sftp.Client, oldpath, newpath string) error {
	if err := client.PosixRename(oldpath, newpath); err == nil {
		return nil
	}
	return client.Rename(oldpath, newpath)
}

func readRemoteRegularFile(client *sftp.Client, remotePath string, size int64) ([]byte, error) {
	file, err := client.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("remote file open target: %w", err)
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // best-effort close
	limit := size
	if limit <= 0 || limit > MaxApplyBytes {
		limit = MaxApplyBytes
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("remote file read target: %w", err)
	}
	if int64(len(data)) > MaxApplyBytes {
		return nil, fmt.Errorf("existing file exceeds %d-byte apply limit", MaxApplyBytes)
	}
	return data, nil
}

func writePrivateFile(client *sftp.Client, remotePath string, data []byte) error {
	file, err := client.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // best-effort close
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Close()
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

func (c *SSHClient) applyWithSudo(req ApplyRequest) (*ApplyOutcome, error) {
	if c.config.SudoPassword == "" {
		return nil, fmt.Errorf("sudo apply requires a resolved sudo password")
	}
	home, err := c.RemoteHome()
	if err != nil {
		return nil, err
	}
	stagingDir := path.Join(home, applyStagingDir)
	client, clientErr := sftp.NewClient(c.client)
	if clientErr != nil {
		return nil, fmt.Errorf("open SFTP session: %w", clientErr)
	}
	defer func() { _ = client.Close() }() //nolint:errcheck // best-effort close

	if mkdirErr := mkdirAllPrivate(client, stagingDir); mkdirErr != nil {
		return nil, mkdirErr
	}
	random := make([]byte, 12)
	if _, randErr := rand.Read(random); randErr != nil {
		return nil, fmt.Errorf("generate staging name: %w", randErr)
	}
	staging := path.Join(stagingDir, hex.EncodeToString(random)+".new")
	if stageErr := writePrivateFile(client, staging, req.Payload); stageErr != nil {
		return nil, fmt.Errorf("stage payload: %w", stageErr)
	}
	defer func() { _ = client.Remove(staging) }() //nolint:errcheck // best-effort staging cleanup

	backupDir := strings.TrimSpace(req.BackupDir)
	if backupDir == "" {
		backupDir = path.Join(home, defaultApplyBackupDir)
	}
	script, err := buildApplySudoScript(req, staging, backupDir)
	if err != nil {
		return nil, err
	}
	result, runErr := c.RunScript(script, true)
	if runErr != nil {
		return nil, runErr
	}
	return parseApplyScriptReport(result)
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
TARGET='%s'
STAGING='%s'
BACKUP_DIR='%s'
EXPECT='%s'
WANT_BACKUP='%s'
FORCE='%s'
PAYLOAD_SHA='%s'

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  fi
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

emit() {
  printf '%%s\n' "$1"
}

if [ -L "$TARGET" ]; then
  emit '{"status":"blocked","error":"target is a symlink"}'
  exit 2
fi
if [ -e "$TARGET" ] && [ ! -f "$TARGET" ]; then
  emit '{"status":"blocked","error":"target is not a regular file"}'
  exit 2
fi
if [ ! -f "$STAGING" ]; then
  emit '{"status":"remote_io","error":"staged payload is missing"}'
  exit 4
fi

created=false
before=""
mode="0600"
if [ -f "$TARGET" ]; then
  before=$(hash_file "$TARGET")
  mode=$(file_mode "$TARGET")
  if [ "$FORCE" != "1" ] && [ -n "$EXPECT" ] && [ "$before" != "$EXPECT" ]; then
    emit "{\"status\":\"precondition\",\"before\":\"$before\",\"error\":\"hash mismatch\"}"
    exit 3
  fi
  if [ "$before" = "$PAYLOAD_SHA" ]; then
    emit "{\"status\":\"ok\",\"changed\":false,\"created\":false,\"before\":\"$before\",\"after\":\"$before\",\"mode\":\"$mode\"}"
    exit 0
  fi
else
  created=true
  if [ "$FORCE" != "1" ] && [ -n "$EXPECT" ]; then
    emit '{"status":"precondition","error":"target does not exist"}'
    exit 3
  fi
fi

backup=""
if [ "$WANT_BACKUP" = "1" ] && [ "$created" = "false" ]; then
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR" || true
  short=$(printf '%%s' "$before" | cut -c1-12)
  stamp=$(date -u +%%Y%%m%%dT%%H%%M%%SZ)
  backup="$BACKUP_DIR/$(basename "$TARGET").$stamp.$short"
  cp -p "$TARGET" "$backup"
  chmod 600 "$backup" || true
fi

dir=$(dirname "$TARGET")
tmp="$dir/.$(basename "$TARGET").sshx.$$.tmp"
cp "$STAGING" "$tmp"
if [ "$created" = "false" ]; then
  chmod "$mode" "$tmp"
  chown "$(file_uid "$TARGET"):$(file_gid "$TARGET")" "$tmp"
else
  chmod 600 "$tmp"
fi
mv -f "$tmp" "$TARGET"
after=$(hash_file "$TARGET")
if [ "$after" != "$PAYLOAD_SHA" ]; then
  emit '{"status":"remote_io","error":"post-apply hash mismatch"}'
  exit 4
fi
emit "{\"status\":\"ok\",\"changed\":true,\"created\":$created,\"before\":\"$before\",\"after\":\"$after\",\"backup\":\"$backup\",\"mode\":\"$mode\"}"
`, req.RemotePath, staging, backupDir, req.ExpectSHA256, wantBackup, force, SHA256Hex(req.Payload))
	return []byte(script), nil
}

func parseApplyScriptReport(result ExecResult) (*ApplyOutcome, error) {
	if result.ExitCode == 0 {
		report, err := decodeApplyScriptReport(result.Stdout)
		if err != nil {
			return nil, err
		}
		return &ApplyOutcome{
			Changed:      report.Changed,
			Created:      report.Created,
			BeforeSHA256: report.Before,
			AfterSHA256:  report.After,
			BackupPath:   report.Backup,
			Mode:         report.Mode,
		}, nil
	}
	report, decodeErr := decodeApplyScriptReport(result.Stdout)
	if decodeErr != nil {
		return nil, fmt.Errorf("privileged apply failed with status %d: %s", result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	switch report.Status {
	case "precondition":
		if report.Before != "" {
			return nil, fmt.Errorf("%w: have %s", ErrPrecondition, report.Before)
		}
		return nil, fmt.Errorf("%w: %s", ErrPrecondition, emptyFallback(report.Error, "target mismatch"))
	case "blocked":
		return nil, fmt.Errorf("%w: %s", ErrApplyBlocked, emptyFallback(report.Error, "target refused"))
	default:
		return nil, fmt.Errorf("remote file %s", emptyFallback(report.Error, "privileged apply failed"))
	}
}

func decodeApplyScriptReport(stdout string) (applyScriptReport, error) {
	line := strings.TrimSpace(stdout)
	if idx := strings.LastIndex(line, "{"); idx >= 0 {
		line = line[idx:]
	}
	var report applyScriptReport
	if err := json.Unmarshal([]byte(line), &report); err != nil {
		return applyScriptReport{}, fmt.Errorf("parse privileged apply result: %w", err)
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
