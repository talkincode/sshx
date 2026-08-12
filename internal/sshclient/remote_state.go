package sshclient

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
)

// RemoteHome resolves the authenticated user's home directory through SFTP.
func (c *SSHClient) RemoteHome() (string, error) {
	client, err := sftp.NewClient(c.client)
	if err != nil {
		return "", fmt.Errorf("open SFTP session: %w", err)
	}
	defer func() { _ = client.Close() }() //nolint:errcheck // best-effort close after read-only query
	home, err := client.RealPath(".")
	if err != nil {
		return "", fmt.Errorf("resolve remote home: %w", err)
	}
	if !path.IsAbs(home) {
		return "", fmt.Errorf("remote home is not absolute: %q", home)
	}
	return path.Clean(home), nil
}

// ReadRemoteFile reads a restrictive, regular remote file with a hard size
// bound. Symlinks and group/world-accessible files fail closed.
func (c *SSHClient) ReadRemoteFile(remotePath string, limit int64, expectedUID string) ([]byte, error) {
	if err := validateAbsoluteRemotePath(remotePath); err != nil {
		return nil, err
	}
	client, clientErr := sftp.NewClient(c.client)
	if clientErr != nil {
		return nil, fmt.Errorf("open SFTP session: %w", clientErr)
	}
	defer func() { _ = client.Close() }() //nolint:errcheck // best-effort close
	info, statErr := client.Lstat(remotePath)
	if statErr != nil {
		return nil, statErr
	}
	if parentErr := validateRemoteStateParents(client, path.Dir(remotePath), expectedUID); parentErr != nil {
		return nil, parentErr
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("remote state is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("remote state has unsafe permissions %04o", info.Mode().Perm())
	}
	if ownerErr := validateRemoteOwner(info, expectedUID); ownerErr != nil {
		return nil, ownerErr
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("remote state exceeds %d-byte limit", limit)
	}
	file, openErr := client.Open(remotePath)
	if openErr != nil {
		return nil, openErr
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // best-effort close
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	if readErr != nil {
		return nil, readErr
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("remote state exceeds %d-byte limit", limit)
	}
	return data, nil
}

func validateRemoteStateParents(client *sftp.Client, dir, expectedUID string) error {
	managedRoot, err := remoteManagedRoot(dir)
	if err != nil {
		return err
	}
	current := dir
	for {
		info, err := client.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect remote directory %s: %w", current, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("remote state path contains a non-directory or symlink: %s", current)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("remote state directory has unsafe permissions %04o: %s", info.Mode().Perm(), current)
		}
		if err := validateRemoteOwner(info, expectedUID); err != nil {
			return fmt.Errorf("remote state directory %s: %w", current, err)
		}
		if current == managedRoot {
			break
		}
		current = path.Dir(current)
	}
	return nil
}

func validateRemoteOwner(info os.FileInfo, expectedUID string) error {
	if expectedUID == "" {
		return nil
	}
	uid, err := strconv.ParseUint(expectedUID, 10, 32)
	if err != nil {
		return fmt.Errorf("target uid %q is invalid", expectedUID)
	}
	stat, ok := info.Sys().(*sftp.FileStat)
	if !ok {
		return fmt.Errorf("remote state ownership is unavailable")
	}
	if stat.UID != uint32(uid) {
		return fmt.Errorf("remote state owner uid %d does not match authenticated uid %d", stat.UID, uid)
	}
	return nil
}

// WriteRemoteFileAtomic writes state through a unique 0600 file in the same
// directory, then atomically renames it over the destination.
func (c *SSHClient) WriteRemoteFileAtomic(remotePath string, data []byte) error {
	if err := validateAbsoluteRemotePath(remotePath); err != nil {
		return err
	}
	client, clientErr := sftp.NewClient(c.client)
	if clientErr != nil {
		return fmt.Errorf("open SFTP session: %w", clientErr)
	}
	defer func() { _ = client.Close() }() //nolint:errcheck // best-effort close
	dir := path.Dir(remotePath)
	if directoryErr := secureRemoteDirectory(client, dir); directoryErr != nil {
		return directoryErr
	}
	random := make([]byte, 12)
	if _, randomErr := rand.Read(random); randomErr != nil {
		return fmt.Errorf("generate remote temp name: %w", randomErr)
	}
	tempPath := path.Join(dir, "."+path.Base(remotePath)+"."+hex.EncodeToString(random)+".tmp")
	file, err := client.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fmt.Errorf("create remote temp file: %w", err)
	}
	cleanup := true
	defer func() {
		_ = file.Close() //nolint:errcheck // best-effort cleanup
		if cleanup {
			_ = client.Remove(tempPath) //nolint:errcheck // best-effort cleanup
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure remote temp file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write remote temp file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close remote temp file: %w", err)
	}
	if err := client.PosixRename(tempPath, remotePath); err != nil {
		return fmt.Errorf("atomically replace remote state: %w", err)
	}
	cleanup = false
	return nil
}

func secureRemoteDirectory(client *sftp.Client, dir string) error {
	if err := validateAbsoluteRemotePath(dir); err != nil {
		return err
	}
	managedRoot, err := remoteManagedRoot(dir)
	if err != nil {
		return err
	}
	relative := strings.TrimPrefix(dir, managedRoot)
	current := managedRoot
	directories := []string{managedRoot}
	for _, component := range strings.Split(strings.TrimPrefix(relative, "/"), "/") {
		if component == "" {
			continue
		}
		current = path.Join(current, component)
		directories = append(directories, current)
	}
	for _, current := range directories {
		info, statErr := client.Lstat(current)
		if statErr != nil {
			if !os.IsNotExist(statErr) {
				return fmt.Errorf("inspect remote directory %s: %w", current, statErr)
			}
			if mkdirErr := client.Mkdir(current); mkdirErr != nil {
				return fmt.Errorf("create remote state directory %s: %w", current, mkdirErr)
			}
			info, statErr = client.Lstat(current)
			if statErr != nil {
				return fmt.Errorf("inspect created remote directory %s: %w", current, statErr)
			}
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("remote state path contains a non-directory or symlink: %s", current)
		}
		if err := client.Chmod(current, 0o700); err != nil {
			return fmt.Errorf("secure remote directory %s: %w", current, err)
		}
		verified, verifyErr := client.Lstat(current)
		if verifyErr != nil {
			return fmt.Errorf("reinspect remote directory %s: %w", current, verifyErr)
		}
		if !verified.IsDir() || verified.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("remote state path changed during validation: %s", current)
		}
	}
	return nil
}

func remoteManagedRoot(dir string) (string, error) {
	const marker = "/.sshx/observations"
	managedIndex := strings.LastIndex(dir, marker)
	if managedIndex < 0 {
		return "", fmt.Errorf("remote state path is outside .sshx/observations")
	}
	afterMarker := dir[managedIndex+len(marker):]
	if afterMarker != "" && !strings.HasPrefix(afterMarker, "/") {
		return "", fmt.Errorf("remote state path is outside .sshx/observations")
	}
	return dir[:managedIndex] + "/.sshx", nil
}

func validateAbsoluteRemotePath(remotePath string) error {
	if !path.IsAbs(remotePath) || path.Clean(remotePath) != remotePath {
		return fmt.Errorf("remote state path must be a clean absolute path")
	}
	if strings.Contains(remotePath, "\x00") {
		return fmt.Errorf("remote state path contains NUL")
	}
	return nil
}
