package sshclient

import (
	"fmt"
	"io"
	"os"
	"path"

	"github.com/pkg/sftp"
	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
)

// TransferTo streams files from this client's remote host directly to the
// destination client's remote host over SFTP, relaying the data through the
// local machine without writing it to local disk. It supports single files
// and recursive directory transfers.
func (c *SSHClient) TransferTo(dst *SSHClient, srcPath, dstPath string) (err error) {
	if srcPath == "" || dstPath == "" {
		return fmt.Errorf("both source and destination paths are required")
	}

	srcSftp, err := sftp.NewClient(c.client)
	if err != nil {
		return fmt.Errorf("failed to create SFTP client on source host: %w", err)
	}
	defer errutil.HandleCloseError(&err, srcSftp)

	dstSftp, err := sftp.NewClient(dst.client)
	if err != nil {
		return fmt.Errorf("failed to create SFTP client on destination host: %w", err)
	}
	defer errutil.HandleCloseError(&err, dstSftp)

	srcStat, err := srcSftp.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("failed to stat source path %s: %w", srcPath, err)
	}

	// If the destination is an existing directory, place the source inside it.
	if dstStat, statErr := dstSftp.Stat(dstPath); statErr == nil && dstStat.IsDir() {
		dstPath = remotePathJoin(dstPath, path.Base(srcPath))
	}

	if srcStat.IsDir() {
		return transferDirectory(srcSftp, dstSftp, srcPath, dstPath)
	}
	return transferFile(srcSftp, dstSftp, srcPath, dstPath, srcStat.Mode())
}

// transferDirectory recursively copies a remote directory tree from the
// source SFTP session to the destination SFTP session.
func transferDirectory(srcSftp, dstSftp *sftp.Client, srcDir, dstDir string) error {
	if err := dstSftp.MkdirAll(dstDir); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dstDir, err)
	}

	entries, err := srcSftp.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("failed to read source directory %s: %w", srcDir, err)
	}

	for _, entry := range entries {
		srcEntry := remotePathJoin(srcDir, entry.Name())
		dstEntry := remotePathJoin(dstDir, entry.Name())

		switch {
		case entry.IsDir():
			if err := transferDirectory(srcSftp, dstSftp, srcEntry, dstEntry); err != nil {
				return err
			}
		case entry.Mode().IsRegular():
			if err := transferFile(srcSftp, dstSftp, srcEntry, dstEntry, entry.Mode()); err != nil {
				return err
			}
		default:
			logger.GetLogger().Warning("Skipping non-regular file: %s", srcEntry)
		}
	}
	return nil
}

// transferFile streams a single remote file from the source SFTP session to
// the destination SFTP session and preserves the file permission bits.
func transferFile(srcSftp, dstSftp *sftp.Client, srcPath, dstPath string, mode os.FileMode) (err error) {
	lg := logger.GetLogger()

	srcFile, err := srcSftp.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", srcPath, err)
	}
	defer errutil.HandleCloseError(&err, srcFile)

	if dir := path.Dir(dstPath); dir != "." && dir != "/" {
		if mkErr := dstSftp.MkdirAll(dir); mkErr != nil {
			return fmt.Errorf("failed to create destination directory %s: %w", dir, mkErr)
		}
	}

	dstFile, err := dstSftp.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dstPath, err)
	}
	defer errutil.HandleCloseError(&err, dstFile)

	lg.Info("Transferring: %s → %s", srcPath, dstPath)

	written, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("failed to transfer file %s: %w", srcPath, err)
	}

	if chmodErr := dstSftp.Chmod(dstPath, mode.Perm()); chmodErr != nil {
		lg.Warning("failed to preserve permissions on %s: %v", dstPath, chmodErr)
	}

	lg.Success("Transferred %d bytes: %s", written, dstPath)
	return nil
}
