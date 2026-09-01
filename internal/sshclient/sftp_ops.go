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

func (c *SSHClient) ExecuteSftp() (err error) {
	sftpClient, err := sftp.NewClient(c.client)
	if err != nil {
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}
	defer errutil.HandleCloseError(&err, sftpClient)
	c.sftpClient = sftpClient

	switch c.config.SftpAction {
	case "upload":
		return c.uploadFile()
	case "download":
		return c.downloadFile()
	case "list", "ls":
		return c.listFiles()
	case "mkdir":
		return c.makeDirectory()
	case "remove", "rm":
		return c.removeFile()
	default:
		return fmt.Errorf("unknown SFTP action: %s", c.config.SftpAction)
	}
}

func (c *SSHClient) uploadFile() (err error) {
	lg := logger.GetLogger()
	localFile, err := os.Open(c.config.LocalPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer errutil.HandleCloseError(&err, localFile)

	remoteFile, err := c.sftpClient.Create(c.config.RemotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer errutil.HandleCloseError(&err, remoteFile)

	lg.Info("Uploading: %s → %s", c.config.LocalPath, c.config.RemotePath)

	written, err := io.Copy(remoteFile, localFile)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	lg.Success("Uploaded %d bytes successfully", written)
	return nil
}

func (c *SSHClient) downloadFile() (err error) {
	lg := logger.GetLogger()
	remoteFile, err := c.sftpClient.Open(c.config.RemotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %w", err)
	}
	defer errutil.HandleCloseError(&err, remoteFile)

	localFile, err := os.Create(c.config.LocalPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer errutil.HandleCloseError(&err, localFile)

	lg.Info("Downloading: %s → %s", c.config.RemotePath, c.config.LocalPath)

	written, err := io.Copy(localFile, remoteFile)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}

	lg.Success("Downloaded %d bytes successfully", written)
	return nil
}

func (c *SSHClient) listFiles() error {
	lg := logger.GetLogger()
	remotePath := c.config.RemotePath
	if remotePath == "" {
		remotePath = "."
	}

	files, err := c.sftpClient.ReadDir(remotePath)
	if err != nil {
		return fmt.Errorf("failed to list directory: %w", err)
	}

	lg.Info("Directory listing: %s", remotePath)
	fmt.Println("\nPermissions  Size      Modified              Name")
	fmt.Println("-------------------------------------------------------")

	for _, file := range files {
		modeStr := file.Mode().String()
		sizeStr := fmt.Sprintf("%10d", file.Size())
		timeStr := file.ModTime().Format("2006-01-02 15:04:05")

		fmt.Printf("%-12s %s  %s  %s\n", modeStr, sizeStr, timeStr, file.Name())
	}

	fmt.Printf("\nTotal: %d items\n", len(files))
	return nil
}

func (c *SSHClient) makeDirectory() error {
	lg := logger.GetLogger()
	if err := c.sftpClient.MkdirAll(c.config.RemotePath); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	lg.Success("Directory created: %s", c.config.RemotePath)
	return nil
}

func (c *SSHClient) removeFile() error {
	lg := logger.GetLogger()
	stat, err := c.sftpClient.Stat(c.config.RemotePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if stat.IsDir() {
		if err := c.removeDirectory(c.config.RemotePath); err != nil {
			return err
		}
		lg.Success("Directory removed: %s", c.config.RemotePath)
	} else {
		if err := c.sftpClient.Remove(c.config.RemotePath); err != nil {
			return fmt.Errorf("failed to remove file: %w", err)
		}
		lg.Success("File removed: %s", c.config.RemotePath)
	}

	return nil
}

func (c *SSHClient) removeDirectory(path string) error {
	files, err := c.sftpClient.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, file := range files {
		fullPath := remotePathJoin(path, file.Name())
		if file.IsDir() {
			if err := c.removeDirectory(fullPath); err != nil {
				return err
			}
		} else {
			if err := c.sftpClient.Remove(fullPath); err != nil {
				return fmt.Errorf("failed to remove file %s: %w", fullPath, err)
			}
		}
	}

	return c.sftpClient.RemoveDirectory(path)
}

func remotePathJoin(elem ...string) string {
	return path.Join(elem...)
}
