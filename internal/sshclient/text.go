package sshclient

import (
	"fmt"
	"io"
	"os"

	"github.com/pkg/sftp"
)

// RemoteTextMeta describes the byte window opened for dissection.
type RemoteTextMeta struct {
	Size        int64
	StartByte   int64
	SkipPartial bool
}

// OpenRemoteText streams a remote regular file. Symlinks, directories, and
// non-regular files are refused. fromEnd seeks to the tail window.
func (c *SSHClient) OpenRemoteText(remotePath string, fromEnd bool, maxBytes int64) (io.ReadCloser, RemoteTextMeta, error) {
	var meta RemoteTextMeta
	if err := validateAbsoluteRemotePath(remotePath); err != nil {
		return nil, meta, fmt.Errorf("%w: %v", ErrApplyBlocked, err)
	}
	if remotePath == "/" {
		return nil, meta, fmt.Errorf("%w: refusing to scan /", ErrApplyBlocked)
	}
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	client, err := sftp.NewClient(c.client)
	if err != nil {
		return nil, meta, fmt.Errorf("open SFTP session: %w", err)
	}
	info, statErr := client.Lstat(remotePath)
	if statErr != nil {
		_ = client.Close() //nolint:errcheck // open failed
		return nil, meta, statErr
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		_ = client.Close() //nolint:errcheck // rejected path
		return nil, meta, fmt.Errorf("remote path must be a regular file, not a symlink or directory")
	}
	file, openErr := client.Open(remotePath)
	if openErr != nil {
		_ = client.Close() //nolint:errcheck // open failed
		return nil, meta, openErr
	}
	meta.Size = info.Size()
	if fromEnd && meta.Size > maxBytes {
		meta.StartByte = meta.Size - maxBytes
		if _, seekErr := file.Seek(meta.StartByte, io.SeekStart); seekErr != nil {
			_ = file.Close()   //nolint:errcheck // seek failed
			_ = client.Close() //nolint:errcheck // seek failed
			return nil, meta, seekErr
		}
		meta.SkipPartial = true
	}
	return &sftpReadCloser{File: file, session: client}, meta, nil
}

type sftpReadCloser struct {
	*sftp.File
	session *sftp.Client
}

func (f *sftpReadCloser) Close() error {
	fileErr := f.File.Close()
	sessErr := f.session.Close()
	if fileErr != nil {
		return fileErr
	}
	return sessErr
}
