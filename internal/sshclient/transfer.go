package sshclient

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/pkg/sftp"
)

// TransferTo preserves the error-only legacy API.
func (c *SSHClient) TransferTo(dst *SSHClient, srcPath, dstPath string) error {
	_, err := c.TransferToResult(dst, srcPath, dstPath)
	return err
}

// TransferToResult relays through memory with per-file atomic publication where
// supported. Canceling either endpoint tears down both owned transports.
func (c *SSHClient) TransferToResult(dst *SSHClient, srcPath, dstPath string) (out *SFTPOutcome, err error) {
	out = &SFTPOutcome{Action: "transfer", SourcePath: srcPath, DestinationPath: dstPath, Phase: "connect"}
	defer func() { finishSFTPOutcome(out, err) }()
	if dst == nil || srcPath == "" || dstPath == "" {
		out.Phase = "admission"
		return out, boundaryError("config", "transfer", fmt.Errorf("both endpoints and paths are required"))
	}
	ctx, cancel := context.WithCancelCause(c.transportContext())
	defer cancel(nil)
	dstCtx := dst.transportContext()
	destinationStopped := make(chan struct{})
	stopDestination := context.AfterFunc(dstCtx, func() {
		cancel(dstCtx.Err())
		close(destinationStopped)
	})
	closed := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() {
		_ = c.Close()   //nolint:errcheck // both sockets are owned by this transfer
		_ = dst.Close() //nolint:errcheck // source cancellation must unblock destination writes
		close(closed)
	})
	defer func() {
		if !stopDestination() {
			<-destinationStopped
		}
		if !stopClose() {
			<-closed
		}
		if cause := context.Cause(ctx); cause != nil {
			err = boundaryError("remote_io", "transfer", cause)
		} else if err != nil {
			err = boundaryError("remote_io", "transfer", err)
		}
	}()
	if contextErr := ctx.Err(); contextErr != nil {
		return out, contextErr
	}
	if contextErr := dstCtx.Err(); contextErr != nil {
		cancel(contextErr)
		return out, contextErr
	}
	srcSFTP, err := c.newSFTPClient()
	if err != nil {
		return out, err
	}
	defer closeSFTP(srcSFTP, &err)
	dstSFTP, err := dst.newSFTPClient()
	if err != nil {
		return out, err
	}
	defer closeSFTP(dstSFTP, &err)
	out.Phase = "execute"
	srcInfo, err := srcSFTP.Lstat(srcPath)
	if err != nil {
		return out, err
	}
	if dstInfo, statErr := dstSFTP.Lstat(dstPath); statErr == nil && dstInfo.IsDir() {
		dstPath = remotePathJoin(dstPath, path.Base(srcPath))
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return out, statErr
	}
	out.DestinationPath = dstPath
	out.directory = srcInfo.IsDir()
	err = transferEntry(ctx, srcSFTP, dstSFTP, srcPath, dstPath, srcInfo, out)
	out.operationComplete = err == nil
	return out, err
}

func transferEntry(ctx context.Context, source, destination *sftp.Client, srcPath, dstPath string, info os.FileInfo, out *SFTPOutcome) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if info.IsDir() {
		entry := FileOutcome{SourcePath: srcPath, Path: dstPath, Type: "directory", ChangeState: "unchanged", Verification: "not_performed"}
		err := ensureRemoteDirectory(ctx, destination, &entry)
		out.Entries = append(out.Entries, entry)
		if err != nil {
			return err
		}
		files, err := source.ReadDir(srcPath)
		if err != nil {
			return err
		}
		for _, child := range files {
			if err := transferEntry(ctx, source, destination, remotePathJoin(srcPath, child.Name()), remotePathJoin(dstPath, child.Name()), child, out); err != nil {
				return err
			}
		}
		return nil
	}
	entry := FileOutcome{SourcePath: srcPath, Path: dstPath, Type: "file", ChangeState: "unchanged", Verification: "not_performed"}
	defer func() { out.Entries = append(out.Entries, entry) }()
	if !info.Mode().IsRegular() {
		entry.Type, entry.Verification = "other", "unsupported"
		return fmt.Errorf("non-regular transfer source is unsupported: %s", srcPath)
	}
	file, err := source.Open(srcPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // read-only source handle
	if dir := path.Dir(dstPath); dir != "." && dir != "/" {
		directory := FileOutcome{Path: dir, Type: "directory", ChangeState: "unchanged", Verification: "not_performed"}
		err := ensureRemoteDirectory(ctx, destination, &directory)
		if directory.ChangeState != "unchanged" {
			out.Entries = append(out.Entries, directory)
		}
		if err != nil {
			return err
		}
	}
	mode := info.Mode()
	return publishRemoteFile(ctx, destination, file, "remote_io", info.Size(), &mode, &entry)
}
