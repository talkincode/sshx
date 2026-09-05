package sshclient

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ErrorKindCancelled retains the released machine-readable spelling.
const ErrorKindCancelled = "cancelled" //nolint:misspell // contract spelling

// BoundaryError preserves protocol errors while exposing a machine-readable kind
// without importing the execution package.
type BoundaryError struct {
	Kind string
	Op   string
	Err  error
}

func (e *BoundaryError) Error() string     { return fmt.Sprintf("%s: %v", e.Op, e.Err) }
func (e *BoundaryError) Unwrap() error     { return e.Err }
func (e *BoundaryError) ErrorKind() string { return e.Kind }

func boundaryError(kind, op string, err error) error {
	if err == nil {
		return nil
	}
	var typed interface{ ErrorKind() string }
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrCommandTimeout):
		kind = "timeout"
	case errors.Is(err, context.Canceled):
		kind = ErrorKindCancelled
	case errors.As(err, &typed):
		if kind != "verification_failed" {
			kind = typed.ErrorKind()
		}
	default:
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			kind = "timeout"
		}
	}
	return &BoundaryError{Kind: kind, Op: op, Err: err}
}

func (c *SSHClient) transportContext() context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		ctx := context.Background()
		if c.config != nil && c.config.Context != nil {
			ctx = c.config.Context
		}
		c.ctx, c.cancel = context.WithCancel(ctx)
		if c.closed {
			c.cancel()
		}
		context.AfterFunc(c.ctx, func() {
			_ = c.Close() //nolint:errcheck // cancellation must tear down the owned socket
		})
	}
	return c.ctx
}

func (c *SSHClient) transportError(kind, op string, err error) error {
	if cause := c.transportContext().Err(); cause != nil {
		return boundaryError(kind, op, cause)
	}
	return boundaryError(kind, op, err)
}

func (c *SSHClient) sshConnection() (*ssh.Client, error) {
	if err := c.transportContext().Err(); err != nil {
		return nil, boundaryError("connect", "SSH connection", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.client == nil {
		return nil, boundaryError("connect", "SSH connection", net.ErrClosed)
	}
	return c.client, nil
}

func (c *SSHClient) newSFTPClient() (*sftp.Client, error) {
	conn, err := c.sshConnection()
	if err != nil {
		return nil, err
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		return nil, c.transportError("remote_io", "open SFTP session", err)
	}
	if err := c.transportContext().Err(); err != nil {
		_ = client.Close() //nolint:errcheck // the transport is already canceled
		return nil, boundaryError("remote_io", "open SFTP session", err)
	}
	return client, nil
}

// PeerAddress is the actual connected TCP peer, not the configured DNS name.
func (c *SSHClient) PeerAddress() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerAddress
}

// HostKeyFingerprint identifies the verified key observed on the connection.
func (c *SSHClient) HostKeyFingerprint() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hostKeyFingerprint
}
