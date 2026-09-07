package sshclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/talkincode/sshx/pkg/logger"
	"golang.org/x/crypto/ssh"
)

var dialTCP = defaultDialTCP

func defaultDialTCP(ctx context.Context, addr string, localAddr net.Addr, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, LocalAddr: localAddr}
	return d.DialContext(ctx, "tcp", addr)
}

// ConnectDirect uses one budget for TCP, SSH negotiation, and any allowed
// password fallback. The connection remains owned by Config.Context afterward.
func (c *SSHClient) ConnectDirect() error {
	return c.connectThrough(nil)
}

// Connect establishes any configured jump chain, then the target session.
// Jump sessions are owned by this client and closed with it.
func (c *SSHClient) Connect() error {
	if c == nil || c.config == nil {
		return boundaryError("config", "connect", fmt.Errorf("client is not configured"))
	}
	var parent *ssh.Client
	for _, hop := range c.config.JumpChain {
		if hop == nil {
			c.closeOwnedJumps()
			return hopError("jump", hop, fmt.Errorf("jump config is required"))
		}
		hopCopy := *hop
		hopCopy.JumpChain = nil
		if hopCopy.Context == nil {
			hopCopy.Context = c.config.Context
		}
		hopClient, err := NewSSHClient(&hopCopy)
		if err != nil {
			c.closeOwnedJumps()
			return hopError("jump", hop, err)
		}
		if hopErr := hopClient.connectThrough(parent); hopErr != nil {
			_ = hopClient.Close() //nolint:errcheck // failed hop
			c.closeOwnedJumps()
			return hopError("jump", hop, hopErr)
		}
		c.mu.Lock()
		c.ownedJumps = append(c.ownedJumps, hopClient)
		c.mu.Unlock()
		parent, err = hopClient.sshConnection()
		if err != nil {
			c.closeOwnedJumps()
			return hopError("jump", hop, err)
		}
	}
	return c.connectThrough(parent)
}

func (c *SSHClient) closeOwnedJumps() {
	c.mu.Lock()
	owned := c.ownedJumps
	c.ownedJumps = nil
	c.mu.Unlock()
	for i := len(owned) - 1; i >= 0; i-- {
		_ = owned[i].Close() //nolint:errcheck // best-effort hop teardown
	}
}

func (c *SSHClient) connectThrough(parent *ssh.Client) (err error) {
	ctx := c.transportContext()
	if contextErr := ctx.Err(); contextErr != nil {
		return boundaryError("connect", "connect", contextErr)
	}
	c.mu.Lock()
	if c.connecting || c.client != nil || c.closed {
		c.mu.Unlock()
		return boundaryError("connect", "connect", fmt.Errorf("client already connected or closed"))
	}
	c.connecting = true
	c.mu.Unlock()
	defer func() {
		if err != nil {
			_ = c.Close() //nolint:errcheck // failed attempts must release cancellation registrations
		}
		c.mu.Lock()
		c.connecting = false
		c.mu.Unlock()
	}()
	timeout := c.config.DialTimeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	lifetime := ctx
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lg := logger.GetLogger()
	var keyAuth ssh.AuthMethod
	var passwordAuth ssh.AuthMethod
	if c.config.UseKeyAuth && c.config.KeyPath != "" {
		keyPath := c.config.KeyPath
		if strings.HasPrefix(keyPath, "~/") {
			if home, homeErr := os.UserHomeDir(); homeErr == nil {
				keyPath = filepath.Join(home, keyPath[2:])
			}
		}
		key, keyErr := os.ReadFile(keyPath) // #nosec G304 -- operator-selected SSH key path is intentionally read.
		var signer ssh.Signer
		if keyErr == nil {
			signer, keyErr = ssh.ParsePrivateKey(key)
		}
		if keyErr != nil {
			if c.config.ExpectedKeyFingerprint != "" {
				return boundaryError("auth", "load admitted signing key", keyErr)
			}
			lg.Warning("failed to load SSH key %s: %v", keyPath, keyErr)
		} else {
			if expected := c.config.ExpectedKeyFingerprint; expected != "" && ssh.FingerprintSHA256(signer.PublicKey()) != expected {
				return boundaryError("auth", "check admitted signing key", fmt.Errorf("signing key fingerprint changed"))
			}
			keyAuth = ssh.PublicKeys(signer)
		}
	}
	if c.config.ExpectedKeyFingerprint != "" && keyAuth == nil {
		return boundaryError("auth", "check admitted signing key", fmt.Errorf("admitted signing key is unavailable"))
	}
	if c.config.Password != "" {
		passwordAuth = ssh.Password(c.config.Password)
	}
	if keyAuth == nil && passwordAuth == nil {
		return boundaryError("auth", "configure authentication", fmt.Errorf("no authentication method available"))
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return boundaryError("connect", "connect", contextErr)
	}

	// Callback-local state cannot race with consumers reading the legacy Config.
	trustConfig := *c.config
	hostKeyCallback, err := getHostKeyCallback(&trustConfig)
	if err != nil {
		return boundaryError("host_key", "configure host key verification", err)
	}
	var localAddr net.Addr
	if parent == nil {
		resolved, bindErr := ResolveBind(c.config.Bind, c.config.Host)
		if bindErr != nil {
			return boundaryError("config", "resolve bind", bindErr)
		}
		localAddr = resolved
	}
	addr := net.JoinHostPort(c.config.Host, c.config.Port)
	callback := func(host string, remote net.Addr, key ssh.PublicKey) error {
		// SSH also invokes this callback during rekey, after the dial budget
		// has been released. Only the transport lifetime applies then.
		if contextErr := lifetime.Err(); contextErr != nil {
			return boundaryError("connect", "verify host key", contextErr)
		}
		if verifyErr := hostKeyCallback(host, remote, key); verifyErr != nil {
			return boundaryError("host_key", "verify host key", verifyErr)
		}
		c.mu.Lock()
		c.hostKeyFingerprint = ssh.FingerprintSHA256(key)
		c.mu.Unlock()
		return nil
	}
	dialWithAuth := func(method ssh.AuthMethod) (*ssh.Client, error) {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		deadline, _ := ctx.Deadline()
		var conn net.Conn
		var dialErr error
		if parent == nil {
			conn, dialErr = dialTCP(ctx, addr, localAddr, time.Until(deadline))
		} else {
			conn, dialErr = dialJump(ctx, parent, addr)
		}
		if dialErr != nil {
			return nil, boundaryError("connect", "dial "+addr, dialErr)
		}
		c.mu.Lock()
		if c.closed || ctx.Err() != nil {
			c.mu.Unlock()
			_ = conn.Close() //nolint:errcheck // late dial must not escape ownership
			if cause := ctx.Err(); cause != nil {
				return nil, cause
			}
			return nil, context.Canceled
		}
		c.conn = conn
		c.mu.Unlock()
		if parent == nil {
			if deadlineErr := conn.SetDeadline(deadline); deadlineErr != nil {
				_ = conn.Close() //nolint:errcheck // failed setup
				return nil, deadlineErr
			}
		}
		// The hook is joined before deadline clearing; a late callback must
		// never close a successfully admitted transport.
		stopped := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			_ = conn.Close() //nolint:errcheck // handshake cancellation
			close(stopped)
		})
		sshConn, chans, reqs, handshakeErr := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
			User: c.config.User, Auth: []ssh.AuthMethod{method}, HostKeyCallback: callback,
		})
		if !stop() {
			<-stopped
		}
		if handshakeErr != nil {
			_ = conn.Close() //nolint:errcheck // failed handshake
			if cause := ctx.Err(); cause != nil {
				return nil, cause
			}
			if isAuthenticationFailure(handshakeErr) {
				return nil, boundaryError("auth", "authenticate", handshakeErr)
			}
			return nil, boundaryError("connect", "SSH handshake", handshakeErr)
		}
		if cause := ctx.Err(); cause != nil {
			_ = conn.Close() //nolint:errcheck // deadline won admission race
			return nil, cause
		}
		if parent == nil {
			if deadlineErr := conn.SetDeadline(time.Time{}); deadlineErr != nil {
				_ = conn.Close() //nolint:errcheck // failed setup
				return nil, deadlineErr
			}
		}
		return ssh.NewClient(sshConn, chans, reqs), nil
	}
	method, authUsed := passwordAuth, AuthMethodPassword
	if keyAuth != nil {
		method, authUsed = keyAuth, AuthMethodKey
	}
	client, err := dialWithAuth(method)
	if shouldFallbackToPassword(err, keyAuth != nil, passwordAuth != nil) && ctx.Err() == nil {
		client, err = dialWithAuth(passwordAuth)
		authUsed = AuthMethodPasswordFallback
	}
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			err = cause
		}
		return boundaryError("connect", "establish SSH connection", err)
	}
	c.mu.Lock()
	if c.closed || ctx.Err() != nil {
		c.mu.Unlock()
		_ = client.Close() //nolint:errcheck // cancellation won publication race
		cause := ctx.Err()
		if cause == nil {
			cause = context.Canceled
		}
		return boundaryError("connect", "establish SSH connection", cause)
	}
	c.client, c.authMethodUsed = client, authUsed
	c.peerAddress = client.RemoteAddr().String()
	c.config.HostKeyFingerprint = c.hostKeyFingerprint
	c.mu.Unlock()
	return nil
}

func isAuthenticationFailure(err error) bool {
	var serverErr *ssh.ServerAuthError
	if errors.As(err, &serverErr) {
		return true
	}
	// x/crypto/ssh has no typed client-side authentication failure.
	return err != nil && strings.Contains(err.Error(), "ssh: unable to authenticate, attempted methods")
}

func shouldFallbackToPassword(err error, hadKeyAuth bool, hasPassword bool) bool {
	if !hadKeyAuth || !hasPassword || err == nil {
		return false
	}
	var typed interface{ ErrorKind() string }
	if errors.As(err, &typed) && typed.ErrorKind() != "auth" {
		return false
	}
	return isAuthenticationFailure(err)
}
