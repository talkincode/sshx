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
func (c *SSHClient) ConnectDirect() (err error) {
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
		key, keyErr := os.ReadFile(keyPath) //nolint:gosec // caller-supplied key path
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
	localAddr, err := ResolveBind(c.config.Bind, c.config.Host)
	if err != nil {
		return boundaryError("config", "resolve bind", err)
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
		conn, dialErr := dialTCP(ctx, addr, localAddr, time.Until(deadline))
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
		if deadlineErr := conn.SetDeadline(deadline); deadlineErr != nil {
			_ = conn.Close() //nolint:errcheck // failed setup
			return nil, deadlineErr
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
		if deadlineErr := conn.SetDeadline(time.Time{}); deadlineErr != nil {
			_ = conn.Close() //nolint:errcheck // failed setup
			return nil, deadlineErr
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
