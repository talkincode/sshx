package sshclient

import (
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

func defaultDialTCP(addr string, localAddr net.Addr, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, LocalAddr: localAddr}
	return d.Dial("tcp", addr)
}

// ConnectDirect establishes a direct SSH connection.
func (c *SSHClient) ConnectDirect() error {
	lg := logger.GetLogger()
	timeout := c.config.DialTimeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	var keyAuthMethods []ssh.AuthMethod
	var passwordAuth ssh.AuthMethod
	c.authMethodUsed = AuthMethodUnknown

	if c.config.UseKeyAuth && c.config.KeyPath != "" {
		keyPath := c.config.KeyPath
		if strings.HasPrefix(keyPath, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				keyPath = filepath.Join(home, keyPath[2:])
			}
		}

		if key, err := os.ReadFile(keyPath); err == nil { //nolint:gosec // G304: key path is provided by user
			signer, signerErr := ssh.ParsePrivateKey(key)
			if signerErr == nil {
				keyAuthMethods = append(keyAuthMethods, ssh.PublicKeys(signer))
				lg.Debug("Using SSH key: %s", keyPath)
			} else {
				lg.Warning("failed to parse SSH key: %v", signerErr)
			}
		} else {
			lg.Warning("failed to read SSH key file %s: %v", keyPath, err)
		}
	}

	if c.config.Password != "" {
		passwordAuth = ssh.Password(c.config.Password)
		lg.Debug("Using password authentication")
	}

	if len(keyAuthMethods) == 0 && passwordAuth == nil {
		return fmt.Errorf("no authentication method available")
	}

	hostKeyCallback, err := getHostKeyCallback(c.config)
	if err != nil {
		return fmt.Errorf("failed to configure host key verification: %w", err)
	}

	dialWithAuth := func(methods []ssh.AuthMethod) (*ssh.Client, error) {
		sshConfig := &ssh.ClientConfig{
			User:            c.config.User,
			Auth:            methods,
			HostKeyCallback: hostKeyCallback,
			Timeout:         timeout,
		}

		addr := net.JoinHostPort(c.config.Host, c.config.Port)
		lg.Debug("Connecting to %s@%s...", c.config.User, addr)

		localAddr, bindErr := ResolveBind(c.config.Bind, c.config.Host)
		if bindErr != nil {
			return nil, bindErr
		}
		if localAddr != nil {
			lg.Debug("Binding source address %s", localAddr.String())
		}

		conn, err := dialTCP(addr, localAddr, timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
		}

		sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
		if err != nil {
			_ = conn.Close() //nolint:errcheck
			return nil, err
		}

		return ssh.NewClient(sshConn, chans, reqs), nil
	}

	if len(keyAuthMethods) > 0 {
		client, err := dialWithAuth(keyAuthMethods)
		if err == nil {
			c.client = client
			c.authMethodUsed = AuthMethodKey
			lg.Debug("Connected successfully")
			return nil
		}

		if shouldFallbackToPassword(err, true, passwordAuth != nil) {
			lg.Warning("Public key authentication failed (%v), retrying with password only", err)
			passwordClient, passErr := dialWithAuth([]ssh.AuthMethod{passwordAuth})
			if passErr == nil {
				c.client = passwordClient
				c.authMethodUsed = AuthMethodPasswordFallback
				lg.Debug("Connected successfully with password fallback")
				return nil
			}
			return fmt.Errorf("failed to establish SSH connection after password fallback: %w", passErr)
		}

		return fmt.Errorf("failed to establish SSH connection: %w", err)
	}

	passwordClient, passErr := dialWithAuth([]ssh.AuthMethod{passwordAuth})
	if passErr == nil {
		c.client = passwordClient
		c.authMethodUsed = AuthMethodPassword
		lg.Debug("Connected successfully with password")
		return nil
	}

	return fmt.Errorf("failed to establish SSH connection: %w", passErr)
}

func shouldFallbackToPassword(err error, hadKeyAuth bool, hasPassword bool) bool {
	if !hadKeyAuth || !hasPassword || err == nil {
		return false
	}
	var serverErr *ssh.ServerAuthError
	if errors.As(err, &serverErr) {
		return true
	}
	// x/crypto/ssh does not expose a client-side authentication error type.
	// It reports this stable RFC 4252 terminal condition after all offered key
	// methods are rejected. Do not fall back on transport or host-key failures.
	return strings.Contains(err.Error(), "ssh: unable to authenticate, attempted methods")
}

// RunCommand executes the configured command and returns a structured result.
//
// When capture is true, stdout and stderr are buffered separately (used for
// --json output). When capture is false they stream live to os.Stdout and
// os.Stderr on independent channels with no PTY, which keeps output clean and
// machine-parseable. A PTY is only requested when UsePTY is set and capture is
// false; note that a PTY merges stderr into stdout.
//
// The returned error is non-nil only for sshx-level failures (validation,
// session setup, timeout, or an abnormal teardown). A remote command that
// exits non-zero is NOT an error here: the status is reported in
