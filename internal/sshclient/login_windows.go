//go:build windows

package sshclient

import "fmt"

func InteractiveLoginSupported() bool { return false }

func (c *SSHClient) loginSession() error {
	return fmt.Errorf("%w: use OpenSSH ssh from a POSIX host", ErrLoginUnsupported)
}
