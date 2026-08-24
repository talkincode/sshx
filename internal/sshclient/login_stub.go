//go:build !unix && !windows

package sshclient

import "fmt"

func InteractiveLoginSupported() bool { return false }

func (c *SSHClient) loginSession() error {
	return fmt.Errorf("%w", ErrLoginUnsupported)
}
