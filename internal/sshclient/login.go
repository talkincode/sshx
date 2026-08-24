package sshclient

import (
	"errors"
	"os"

	"golang.org/x/term"
)

var (
	// ErrLoginNotTTY is returned when login is requested without a local TTY.
	ErrLoginNotTTY = errors.New("login requires an interactive terminal (stdin is not a TTY)")
	// ErrLoginUnsupported is returned on platforms without a native login session.
	ErrLoginUnsupported = errors.New("interactive login is not supported on this platform")
)

// PrivilegedLoginCommand is the remote program used by login --sudo.
// The sudo password is written to the session stdin ahead of the human TTY;
// it is never interpolated into argv. After authentication, echo is restored
// and a privileged login shell replaces the helper.
const PrivilegedLoginCommand = "sudo -S -p '' sh -c 'stty echo 2>/dev/null; exec sudo -i'"

// StdinIsTerminal reports whether stdin is an interactive terminal.
func StdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// Login attaches the local TTY to a remote interactive session.
// Callers must already have connected the client.
func (c *SSHClient) Login() error {
	if c == nil || c.client == nil {
		return errors.New("login requires an established SSH connection")
	}
	return c.loginSession()
}
