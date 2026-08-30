package sshclient

import (
	"errors"
	"os"

	"golang.org/x/crypto/ssh"
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

func loginTermName() string {
	if name := os.Getenv("TERM"); name != "" {
		return name
	}
	return "xterm-256color"
}

// loginPtyModes is the cooked UTF-8 tty state OpenSSH typically sends with
// pty-req. A sparse ECHO-only list leaves IUTF8/ONLCR/ICRNL at the PTY
// allocator default, which on some hosts makes zsh/zle and autosuggestions
// reprint typed characters.
func loginPtyModes(sudo bool) ssh.TerminalModes {
	echo := uint32(1)
	echoCtl := uint32(1)
	if sudo {
		echo = 0
		echoCtl = 0
	}
	return ssh.TerminalModes{
		ssh.VINTR:         3,
		ssh.VQUIT:         28,
		ssh.VERASE:        127,
		ssh.VKILL:         21,
		ssh.VEOF:          4,
		ssh.VSTART:        17,
		ssh.VSTOP:         19,
		ssh.VSUSP:         26,
		ssh.IGNPAR:        0,
		ssh.INLCR:         0,
		ssh.IGNCR:         0,
		ssh.ICRNL:         1,
		ssh.IUCLC:         0,
		ssh.IXON:          1,
		ssh.IXANY:         1,
		ssh.IXOFF:         0,
		ssh.IMAXBEL:       1,
		ssh.IUTF8:         1,
		ssh.ISIG:          1,
		ssh.ICANON:        1,
		ssh.ECHO:          echo,
		ssh.ECHOE:         1,
		ssh.ECHOK:         1,
		ssh.ECHONL:        0,
		ssh.IEXTEN:        1,
		ssh.ECHOCTL:       echoCtl,
		ssh.ECHOKE:        1,
		ssh.OPOST:         1,
		ssh.ONLCR:         1,
		ssh.OCRNL:         0,
		ssh.CS8:           1,
		ssh.PARENB:        0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
}

func loginEnvVars() [][2]string {
	keys := []string{"LANG", "LC_ALL", "LC_CTYPE", "COLORTERM"}
	out := make([][2]string, 0, len(keys))
	for _, key := range keys {
		if val := os.Getenv(key); val != "" {
			out = append(out, [2]string{key, val})
		}
	}
	return out
}
