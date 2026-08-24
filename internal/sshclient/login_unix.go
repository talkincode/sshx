//go:build unix

package sshclient

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func InteractiveLoginSupported() bool { return true }

func (c *SSHClient) loginSession() error {
	if !StdinIsTerminal() {
		return ErrLoginNotTTY
	}

	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create login session: %w", err)
	}
	defer func() { _ = session.Close() }() //nolint:errcheck // best-effort session teardown

	fd := int(os.Stdin.Fd())
	width, height := terminalSize(fd)
	termName := os.Getenv("TERM")
	if termName == "" {
		termName = "xterm-256color"
	}

	echo := uint32(1)
	if c.config.LoginUseSudo {
		echo = 0
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          echo,
		ssh.ECHOCTL:       0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if ptyErr := session.RequestPty(termName, height, width, modes); ptyErr != nil {
		return fmt.Errorf("failed to request login PTY: %w", ptyErr)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to open login stdin: %w", err)
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	state, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("failed to put local terminal in raw mode: %w", err)
	}
	defer func() { _ = term.Restore(fd, state) }() //nolint:errcheck // always try to restore the TTY

	if c.config.LoginUseSudo {
		if c.config.SudoPassword == "" {
			return fmt.Errorf("login --sudo requires a resolved sudo password")
		}
		if startErr := session.Start(PrivilegedLoginCommand); startErr != nil {
			return fmt.Errorf("failed to start privileged login shell: %w", startErr)
		}
		if _, writeErr := io.WriteString(stdin, c.config.SudoPassword+"\n"); writeErr != nil {
			return fmt.Errorf("failed to deliver sudo password: %w", writeErr)
		}
	} else if startErr := session.Shell(); startErr != nil {
		return fmt.Errorf("failed to start login shell: %w", startErr)
	}

	done := make(chan struct{})
	go watchWindowChanges(session, fd, done)
	go func() {
		_, _ = io.Copy(stdin, os.Stdin) //nolint:errcheck // session close unblocks copy
		_ = stdin.Close()               //nolint:errcheck // best-effort close after local stdin EOF
	}()

	waitErr := session.Wait()
	close(done)
	return waitErr
}

func terminalSize(fd int) (width, height int) {
	width, height, err := term.GetSize(fd)
	if err != nil || width <= 0 || height <= 0 {
		return 80, 24
	}
	return width, height
}

func watchWindowChanges(session *ssh.Session, fd int, done <-chan struct{}) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	defer signal.Stop(ch)
	for {
		select {
		case <-done:
			return
		case <-ch:
			width, height := terminalSize(fd)
			_ = session.WindowChange(height, width) //nolint:errcheck // best-effort resize
		}
	}
}
