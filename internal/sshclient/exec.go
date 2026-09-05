package sshclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/talkincode/sshx/pkg/logger"
	"golang.org/x/crypto/ssh"
)

// RunCommand preserves nonzero remote exits as results, not transport errors.
func (c *SSHClient) RunCommand(capture bool) (ExecResult, error) {
	return c.runConfiguredCommand(capture, c.config.UsePTY && !capture)
}

func (c *SSHClient) runConfiguredCommand(capture, pty bool) (ExecResult, error) {
	if c.config.SafetyCheck && !c.config.Force {
		if err := ValidateCommand(c.config.Command); err != nil {
			return ExecResult{ExitCode: -1}, boundaryError("blocked", "validate command", err)
		}
	}
	command := c.config.Command
	var stdin io.Reader
	if c.config.SudoPassword != "" && CommandUsesSudo(command) {
		command = sudoStdinCommand(command)
		stdin = strings.NewReader(c.config.SudoPassword + "\n")
	}
	return c.execute(command, stdin, capture, pty)
}

// RunScript streams a collector without installing it on the remote host.
func (c *SSHClient) RunScript(payload []byte, useSudo bool) (ExecResult, error) {
	return c.RunScriptWithShell(payload, "sh", useSudo)
}

func (c *SSHClient) RunScriptWithShell(payload []byte, shell string, useSudo bool) (ExecResult, error) {
	if shell == "" {
		shell = "sh"
	}
	if !shellNames[shell] {
		return ExecResult{ExitCode: -1}, boundaryError("config", "prepare script", fmt.Errorf("unsupported script shell %q", shell))
	}
	limit := c.config.MaxPayloadBytes
	if limit <= 0 {
		limit = MaxCaptureBytes
	}
	if len(payload) > limit {
		return ExecResult{ExitCode: -1}, boundaryError("config", "prepare script", fmt.Errorf("collector payload exceeds %d-byte limit", limit))
	}
	if useSudo && c.config.SudoPassword == "" {
		return ExecResult{ExitCode: -1}, boundaryError("auth", "prepare script", fmt.Errorf("sudo inspection requires a resolved sudo password"))
	}
	command := shell + " -s --"
	var stdin io.Reader = bytes.NewReader(payload)
	if useSudo {
		command = "sudo -S -p '' " + shell + " -s --"
		stdin = io.MultiReader(strings.NewReader(c.config.SudoPassword+"\n"), bytes.NewReader(payload), strings.NewReader("\n"))
	}
	return c.execute(command, stdin, true, false)
}

// RunCommandWithInput carries caller-prepared data and secrets over stdin.
func (c *SSHClient) RunCommandWithInput(command string, stdin []byte) (ExecResult, error) {
	if strings.TrimSpace(command) == "" {
		return ExecResult{ExitCode: -1}, boundaryError("config", "prepare command", fmt.Errorf("command is empty"))
	}
	return c.execute(command, bytes.NewReader(stdin), true, false)
}

func (c *SSHClient) execute(command string, stdin io.Reader, capture, pty bool) (ExecResult, error) {
	result := ExecResult{ExitCode: -1}
	conn, err := c.sshConnection()
	if err != nil {
		return result, err
	}
	session, err := conn.NewSession()
	if err != nil {
		return result, c.transportError("connect", "create session", err)
	}
	defer func() { _ = session.Close() }() //nolint:errcheck // best-effort session teardown
	session.Stdin = stdin
	if pty {
		modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
		if ptyErr := session.RequestPty("xterm", 80, 40, modes); ptyErr != nil {
			if c.transportContext().Err() != nil {
				return result, c.transportError("connect", "request PTY", ptyErr)
			}
			logger.GetLogger().Warning("failed to request PTY: %v", ptyErr)
		}
	}
	stdout, stderr := newCappedBuffer(c.captureLimit()), newCappedBuffer(c.captureLimit())
	if capture {
		session.Stdout, session.Stderr = stdout, stderr
	} else {
		session.Stdout, session.Stderr = os.Stdout, os.Stderr
	}
	ctx := c.transportContext()
	var cancel context.CancelFunc
	if c.config.Timeout > 0 {
		ctx, cancel = context.WithTimeoutCause(ctx, c.config.Timeout, ErrCommandTimeout)
		defer cancel()
	}
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = c.Close() //nolint:errcheck // socket teardown unblocks Start, Wait and SSH copies
		close(finished)
	})
	err = ctx.Err()
	if err == nil {
		result.StartAttempted = true
		err = session.Start(command)
		if err == nil {
			result.Started = true
			err = session.Wait()
			var exit *ssh.ExitError
			result.ExitObserved = err == nil || errors.As(err, &exit)
			if err == nil {
				result.ExitCode = 0
			} else if exit != nil {
				result.ExitCode = exit.ExitStatus()
			}
		}
	}
	if !stop() {
		<-finished
	}
	if capture {
		result.Stdout, result.Stderr = stdout.String(), stderr.String()
		result.StdoutTruncated, result.StderrTruncated = stdout.Truncated(), stderr.Truncated()
	}
	// An observed exit remains evidence even if the outer budget expires while
	// final output is being drained. Never infer an exit from a local close.
	if cause := ctx.Err(); cause != nil {
		if errors.Is(context.Cause(ctx), ErrCommandTimeout) {
			cause = errors.Join(ErrCommandTimeout, cause)
		}
		return result, boundaryError("remote_io", "execute command", cause)
	}
	if err == nil {
		result.ExitCode = 0
		return result, nil
	}
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		result.ExitCode = exit.ExitStatus()
		return result, nil
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) {
		return result, boundaryError("exit_missing", "execute command", errors.Join(ErrNoExitStatus, err))
	}
	return result, c.transportError("remote_io", "execute command", err)
}

func (c *SSHClient) captureLimit() int {
	if c.config.MaxOutputBytes > 0 {
		return c.config.MaxOutputBytes
	}
	return MaxCaptureBytes
}

// ExecuteCommandWithOutput is the legacy combined-output adapter.
func (c *SSHClient) ExecuteCommandWithOutput() (string, error) {
	useSudo := c.config.SudoPassword != "" && CommandUsesSudo(c.config.Command)
	result, err := c.runConfiguredCommand(true, !useSudo)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", boundaryError("remote_exit", "execute command", fmt.Errorf("remote command exited with status %d: %s", result.ExitCode, result.Stderr))
	}
	output := result.Stdout
	if result.Stderr != "" {
		output += "\n--- STDERR ---\n" + result.Stderr
	}
	return output, nil
}

// ExecResult distinguishes a positive start acknowledgement from observed exit.
// A disconnect after Started does not prove remote termination or rollback.
type ExecResult struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	Started         bool
	ExitObserved    bool
	// StartAttempted without Started means the exec request may have reached
	// the peer but no positive acknowledgement was observed.
	StartAttempted bool
}

const MaxCaptureBytes = 10 << 20

var (
	ErrCommandTimeout = errors.New("command execution timed out")
	ErrNoExitStatus   = errors.New("remote command terminated without exit status")
)

type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newCappedBuffer(limit int) *cappedBuffer { return &cappedBuffer{limit: limit} }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.limit > 0 {
		remaining := c.limit - c.buf.Len()
		if remaining <= 0 {
			c.truncated = true
			return len(p), nil
		}
		if len(p) > remaining {
			if _, err := c.buf.Write(p[:remaining]); err != nil {
				return 0, err
			}
			c.truncated = true
			return len(p), nil
		}
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) String() string  { return c.buf.String() }
func (c *cappedBuffer) Truncated() bool { return c.truncated }

func sudoStdinCommand(command string) string {
	remainder, ok := leadingSudoRemainder(command)
	if !ok {
		return command
	}
	if remainder == "" {
		return "sudo -S -p ''"
	}
	return "sudo -S -p '' " + remainder
}
