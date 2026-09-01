package sshclient

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
	"golang.org/x/crypto/ssh"
)

func (c *SSHClient) RunCommand(capture bool) (ExecResult, error) {
	lg := logger.GetLogger()
	var result ExecResult

	if c.config.SafetyCheck && !c.config.Force {
		if validateErr := ValidateCommand(c.config.Command); validateErr != nil {
			result.ExitCode = -1
			return result, validateErr
		}
	} else if c.config.Force {
		lg.Warning("Safety check skipped (--force mode)")
	}

	session, err := c.client.NewSession()
	if err != nil {
		result.ExitCode = -1
		return result, fmt.Errorf("failed to create session: %w", err)
	}
	defer func() { _ = session.Close() }() //nolint:errcheck // best-effort session teardown

	command := c.config.Command
	if c.config.SudoPassword != "" && CommandUsesSudo(command) {
		lg.Info("Auto-filling sudo password...")
		command = sudoStdinCommand(command)
		session.Stdin = strings.NewReader(c.config.SudoPassword + "\n")
	}

	if c.config.UsePTY && !capture {
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if ptyErr := session.RequestPty("xterm", 80, 40, modes); ptyErr != nil {
			lg.Warning("failed to request PTY: %v", ptyErr)
		}
	}

	var stdoutBuf, stderrBuf *cappedBuffer
	if capture {
		stdoutBuf = newCappedBuffer(MaxCaptureBytes)
		stderrBuf = newCappedBuffer(MaxCaptureBytes)
		session.Stdout = stdoutBuf
		session.Stderr = stderrBuf
	} else {
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
	}

	lg.Debug("Executing: %s", c.config.Command)
	runErr := runSession(session, command, c.config.Timeout)

	if capture {
		result.Stdout = stdoutBuf.String()
		result.Stderr = stderrBuf.String()
		result.StdoutTruncated = stdoutBuf.Truncated()
		result.StderrTruncated = stderrBuf.Truncated()
	}

	switch {
	case runErr == nil:
		result.ExitCode = 0
		return result, nil
	case errors.Is(runErr, ErrCommandTimeout):
		result.ExitCode = -1
		return result, runErr
	}

	var exitErr *ssh.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitStatus()
		return result, nil
	}

	var missingErr *ssh.ExitMissingError
	if errors.As(runErr, &missingErr) {
		result.ExitCode = -1
		return result, fmt.Errorf("%w: %v", ErrNoExitStatus, runErr)
	}

	result.ExitCode = -1
	return result, fmt.Errorf("command failed: %w", runErr)
}

// RunScript streams a trusted local collector to a fresh SSH session using the
// POSIX shell. The payload is never installed on the target.
func (c *SSHClient) RunScript(payload []byte, useSudo bool) (ExecResult, error) {
	return c.RunScriptWithShell(payload, "sh", useSudo)
}

// RunScriptWithShell streams a trusted local script to a fresh SSH session and
// executes it with the named POSIX-shell-family interpreter. The payload is
// never installed on the target. When useSudo is true, the password and script
// share stdin in that order: sudo consumes one line and the shell consumes the
// remaining bytes.
func (c *SSHClient) RunScriptWithShell(payload []byte, shell string, useSudo bool) (ExecResult, error) {
	var result ExecResult
	if shell == "" {
		shell = "sh"
	}
	if !shellNames[shell] {
		result.ExitCode = -1
		return result, fmt.Errorf("unsupported script shell %q", shell)
	}
	if len(payload) == 0 {
		result.ExitCode = -1
		return result, fmt.Errorf("collector payload is empty")
	}
	if len(payload) > MaxCaptureBytes {
		result.ExitCode = -1
		return result, fmt.Errorf("collector payload exceeds %d-byte limit", MaxCaptureBytes)
	}
	if useSudo && c.config.SudoPassword == "" {
		result.ExitCode = -1
		return result, fmt.Errorf("sudo inspection requires a resolved sudo password")
	}

	session, err := c.client.NewSession()
	if err != nil {
		result.ExitCode = -1
		return result, fmt.Errorf("failed to create collector session: %w", err)
	}
	defer func() { _ = session.Close() }() //nolint:errcheck // best-effort session teardown

	command := shell + " -s --"
	stdin := bytes.NewReader(payload)
	if useSudo {
		command = "sudo -S -p '' " + shell + " -s --"
		stdin = bytes.NewReader(append(append([]byte(c.config.SudoPassword+"\n"), payload...), '\n'))
	}
	session.Stdin = stdin
	stdoutBuf := newCappedBuffer(MaxCaptureBytes)
	stderrBuf := newCappedBuffer(MaxCaptureBytes)
	session.Stdout = stdoutBuf
	session.Stderr = stderrBuf

	runErr := runSession(session, command, c.config.Timeout)
	result.Stdout = stdoutBuf.String()
	result.Stderr = stderrBuf.String()
	result.StdoutTruncated = stdoutBuf.Truncated()
	result.StderrTruncated = stderrBuf.Truncated()

	switch {
	case runErr == nil:
		result.ExitCode = 0
		return result, nil
	case errors.Is(runErr, ErrCommandTimeout):
		result.ExitCode = -1
		return result, runErr
	}
	var exitErr *ssh.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitStatus()
		return result, nil
	}
	var missingErr *ssh.ExitMissingError
	if errors.As(runErr, &missingErr) {
		result.ExitCode = -1
		return result, fmt.Errorf("%w: %v", ErrNoExitStatus, runErr)
	}
	result.ExitCode = -1
	return result, fmt.Errorf("collector failed: %w", runErr)
}

// RunCommandWithInput runs a caller-assembled command on a fresh SSH session
// with the given bytes streamed to its stdin, capturing separated output. It
// is used by the sql mode, whose commands are built from validated templates
// and may carry a leading secret line on stdin (never in argv).
func (c *SSHClient) RunCommandWithInput(command string, stdin []byte) (ExecResult, error) {
	var result ExecResult
	if strings.TrimSpace(command) == "" {
		result.ExitCode = -1
		return result, fmt.Errorf("command is empty")
	}

	session, err := c.client.NewSession()
	if err != nil {
		result.ExitCode = -1
		return result, fmt.Errorf("failed to create session: %w", err)
	}
	defer func() { _ = session.Close() }() //nolint:errcheck // best-effort session teardown

	session.Stdin = bytes.NewReader(stdin)
	stdoutBuf := newCappedBuffer(MaxCaptureBytes)
	stderrBuf := newCappedBuffer(MaxCaptureBytes)
	session.Stdout = stdoutBuf
	session.Stderr = stderrBuf

	runErr := runSession(session, command, c.config.Timeout)
	result.Stdout = stdoutBuf.String()
	result.Stderr = stderrBuf.String()
	result.StdoutTruncated = stdoutBuf.Truncated()
	result.StderrTruncated = stderrBuf.Truncated()

	switch {
	case runErr == nil:
		result.ExitCode = 0
		return result, nil
	case errors.Is(runErr, ErrCommandTimeout):
		result.ExitCode = -1
		return result, runErr
	}
	var exitErr *ssh.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitStatus()
		return result, nil
	}
	var missingErr *ssh.ExitMissingError
	if errors.As(runErr, &missingErr) {
		result.ExitCode = -1
		return result, fmt.Errorf("%w: %v", ErrNoExitStatus, runErr)
	}
	result.ExitCode = -1
	return result, fmt.Errorf("command failed: %w", runErr)
}

// runSession runs command on session, optionally bounded by timeout. When the
// timeout fires the session is closed (which unblocks Run) and we wait for the
// run goroutine to finish before returning, so capture buffers are no longer
// being written and are safe to read.
func runSession(session *ssh.Session, command string, timeout time.Duration) error {
	if timeout <= 0 {
		return session.Run(command)
	}

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = session.Signal(ssh.SIGKILL) //nolint:errcheck // best-effort kill on timeout
		_ = session.Close()             //nolint:errcheck // best-effort close on timeout
		<-done
		return ErrCommandTimeout
	}
}

// ExecuteCommandWithOutput executes a command and returns the output
func (c *SSHClient) ExecuteCommandWithOutput() (output string, err error) {
	lg := logger.GetLogger()

	if c.config.SafetyCheck && !c.config.Force {
		if validateErr := ValidateCommand(c.config.Command); validateErr != nil {
			return "", validateErr
		}
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	// Use new error handling mechanism
	defer errutil.HandleCloseError(&err, session)

	useSudo := c.config.SudoPassword != "" && CommandUsesSudo(c.config.Command)
	command := c.config.Command
	if useSudo {
		// Feed the sudo password via stdin instead of embedding it in the
		// command string (avoids quote breakage and shell injection).
		command = sudoStdinCommand(command)
		session.Stdin = strings.NewReader(c.config.SudoPassword + "\n")
	} else {
		// Request PTY for better compatibility on the non-sudo path.
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if ptyErr := session.RequestPty("xterm", 80, 40, modes); ptyErr != nil {
			lg.Warning("failed to request PTY: %v", ptyErr)
		}
	}

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	execErr := session.Run(command)

	// Build output
	output = stdout.String()
	stderrStr := stderr.String()

	// Use enhanced error handling
	if execErr != nil {
		enhancedErr := errutil.EnhanceError(execErr, output, stderrStr)
		if enhancedErr != nil {
			return "", enhancedErr
		}
		// If EnhanceError returns nil, it means EOF with output (success)
	}

	// For successful execution, include stderr in output if present
	if stderrStr != "" {
		output += "\n--- STDERR ---\n" + stderrStr
	}

	return output, nil
}

// ExecResult captures the outcome of running a remote command.
type ExecResult struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
}

// MaxCaptureBytes bounds how much stdout/stderr is buffered in capture mode so
// a runaway command cannot exhaust memory.
const MaxCaptureBytes = 10 << 20 // 10 MiB

var (
	// ErrCommandTimeout indicates the command exceeded the configured timeout.
	ErrCommandTimeout = errors.New("command execution timed out")
	// ErrNoExitStatus indicates the remote closed the session without reporting
	// an exit status (for example, the command was terminated by a signal).
	ErrNoExitStatus = errors.New("remote command terminated without exit status")
)

// cappedBuffer accumulates output up to a byte limit and records truncation.
// Writes beyond the limit are discarded but still reported as fully consumed so
// the underlying ssh copy loop keeps draining the channel without blocking.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newCappedBuffer(limit int) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

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

// sudoStdinCommand rewrites a command that begins with "sudo" so that sudo
// reads the password from standard input (-S) using an empty prompt. The
// password itself is supplied through the SSH session's stdin and is never
// interpolated into the command string, which previously broke on quotes and
// allowed shell injection.
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
