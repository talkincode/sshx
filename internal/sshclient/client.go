package sshclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	DefaultSSHPort    = "22"
	DefaultSSHUser    = "master"
	DefaultSudoKey    = "master"
	DefaultTimeout    = 30 * time.Second
	SudoPrompt        = "[sudo] password"
	PasswordPromptEnd = ": "
)

// AuthMethod indicates which authentication mechanism was used for the SSH connection.
type AuthMethod string

const (
	AuthMethodUnknown          AuthMethod = "unknown"
	AuthMethodKey              AuthMethod = "key"
	AuthMethodPassword         AuthMethod = "password"
	AuthMethodPasswordFallback AuthMethod = "password-fallback"
)

// Config represents SSH configuration properties for connecting to remote hosts.
type Config struct {
	Host        string
	Port        string
	User        string
	Password    string
	KeyPath     string
	UseKeyAuth  bool
	SudoKey     string
	Command     string
	Mode        string
	DialTimeout time.Duration
	// Timeout bounds the execution of a single remote command. Zero means no
	// command timeout (the dial timeout still applies).
	Timeout time.Duration
	// JSONOutput emits a single structured JSON result instead of streaming
	// human-readable output. It implies clean, separated stdout/stderr capture.
	JSONOutput bool
	// UsePTY requests a pseudo-terminal for command execution. It is off by
	// default because a PTY merges stderr into stdout and injects terminal
	// control characters; it is ignored in JSON/capture mode.
	UsePTY bool

	SafetyCheck bool
	Force       bool
	// AcceptUnknownHost controls whether sshx will automatically add
	// previously unseen host keys to the user's known_hosts file.
	AcceptUnknownHost bool
	// AllowInsecureHostKey controls whether sshx may fall back to
	// ssh.InsecureIgnoreHostKey (legacy behavior). Disabled by default.
	AllowInsecureHostKey bool
	// KnownHostsPath allows overriding the path to the known_hosts file.
	KnownHostsPath string

	SftpAction string
	LocalPath  string
	RemotePath string

	PasswordAction string
	PasswordKey    string
	PasswordValue  string

	// Host management fields
	HostAction      string
	HostName        string
	HostDescription string
	HostType        string
}

// SSHClient wraps an ssh.Client with optional pooled and sftp helpers.
type SSHClient struct {
	config         *Config
	client         *ssh.Client
	sftpClient     *sftp.Client
	authMethodUsed AuthMethod
}

// AuthMethodUsed returns the authentication method used for the current connection.
func (c *SSHClient) AuthMethodUsed() AuthMethod {
	if c == nil {
		return AuthMethodUnknown
	}
	if c.authMethodUsed == "" {
		return AuthMethodUnknown
	}
	return c.authMethodUsed
}

// getHostKeyCallback returns a secure host key callback function.
// It enforces strict host key checking and only falls back to the insecure
// mode when explicitly requested via configuration.
func getHostKeyCallback(cfg *Config) (ssh.HostKeyCallback, error) {
	lg := logger.GetLogger()
	if cfg == nil {
		cfg = &Config{}
	}

	knownHostsPath := cfg.KnownHostsPath
	if knownHostsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			lg.Warning("Unable to determine home directory for known_hosts: %v", err)
			if cfg.AllowInsecureHostKey {
				lg.Warning("Falling back to insecure host key verification (explicitly allowed)")
				// #nosec G106 -- Only allowed when the user opts in
				return ssh.InsecureIgnoreHostKey(), nil
			}
			return nil, fmt.Errorf("unable to determine known_hosts path (set HOME or use --known-hosts): %w", err)
		}
		knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}

	if err := ensureKnownHostsFile(knownHostsPath); err != nil {
		if cfg.AllowInsecureHostKey {
			lg.Warning("Unable to prepare known_hosts at %s: %v", knownHostsPath, err)
			lg.Warning("Falling back to insecure host key verification (explicitly allowed)")
			// #nosec G106 -- User explicitly allowed insecure host key verification
			return ssh.InsecureIgnoreHostKey(), nil
		}
		return nil, err
	}

	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		if cfg.AllowInsecureHostKey {
			lg.Warning("Failed to load known_hosts from %s: %v", knownHostsPath, err)
			lg.Warning("Falling back to insecure host key verification (explicitly allowed)")
			// #nosec G106 -- User explicitly allowed insecure host key verification
			return ssh.InsecureIgnoreHostKey(), nil
		}
		return nil, fmt.Errorf("failed to load known_hosts from %s: %w", knownHostsPath, err)
	}

	var callbackMu sync.Mutex

	// Wrap the callback to handle key verification errors gracefully
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		callbackMu.Lock()
		defer callbackMu.Unlock()

		err := hostKeyCallback(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}

		// If there are known keys but they don't match, it's a key change
		if len(keyErr.Want) > 0 {
			return fmt.Errorf("⚠️  HOST KEY VERIFICATION FAILED!\n"+
				"The host key for %s has changed.\n"+
				"This could indicate a man-in-the-middle attack.\n"+
				"Remove the old key from %s and verify the new key before connecting.\n"+
				"Original error: %w", hostname, knownHostsPath, err)
		}

		if cfg.AcceptUnknownHost {
			hostPatterns := normalizeHostPatterns(hostname, remote)
			if len(hostPatterns) == 0 {
				hostPatterns = []string{hostname}
			}
			if appendErr := appendHostKey(knownHostsPath, hostPatterns, key); appendErr != nil {
				return fmt.Errorf("failed to record new host key for %s: %w", hostname, appendErr)
			}
			lg.Success("Trusted new host %s and saved its key to %s", hostname, knownHostsPath)
			freshCallback, reloadErr := knownhosts.New(knownHostsPath)
			if reloadErr != nil {
				return fmt.Errorf("failed to reload known_hosts after adding %s: %w", hostname, reloadErr)
			}
			hostKeyCallback = freshCallback
			return nil
		}

		return fmt.Errorf("⚠️  Host %s is not in known_hosts file (%s).\n"+
			"To add this host, run:\n"+
			"  ssh-keyscan -H %s >> %s\n"+
			"Or re-run sshx with --accept-unknown-host to trust it automatically.\n"+
			"Original error: %w",
			hostname, knownHostsPath, hostname, knownHostsPath, err)
	}, nil
}

func ensureKnownHostsFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %s for known_hosts: %w", dir, err)
	}

	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("known_hosts path %s is a directory", path)
		}
		return nil
	}

	if os.IsNotExist(err) {
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- user-provided path validated earlier
		if createErr != nil {
			return fmt.Errorf("failed to create known_hosts file at %s: %w", path, createErr)
		}
		return file.Close()
	}

	return fmt.Errorf("unable to access known_hosts file at %s: %w", path, err)
}

func appendHostKey(path string, hostnames []string, key ssh.PublicKey) (err error) {
	if len(hostnames) == 0 {
		return fmt.Errorf("no hostnames provided for known_hosts entry")
	}
	line := knownhosts.Line(hostnames, key)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- caller controls path and permissions
	if os.IsNotExist(err) {
		if ensureErr := ensureKnownHostsFile(path); ensureErr != nil {
			return ensureErr
		}
		file, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- path validated above
	}
	if err != nil {
		return fmt.Errorf("failed to open known_hosts file %s: %w", path, err)
	}
	defer errutil.HandleCloseError(&err, file)
	if _, writeErr := file.WriteString(line + "\n"); writeErr != nil {
		return fmt.Errorf("failed to append host key to %s: %w", path, writeErr)
	}
	return nil
}

func normalizeHostPatterns(hostname string, remote net.Addr) []string {
	patterns := map[string]struct{}{}
	add := func(value string) {
		if value == "" {
			return
		}
		patterns[value] = struct{}{}
	}

	if host, port, err := net.SplitHostPort(hostname); err == nil {
		add(fmt.Sprintf("[%s]:%s", host, port))
		add(host)
	} else {
		add(hostname)
	}

	if remote != nil {
		if host, _, err := net.SplitHostPort(remote.String()); err == nil {
			add(host)
		}
	}

	result := make([]string, 0, len(patterns))
	for entry := range patterns {
		result = append(result, entry)
	}
	sort.Strings(result)
	return result
}

// NewSSHClient 创建SSH客户端
func NewSSHClient(config *Config) (*SSHClient, error) {
	if config.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if config.Port == "" {
		config.Port = DefaultSSHPort
	}
	if config.User == "" {
		config.User = DefaultSSHUser
	}
	// Default to key authentication unless explicitly disabled
	if !config.UseKeyAuth {
		config.KeyPath = ""
	}
	if config.UseKeyAuth && config.KeyPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			config.KeyPath = filepath.Join(home, ".ssh", "id_rsa")
		}
	}

	return &SSHClient{config: config, authMethodUsed: AuthMethodUnknown}, nil
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

		conn, err := net.DialTimeout("tcp", addr, timeout)
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
	return errors.As(err, &serverErr)
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
// ExecResult.ExitCode with a nil error.
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
	if c.config.Password != "" && commandStartsWithSudo(command) {
		lg.Info("Auto-filling sudo password...")
		command = sudoStdinCommand(command)
		session.Stdin = strings.NewReader(c.config.Password + "\n")
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

	useSudo := c.config.Password != "" && CommandUsesSudo(c.config.Command)
	command := c.config.Command
	if useSudo {
		// Feed the sudo password via stdin instead of embedding it in the
		// command string (avoids quote breakage and shell injection).
		command = sudoStdinCommand(command)
		session.Stdin = strings.NewReader(c.config.Password + "\n")
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

// commandStartsWithSudo reports whether the command's first token is sudo, which
// is the only form sudoStdinCommand can safely rewrite for password injection.
func commandStartsWithSudo(command string) bool {
	trimmed := strings.TrimLeft(command, " \t")
	return trimmed == "sudo" || strings.HasPrefix(trimmed, "sudo ")
}

// sudoStdinCommand rewrites a command that begins with "sudo" so that sudo
// reads the password from standard input (-S) using an empty prompt. The
// password itself is supplied through the SSH session's stdin and is never
// interpolated into the command string, which previously broke on quotes and
// allowed shell injection.
func sudoStdinCommand(command string) string {
	trimmed := strings.TrimLeft(command, " \t")
	switch {
	case trimmed == "sudo":
		return "sudo -S -p ''"
	case strings.HasPrefix(trimmed, "sudo "):
		return "sudo -S -p '' " + strings.TrimSpace(trimmed[len("sudo "):])
	default:
		return command
	}
}

// ExecuteSftp executes SFTP operations
func (c *SSHClient) ExecuteSftp() (err error) {
	sftpClient, err := sftp.NewClient(c.client)
	if err != nil {
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}
	defer errutil.HandleCloseError(&err, sftpClient)
	c.sftpClient = sftpClient

	switch c.config.SftpAction {
	case "upload":
		return c.uploadFile()
	case "download":
		return c.downloadFile()
	case "list", "ls":
		return c.listFiles()
	case "mkdir":
		return c.makeDirectory()
	case "remove", "rm":
		return c.removeFile()
	default:
		return fmt.Errorf("unknown SFTP action: %s", c.config.SftpAction)
	}
}

func (c *SSHClient) uploadFile() (err error) {
	lg := logger.GetLogger()
	localFile, err := os.Open(c.config.LocalPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer errutil.HandleCloseError(&err, localFile)

	remoteFile, err := c.sftpClient.Create(c.config.RemotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer errutil.HandleCloseError(&err, remoteFile)

	lg.Info("Uploading: %s → %s", c.config.LocalPath, c.config.RemotePath)

	written, err := io.Copy(remoteFile, localFile)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	lg.Success("Uploaded %d bytes successfully", written)
	return nil
}

func (c *SSHClient) downloadFile() (err error) {
	lg := logger.GetLogger()
	remoteFile, err := c.sftpClient.Open(c.config.RemotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %w", err)
	}
	defer errutil.HandleCloseError(&err, remoteFile)

	localFile, err := os.Create(c.config.LocalPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer errutil.HandleCloseError(&err, localFile)

	lg.Info("Downloading: %s → %s", c.config.RemotePath, c.config.LocalPath)

	written, err := io.Copy(localFile, remoteFile)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}

	lg.Success("Downloaded %d bytes successfully", written)
	return nil
}

func (c *SSHClient) listFiles() error {
	lg := logger.GetLogger()
	remotePath := c.config.RemotePath
	if remotePath == "" {
		remotePath = "."
	}

	files, err := c.sftpClient.ReadDir(remotePath)
	if err != nil {
		return fmt.Errorf("failed to list directory: %w", err)
	}

	lg.Info("Directory listing: %s", remotePath)
	fmt.Println("\nPermissions  Size      Modified              Name")
	fmt.Println("-------------------------------------------------------")

	for _, file := range files {
		modeStr := file.Mode().String()
		sizeStr := fmt.Sprintf("%10d", file.Size())
		timeStr := file.ModTime().Format("2006-01-02 15:04:05")

		fmt.Printf("%-12s %s  %s  %s\n", modeStr, sizeStr, timeStr, file.Name())
	}

	fmt.Printf("\nTotal: %d items\n", len(files))
	return nil
}

func (c *SSHClient) makeDirectory() error {
	lg := logger.GetLogger()
	if err := c.sftpClient.MkdirAll(c.config.RemotePath); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	lg.Success("Directory created: %s", c.config.RemotePath)
	return nil
}

func (c *SSHClient) removeFile() error {
	lg := logger.GetLogger()
	stat, err := c.sftpClient.Stat(c.config.RemotePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if stat.IsDir() {
		if err := c.removeDirectory(c.config.RemotePath); err != nil {
			return err
		}
		lg.Success("Directory removed: %s", c.config.RemotePath)
	} else {
		if err := c.sftpClient.Remove(c.config.RemotePath); err != nil {
			return fmt.Errorf("failed to remove file: %w", err)
		}
		lg.Success("File removed: %s", c.config.RemotePath)
	}

	return nil
}

func (c *SSHClient) removeDirectory(path string) error {
	files, err := c.sftpClient.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, file := range files {
		fullPath := filepath.Join(path, file.Name())
		if file.IsDir() {
			if err := c.removeDirectory(fullPath); err != nil {
				return err
			}
		} else {
			if err := c.sftpClient.Remove(fullPath); err != nil {
				return fmt.Errorf("failed to remove file %s: %w", fullPath, err)
			}
		}
	}

	return c.sftpClient.RemoveDirectory(path)
}

// Close closes the SFTP and SSH connections.
func (c *SSHClient) Close() error {
	var firstErr error
	if c.sftpClient != nil {
		if err := c.sftpClient.Close(); err != nil {
			firstErr = err
		}
		c.sftpClient = nil
	}
	if c.client != nil {
		if err := c.client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.client = nil
	}
	return firstErr
}

// ForceClose forcefully closes the underlying SSH connection.
func (c *SSHClient) ForceClose() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}
