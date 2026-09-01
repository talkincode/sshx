package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	operatorPassword = "operator-pass" // #nosec G101 -- isolated E2E fixture credential.
	readerPassword   = "reader-pass"   // #nosec G101 -- isolated E2E fixture credential.
)

var (
	testBinary        string
	testKeyringBinary string
	testRoot          string
)

type commandResult struct {
	Host       string `json:"host"`
	Port       string `json:"port"`
	ExitCode   int    `json:"exit_code"`
	Success    bool   `json:"success"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	AuthMethod string `json:"auth_method"`
	ErrorKind  string `json:"error_kind"`
	Error      string `json:"error"`
}

type cliResult struct {
	stdout   string
	stderr   string
	exitCode int
}

type serverOptions struct {
	root          string
	sftpReadOnly  bool
	authorizedKey ssh.PublicKey
	reportedUID   string
}

type testSSHServer struct {
	host          string
	port          string
	listener      net.Listener
	root          string
	sftpReadOnly  bool
	connections   atomic.Int64
	collectorRuns atomic.Int64
	reportedUID   string
	stateMu       sync.Mutex
	state         string
}

func TestMain(m *testing.M) {
	flag.Parse()
	if !testing.Short() {
		var err error
		testRoot, err = os.MkdirTemp("", "sshx-e2e-")
		if err != nil {
			fmt.Fprintf(os.Stderr, "create E2E temp directory: %v\n", err)
			os.Exit(1)
		}
		testBinary = filepath.Join(testRoot, "sshx")
		testKeyringBinary = filepath.Join(testRoot, "sshx-keyring-e2e")
		if runtime.GOOS == "windows" {
			testBinary += ".exe"
			testKeyringBinary += ".exe"
		}
		if output, buildErr := buildTestBinary(testBinary); buildErr != nil {
			fmt.Fprintf(os.Stderr, "build sshx E2E binary: %v\n%s", buildErr, output)
			_ = os.RemoveAll(testRoot) //nolint:errcheck // best-effort TestMain cleanup
			os.Exit(1)
		}
		if output, buildErr := buildTestBinary(testKeyringBinary, "sshx_e2e"); buildErr != nil {
			fmt.Fprintf(os.Stderr, "build sshx keyring E2E binary: %v\n%s", buildErr, output)
			_ = os.RemoveAll(testRoot) //nolint:errcheck // best-effort TestMain cleanup
			os.Exit(1)
		}
	}

	code := m.Run()
	if testRoot != "" {
		_ = os.RemoveAll(testRoot) //nolint:errcheck // best-effort TestMain cleanup
	}
	os.Exit(code)
}

func buildTestBinary(output string, tags ...string) ([]byte, error) {
	args := []string{"build"}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, "-o", output, "./cmd/sshx")
	build := exec.Command("go", args...)
	build.Dir = repositoryRoot()
	return build.CombinedOutput()
}

func repositoryRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("cannot resolve E2E harness path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func startSSHServer(t *testing.T, options serverOptions) *testSSHServer {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping compiled-binary E2E in short mode")
	}

	signer := newHostSigner(t)

	config := &ssh.ServerConfig{
		PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			switch {
			case metadata.User() == "operator" && string(password) == operatorPassword:
				return &ssh.Permissions{Extensions: map[string]string{"role": "operator"}}, nil
			case metadata.User() == "reader" && string(password) == readerPassword:
				return &ssh.Permissions{Extensions: map[string]string{"role": "reader"}}, nil
			}
			return nil, fmt.Errorf("invalid E2E credentials")
		},
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata.User() == "operator" && options.authorizedKey != nil &&
				bytes.Equal(key.Marshal(), options.authorizedKey.Marshal()) {
				return &ssh.Permissions{Extensions: map[string]string{"role": "operator"}}, nil
			}
			return nil, fmt.Errorf("invalid E2E public key")
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	if options.root == "" {
		options.root = t.TempDir()
	}
	if options.reportedUID == "" {
		current, currentErr := user.Current()
		require.NoError(t, currentErr)
		options.reportedUID = current.Uid
	}

	server := &testSSHServer{
		host: host, port: port, listener: listener,
		root: options.root, sftpReadOnly: options.sftpReadOnly, reportedUID: options.reportedUID,
	}
	t.Cleanup(func() { _ = listener.Close() }) //nolint:errcheck // best-effort E2E teardown

	go server.serve(config)
	return server
}

func newHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	return signer
}

func newClientKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(privateKey, "sshx-e2e")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
	return signer, path
}

func (s *testSSHServer) serve(config *ssh.ServerConfig) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.connections.Add(1)
		go handleSSHConnection(conn, config, s)
	}
}

func handleSSHConnection(conn net.Conn, config *ssh.ServerConfig, server *testSSHServer) {
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close() //nolint:errcheck // handshake did not establish an SSH connection
		return
	}
	defer func() { _ = serverConn.Close() }() //nolint:errcheck // best-effort E2E teardown
	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "session channels only") //nolint:errcheck // test protocol response
			continue
		}
		channel, channelRequests, acceptErr := newChannel.Accept()
		if acceptErr != nil {
			continue
		}
		role := ""
		if serverConn.Permissions != nil {
			role = serverConn.Permissions.Extensions["role"]
		}
		go handleSSHSession(channel, channelRequests, server, role)
	}
}

func handleSSHSession(channel ssh.Channel, requests <-chan *ssh.Request, server *testSSHServer, role string) {
	defer func() { _ = channel.Close() }() //nolint:errcheck // best-effort E2E teardown
	for request := range requests {
		if request.Type == "subsystem" {
			var payload struct{ Name string }
			if err := ssh.Unmarshal(request.Payload, &payload); err != nil || payload.Name != "sftp" {
				_ = request.Reply(false, nil) //nolint:errcheck // unsupported fixture subsystem
				return
			}
			_ = request.Reply(true, nil) //nolint:errcheck // test protocol response
			options := []sftp.ServerOption{sftp.WithServerWorkingDirectory(server.root)}
			if role == "reader" || server.sftpReadOnly {
				options = append(options, sftp.ReadOnly())
			}
			sftpServer, err := sftp.NewServer(channel, options...)
			if err != nil {
				return
			}
			_ = sftpServer.Serve() //nolint:errcheck // client disconnect ends the isolated fixture server
			_ = sftpServer.Close() //nolint:errcheck // best-effort fixture teardown
			return
		}
		if request.Type != "exec" {
			if request.WantReply {
				_ = request.Reply(false, nil) //nolint:errcheck // test protocol response
			}
			continue
		}

		var payload struct{ Command string }
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
			_ = request.Reply(false, nil) //nolint:errcheck // malformed test request
			return
		}
		_ = request.Reply(true, nil) //nolint:errcheck // test protocol response

		exitCode := uint32(0)
		switch {
		case isCollectorCommand(payload.Command) != "":
			handleCollectorSession(channel, server, role, false, isCollectorCommand(payload.Command))
			return
		case isSudoCollectorCommand(payload.Command) != "":
			handleCollectorSession(channel, server, role, true, isSudoCollectorCommand(payload.Command))
			return
		case payload.Command == "probe" || strings.HasPrefix(payload.Command, "probe "):
			_, _ = io.WriteString(channel, "probe-ok\n") //nolint:errcheck // fixture response
		case payload.Command == "bothstreams":
			_, _ = io.WriteString(channel, "to-out\n")          //nolint:errcheck // fixture response
			_, _ = io.WriteString(channel.Stderr(), "to-err\n") //nolint:errcheck // fixture response
		case payload.Command == "exit7":
			exitCode = 7
			_, _ = io.WriteString(channel, "partial\n") //nolint:errcheck // fixture response
		case payload.Command == "sleep":
			time.Sleep(2 * time.Second)
		case payload.Command == "read-state":
			_, _ = io.WriteString(channel, server.readState()+"\n") //nolint:errcheck // fixture response
		case strings.HasPrefix(payload.Command, "set-state-and-drop "):
			if role != "operator" {
				_, _ = io.WriteString(channel.Stderr(), "permission denied\n") //nolint:errcheck // fixture response
				sendExitStatus(channel, 13)
				return
			}
			server.writeState(strings.TrimPrefix(payload.Command, "set-state-and-drop "))
			_, _ = io.WriteString(channel, "state-updated\n") //nolint:errcheck // fixture response
			return
		case strings.HasPrefix(payload.Command, "set-state "):
			if role != "operator" {
				exitCode = 13
				_, _ = io.WriteString(channel.Stderr(), "permission denied\n") //nolint:errcheck // fixture response
				break
			}
			server.writeState(strings.TrimPrefix(payload.Command, "set-state "))
			_, _ = io.WriteString(channel, "state-updated\n") //nolint:errcheck // fixture response
		case strings.Contains(payload.Command, "sqlite3"):
			handleSQLiteSession(channel, server, payload.Command)
			return
		case strings.Contains(payload.Command, "mysql"):
			handleMySQLSession(channel, server, payload.Command)
			return
		case payload.Command == "rm -rf /":
			_, _ = io.WriteString(channel, "forced-ok\n") //nolint:errcheck // fixture response
		case payload.Command == "sudo -S -p '' whoami":
			password, err := bufio.NewReader(channel).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				exitCode = 24
				_, _ = io.WriteString(channel.Stderr(), "sudo stdin read failed\n") //nolint:errcheck // fixture response
				break
			}
			if strings.TrimSpace(password) != operatorPassword {
				exitCode = 25
				_, _ = io.WriteString(channel.Stderr(), "sudo password mismatch\n") //nolint:errcheck // fixture response
				break
			}
			_, _ = io.WriteString(channel, "sudo-ok\n") //nolint:errcheck // fixture response
		default:
			exitCode = 127
			_, _ = io.WriteString(channel.Stderr(), "unknown fixture command\n") //nolint:errcheck // fixture response
		}
		sendExitStatus(channel, exitCode)
		return
	}
}

func handleSQLiteSession(channel ssh.Channel, server *testSSHServer, cmdline string) {
	stdin, err := io.ReadAll(io.LimitReader(channel, 12<<20))
	if err != nil {
		_, _ = io.WriteString(channel.Stderr(), "sqlite stdin read failed\n") //nolint:errcheck // fixture response
		sendExitStatus(channel, 24)
		return
	}
	command := exec.Command("sh", "-c", cmdline) // #nosec G204 -- isolated E2E fixture executes generated sqlite3 scripts only
	command.Dir = server.root
	command.Env = append(os.Environ(), "HOME="+server.root)
	command.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	_, _ = channel.Write(stdout.Bytes())          //nolint:errcheck // fixture response
	_, _ = channel.Stderr().Write(stderr.Bytes()) //nolint:errcheck // fixture response
	if runErr == nil {
		sendExitStatus(channel, 0)
		return
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		sendExitStatus(channel, uint32(exitErr.ExitCode())) // #nosec G115 -- process exit codes are bounded.
		return
	}
	sendExitStatus(channel, 126)
}

func handleMySQLSession(channel ssh.Channel, server *testSSHServer, cmdline string) {
	stdin, err := io.ReadAll(io.LimitReader(channel, 12<<20))
	if err != nil {
		_, _ = io.WriteString(channel.Stderr(), "mysql stdin read failed\n") //nolint:errcheck // fixture response
		sendExitStatus(channel, 24)
		return
	}
	command := exec.Command("sh", "-c", cmdline) // #nosec G204 -- isolated E2E fixture executes generated mysql client scripts only
	command.Dir = server.root
	command.Env = append(os.Environ(),
		"HOME="+server.root,
		"PATH="+filepath.Join(server.root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	command.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	_, _ = channel.Write(stdout.Bytes())          //nolint:errcheck // fixture response
	_, _ = channel.Stderr().Write(stderr.Bytes()) //nolint:errcheck // fixture response
	if runErr == nil {
		sendExitStatus(channel, 0)
		return
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		sendExitStatus(channel, uint32(exitErr.ExitCode())) // #nosec G115 -- process exit codes are bounded.
		return
	}
	sendExitStatus(channel, 126)
}

func installFakeMySQL(t *testing.T, server *testSSHServer) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	bin := filepath.Join(server.root, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o750)) // #nosec G301 -- isolated fixture PATH dir must be executable
	src, err := os.ReadFile("fake_mysql.py")    // #nosec G304 -- package-local E2E fixture
	require.NoError(t, err)
	dest := filepath.Join(bin, "mysql")
	require.NoError(t, os.WriteFile(dest, src, 0o750)) // #nosec G306,G703 -- isolated fixture PATH binary must be executable
}

// collectorShells mirrors the shell family sshx may select from a script
// shebang or an explicit --shell.
var collectorShells = []string{"sh", "bash", "zsh", "dash", "ksh", "ash"}

// isCollectorCommand returns the shell name when cmd is a streamed-script
// invocation such as `bash -s --`, or "" when it is an ordinary command.
func isCollectorCommand(cmd string) string {
	for _, shell := range collectorShells {
		if cmd == shell+" -s --" {
			return shell
		}
	}
	return ""
}

// isSudoCollectorCommand is the privileged form, `sudo -S -p ” bash -s --`.
func isSudoCollectorCommand(cmd string) string {
	const prefix = "sudo -S -p '' "
	rest, ok := strings.CutPrefix(cmd, prefix)
	if !ok {
		return ""
	}
	return isCollectorCommand(rest)
}

func handleCollectorSession(channel ssh.Channel, server *testSSHServer, role string, useSudo bool, shell string) {
	reader := bufio.NewReader(channel)
	if useSudo {
		password, err := reader.ReadString('\n')
		if err != nil || role != "operator" || strings.TrimSpace(password) != operatorPassword {
			_, _ = io.WriteString(channel.Stderr(), "sudo password mismatch\n") //nolint:errcheck // fixture response
			sendExitStatus(channel, 25)
			return
		}
	}
	payload, err := io.ReadAll(io.LimitReader(reader, 12<<20))
	if err != nil {
		_, _ = io.WriteString(channel.Stderr(), "collector stdin read failed\n") //nolint:errcheck // fixture response
		sendExitStatus(channel, 24)
		return
	}
	if bytes.Contains(payload, []byte("/proc/sys/kernel/random/boot_id")) && bytes.Contains(payload, []byte("uname -s")) && !bytes.Contains(payload, []byte("capability=")) {
		_, _ = io.WriteString(channel, "Linux\nboot-e2e\n"+server.reportedUID+"\n") //nolint:errcheck // fixture response
		sendExitStatus(channel, 0)
		return
	}
	server.collectorRuns.Add(1)
	if shell == "" {
		shell = "sh"
	}
	command := exec.Command(shell) // #nosec G204 -- shell name comes from a fixed allowlist and executes only isolated test-created collector fixtures.
	command.Dir = server.root
	command.Env = append(os.Environ(), "HOME="+server.root, "SSHX_E2E_ROLE="+role)
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	_, _ = channel.Write(stdout.Bytes())          //nolint:errcheck // fixture response
	_, _ = channel.Stderr().Write(stderr.Bytes()) //nolint:errcheck // fixture response
	if runErr == nil {
		sendExitStatus(channel, 0)
		return
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		sendExitStatus(channel, uint32(exitErr.ExitCode())) // #nosec G115 -- process exit codes are bounded.
		return
	}
	sendExitStatus(channel, 126)
}

func (s *testSSHServer) readState() string {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.state
}

func (s *testSSHServer) writeState(value string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.state = value
}

func sendExitStatus(channel ssh.Channel, status uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, status)
	_, _ = channel.SendRequest("exit-status", false, payload) //nolint:errcheck // fixture response
}

func runSSHX(t *testing.T, home string, args []string, extraEnv map[string]string) cliResult {
	return runSSHXBinary(t, testBinary, home, args, extraEnv)
}

func runSSHXWithTestKeyring(t *testing.T, home string, args []string, extraEnv map[string]string) cliResult {
	return runSSHXBinary(t, testKeyringBinary, home, args, extraEnv)
}

func runSSHXBinary(t *testing.T, binary, home string, args []string, extraEnv map[string]string) cliResult {
	return runSSHXBinaryWithHome(t, binary, home, home, args, extraEnv)
}

func runSSHXWithNativeKeyring(t *testing.T, workDir string, args []string, extraEnv map[string]string) cliResult {
	t.Helper()
	nativeHome := os.Getenv("HOME")
	require.NotEmpty(t, nativeHome, "native keyring E2E requires the platform user HOME")
	return runSSHXBinaryWithHome(t, testBinary, workDir, nativeHome, args, extraEnv)
}

func runSSHXBinaryWithHome(t *testing.T, binary, workDir, environmentHome string, args []string, extraEnv map[string]string) cliResult {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping compiled-binary E2E in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- binary is one of the harness-built sshx executables and args are isolated test inputs.
	command.Dir = workDir
	command.Env = isolatedEnvironment(environmentHome, extraEnv)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			require.NoError(t, err)
		}
	}
	require.NoError(t, ctx.Err(), "sshx E2E process timed out")
	return cliResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: exitCode}
}

func isolatedEnvironment(home string, extra map[string]string) []string {
	blocked := map[string]struct{}{
		"HOME": {}, "SSH_PASSWORD": {}, "SSH_KEY_PATH": {}, "SSH_SUDO_KEY": {},
		"SSH_DISABLE_KEY": {}, "SSH_KNOWN_HOSTS": {}, "SSHX_AUDIT_OUTPUT": {},
		"SSHX_NO_AUDIT": {}, "SSH_ACCEPT_UNKNOWN_HOST": {}, "SSH_INSECURE_HOST_KEY": {},
		"SSH_NO_SAFETY_CHECK": {}, "SSH_FORCE": {}, "SSH_TIMEOUT": {}, "SSHX_LOG_LEVEL": {},
		"SSHX_HOME": {}, "SSHX_SKILLS_DIR": {},
		"SSHX_SECRET_BACKEND": {}, "SSHX_VAULT_PASSPHRASE": {}, "SSHX_VAULT_KEY_FILE": {},
	}
	env := make([]string, 0, len(os.Environ())+len(extra)+3)
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if _, found := blocked[name]; !found {
			env = append(env, item)
		}
	}
	values := map[string]string{
		"HOME":           home,
		"SSHX_NO_AUDIT":  "true",
		"SSHX_LOG_LEVEL": "error",
	}
	for name, value := range extra {
		values[name] = value
	}
	for name, value := range values {
		env = append(env, name+"="+value)
	}
	return env
}
