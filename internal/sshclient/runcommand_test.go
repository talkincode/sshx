package sshclient

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// startTestSSHServer spins up an in-process SSH server on 127.0.0.1 that
// understands a small set of canned commands. It returns the host and port the
// client should dial. The listener is closed when the test finishes.
func startTestSSHServer(t *testing.T) (host, port string) {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	require.NoError(t, err)

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() }) //nolint:errcheck // best-effort listener teardown

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go handleTestConn(conn, serverConfig)
		}
	}()

	h, p, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return h, p
}

func handleTestConn(nConn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		_ = nConn.Close() //nolint:errcheck // handshake failed; nothing to recover
		return
	}
	defer func() { _ = sshConn.Close() }() //nolint:errcheck // best-effort conn teardown
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type") //nolint:errcheck // test server
			continue
		}
		ch, requests, acceptErr := newChan.Accept()
		if acceptErr != nil {
			continue
		}
		go handleTestSession(ch, requests)
	}
}

func handleTestSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "exec":
			command := ""
			if len(req.Payload) >= 4 {
				command = string(req.Payload[4:])
			}
			replyOK(req)
			status := runFakeCommand(ch, command)
			sendExitStatus(ch, status)
			_ = ch.Close() //nolint:errcheck // best-effort channel close
			return
		case "pty-req", "shell", "env":
			replyOK(req)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil) //nolint:errcheck // test server
			}
		}
	}
}

func replyOK(req *ssh.Request) {
	if req.WantReply {
		_ = req.Reply(true, nil) //nolint:errcheck // test server
	}
}

func runFakeCommand(ch ssh.Channel, command string) uint32 {
	switch command {
	case "exit0":
		writeAll(ch, "hello\n")
		return 0
	case "exit7":
		writeAll(ch, "partial\n")
		return 7
	case "bothstreams":
		writeAll(ch, "to-out\n")
		writeAll(ch.Stderr(), "to-err\n")
		return 0
	case "sudo -S -p '' whoami":
		stdin, err := bufio.NewReader(ch).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			writeAll(ch.Stderr(), "failed to read sudo stdin\n")
			return 24
		}
		if stdin != "sudo-fixture\n" {
			writeAll(ch.Stderr(), "unexpected sudo stdin\n")
			return 25
		}
		writeAll(ch, "sudo-ok\n")
		return 0
	case "sleep":
		time.Sleep(5 * time.Second)
		return 0
	default:
		return 0
	}
}

func writeAll(w io.Writer, s string) {
	_, _ = io.WriteString(w, s) //nolint:errcheck // test server best-effort write
}

func sendExitStatus(ch ssh.Channel, status uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, status)
	_, _ = ch.SendRequest("exit-status", false, payload) //nolint:errcheck // test server
}

func dialTestClient(t *testing.T, host, port string) *SSHClient {
	t.Helper()
	t.Setenv("HOME", t.TempDir())

	client, err := NewSSHClient(&Config{
		Host:              host,
		Port:              port,
		User:              "tester",
		Password:          "secret",
		UseKeyAuth:        false,
		AcceptUnknownHost: true,
	})
	require.NoError(t, err)
	require.NoError(t, client.ConnectDirect())
	t.Cleanup(func() { _ = client.ForceClose() }) //nolint:errcheck // best-effort client teardown
	return client
}

func TestRunCommandSuccess(t *testing.T) {
	host, port := startTestSSHServer(t)
	client := dialTestClient(t, host, port)
	client.config.Command = "exit0"

	res, err := client.RunCommand(true)
	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitCode)
	assert.Equal(t, "hello\n", res.Stdout)
	assert.Empty(t, res.Stderr)
	assert.False(t, res.StdoutTruncated)
}

func TestRunCommandNonZeroExit(t *testing.T) {
	host, port := startTestSSHServer(t)
	client := dialTestClient(t, host, port)
	client.config.Command = "exit7"

	res, err := client.RunCommand(true)
	require.NoError(t, err, "a non-zero remote exit must not be a sshx-level error")
	assert.Equal(t, 7, res.ExitCode)
	assert.Equal(t, "partial\n", res.Stdout)
}

func TestRunCommandSeparatesStreams(t *testing.T) {
	host, port := startTestSSHServer(t)
	client := dialTestClient(t, host, port)
	client.config.Command = "bothstreams"

	res, err := client.RunCommand(true)
	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitCode)
	assert.Equal(t, "to-out\n", res.Stdout)
	assert.Equal(t, "to-err\n", res.Stderr)
}

func TestRunCommandTimeout(t *testing.T) {
	host, port := startTestSSHServer(t)
	client := dialTestClient(t, host, port)
	client.config.Command = "sleep"
	client.config.Timeout = 200 * time.Millisecond

	start := time.Now()
	res, err := client.RunCommand(true)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCommandTimeout), "expected ErrCommandTimeout, got %v", err)
	assert.Equal(t, -1, res.ExitCode)
	assert.Less(t, elapsed, 4*time.Second, "timeout should fire well before the command finishes")
}

func TestRunCommandSudoFeedsPasswordOnStdin(t *testing.T) {
	host, port := startTestSSHServer(t)
	client := dialTestClient(t, host, port)
	sudoPassword := "sudo-fixture" // #nosec G101 -- fake test password used only for stdin contract coverage.
	client.config.Command = "sudo whoami"
	client.config.Password = sudoPassword
	client.config.Timeout = 2 * time.Second

	res, err := client.RunCommand(true)

	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitCode)
	assert.Equal(t, "sudo-ok\n", res.Stdout)
	assert.Empty(t, res.Stderr)
	assert.NotContains(t, res.Stdout, sudoPassword)
	assert.NotContains(t, res.Stderr, sudoPassword)
}

func TestCappedBufferTruncates(t *testing.T) {
	buf := newCappedBuffer(8)
	n, err := buf.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.False(t, buf.Truncated())

	n, err = buf.Write([]byte("world!!"))
	require.NoError(t, err)
	assert.Equal(t, 7, n, "write must report full length so the ssh copy loop keeps draining")
	assert.True(t, buf.Truncated())
	assert.Equal(t, "hellowor", buf.String())

	n, err = buf.Write([]byte("more"))
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, "hellowor", buf.String())
}

func TestCommandUsesSudoLeadingOnly(t *testing.T) {
	cases := map[string]bool{
		"sudo apt update":     true,
		"sudo":                true,
		"  sudo ls":           true,
		"\tsudo ls":           true,
		"\nsudo ls":           true,
		"ls -la":              false,
		"echo sudo":           false,
		"echo do sudo things": false,
		"sh -c 'sudo whoami'": false,
		"sudoedit /etc/hosts": false,
	}
	for command, want := range cases {
		assert.Equalf(t, want, CommandUsesSudo(command), "command=%q", command)
	}
}

func TestCommandBlockedErrorIsDetectable(t *testing.T) {
	err := ValidateCommand("rm -rf /")
	require.Error(t, err)

	var blocked *CommandBlockedError
	assert.True(t, errors.As(err, &blocked), "ValidateCommand should return a *CommandBlockedError")
	assert.True(t, strings.Contains(err.Error(), "Dangerous command blocked"))
}
