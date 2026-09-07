package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type channelOpenDirectMsg struct {
	Raddr string
	Rport uint32
	Laddr string
	Lport uint32
}

func startDirectTCPIPServer(t *testing.T, rewrite map[string]string) (host, port string, hits *atomic.Int64) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	require.NoError(t, err)
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) != "secret" {
				return nil, fmt.Errorf("denied")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() }) //nolint:errcheck // best-effort listener teardown

	hits = &atomic.Int64{}
	host, port, err = net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go serveJumpConn(conn, serverConfig, rewrite, hits)
		}
	}()
	return host, port, hits
}

func serveJumpConn(nConn net.Conn, config *ssh.ServerConfig, rewrite map[string]string, hits *atomic.Int64) {
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		_ = nConn.Close() //nolint:errcheck // handshake failed
		return
	}
	defer func() { _ = sshConn.Close() }() //nolint:errcheck // best-effort
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			ch, requests, acceptErr := newChan.Accept()
			if acceptErr != nil {
				continue
			}
			go handleTestSession(ch, requests)
		case "direct-tcpip":
			hits.Add(1)
			go handleDirectTCPIP(newChan, rewrite)
		default:
			_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type") //nolint:errcheck // test server
		}
	}
}

func handleDirectTCPIP(newChan ssh.NewChannel, rewrite map[string]string) {
	var msg channelOpenDirectMsg
	if err := ssh.Unmarshal(newChan.ExtraData(), &msg); err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "bad extra data") //nolint:errcheck // test server
		return
	}
	dest := net.JoinHostPort(msg.Raddr, strconv.FormatUint(uint64(msg.Rport), 10))
	if mapped, ok := rewrite[dest]; ok {
		dest = mapped
	}
	backend, err := net.Dial("tcp", dest)
	if err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, err.Error()) //nolint:errcheck // test server
		return
	}
	channel, requests, err := newChan.Accept()
	if err != nil {
		_ = backend.Close() //nolint:errcheck // failed accept
		return
	}
	go ssh.DiscardRequests(requests)
	go func() {
		_, _ = io.Copy(backend, channel) //nolint:errcheck // relay
		_ = backend.Close()              //nolint:errcheck // relay
	}()
	_, _ = io.Copy(channel, backend) //nolint:errcheck // relay
	_ = channel.Close()              //nolint:errcheck // relay
}

func TestConnectThroughJumpDoesNotDialTarget(t *testing.T) {
	targetHost, targetPort := startTestSSHServer(t)
	rewriteKey := net.JoinHostPort("192.0.2.10", targetPort)
	rewriteVal := net.JoinHostPort(targetHost, targetPort)
	jumpHost, jumpPort, hits := startDirectTCPIPServer(t, map[string]string{rewriteKey: rewriteVal})

	var dialed []string
	originalDial := dialTCP
	t.Cleanup(func() { dialTCP = originalDial })
	dialTCP = func(ctx context.Context, addr string, localAddr net.Addr, timeout time.Duration) (net.Conn, error) {
		dialed = append(dialed, addr)
		return originalDial(ctx, addr, localAddr, timeout)
	}

	setTestHome(t, t.TempDir())
	client, err := NewSSHClient(&Config{
		Host:              "192.0.2.10",
		Port:              targetPort,
		User:              "tester",
		Password:          "secret",
		UseKeyAuth:        false,
		AcceptUnknownHost: true,
		JumpChain: []*Config{{
			Host:              jumpHost,
			Port:              jumpPort,
			User:              "tester",
			Password:          "secret",
			UseKeyAuth:        false,
			AcceptUnknownHost: true,
			HostAlias:         "edge",
		}},
	})
	require.NoError(t, err)
	require.NoError(t, client.Connect())
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // best-effort

	client.config.Command = "exit0"
	res, err := client.RunCommand(true)
	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitCode)
	assert.Equal(t, "hello\n", res.Stdout)
	assert.GreaterOrEqual(t, hits.Load(), int64(1))
	require.Len(t, dialed, 1)
	assert.Equal(t, net.JoinHostPort(jumpHost, jumpPort), dialed[0])

	hops := client.Hops()
	require.Len(t, hops, 2)
	assert.Equal(t, "jump", hops[0].Role)
	assert.Equal(t, "edge", hops[0].Alias)
	assert.Equal(t, "target", hops[1].Role)
}

func TestConnectJumpAuthFailureDoesNotReachTarget(t *testing.T) {
	_, targetPort := startTestSSHServer(t)
	jumpHost, jumpPort, hits := startDirectTCPIPServer(t, nil)

	setTestHome(t, t.TempDir())
	client, err := NewSSHClient(&Config{
		Host:              "192.0.2.10",
		Port:              targetPort,
		User:              "tester",
		Password:          "secret",
		UseKeyAuth:        false,
		AcceptUnknownHost: true,
		DialTimeout:       2 * time.Second,
		JumpChain: []*Config{{
			Host:              jumpHost,
			Port:              jumpPort,
			User:              "tester",
			Password:          "wrong",
			UseKeyAuth:        false,
			AcceptUnknownHost: true,
			HostAlias:         "edge",
			DialTimeout:       2 * time.Second,
		}},
	})
	require.NoError(t, err)
	err = client.Connect()
	require.Error(t, err)
	assert.Equal(t, int64(0), hits.Load())
	var hop *HopError
	require.ErrorAs(t, err, &hop)
	assert.Equal(t, "jump", hop.Role)
	assert.Equal(t, "edge", hop.Alias)
}
