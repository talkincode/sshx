package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func reliabilityDirectory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".transport-fixture-")
	require.NoError(t, err)
	absolute, err := filepath.Abs(dir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(absolute)) })
	return absolute
}

type reliabilityServer struct {
	host, port string
	key        ssh.PublicKey
}

func newReliabilityServer(t *testing.T, config *ssh.ServerConfig, handle func(ssh.NewChannel, *ssh.ServerConn)) reliabilityServer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	if config == nil {
		config = &ssh.ServerConfig{NoClientAuth: true}
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var connections sync.Map
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			connections.Store(conn, struct{}{})
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connections.Delete(conn)
				defer func() { _ = conn.Close() }() //nolint:errcheck // fixture cleanup
				server, channels, requests, handshakeErr := ssh.NewServerConn(conn, config)
				if handshakeErr != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					handle(channel, server)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close() //nolint:errcheck // fixture listener
		<-accepted
		connections.Range(func(conn, _ any) bool {
			_ = conn.(net.Conn).Close() //nolint:errcheck // fixture socket teardown
			return true
		})
		workers.Wait()
	})
	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	return reliabilityServer{host: host, port: port, key: signer.PublicKey()}
}

func (s reliabilityServer) client(t *testing.T, ctx context.Context) *SSHClient {
	t.Helper()
	client, err := NewSSHClient(&Config{
		Host: s.host, Port: s.port, User: "fixture", Password: "fixture",
		Context:        ctx,
		KnownHostsData: []byte(knownhosts.Line([]string{net.JoinHostPort(s.host, s.port)}, s.key)),
	})
	require.NoError(t, err)
	require.NoError(t, client.ConnectDirect())
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // fixture client teardown
	return client
}

func errorKind(t *testing.T, err error) string {
	t.Helper()
	var classified interface{ ErrorKind() string }
	require.ErrorAs(t, err, &classified)
	return classified.ErrorKind()
}

func awaitReliability(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("fixture did not reach barrier")
	}
}

func TestTransportDialContextCancelled(t *testing.T) {
	original := dialTCP
	t.Cleanup(func() { dialTCP = original })
	entered := make(chan struct{})
	dialTCP = func(ctx context.Context, _ string, _ net.Addr, _ time.Duration) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := NewSSHClient(&Config{Host: "fixture", Password: "fixture", Context: ctx, KnownHostsData: []byte{}})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- client.ConnectDirect() }()
	awaitReliability(t, entered)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, ErrorKindCancelled, errorKind(t, err))
	case <-time.After(time.Second):
		t.Fatal("DialContext did not cancel")
	}
}

func TestTransportHandshakeDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() }) //nolint:errcheck // fixture listener
	closed := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			close(closed)
			return
		}
		defer func() { _ = conn.Close() }() //nolint:errcheck // fixture socket
		_, _ = io.Copy(io.Discard, conn)    //nolint:errcheck // wait for client teardown without SSH identification
		close(closed)
	}()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	client, err := NewSSHClient(&Config{Host: host, Port: port, Password: "fixture", DialTimeout: 80 * time.Millisecond, KnownHostsData: []byte{}})
	require.NoError(t, err)
	start := time.Now()
	err = client.ConnectDirect()
	require.Error(t, err)
	assert.Equal(t, "timeout", errorKind(t, err))
	assert.Less(t, time.Since(start), time.Second)
	awaitReliability(t, closed)
}

func TestTransportCancellationBoundaries(t *testing.T) {
	for _, phase := range []string{"session", "pty", "start", "wait", "sftp_subsystem", "sftp_version"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reached := make(chan struct{})
			server := newReliabilityServer(t, nil, func(newChannel ssh.NewChannel, conn *ssh.ServerConn) {
				if phase == "session" {
					close(reached)
					_ = conn.Wait() //nolint:errcheck // fixture deliberately withholds channel acknowledgement
					return
				}
				channel, requests, err := newChannel.Accept()
				if err != nil {
					return
				}
				defer func() { _ = channel.Close() }() //nolint:errcheck // fixture channel
				for request := range requests {
					switch {
					case phase == "pty" && request.Type == "pty-req",
						phase == "start" && request.Type == "exec",
						phase == "sftp_subsystem" && request.Type == "subsystem":
						close(reached)
						_ = conn.Wait() //nolint:errcheck // no acknowledgement until cancellation closes socket
						return
					case phase == "wait" && request.Type == "exec",
						phase == "sftp_version" && request.Type == "subsystem":
						replyOK(request)
						if phase == "wait" {
							var first [1]byte
							if _, err := io.ReadFull(channel, first[:]); err != nil {
								return
							}
						}
						close(reached)
						_ = conn.Wait() //nolint:errcheck // withhold exit status / SFTP version
						return
					default:
						replyOK(request)
					}
				}
			})
			client := server.client(t, ctx)
			client.config.Command = "fixture"
			client.config.UsePTY = phase == "pty"
			if phase == "wait" {
				client.config.Command, client.config.SudoPassword = "sudo fixture", "fixture"
			}
			type execution struct {
				result ExecResult
				err    error
			}
			done := make(chan execution, 1)
			go func() {
				if strings.HasPrefix(phase, "sftp") {
					client.config.SftpAction = "list"
					_, err := client.ExecuteSftpResult()
					done <- execution{err: err}
				} else {
					result, err := client.RunCommand(phase != "pty")
					done <- execution{result, err}
				}
			}()
			awaitReliability(t, reached)
			cancel()
			select {
			case outcome := <-done:
				require.ErrorIs(t, outcome.err, context.Canceled)
				assert.Equal(t, ErrorKindCancelled, errorKind(t, outcome.err))
				assert.Equal(t, phase == "wait", outcome.result.Started)
				assert.False(t, outcome.result.ExitObserved)
			case <-time.After(time.Second):
				t.Fatal("transport phase did not cancel")
			}
		})
	}
}

func TestTransportConcurrentCloseAndEvidence(t *testing.T) {
	server := newReliabilityServer(t, nil, func(channel ssh.NewChannel, _ *ssh.ServerConn) {
		_ = channel.Reject(ssh.Prohibited, "fixture") //nolint:errcheck // test server rejects channels
	})
	client := server.client(t, context.Background())
	var workers sync.WaitGroup
	for i := 0; i < 30; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			assert.Equal(t, net.JoinHostPort(server.host, server.port), client.PeerAddress())
			assert.Equal(t, ssh.FingerprintSHA256(server.key), client.HostKeyFingerprint())
			_ = client.AuthMethodUsed()
			assert.NoError(t, client.Close())
		}()
	}
	workers.Wait()
	_, err := client.RunCommand(true)
	assert.Equal(t, ErrorKindCancelled, errorKind(t, err))
}

func TestTransportCaptureLimitAndExitObservations(t *testing.T) {
	host, port := startTestSSHServer(t)
	client := dialTestClient(t, host, port)
	client.config.MaxOutputBytes = 3
	client.config.Command = "bothstreams"
	outcome, err := client.RunCommand(true)
	require.NoError(t, err)
	assert.True(t, outcome.Started)
	assert.True(t, outcome.ExitObserved)
	assert.Equal(t, "to-", outcome.Stdout)
	assert.Equal(t, "to-", outcome.Stderr)
	assert.True(t, outcome.StdoutTruncated)
	assert.True(t, outcome.StderrTruncated)
	outcome, err = client.RunScript([]byte{}, false)
	require.NoError(t, err)
	assert.True(t, outcome.ExitObserved)
	assert.Equal(t, "pay", outcome.Stdout)
}

func TestTransportObservedExitSurvivesTimeout(t *testing.T) {
	server := newReliabilityServer(t, nil, func(newChannel ssh.NewChannel, conn *ssh.ServerConn) {
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		defer func() { _ = channel.Close() }() //nolint:errcheck // fixture channel
		for request := range requests {
			replyOK(request)
			if request.Type != "exec" {
				continue
			}
			sendExitStatus(channel, 7)
			_ = conn.Wait() //nolint:errcheck // withhold output EOF until the command budget expires
			return
		}
	})
	client := server.client(t, context.Background())
	client.config.Command = "exit-before-output-eof"
	client.config.Timeout = 500 * time.Millisecond
	outcome, err := client.RunCommand(true)
	require.ErrorIs(t, err, ErrCommandTimeout)
	assert.True(t, outcome.Started)
	assert.True(t, outcome.ExitObserved)
	assert.Equal(t, 7, outcome.ExitCode)
}

func TestTransportRekeyAfterConnect(t *testing.T) {
	server := newReliabilityServer(t, &ssh.ServerConfig{
		NoClientAuth: true,
		Config:       ssh.Config{RekeyThreshold: 1024},
	}, func(newChannel ssh.NewChannel, _ *ssh.ServerConn) {
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		defer func() { _ = channel.Close() }() //nolint:errcheck // fixture channel
		for request := range requests {
			replyOK(request)
			if request.Type != "exec" {
				continue
			}
			_, _ = io.Copy(channel, strings.NewReader(strings.Repeat("x", 256<<10))) //nolint:errcheck // client test asserts complete execution
			sendExitStatus(channel, 0)
			return
		}
	})
	client := server.client(t, context.Background())
	client.config.Command, client.config.MaxOutputBytes = "rekey", 16
	result, err := client.RunCommand(true)
	require.NoError(t, err)
	assert.True(t, result.ExitObserved)
	assert.True(t, result.StdoutTruncated)
	assert.Equal(t, strings.Repeat("x", 16), result.Stdout)
}

func TestTransportSignerPinBeforeDial(t *testing.T) {
	dir := reliabilityDirectory(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.MarshalPrivateKey(private, "")
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(key), 0o600))
	original := dialTCP
	t.Cleanup(func() { dialTCP = original })
	dialTCP = func(context.Context, string, net.Addr, time.Duration) (net.Conn, error) {
		t.Error("dial before signing-key comparison")
		return nil, errors.New("unexpected dial")
	}
	client, err := NewSSHClient(&Config{Host: "fixture", UseKeyAuth: true, KeyPath: keyPath, ExpectedKeyFingerprint: "SHA256:not-admitted"})
	require.NoError(t, err)
	err = client.ConnectDirect()
	assert.Equal(t, "auth", errorKind(t, err))
	assert.Contains(t, err.Error(), "fingerprint changed")
}

func TestTransportFallbackSharesBudget(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(private, "")
	require.NoError(t, err)
	dir := reliabilityDirectory(t)
	keyPath := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600))
	server := newReliabilityServer(t, &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("rejected fixture key")
		},
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}, func(channel ssh.NewChannel, _ *ssh.ServerConn) {
		_ = channel.Reject(ssh.Prohibited, "fixture") //nolint:errcheck // no command expected
	})
	original := dialTCP
	t.Cleanup(func() { dialTCP = original })
	var attempts atomic.Int32
	var firstDeadline time.Time
	dialTCP = func(ctx context.Context, address string, local net.Addr, timeout time.Duration) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		if attempts.Add(1) == 1 {
			firstDeadline = deadline
		} else {
			assert.Equal(t, firstDeadline, deadline)
		}
		return defaultDialTCP(ctx, address, local, timeout)
	}
	client, err := NewSSHClient(&Config{Host: server.host, Port: server.port, Password: "fixture", UseKeyAuth: true, KeyPath: keyPath, KnownHostsData: []byte(knownhosts.Line([]string{net.JoinHostPort(server.host, server.port)}, server.key))})
	require.NoError(t, err)
	require.NoError(t, client.ConnectDirect())
	defer func() { _ = client.Close() }() //nolint:errcheck // fixture teardown
	assert.EqualValues(t, 2, attempts.Load())
	assert.Equal(t, AuthMethodPasswordFallback, client.AuthMethodUsed())
}

func TestTransportTrustSnapshot(t *testing.T) {
	key, other := generateTestPublicKey(t), generateTestPublicKey(t)
	address := "example.test:2222"
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
	for _, pattern := range []string{"[example.test]:2222", "[*.test]:2222", knownhosts.HashHostname(knownhosts.Normalize(address))} {
		t.Run(pattern, func(t *testing.T) {
			trust := []byte(pattern + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + "\n")
			cfg := &Config{KnownHostsData: trust, KnownHostsPath: filepath.Join(reliabilityDirectory(t), "must-not-exist"), AcceptUnknownHost: true}
			callback, err := getHostKeyCallback(cfg)
			require.NoError(t, err)
			for i := range trust {
				trust[i] = 0
			}
			require.NoError(t, callback(address, remote, key))
			require.Error(t, callback(address, remote, other))
			_, err = os.Stat(cfg.KnownHostsPath)
			assert.True(t, os.IsNotExist(err))
		})
	}
	for _, entry := range []string{
		"*.test " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		"[*.test]:2222,![example.test]:2222 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		"@revoked [example.test]:2222 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
	} {
		callback, err := getHostKeyCallback(&Config{KnownHostsData: []byte(entry)})
		require.NoError(t, err)
		require.Error(t, callback(address, remote, key))
	}
	callback, err := getHostKeyCallback(&Config{KnownHostsData: []byte{}, AcceptUnknownHost: true, AllowInsecureHostKey: true})
	require.NoError(t, err)
	assert.Equal(t, "host_key", errorKind(t, callback(address, remote, key)))
	_, err = getHostKeyCallback(&Config{KnownHostsData: []byte("malformed")})
	require.Error(t, err)
}

func TestTransportTrustSnapshotCertificates(t *testing.T) {
	_, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	authority, err := ssh.NewSignerFromKey(authorityPrivate)
	require.NoError(t, err)
	certificate := &ssh.Certificate{
		Key: generateTestPublicKey(t), CertType: ssh.HostCert,
		ValidPrincipals: []string{"example.test"},
		ValidAfter:      1, ValidBefore: ssh.CertTimeInfinity,
	}
	require.NoError(t, certificate.SignCert(rand.Reader, authority))
	trust := "@cert-authority [*.test]:2222 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(authority.PublicKey())))
	callback, err := getHostKeyCallback(&Config{KnownHostsData: []byte(trust)})
	require.NoError(t, err)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
	require.NoError(t, callback("example.test:2222", remote, certificate))
	require.Error(t, callback("different.test:2222", remote, certificate))
	require.Error(t, callback("example.test:2222", remote, authority.PublicKey()))
	trust += "\n@revoked * " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(authority.PublicKey())))
	callback, err = getHostKeyCallback(&Config{KnownHostsData: []byte(trust)})
	require.NoError(t, err)
	require.Error(t, callback("example.test:2222", remote, certificate))
}

type noExtensionsChannel struct{ ssh.Channel }

func (c noExtensionsChannel) Write(p []byte) (int, error) {
	if len(p) >= 9 && p[4] == 2 {
		packet := append([]byte(nil), p[:9]...)
		binary.BigEndian.PutUint32(packet[:4], 5)
		if _, err := c.Channel.Write(packet); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Channel.Write(p)
}

func reliabilitySFTP(t *testing.T, root string, readOnly bool, noAtomic ...bool) reliabilityServer {
	t.Helper()
	return newReliabilityServer(t, nil, func(newChannel ssh.NewChannel, _ *ssh.ServerConn) {
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		defer func() { _ = channel.Close() }() //nolint:errcheck // fixture channel
		for request := range requests {
			if request.Type != "subsystem" {
				replyOK(request)
				continue
			}
			replyOK(request)
			options := []sftp.ServerOption{sftp.WithServerWorkingDirectory(root)}
			if readOnly {
				options = append(options, sftp.ReadOnly())
			}
			var stream io.ReadWriteCloser = channel
			if len(noAtomic) > 0 && noAtomic[0] {
				stream = noExtensionsChannel{channel}
			}
			server, err := sftp.NewServer(stream, options...)
			if err != nil {
				return
			}
			_ = server.Serve() //nolint:errcheck // EOF ends fixture
			_ = server.Close() //nolint:errcheck // fixture teardown
			return
		}
	})
}

func TestSFTPReliabilityWithoutAtomicReplace(t *testing.T) {
	root := reliabilityDirectory(t)
	server := reliabilitySFTP(t, root, false, true)
	client := server.client(t, context.Background())
	client.config.SftpAction, client.config.RemotePath = "upload", filepath.Join(root, "destination")
	client.config.PreparedPayload = []byte("first")
	outcome, err := client.ExecuteSftpResult()
	require.NoError(t, err)
	require.Len(t, outcome.Entries, 1)
	assert.Equal(t, "sftp_rename_no_replace", outcome.Entries[0].Publication)
	client.config.PreparedPayload = []byte("second")
	outcome, err = client.ExecuteSftpResult()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lacks atomic replacement")
	assert.Equal(t, "unchanged", outcome.ChangeState)
	actual, err := os.ReadFile(client.config.RemotePath) // #nosec G304 -- isolated fixture path
	require.NoError(t, err)
	assert.Equal(t, "first", string(actual))
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestSFTPReliabilityStagedUploadDownload(t *testing.T) {
	root := reliabilityDirectory(t)
	server := reliabilitySFTP(t, root, false)
	client := server.client(t, context.Background())
	destination := filepath.Join(root, "destination")
	require.NoError(t, os.WriteFile(destination, []byte("old"), 0o640)) // #nosec G306 -- permission preservation fixture
	client.config.SftpAction, client.config.LocalPath, client.config.RemotePath = "upload", "unread-legacy-source", destination
	client.config.PreparedPayload = []byte("admitted bytes")
	outcome, err := client.ExecuteSftpResult()
	require.NoError(t, err)
	assert.True(t, outcome.Started)
	assert.True(t, outcome.Verified)
	assert.Equal(t, "changed", outcome.ChangeState)
	require.Len(t, outcome.Entries, 1)
	assert.True(t, outcome.Entries[0].Published)
	assert.Equal(t, SHA256Hex(client.config.PreparedPayload), outcome.Entries[0].SHA256)
	actual, err := os.ReadFile(destination) // #nosec G304 -- isolated fixture path
	require.NoError(t, err)
	assert.Equal(t, client.config.PreparedPayload, actual)
	client.config.PreparedPayload = []byte{}
	outcome, err = client.ExecuteSftpResult()
	require.NoError(t, err)
	assert.True(t, outcome.Verified)
	assert.EqualValues(t, 0, outcome.BytesTransferred)
	client.config.SftpAction, client.config.LocalPath = "download", filepath.Join(root, "local")
	outcome, err = client.ExecuteSftpResult()
	require.NoError(t, err)
	assert.True(t, outcome.Verified)
	actual, err = os.ReadFile(client.config.LocalPath)
	require.NoError(t, err)
	assert.Empty(t, actual)
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Len(t, entries, 2, "staging files must be removed")
}

func TestSFTPReliabilityPermissionAndLocalFailure(t *testing.T) {
	root := reliabilityDirectory(t)
	server := reliabilitySFTP(t, root, true)
	client := server.client(t, context.Background())
	destination := filepath.Join(root, "destination")
	require.NoError(t, os.WriteFile(destination, []byte("preserve"), 0o600))
	client.config.SftpAction, client.config.RemotePath = "upload", destination
	client.config.PreparedPayload = []byte("replace")
	outcome, err := client.ExecuteSftpResult()
	assert.Equal(t, "remote_io", errorKind(t, err))
	assert.False(t, outcome.Verified)
	actual, err := os.ReadFile(destination) // #nosec G304 -- isolated fixture path
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(actual))
	client.config.PreparedPayload, client.config.LocalPath = nil, filepath.Join(root, "absent")
	outcome, err = client.ExecuteSftpResult()
	assert.Equal(t, "local_io", errorKind(t, err))
	assert.False(t, outcome.Started)
	assert.Equal(t, "unchanged", outcome.ChangeState)
}

type failedCopyReader struct{}

func (failedCopyReader) Read([]byte) (int, error) { return 0, errors.New("source failed") }

func TestSFTPReliabilityPartialCopyPreservesDestination(t *testing.T) {
	root := reliabilityDirectory(t)
	server := reliabilitySFTP(t, root, false)
	client := server.client(t, context.Background())
	sftpClient, err := client.newSFTPClient()
	require.NoError(t, err)
	defer func() { _ = sftpClient.Close() }() //nolint:errcheck // fixture
	destination := filepath.Join(root, "destination")
	require.NoError(t, os.WriteFile(destination, []byte("original"), 0o600))
	entry := FileOutcome{Path: destination, ChangeState: "unchanged"}
	source := io.MultiReader(bytes.NewBufferString("partial"), failedCopyReader{})
	err = publishRemoteFile(context.Background(), sftpClient, source, "local_io", 100, nil, &entry)
	assert.Equal(t, "local_io", errorKind(t, err))
	assert.EqualValues(t, 7, entry.BytesTransferred)
	assert.False(t, entry.Published)
	assert.False(t, entry.Verified)
	assert.Empty(t, entry.StagingPath)
	actual, err := os.ReadFile(destination) // #nosec G304 -- isolated fixture path
	require.NoError(t, err)
	assert.Equal(t, "original", string(actual))
	files, err := os.ReadDir(root)
	require.NoError(t, err)
	assert.Len(t, files, 1)
}

func TestSFTPReliabilityDirectoryEvidence(t *testing.T) {
	root := reliabilityDirectory(t)
	server := reliabilitySFTP(t, root, false)
	client := server.client(t, context.Background())
	client.config.SftpAction, client.config.RemotePath = "mkdir", filepath.Join(root, "new", "child")
	outcome, err := client.ExecuteSftpResult()
	require.NoError(t, err)
	assert.True(t, outcome.Verified)
	assert.Equal(t, "changed", outcome.ChangeState)
	outcome, err = client.ExecuteSftpResult()
	require.NoError(t, err)
	assert.Equal(t, "unchanged", outcome.ChangeState)
	client.config.SftpAction, client.config.RemotePath = "remove", filepath.Join(root, "new")
	outcome, err = client.ExecuteSftpResult()
	require.NoError(t, err)
	assert.True(t, outcome.Verified)
	assert.False(t, outcome.DirectoryAtomic)
	assert.Len(t, outcome.Entries, 2)
	_, err = os.Stat(client.config.RemotePath)
	assert.True(t, os.IsNotExist(err))
}

func TestTransferReliabilityVerifiedTree(t *testing.T) {
	root := reliabilityDirectory(t)
	sourcePath, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	require.NoError(t, os.Mkdir(sourcePath, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(sourcePath, "file"), []byte("transfer fixture"), 0o640)) // #nosec G306 -- permission preservation fixture
	src := reliabilitySFTP(t, root, false).client(t, context.Background())
	dst := reliabilitySFTP(t, root, false).client(t, context.Background())
	outcome, err := src.TransferToResult(dst, sourcePath, destination)
	require.NoError(t, err)
	assert.True(t, outcome.Verified)
	assert.False(t, outcome.DirectoryAtomic)
	assert.Len(t, outcome.Entries, 2)
	actual, err := os.ReadFile(filepath.Join(destination, "file")) // #nosec G304 -- isolated fixture path
	require.NoError(t, err)
	assert.Equal(t, "transfer fixture", string(actual))
}

func TestTransferReliabilityPartialDirectory(t *testing.T) {
	root := reliabilityDirectory(t)
	sourcePath, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	require.NoError(t, os.MkdirAll(filepath.Join(sourcePath, "b"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(sourcePath, "a"), []byte("first committed"), 0o600))
	target := filepath.Join(destination, "source")
	require.NoError(t, os.MkdirAll(target, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(target, "b"), []byte("not a directory"), 0o600))
	source := reliabilitySFTP(t, root, false).client(t, context.Background())
	dest := reliabilitySFTP(t, root, false).client(t, context.Background())
	outcome, err := source.TransferToResult(dest, sourcePath, destination)
	require.Error(t, err)
	assert.True(t, outcome.Partial)
	assert.False(t, outcome.Verified)
	assert.False(t, outcome.DirectoryAtomic)
	assert.Equal(t, "changed", outcome.ChangeState)
	actual, err := os.ReadFile(filepath.Join(target, "a")) // #nosec G304 -- isolated fixture path
	require.NoError(t, err)
	assert.Equal(t, "first committed", string(actual))
	actual, err = os.ReadFile(filepath.Join(target, "b")) // #nosec G304 -- isolated fixture path
	require.NoError(t, err)
	assert.Equal(t, "not a directory", string(actual))
	require.Len(t, outcome.Entries, 3)
	assert.True(t, outcome.Entries[1].Published)
	assert.True(t, outcome.Entries[1].Verified)
}

type blockingSFTPWriter struct {
	base    sftp.FileWriter
	reached chan struct{}
	release <-chan struct{}
}

func (w blockingSFTPWriter) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	file, err := w.base.Filewrite(request)
	if err != nil {
		return nil, err
	}
	return &blockingWriterAt{base: file, reached: w.reached, release: w.release}, nil
}

type blockingWriterAt struct {
	base    io.WriterAt
	once    sync.Once
	reached chan struct{}
	release <-chan struct{}
}

func (w *blockingWriterAt) WriteAt(p []byte, offset int64) (int, error) {
	w.once.Do(func() { close(w.reached) })
	<-w.release
	return w.base.WriteAt(p, offset)
}

func (w *blockingWriterAt) Close() error {
	if closer, ok := w.base.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func TestSFTPReliabilityCancelledCopyRetainsEvidence(t *testing.T) {
	reached, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	handlers := sftp.InMemHandler()
	handlers.FilePut = blockingSFTPWriter{base: handlers.FilePut, reached: reached, release: release}
	server := newReliabilityServer(t, nil, func(newChannel ssh.NewChannel, _ *ssh.ServerConn) {
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		defer func() { _ = channel.Close() }() //nolint:errcheck // fixture
		for request := range requests {
			replyOK(request)
			if request.Type != "subsystem" {
				continue
			}
			backend := sftp.NewRequestServer(channel, handlers)
			_ = backend.Serve() //nolint:errcheck // fixture disconnect
			_ = backend.Close() //nolint:errcheck // fixture shutdown
			return
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := server.client(t, ctx)
	client.config.SftpAction, client.config.RemotePath = "upload", "/destination"
	client.config.PreparedPayload = []byte("not acknowledged")
	type result struct {
		out *SFTPOutcome
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := client.ExecuteSftpResult()
		done <- result{out, err}
	}()
	awaitReliability(t, reached)
	cancel()
	select {
	case outcome := <-done:
		assert.Equal(t, ErrorKindCancelled, errorKind(t, outcome.err))
		assert.True(t, outcome.out.Partial)
		assert.False(t, outcome.out.Verified)
		assert.Equal(t, "unchanged", outcome.out.ChangeState, "destination was never published")
		require.Len(t, outcome.out.Entries, 1)
		entry := outcome.out.Entries[0]
		assert.True(t, entry.Started)
		assert.False(t, entry.Published)
		assert.NotEmpty(t, entry.StagingPath)
		assert.NotEmpty(t, entry.CleanupError, "disconnect prevents promising staging cleanup")
	case <-time.After(time.Second):
		t.Fatal("canceled SFTP write did not return")
	}
	unblock()
}

func TestTransferReliabilityCancellationClosesBoth(t *testing.T) {
	root := reliabilityDirectory(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := reliabilitySFTP(t, root, false).client(t, ctx)
	reached := make(chan struct{})
	destinationServer := newReliabilityServer(t, nil, func(_ ssh.NewChannel, conn *ssh.ServerConn) {
		close(reached)
		_ = conn.Wait() //nolint:errcheck // stalled destination SFTP session
	})
	destination := destinationServer.client(t, context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := source.TransferToResult(destination, filepath.Join(root, "file"), "/destination")
		done <- err
	}()
	awaitReliability(t, reached)
	cancel()
	select {
	case err := <-done:
		assert.Equal(t, ErrorKindCancelled, errorKind(t, err))
	case <-time.After(time.Second):
		t.Fatal("relay cancellation did not unblock both transports")
	}
	_, err := destination.sshConnection()
	require.ErrorIs(t, err, context.Canceled)
}

func TestTransportBoundaryErrorWrapping(t *testing.T) {
	for _, tc := range []struct {
		kind  string
		cause error
		want  string
	}{
		{"connect", context.Canceled, ErrorKindCancelled},
		{"connect", context.DeadlineExceeded, "timeout"},
		{"remote_io", boundaryError("local_io", "read", io.ErrUnexpectedEOF), "local_io"},
		{"remote_io", fmt.Errorf("wrapped: %w", ErrCommandTimeout), "timeout"},
		{"verification_failed", boundaryError("remote_io", "read", io.ErrUnexpectedEOF), "verification_failed"},
	} {
		err := boundaryError(tc.kind, "outer", tc.cause)
		assert.Equal(t, tc.want, errorKind(t, err))
		assert.ErrorIs(t, err, tc.cause)
	}
}
