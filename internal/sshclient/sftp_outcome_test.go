package sshclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSFTPLifecycleEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		out                             SFTPOutcome
		err                             error
		executed                        int
		phase, completion, verification string
	}{
		{
			name: "setup never started",
			out:  SFTPOutcome{Action: "upload", Phase: "connect"}, err: context.Canceled,
			executed: 0, phase: "connect", completion: "not_started", verification: "not_performed",
		},
		{
			name: "partial staging is not target publication",
			out: SFTPOutcome{Action: "upload", Phase: "execute", Entries: []FileOutcome{
				{Started: true, ChangeState: "unchanged", BytesTransferred: 4, phase: "execute", Verification: "not_performed"},
			}}, err: io.ErrUnexpectedEOF,
			executed: 0, phase: "execute", completion: "partial", verification: "unknown",
		},
		{
			name: "lost publication acknowledgement",
			out: SFTPOutcome{Action: "upload", Phase: "execute", Entries: []FileOutcome{
				{Started: true, ChangeState: "unknown", phase: "execute", Publication: "posix_rename", Verification: "not_performed"},
			}}, err: context.Canceled,
			executed: -1, phase: "execute", completion: "unknown", verification: "unknown",
		},
		{
			name: "post publication mismatch",
			out: SFTPOutcome{Action: "upload", DestinationPath: "/target", Phase: "execute", Entries: []FileOutcome{
				{Path: "/target", Started: true, Published: true, ChangeState: "changed", phase: "collect", Verification: "failed"},
			}}, err: io.ErrUnexpectedEOF,
			executed: 1, phase: "collect", completion: "completed", verification: "failed",
		},
		{
			name: "post publication unavailable",
			out: SFTPOutcome{Action: "upload", DestinationPath: "/target", Phase: "execute", Entries: []FileOutcome{
				{Path: "/target", Started: true, Published: true, ChangeState: "changed", phase: "collect", Verification: "unknown"},
			}}, err: context.DeadlineExceeded,
			executed: 1, phase: "collect", completion: "completed", verification: "unknown",
		},
		{
			name: "verified publication",
			out: SFTPOutcome{Action: "upload", Phase: "execute", operationComplete: true, Entries: []FileOutcome{
				{Started: true, Published: true, ChangeState: "changed", Verified: true, Verification: "passed", phase: "collect"},
			}},
			executed: 1, phase: "complete", completion: "completed", verification: "passed",
		},
		{
			name: "verified no-op directory",
			out: SFTPOutcome{Action: "mkdir", Phase: "execute", operationComplete: true, Entries: []FileOutcome{
				{Started: true, ChangeState: "unchanged", Verified: true, Verification: "passed", phase: "collect"},
			}},
			executed: 0, phase: "complete", completion: "completed", verification: "passed",
		},
		{
			name: "directory partial progress",
			out: SFTPOutcome{Action: "transfer", Phase: "execute", DestinationPath: "/target", directory: true, Entries: []FileOutcome{
				{Path: "/target", Started: true, ChangeState: "changed", Verified: true, Verification: "passed"},
				{Path: "/target/first", Started: true, Published: true, ChangeState: "changed", Verified: true, Verification: "passed"},
				{Path: "/target/second", ChangeState: "unchanged", Verification: "not_performed", phase: "execute"},
			}}, err: io.ErrUnexpectedEOF,
			executed: 1, phase: "execute", completion: "partial", verification: "unknown",
		},
		{
			name: "cleanup failure preserves completed facts",
			out: SFTPOutcome{Action: "upload", Phase: "execute", operationComplete: true, Entries: []FileOutcome{
				{Started: true, Published: true, ChangeState: "changed", Verified: true, Verification: "passed", phase: "collect"},
			}}, err: io.ErrClosedPipe,
			executed: 1, phase: "collect", completion: "completed", verification: "passed",
		},
		{
			name: "listing request acknowledgement lost",
			out:  SFTPOutcome{Action: "list", Phase: "execute", readAttempted: true}, err: context.Canceled,
			executed: -1, phase: "execute", completion: "unknown", verification: "unknown",
		},
		{
			name:     "empty listing acknowledged",
			out:      SFTPOutcome{Action: "list", Phase: "execute", Started: true, operationComplete: true},
			executed: 1, phase: "complete", completion: "completed", verification: "passed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			finishSFTPOutcome(&tc.out, tc.err)
			if tc.executed < 0 {
				assert.Nil(t, tc.out.Executed)
			} else {
				require.NotNil(t, tc.out.Executed)
				assert.Equal(t, tc.executed == 1, *tc.out.Executed)
			}
			assert.Equal(t, tc.phase, tc.out.Phase)
			assert.Equal(t, tc.completion, tc.out.Completion)
			assert.Equal(t, tc.verification, tc.out.Verification)
			assert.Equal(t, tc.verification == "passed", tc.out.Verified)
			encoded, err := json.Marshal(tc.out)
			require.NoError(t, err)
			if tc.executed < 0 {
				assert.Contains(t, string(encoded), `"executed":null`)
			}
			assert.Contains(t, string(encoded), `"phase":"`+tc.phase+`"`)
			assert.Contains(t, string(encoded), `"completion":"`+tc.completion+`"`)
			assert.Contains(t, string(encoded), `"verification_method":`)
		})
	}
}

type sftpRenderFailureWriter struct{}

func (sftpRenderFailureWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestRenderSFTPOutcomeWithoutExecution(t *testing.T) {
	root := reliabilityDirectory(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "artifact.txt"), []byte("listing fixture"), 0o600))
	client := reliabilitySFTP(t, root, false).client(t, context.Background())
	client.config.SftpAction, client.config.RemotePath = "list", root
	out, err := client.ExecuteSftpResult()
	require.NoError(t, err)
	require.NoError(t, client.Close())
	require.NotNil(t, out.Executed)
	assert.True(t, *out.Executed)
	assert.Equal(t, "passed", out.Verification)
	assert.Equal(t, "metadata", out.VerificationMethod)
	require.Len(t, out.Entries, 1)
	assert.Equal(t, "passed", out.Entries[0].Verification)
	assert.Equal(t, "metadata", out.Entries[0].VerificationMethod)
	before, err := json.Marshal(out)
	require.NoError(t, err)
	var rendered bytes.Buffer
	require.NoError(t, renderSFTPOutcome(&rendered, out))
	assert.Contains(t, rendered.String(), "Permissions")
	assert.Contains(t, rendered.String(), "Modified")
	assert.Contains(t, rendered.String(), "artifact.txt")
	assert.Contains(t, rendered.String(), "Total: 1 items")
	assert.Contains(t, rendered.String(), "rw")
	require.ErrorIs(t, renderSFTPOutcome(sftpRenderFailureWriter{}, out), io.ErrClosedPipe)
	after, err := json.Marshal(out)
	require.NoError(t, err)
	assert.Equal(t, before, after, "rendering must not change finalized evidence")
	require.Error(t, renderSFTPOutcome(&rendered, nil))
}

func TestSFTPLifecycleBeforeConnection(t *testing.T) {
	client, err := NewSSHClient(&Config{Host: "fixture", SftpAction: "download", RemotePath: "/source", LocalPath: "destination"})
	require.NoError(t, err)
	out, err := client.ExecuteSftpResult()
	require.Error(t, err)
	require.NotNil(t, out.Executed)
	assert.False(t, *out.Executed)
	assert.Equal(t, "connect", out.Phase)
	assert.Equal(t, "not_started", out.Completion)
	assert.Equal(t, "/source", out.SourcePath)
	assert.Equal(t, "destination", out.DestinationPath)
	require.NoError(t, client.Close())
}

type unacknowledgedRename struct {
	base      sftp.FileCmder
	once      sync.Once
	published chan struct{}
	release   <-chan struct{}
}

func (r *unacknowledgedRename) Filecmd(request *sftp.Request) error {
	return r.base.Filecmd(request)
}

func (r *unacknowledgedRename) PosixRename(request *sftp.Request) error {
	var err error
	if atomic, ok := r.base.(sftp.PosixRenameFileCmder); ok {
		err = atomic.PosixRename(request)
	} else {
		err = r.base.Filecmd(&sftp.Request{Method: "Rename", Filepath: request.Filepath, Target: request.Target})
	}
	if err != nil {
		return err
	}
	r.once.Do(func() { close(r.published) })
	<-r.release
	return nil
}

func TestSFTPLifecycleLostPublicationAcknowledgement(t *testing.T) {
	published, release := make(chan struct{}), make(chan struct{})
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(release) }) }
	defer unblock()
	handlers := sftp.InMemHandler()
	handlers.FileCmd = &unacknowledgedRename{base: handlers.FileCmd, published: published, release: release}
	server := newReliabilityServer(t, nil, func(newChannel ssh.NewChannel, _ *ssh.ServerConn) {
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		defer func() { _ = channel.Close() }() //nolint:errcheck // fixture channel
		for request := range requests {
			replyOK(request)
			if request.Type != "subsystem" {
				continue
			}
			backend := sftp.NewRequestServer(channel, handlers)
			_ = backend.Serve() //nolint:errcheck // fixture disconnect
			_ = backend.Close() //nolint:errcheck // fixture teardown
			return
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := server.client(t, ctx)
	client.config.SftpAction, client.config.RemotePath = "upload", "/destination"
	client.config.PreparedPayload = []byte("actually published")
	type result struct {
		out *SFTPOutcome
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := client.ExecuteSftpResult()
		done <- result{out, err}
	}()
	awaitReliability(t, published)
	cancel()
	var resultWithLostAck result
	select {
	case resultWithLostAck = <-done:
		require.ErrorIs(t, resultWithLostAck.err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("unacknowledged publication did not cancel")
	}
	assert.Nil(t, resultWithLostAck.out.Executed)
	assert.Equal(t, "execute", resultWithLostAck.out.Phase)
	assert.Equal(t, "unknown", resultWithLostAck.out.Completion)
	assert.Equal(t, "unknown", resultWithLostAck.out.ChangeState)
	assert.Equal(t, "unknown", resultWithLostAck.out.Verification)
	unblock()
	observer := server.client(t, context.Background())
	sftpClient, err := observer.newSFTPClient()
	require.NoError(t, err)
	defer func() { _ = sftpClient.Close() }() //nolint:errcheck // fixture observer
	file, err := sftpClient.Open("/destination")
	require.NoError(t, err)
	defer func() { _ = file.Close() }() //nolint:errcheck // fixture observer
	actual, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.Equal(t, "actually published", string(actual), "missing acknowledgement must not be projected as no effect")
}
