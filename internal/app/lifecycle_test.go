package app

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestCommandResultAcknowledgementLoss(t *testing.T) {
	config := &sshclient.Config{Mode: "ssh", Command: "unknown-writer"}
	result := commandResult(config, sshclient.AuthMethodPassword,
		sshclient.ExecResult{StartAttempted: true, ExitCode: -1}, time.Second, "connection_lost", context.Canceled)
	require.Nil(t, result.Executed)
	require.Equal(t, execution.PhaseExecute, result.Phase)
	require.Equal(t, execution.CompletionUnknown, result.Completion)
}

func TestCommandResultPreservesObservedExitOnCancellation(t *testing.T) {
	config := &sshclient.Config{Mode: "ssh", Command: "true"}
	result := commandResult(config, sshclient.AuthMethodPassword,
		sshclient.ExecResult{StartAttempted: true, Started: true, ExitObserved: true, ExitCode: 0},
		time.Second, execution.ErrorKindCancelled, context.Canceled)
	require.Equal(t, 0, result.ExitCode)
	require.Equal(t, execution.CompletionCompleted, result.Completion)
	require.False(t, result.Success)
}

func TestLifecycleFingerprintRetainsObservedPeer(t *testing.T) {
	config := &sshclient.Config{Mode: "ssh", Command: "true", ExecutionID: "invocation"}
	p := &preparedOperation{meta: execution.NewMetadata(nil, config.ExecutionID)}
	p.meta.Peers = []execution.PeerIdentity{{Role: "target", Address: "127.0.0.1:22", HostKeyFingerprint: "SHA256:observed"}}
	attachPrepared(config, p)
	document, err := finalizeLifecycle(config, commandResult(config, sshclient.AuthMethodPassword,
		sshclient.ExecResult{StartAttempted: true, Started: true, ExitObserved: true}, time.Second, "", nil))
	require.NoError(t, err)
	var metadata execution.Metadata
	data, err := json.Marshal(document)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &metadata))
	require.Equal(t, p.meta.ExecutionFingerprint, metadata.ExecutionFingerprint)
	require.Equal(t, "SHA256:observed", metadata.Peers[0].HostKeyFingerprint)
	metadata.Peers = []execution.PeerIdentity{{Role: "target", HostKeyFingerprint: "SHA256:changed"}}
	metadata.Finish(execution.StatusSucceeded, execution.PhaseComplete, execution.CompletionCompleted, 0, "")
	require.NotEqual(t, p.meta.ExecutionFingerprint, metadata.ExecutionFingerprint)
}

func TestLifecycleRetainsEarliestDeadlineScope(t *testing.T) {
	global, cancelGlobal := execution.WithScopedTimeout(context.Background(), -time.Second, "global")
	defer cancelGlobal()
	host, cancelHost := execution.WithScopedTimeout(global, time.Second, "host")
	defer cancelHost()
	var metadata execution.Metadata
	metadata.ObserveContext(host)
	require.Equal(t, "global", metadata.DeadlineScope)
	require.Equal(t, "deadline_exceeded", metadata.CancellationCause)
}

func TestFileEvidenceDoesNotPublishStagingObservation(t *testing.T) {
	config := &sshclient.Config{Mode: "sftp", SftpAction: "download"}
	outcome := &sshclient.SFTPOutcome{Action: "download", Entries: []sshclient.FileOutcome{{
		Path: "/destination", StagingPath: "/staging", Type: "file",
		SourceSHA256: "matching-digest", SHA256: "matching-digest", Published: false,
	}}}
	result, err := fileOperationResult(config, outcome, time.Now(), errors.New("sync failed"))
	require.NoError(t, err)
	conditions, ok := result["postconditions"].([]execution.Condition)
	require.True(t, ok)
	var destination, staging *execution.Condition
	for i := range conditions {
		switch conditions[i].Kind {
		case "file_sha256":
			destination = &conditions[i]
		case "staging_sha256":
			staging = &conditions[i]
		}
	}
	require.NotNil(t, destination)
	require.Equal(t, "unknown", destination.Status)
	require.Empty(t, destination.Observed)
	require.NotNil(t, staging)
	require.Equal(t, "passed", staging.Status)
	require.Equal(t, "/staging", staging.Subject)
}

func TestFileEvidenceIncludesObservedOwnership(t *testing.T) {
	config := &sshclient.Config{Mode: "sftp", SftpAction: "upload"}
	uid, gid := uint32(0), uint32(42)
	outcome := &sshclient.SFTPOutcome{Action: "upload", Entries: []sshclient.FileOutcome{{
		Path: "/destination", Type: "file", UID: &uid, GID: &gid, Published: true, Verified: true,
	}}}
	result, err := fileOperationResult(config, outcome, time.Now(), nil)
	require.NoError(t, err)
	conditions, ok := result["postconditions"].([]execution.Condition)
	require.True(t, ok)
	require.Contains(t, conditions, execution.Condition{Kind: "file_uid", Subject: "/destination", Observed: "0", Status: "passed"})
	require.Contains(t, conditions, execution.Condition{Kind: "file_gid", Subject: "/destination", Observed: "42", Status: "passed"})
}
