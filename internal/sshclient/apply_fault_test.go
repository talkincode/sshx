package sshclient

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

type applyFaultFS struct {
	base    sftp.Handlers
	conn    net.Conn
	mu      sync.Mutex
	fault   string
	reads   int
	renames int
}

func (f *applyFaultFS) Fileread(req *sftp.Request) (io.ReaderAt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.Filepath == "/app.conf" {
		f.reads++
		if f.reads > 1 {
			switch f.fault {
			case "readback":
				return nil, sftp.ErrSSHFxPermissionDenied
			case "mismatch", "recheck":
				return bytes.NewReader([]byte("other writer\n")), nil
			}
		}
	}
	return f.base.FileGet.Fileread(req)
}

func (f *applyFaultFS) Filewrite(req *sftp.Request) (io.WriterAt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	writer, err := f.base.FilePut.Filewrite(req)
	if err == nil && strings.Contains(req.Filepath, ".sshx.tmp") && f.fault == "write" {
		return &applyFailWriter{WriterAt: writer}, nil
	}
	return writer, err
}

type applyFailWriter struct{ io.WriterAt }

func (w *applyFailWriter) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, sftp.ErrSSHFxPermissionDenied
}
func (w *applyFailWriter) Close() error {
	if closer, ok := w.WriterAt.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (f *applyFaultFS) Filecmd(req *sftp.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.Method == "Rename" {
		f.renames++
	}
	return f.base.FileCmd.Filecmd(req)
}

func (f *applyFaultFS) PosixRename(req *sftp.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch f.fault {
	case "rename-denied":
		return sftp.ErrSSHFxPermissionDenied
	case "unsupported":
		return sftp.ErrSSHFxOpUnsupported
	}
	var err error
	if handler, ok := f.base.FileCmd.(sftp.PosixRenameFileCmder); ok {
		err = handler.PosixRename(req)
	} else {
		err = f.base.FileCmd.Filecmd(req)
	}
	if err == nil && f.fault == "ack-loss" {
		_ = f.conn.Close() //nolint:errcheck // intentional acknowledgement-loss fault
	}
	return err
}

func newApplyTestSFTP(t *testing.T, fault string) (*sftp.Client, *applyFaultFS) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	base := sftp.InMemHandler()
	fs := &applyFaultFS{base: base, conn: serverConn, fault: fault}
	server := sftp.NewRequestServer(serverConn, sftp.Handlers{
		FileGet: fs, FilePut: fs, FileCmd: fs, FileList: base.FileList,
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve() //nolint:errcheck // EOF is expected when this fixture closes
	}()
	client, err := sftp.NewClientPipe(clientConn, clientConn)
	require.NoError(t, err)
	require.NoError(t, client.Mkdir("/backups"))
	t.Cleanup(func() {
		_ = client.Close()     //nolint:errcheck // fixture teardown
		_ = server.Close()     //nolint:errcheck // fixture teardown
		_ = clientConn.Close() //nolint:errcheck // fixture teardown
		<-done
	})
	return client, fs
}

func TestApplySFTPPartialEvidence(t *testing.T) {
	for _, tc := range []struct {
		fault             string
		executed          *bool
		state             string
		verificationError bool
	}{
		{"write", applyTestBool(false), "unchanged", false},
		{"rename-denied", applyTestBool(false), "unchanged", false},
		{"readback", applyTestBool(true), "changed", true},
		{"mismatch", applyTestBool(true), "changed", true},
		{"ack-loss", nil, "unknown", true},
		{"recheck", applyTestBool(false), "unchanged", false},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			client, fs := newApplyTestSFTP(t, tc.fault)
			before, payload := []byte("before\n"), []byte("after\n")
			require.NoError(t, writePrivateFile(client, "/app.conf", before))
			require.NoError(t, client.Chmod("/app.conf", 0o640))
			req := ApplyRequest{RemotePath: "/app.conf", Payload: payload, Backup: true, BackupDir: "/backups"}
			if tc.fault == "recheck" {
				req.ExpectSHA256 = SHA256Hex(before)
			}
			outcome, err := (&SSHClient{}).applySFTPFile(client, req)
			require.Error(t, err)
			require.NotNil(t, outcome)
			require.Equal(t, tc.verificationError, errors.Is(err, ErrApplyVerification), "%v", err)
			require.Equal(t, SHA256Hex(before), outcome.BeforeSHA256)
			require.Equal(t, SHA256Hex(payload), outcome.PayloadSHA256)
			require.Equal(t, tc.state, outcome.ChangeState)
			require.Equal(t, tc.executed, outcome.Executed)
			require.False(t, outcome.Verified)
			require.Equal(t, "0644", outcome.Mode) // InMemHandler exposes fixed permissions.
			require.NotNil(t, outcome.UID)
			require.NotEmpty(t, outcome.BackupPath)
			require.True(t, outcome.BackupVerified)
			if tc.fault == "ack-loss" {
				require.NotEmpty(t, outcome.CleanupPending)
				return
			}
			if tc.fault == "mismatch" {
				require.Equal(t, SHA256Hex([]byte("other writer\n")), outcome.AfterSHA256)
			}
			if tc.fault == "recheck" {
				require.ErrorIs(t, err, ErrPrecondition)
				require.Equal(t, "failed", outcome.PreconditionStatus)
				require.Equal(t, SHA256Hex([]byte("other writer\n")), outcome.PreconditionSHA256)
			}
			saved, readErr := readRemoteRegularFile(client, outcome.BackupPath, 0)
			require.NoError(t, readErr)
			require.Equal(t, before, saved)
			entries, listErr := client.ReadDir("/")
			require.NoError(t, listErr)
			for _, entry := range entries {
				require.NotContains(t, entry.Name(), ".sshx.tmp", "owned temporary files must be cleaned")
			}
			fs.mu.Lock()
			renames := fs.renames
			fs.mu.Unlock()
			require.Zero(t, renames, "must not fall back from a permission or transport failure")
		})
	}
}

func TestApplySFTPZeroByteNoopAndPrecondition(t *testing.T) {
	client, _ := newApplyTestSFTP(t, "")
	req := ApplyRequest{RemotePath: "/app.conf", Payload: []byte{}, Backup: true, BackupDir: "/backups"}
	outcome, err := (&SSHClient{}).applySFTPFile(client, req)
	require.NoError(t, err)
	require.True(t, outcome.Created)
	require.True(t, outcome.Verified)
	require.Equal(t, SHA256Hex(nil), outcome.AfterSHA256)
	outcome, err = (&SSHClient{}).applySFTPFile(client, req)
	require.NoError(t, err)
	require.False(t, *outcome.Executed)
	require.False(t, outcome.Changed)
	require.True(t, outcome.Verified)
	require.Empty(t, outcome.BackupPath)
	req.Payload = []byte("different")
	req.ExpectSHA256 = SHA256Hex([]byte("wrong"))
	outcome, err = (&SSHClient{}).applySFTPFile(client, req)
	require.ErrorIs(t, err, ErrPrecondition)
	require.Equal(t, SHA256Hex(nil), outcome.BeforeSHA256)
	require.False(t, *outcome.Executed)
	req.Force = true
	outcome, err = (&SSHClient{}).applySFTPFile(client, req)
	require.NoError(t, err)
	require.True(t, outcome.Changed)
	require.True(t, outcome.BackupVerified)
	require.Equal(t, "bypassed", outcome.PreconditionStatus)
}

func TestApplyRenameFallbackOnlyWhenUnsupported(t *testing.T) {
	client, fs := newApplyTestSFTP(t, "unsupported")
	outcome, err := (&SSHClient{}).applySFTPFile(client, ApplyRequest{RemotePath: "/app.conf", Payload: []byte("new")})
	require.NoError(t, err)
	require.True(t, outcome.Verified)
	fs.mu.Lock()
	renames := fs.renames
	fs.mu.Unlock()
	require.Equal(t, 1, renames)
}

func TestApplyReadUsesActualBytesNotOldSize(t *testing.T) {
	client, _ := newApplyTestSFTP(t, "")
	payload := []byte("larger-than-the-old-stat")
	require.NoError(t, writePrivateFile(client, "/app.conf", payload))
	data, err := readRemoteRegularFile(client, "/app.conf", 1)
	require.NoError(t, err)
	require.Equal(t, payload, data)
	require.Equal(t, "7640", applyModeString(0o640|os.ModeSetuid|os.ModeSetgid|os.ModeSticky))
}

func applyTestBool(value bool) *bool { return &value }
