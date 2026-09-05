package sshclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type publishMetadata struct {
	mode     os.FileMode
	uid, gid uint32
}

// InMemHandler does not implement chmod/chown. This overlay models the
// server's creation policy and authorization without changing process umask
// or requiring privileged native chown in the shared test environment.
type publishMetadataFS struct {
	base                                     sftp.Handlers
	mu                                       sync.Mutex
	files                                    map[string]publishMetadata
	createMode                               os.FileMode
	denyChown, ignoreChown, driftAfterRename bool
	chownCalls, renameCalls                  int
	operations                               []string
}

func (f *publishMetadataFS) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	return f.base.FileGet.Fileread(request)
}

func (f *publishMetadataFS) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	writer, err := f.base.FilePut.Filewrite(request)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.files[request.Filepath]; !exists {
		f.files[request.Filepath] = publishMetadata{mode: f.createMode, uid: 1001, gid: 1002}
	}
	return writer, nil
}

func (f *publishMetadataFS) Filecmd(request *sftp.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	flags := request.AttrFlags()
	if request.Method == "Setstat" && flags.UidGid {
		f.chownCalls++
		f.operations = append(f.operations, "chown")
		if f.denyChown {
			return sftp.ErrSSHFxPermissionDenied
		}
	}
	if err := f.base.FileCmd.Filecmd(request); err != nil {
		return err
	}
	switch request.Method {
	case "Setstat":
		metadata := f.files[request.Filepath]
		if flags.UidGid && !f.ignoreChown {
			metadata.uid, metadata.gid = request.Attributes().UID, request.Attributes().GID
		}
		if flags.Permissions {
			metadata.mode = request.Attributes().FileMode().Perm()
			f.operations = append(f.operations, fmt.Sprintf("chmod:%04o", metadata.mode))
		}
		f.files[request.Filepath] = metadata
	case "Rename":
		f.renameMetadata(request.Filepath, request.Target)
	case "Remove":
		delete(f.files, request.Filepath)
	}
	return nil
}

func (f *publishMetadataFS) PosixRename(request *sftp.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if atomic, ok := f.base.FileCmd.(sftp.PosixRenameFileCmder); ok {
		if err := atomic.PosixRename(request); err != nil {
			return err
		}
	} else if err := f.base.FileCmd.Filecmd(&sftp.Request{Method: "Rename", Filepath: request.Filepath, Target: request.Target}); err != nil {
		return err
	}
	f.renameMetadata(request.Filepath, request.Target)
	return nil
}

func (f *publishMetadataFS) renameMetadata(source, destination string) {
	f.renameCalls++
	metadata := f.files[source]
	if f.driftAfterRename {
		metadata.uid, metadata.gid = 1001, 1002
	}
	f.files[destination] = metadata
	delete(f.files, source)
}

func (f *publishMetadataFS) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	list, err := f.base.FileList.Filelist(request)
	if err != nil {
		return nil, err
	}
	return publishMetadataLister{ListerAt: list, fs: f, requestPath: request.Filepath, directory: request.Method == "List"}, nil
}

type publishMetadataLister struct {
	sftp.ListerAt
	fs          *publishMetadataFS
	requestPath string
	directory   bool
}

func (l publishMetadataLister) ListAt(entries []os.FileInfo, offset int64) (int, error) {
	n, err := l.ListerAt.ListAt(entries, offset)
	l.fs.mu.Lock()
	defer l.fs.mu.Unlock()
	for i := 0; i < n; i++ {
		name := l.requestPath
		if l.directory {
			name = path.Join(name, entries[i].Name())
		}
		if metadata, exists := l.fs.files[name]; exists {
			entries[i] = publishMetadataInfo{FileInfo: entries[i], metadata: metadata}
		}
	}
	return n, err
}

type publishMetadataInfo struct {
	os.FileInfo
	metadata publishMetadata
}

func (f publishMetadataInfo) Mode() os.FileMode {
	return f.FileInfo.Mode()&^os.ModePerm | f.metadata.mode
}
func (f publishMetadataInfo) Uid() uint32 { return f.metadata.uid }
func (f publishMetadataInfo) Gid() uint32 { return f.metadata.gid }

func newPublishMetadataSFTP(t *testing.T, creationMode os.FileMode) (*sftp.Client, *publishMetadataFS) {
	t.Helper()
	fs := &publishMetadataFS{base: sftp.InMemHandler(), createMode: creationMode, files: map[string]publishMetadata{}}
	serverConn, clientConn := net.Pipe()
	server := sftp.NewRequestServer(serverConn, sftp.Handlers{FileGet: fs, FilePut: fs, FileCmd: fs, FileList: fs})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve() //nolint:errcheck // fixture disconnect
	}()
	client, err := sftp.NewClientPipe(clientConn, clientConn)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()     //nolint:errcheck // fixture cleanup
		_ = server.Close()     //nolint:errcheck // fixture cleanup
		_ = clientConn.Close() //nolint:errcheck // fixture cleanup
		<-done
	})
	return client, fs
}

func TestPublishRemoteFileRespectsServerCreationMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644} {
		t.Run(fmt.Sprintf("server_mode_%04o", mode), func(t *testing.T) {
			client, fs := newPublishMetadataSFTP(t, mode)
			entry := FileOutcome{Path: "/destination", Type: "file", ChangeState: "unchanged"}
			payload := "server-selected permissions"
			require.NoError(t, publishRemoteFile(context.Background(), client, strings.NewReader(payload), "local_io", int64(len(payload)), nil, &entry))
			assert.True(t, entry.Published)
			assert.True(t, entry.Verified)
			assert.Equal(t, fmt.Sprintf("%04o", mode), entry.Mode)
			fs.mu.Lock()
			metadata := fs.files["/destination"]
			operations := append([]string(nil), fs.operations...)
			fs.mu.Unlock()
			assert.Equal(t, mode, metadata.mode)
			assert.Equal(t, []string{"chmod:0600", fmt.Sprintf("chmod:%04o", mode)}, operations)
		})
	}
}

func TestPublishRemoteFilePreservesDestinationOwner(t *testing.T) {
	for _, tc := range []struct {
		name                string
		uid, gid            uint32
		deny, ignore, drift bool
		wantError           bool
	}{
		{name: "service owner retained", uid: 2001, gid: 2002},
		{name: "group-only ownership retained", uid: 1001, gid: 2002},
		{name: "same owner needs no chown", uid: 1001, gid: 1002, deny: true},
		{name: "denied chown preserves original", uid: 2001, gid: 2002, deny: true, wantError: true},
		{name: "unimplemented chown preserves original", uid: 2001, gid: 2002, ignore: true, wantError: true},
		{name: "post rename owner drift is unverified", uid: 2001, gid: 2002, drift: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, fs := newPublishMetadataSFTP(t, 0o644)
			original, err := client.Create("/destination")
			require.NoError(t, err)
			_, err = original.Write([]byte("original"))
			require.NoError(t, err)
			require.NoError(t, original.Close())
			fs.mu.Lock()
			fs.files["/destination"] = publishMetadata{mode: 0o660, uid: tc.uid, gid: tc.gid}
			fs.denyChown, fs.ignoreChown, fs.driftAfterRename = tc.deny, tc.ignore, tc.drift
			fs.mu.Unlock()
			entry := FileOutcome{Path: "/destination", Type: "file", ChangeState: "unchanged"}
			err = publishRemoteFile(context.Background(), client, strings.NewReader("replacement"), "local_io", 11, nil, &entry)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			fs.mu.Lock()
			metadata := fs.files["/destination"]
			renames, chowns := fs.renameCalls, fs.chownCalls
			operations := append([]string(nil), fs.operations...)
			remaining := len(fs.files)
			fs.mu.Unlock()
			current, openErr := client.Open("/destination")
			require.NoError(t, openErr)
			data, readErr := io.ReadAll(current)
			require.NoError(t, readErr)
			require.NoError(t, current.Close())
			assert.Equal(t, os.FileMode(0o660), metadata.mode)
			assert.Equal(t, 1, remaining, "owned staging files must be removed")
			require.NotNil(t, entry.UID)
			require.NotNil(t, entry.GID)
			switch {
			case tc.drift:
				assert.Equal(t, "verification_failed", errorKind(t, err))
				assert.True(t, entry.Published)
				assert.False(t, entry.Verified)
				assert.Equal(t, "failed", entry.Verification)
				assert.Equal(t, "changed", entry.ChangeState)
				assert.Equal(t, uint32(1001), *entry.UID)
				assert.Equal(t, uint32(1002), *entry.GID)
			case tc.wantError:
				assert.Equal(t, "remote_io", errorKind(t, err))
				assert.Equal(t, "original", string(data))
				assert.Zero(t, renames, "owner preservation must fail before replacement")
				assert.False(t, entry.Published)
				assert.Equal(t, "unchanged", entry.ChangeState)
				assert.Equal(t, tc.uid, metadata.uid)
				assert.Equal(t, tc.gid, metadata.gid)
			default:
				assert.Equal(t, "replacement", string(data))
				assert.True(t, entry.Verified)
				assert.Equal(t, tc.uid, *entry.UID)
				assert.Equal(t, tc.gid, *entry.GID)
				assert.Equal(t, tc.uid, metadata.uid)
				assert.Equal(t, tc.gid, metadata.gid)
				if tc.uid == 1001 && tc.gid == 1002 {
					assert.Zero(t, chowns, "do not require chown privileges when owner already matches")
				} else {
					assert.Equal(t, []string{"chmod:0600", "chown", "chmod:0660"}, operations)
				}
			}
		})
	}
}

func TestSFTPUploadMatchesServerCreatePermissions(t *testing.T) {
	root := reliabilityDirectory(t)
	client := reliabilitySFTP(t, root, false).client(t, context.Background())
	protocol, err := client.newSFTPClient()
	require.NoError(t, err)
	baseline, err := protocol.Create(filepath.Join(root, "ordinary-create"))
	require.NoError(t, err)
	info, err := baseline.Stat()
	require.NoError(t, err)
	require.NoError(t, baseline.Close())
	require.NoError(t, protocol.Close())
	client.config.SftpAction, client.config.RemotePath = "upload", filepath.Join(root, "staged-upload")
	client.config.PreparedPayload = []byte("fixture")
	out, err := client.ExecuteSftpResult()
	require.NoError(t, err)
	require.Len(t, out.Entries, 1)
	assert.Equal(t, fmt.Sprintf("%04o", info.Mode().Perm()), out.Entries[0].Mode)
	assert.True(t, out.Verified)
}
