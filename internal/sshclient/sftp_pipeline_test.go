package sshclient

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

type delayedSFTPReader struct {
	io.ReaderAt
	active, peak *atomic.Int64
}

func (r delayedSFTPReader) ReadAt(p []byte, off int64) (int, error) {
	n := r.active.Add(1)
	defer r.active.Add(-1)
	for {
		old := r.peak.Load()
		if n <= old || r.peak.CompareAndSwap(old, n) {
			break
		}
	}
	time.Sleep(5 * time.Millisecond)
	return r.ReaderAt.ReadAt(p, off)
}

type delayedSFTPGet struct {
	sftp.FileReader
	active, peak *atomic.Int64
}

func (r delayedSFTPGet) Fileread(req *sftp.Request) (io.ReaderAt, error) {
	reader, err := r.FileReader.Fileread(req)
	return delayedSFTPReader{reader, r.active, r.peak}, err
}

func TestSFTPCopyBoundaryPipelinesReads(t *testing.T) {
	handlers := sftp.InMemHandler()
	file, err := handlers.FilePut.Filewrite(&sftp.Request{Method: "Put", Filepath: "/fixture", Flags: 26})
	require.NoError(t, err)
	payload := bytes.Repeat([]byte("x"), 1<<20)
	_, err = file.WriteAt(payload, 0)
	require.NoError(t, err)
	var active, peak atomic.Int64
	handlers.FileGet = delayedSFTPGet{handlers.FileGet, &active, &peak}
	left, right := net.Pipe()
	server := sftp.NewRequestServer(left, handlers)
	go func() { _ = server.Serve() }() //nolint:errcheck // fixture disconnect
	client, err := sftp.NewClientPipe(right, right, sftpClientOptions()...)
	require.NoError(t, err)
	defer func() { _ = client.Close(); _ = server.Close(); _ = right.Close() }() //nolint:errcheck // isolated fixture teardown
	remote, err := client.Open("/fixture")
	require.NoError(t, err)
	var out bytes.Buffer
	_, err = copyBoundary(context.Background(), &out, remote, "remote_io", "local_io")
	require.NoError(t, err)
	require.Equal(t, payload, out.Bytes())
	require.Greater(t, peak.Load(), int64(1), "copy wrappers must not collapse SFTP to one RTT per packet")
	require.LessOrEqual(t, peak.Load(), int64(sftpMaxConcurrentRequests))
}
