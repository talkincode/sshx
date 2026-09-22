package sshclient

import (
	"errors"
	"io"

	"github.com/pkg/sftp"
)

// SFTP read pipelining.
//
// The SFTP protocol is request/response: every read the caller asks for costs a
// round trip unless several requests for the same file are in flight. pkg/sftp
// only overlaps round trips when it is handed a buffer larger than its 32 KiB
// packet size — see sftp.File.readAt, which splits such a read into
// maxPacket-sized requests bounded by MaxConcurrentRequestsPerFile.
//
// A line scanner asks for a few kilobytes at a time, so a plain file.Read loop
// is RTT-bound: on a ~350 ms link an 8 MiB window costs ~256 sequential round
// trips (observed: 90 s). Handing the layer 1 MiB reads keeps up to
// sftpMaxConcurrentRequests requests in flight, which turns the same window
// into ~8 waves.
const (
	// sftpReadApertureBytes is the read-ahead buffer handed to the SFTP layer.
	// It is deliberately equal to sftpMaxConcurrentRequests * 32 KiB so the
	// pipelining window, not the buffer, stays the limiting factor.
	sftpReadApertureBytes = 1 << 20
	// sftpMinPipelinedReadBytes is the smallest caller read worth pipelining.
	// Smaller reads are served straight from the source so the truncation probe
	// (a single byte past --max-scan-bytes) never over-fetches.
	sftpMinPipelinedReadBytes = 32 << 10
	// sftpMaxConcurrentRequests bounds in-flight SFTP requests per file.
	sftpMaxConcurrentRequests = 32
)

// sftpClientOptions makes the pipelining window explicit instead of relying on
// package defaults, so a dependency upgrade cannot silently degrade a scan back
// to one round trip per read.
func sftpClientOptions() []sftp.ClientOption {
	return []sftp.ClientOption{
		sftp.UseConcurrentReads(true),
		sftp.MaxConcurrentRequestsPerFile(sftpMaxConcurrentRequests),
	}
}

// pipelinedReader reads through a read-ahead aperture so the SFTP layer can
// overlap round trips. Reads smaller than sftpMinPipelinedReadBytes bypass the
// aperture, and budget bounds how much read-ahead may ever pull, so the bytes
// offered to a caller are identical to a plain file.Read loop.
type pipelinedReader struct {
	src     io.Reader
	buf     []byte
	start   int
	end     int
	budget  int64
	pending error
}

func newPipelinedReader(src io.Reader, aperture int, budget int64) *pipelinedReader {
	if aperture <= 0 {
		aperture = sftpReadApertureBytes
	}
	return &pipelinedReader{src: src, buf: make([]byte, aperture), budget: budget}
}

func (p *pipelinedReader) Read(b []byte) (int, error) {
	if p.start == p.end {
		if p.pending != nil {
			err := p.pending
			p.pending = nil
			return 0, err
		}
		if len(b) < sftpMinPipelinedReadBytes || p.budget <= 0 {
			return p.src.Read(b)
		}
		if err := p.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(b, p.buf[p.start:p.end])
	p.start += n
	return n, nil
}

// fill tops the aperture up from the source. Bytes already buffered are served
// before any deferred error, matching io.Reader semantics.
func (p *pipelinedReader) fill() error {
	want := int64(len(p.buf))
	if p.budget < want {
		want = p.budget
	}
	n, err := p.src.Read(p.buf[:want])
	p.start, p.end = 0, n
	p.budget -= int64(n)
	if n > 0 {
		p.pending = err
		return nil
	}
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	return err
}
