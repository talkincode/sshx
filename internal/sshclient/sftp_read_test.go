package sshclient

import (
	"bytes"
	"io"
	"testing"
)

// recordingReader counts how many bytes were pulled from the source and the
// size of each request, which is what the pipelining window depends on.
type recordingReader struct {
	data    []byte
	pos     int
	pulls   int
	pullMax int
}

func (r *recordingReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	r.pulls++
	if n > r.pullMax {
		r.pullMax = n
	}
	return n, nil
}

// TestPipelinedReaderServesSameBytes feeds the same source through the
// pipelined reader and compares with the original: the bytes and the EOF
// position must match exactly, otherwise read-ahead would change scan results.
func TestPipelinedReaderServesSameBytes(t *testing.T) {
	source := make([]byte, 3*(1<<20)+12345)
	for i := range source {
		source[i] = byte(i % 251)
	}

	pr := newPipelinedReader(&recordingReader{data: source}, 1<<20, int64(len(source)))
	var got bytes.Buffer
	buf := make([]byte, 64<<10)
	for {
		n, err := pr.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
	}
	if !bytes.Equal(got.Bytes(), source) {
		t.Fatalf("pipelined reader returned %d bytes differing from the source", got.Len())
	}
}

// TestPipelinedReaderSmallReadsBypassAperture pins the truncation-probe
// guarantee: a caller read below the pipelining threshold must pull exactly
// what it asked for, never a read-ahead block.
func TestPipelinedReaderSmallReadsBypassAperture(t *testing.T) {
	src := &recordingReader{data: make([]byte, 1<<20)}
	pr := newPipelinedReader(src, 1<<20, 1<<20)

	one := make([]byte, 1)
	if _, err := pr.Read(one); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if src.pos != 1 {
		t.Fatalf("1-byte read pulled %d bytes from the source, want 1", src.pos)
	}

	two := make([]byte, 4096)
	if _, err := pr.Read(two); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if src.pos != 1+len(two) {
		t.Fatalf("4 KiB read pulled %d bytes total, want %d", src.pos, 1+len(two))
	}
}

// TestPipelinedReaderLargeReadsUseAperture verifies the read-ahead path is
// actually taken, and that its requests are aperture-sized rather than
// line-sized, which is what lets pkg/sftp overlap round trips.
func TestPipelinedReaderLargeReadsUseAperture(t *testing.T) {
	const aperture = 1 << 20
	src := &recordingReader{data: make([]byte, 5<<20)}
	pr := newPipelinedReader(src, aperture, 5<<20)

	buf := make([]byte, 64<<10)
	if _, err := pr.Read(buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if src.pulls != 1 {
		t.Fatalf("source pulled %d times, want a single read-ahead", src.pulls)
	}
	if src.pullMax != aperture {
		t.Fatalf("read-ahead was %d bytes, want the %d-byte aperture", src.pullMax, aperture)
	}
	// The caller asked for 64 KiB and got it from the aperture.
	if src.pos != aperture {
		t.Fatalf("source advanced to %d, want %d", src.pos, aperture)
	}
}

// TestPipelinedReaderBudgetBoundsReadAhead is the --max-scan-bytes guard: the
// read-ahead may never pull past the window budget, so a scan cannot fetch
// remote bytes the caller was not allowed to read.
func TestPipelinedReaderBudgetBoundsReadAhead(t *testing.T) {
	const budget = 2 << 20
	src := &recordingReader{data: make([]byte, 8<<20)}
	pr := newPipelinedReader(src, 1<<20, budget)

	remaining := int64(budget)
	buf := make([]byte, 64<<10)
	for remaining > 0 {
		want := int64(len(buf))
		if remaining < want {
			want = remaining
		}
		n, err := pr.Read(buf[:want])
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
		remaining -= int64(n)
	}
	if int64(src.pos) != budget {
		t.Fatalf("source advanced to %d after the budget was consumed, want %d", src.pos, budget)
	}

	// Past the budget the reader serves the caller directly, which is how the
	// truncation probe sees one byte beyond --max-scan-bytes and no more.
	if _, err := pr.Read(buf[:64<<10]); err != nil {
		t.Fatalf("read past budget failed: %v", err)
	}
	if src.pos != budget+(64<<10) {
		t.Fatalf("read past the budget pulled %d bytes, want %d", src.pos, budget+(64<<10))
	}
}

// TestPipelinedReaderPreservesFinalPartialRead covers a source that returns
// data and io.EOF together: the bytes must be delivered before the error.
func TestPipelinedReaderPreservesFinalPartialRead(t *testing.T) {
	pr := newPipelinedReader(&eofWithDataReader{data: []byte("tail-bytes")}, 64<<10, 1<<20)

	var got bytes.Buffer
	buf := make([]byte, 64<<10)
	for {
		n, err := pr.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
	}
	if got.String() != "tail-bytes" {
		t.Fatalf("got %q, want %q", got.String(), "tail-bytes")
	}
}

type eofWithDataReader struct {
	data []byte
	done bool
}

func (r *eofWithDataReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, r.data), io.EOF
}

// TestSFTPClientOptionsEnablePipelining guards the dependency-dependent part of
// the fix: the options that keep pkg/sftp overlapping reads must stay wired.
func TestSFTPClientOptionsEnablePipelining(t *testing.T) {
	opts := sftpClientOptions()
	if len(opts) != 2 {
		t.Fatalf("sftpClientOptions returned %d options, want 2 (UseConcurrentReads + MaxConcurrentRequestsPerFile)", len(opts))
	}
	if sftpMaxConcurrentRequests <= 1 {
		t.Fatalf("sftpMaxConcurrentRequests = %d, want a pipelining window", sftpMaxConcurrentRequests)
	}
	if sftpReadApertureBytes < sftpMaxConcurrentRequests<<10 {
		t.Fatalf("aperture %d cannot keep %d requests in flight", sftpReadApertureBytes, sftpMaxConcurrentRequests)
	}
}
