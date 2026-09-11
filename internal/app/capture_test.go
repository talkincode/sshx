package app

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// capturePipe replaces os.Stdout (and, when combinedStderr is set, os.Stderr)
// with a pipe whose reader drains concurrently with fn.
//
// Draining only after fn returns deadlocks whenever the captured output is
// larger than the OS pipe buffer. Windows anonymous pipes hold roughly 4 KiB
// while macOS pipes hold 64 KiB, so TestRun_NoArgs printing ~34 KiB of usage
// text blocked the Windows CI job until the 10 minute test timeout.
func capturePipe(t *testing.T, combinedStderr bool, fn func()) []byte {
	t.Helper()

	oldStdout, oldStderr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := r.Close(); closeErr != nil {
			t.Logf("failed to close pipe reader: %v", closeErr)
		}
	})

	type readResult struct {
		data []byte
		err  error
	}
	done := make(chan readResult, 1)
	go func() {
		var buf bytes.Buffer
		_, copyErr := io.Copy(&buf, r)
		done <- readResult{data: buf.Bytes(), err: copyErr}
	}()

	os.Stdout = w
	if combinedStderr {
		os.Stderr = w
	}

	// The inner function restores the streams and closes the writer even when
	// fn calls t.Fatalf, because runtime.Goexit still runs deferred calls.
	func() {
		defer func() {
			os.Stdout, os.Stderr = oldStdout, oldStderr
			if closeErr := w.Close(); closeErr != nil {
				t.Logf("failed to close pipe writer: %v", closeErr)
			}
		}()
		fn()
	}()

	res := <-done
	if res.err != nil {
		t.Logf("failed to read captured output: %v", res.err)
	}
	return res.data
}

// captureStdout runs fn with os.Stdout replaced by a pipe and returns what was
// written while draining the pipe concurrently.
func captureStdout(t *testing.T, fn func()) []byte {
	t.Helper()
	return capturePipe(t, false, fn)
}

// captureCombinedOutput runs fn with os.Stdout and os.Stderr sharing one pipe
// and returns everything they wrote.
func captureCombinedOutput(t *testing.T, fn func()) []byte {
	t.Helper()
	return capturePipe(t, true, fn)
}

// TestCaptureOutputDrainsLargerThanPipeBuffer guards the capture helpers
// against regressing to sequential draining: a single 1 MiB write cannot fit
// in any supported platform's default pipe buffer, so it only completes when
// the capture is reading concurrently.
func TestCaptureOutputDrainsLargerThanPipeBuffer(t *testing.T) {
	payload := strings.Repeat("x", 1<<20)

	var written int
	out := captureStdout(t, func() {
		var writeErr error
		written, writeErr = io.WriteString(os.Stdout, payload)
		if writeErr != nil {
			t.Errorf("captured write failed: %v", writeErr)
		}
	})

	if written != len(payload) {
		t.Errorf("wrote %d bytes, want %d", written, len(payload))
	}
	if len(out) != len(payload) {
		t.Errorf("captured %d bytes, want %d", len(out), len(payload))
	}
}
