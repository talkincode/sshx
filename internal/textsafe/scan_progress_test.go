package textsafe

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// progressRecorder captures the samples a scan offers.
type progressRecorder struct {
	samples []ScanProgress
}

func (p *progressRecorder) Progress(s ScanProgress) {
	p.samples = append(p.samples, s)
}

// TestScanWithProgressSamplesAreBoundedAndMonotonic guards the monitoring
// contract: samples arrive during a long scan, in order, and never claim more
// bytes or lines than the scan has read.
func TestScanWithProgressSamplesAreBoundedAndMonotonic(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 20000; i++ {
		body.WriteString("2026-01-01 INFO line with pattern=matcher and padding\n")
	}
	req := Request{
		Kind:     SourceFile,
		Path:     "/var/log/app.log",
		Scan:     ScanStart,
		Pattern:  "matcher",
		FileSize: int64(body.Len()),
	}
	rec := &progressRecorder{}
	out, err := ScanWithProgress(strings.NewReader(body.String()), req, rec)
	require.NoError(t, err)
	require.NotEmpty(t, rec.samples, "a 20k-line scan must offer progress samples")

	var lastBytes int64
	var lastLines int
	for _, s := range rec.samples {
		require.GreaterOrEqual(t, s.Bytes, lastBytes, "byte progress must not go backwards")
		require.GreaterOrEqual(t, s.Lines, lastLines, "line progress must not go backwards")
		require.LessOrEqual(t, s.Bytes, out.Stats.BytesScanned, "progress must not exceed the scan total")
		require.Equal(t, int64(body.Len()), s.FileSize)
		lastBytes, lastLines = s.Bytes, s.Lines
	}
	require.Positive(t, rec.samples[len(rec.samples)-1].MatchedLines, "pattern matches must be reported")
	require.Greater(t, len(rec.samples), 1, "sampling must repeat during a long scan")
}

// TestScanWithoutObserverMatchesScan pins the compatibility contract: adding a
// progress observer must not change what a scan returns.
func TestScanWithoutObserverMatchesScan(t *testing.T) {
	req := Request{Kind: SourceFile, Path: "/var/log/app.log", Scan: ScanStart, Presets: []string{"exception"}}
	plain, err := Scan(strings.NewReader(pythonTrace), req)
	require.NoError(t, err)
	rec := &progressRecorder{}
	watched, err := ScanWithProgress(strings.NewReader(pythonTrace), req, rec)
	require.NoError(t, err)
	require.Equal(t, plain, watched)
}

// TestExpectedScanBytesReportsWindowBudget documents the additive stats field:
// it is the byte window capped by --max-scan-bytes, and the empty value (not
// zero) when the source size is unknown.
func TestExpectedScanBytesReportsWindowBudget(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		want int64
	}{
		{
			name: "whole file within budget",
			req:  Request{MaxScanBytes: 1 << 20, FileSize: 4096},
			want: 4096,
		},
		{
			name: "budget truncates the window",
			req:  Request{MaxScanBytes: 1 << 20, FileSize: 64 << 20},
			want: 1 << 20,
		},
		{
			name: "window already seeks into the file",
			req:  Request{MaxScanBytes: 8 << 20, FileSize: 3 << 20, WindowStartByte: 1 << 20},
			want: 2 << 20,
		},
		{
			name: "unknown source size",
			req:  Request{MaxScanBytes: 1 << 20, FileSize: 0},
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			req.Kind = SourceFile
			req.Path = "/var/log/app.log"
			req.Scan = ScanStart
			out, err := Scan(strings.NewReader("INFO ok\n"), req)
			require.NoError(t, err)
			require.Equal(t, tc.want, out.Stats.ExpectedScanBytes)
		})
	}
}

// TestExpectedScanBytesIsOmittedForJournal keeps sshx.text.v1 compatible: the
// field is additive, so unknown sources must not grow a misleading zero.
func TestExpectedScanBytesIsOmittedForJournal(t *testing.T) {
	out := Result{
		Stats: Stats{LinesScanned: 3},
		Hits:  []Hit{},
	}
	encoded, err := json.Marshal(out)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "expected_scan_bytes")

	out.Stats.ExpectedScanBytes = 1 << 20
	encoded, err = json.Marshal(out)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"expected_scan_bytes":1048576`)
}

func TestHasTruncationReason(t *testing.T) {
	tests := []struct {
		reason string
		want   string
		wantOK bool
	}{
		{reason: "max_scan_bytes", want: "max_scan_bytes", wantOK: true},
		{reason: "max_scan_bytes,max_hits", want: "max_scan_bytes", wantOK: true},
		{reason: "max_hits,max_scan_bytes", want: "max_scan_bytes", wantOK: true},
		{reason: "max_scan_bytes,max_hits", want: "max_hits", wantOK: true},
		{reason: "max_hits", want: "max_scan_bytes", wantOK: false},
		{reason: "max_bytes", want: "max_scan_bytes", wantOK: false},
		{reason: "", want: "max_scan_bytes", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.reason+"/"+tc.want, func(t *testing.T) {
			assert.Equal(t, tc.wantOK, HasTruncationReason(tc.reason, tc.want))
		})
	}
}
