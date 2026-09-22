package app

import (
	"fmt"
	"io"
	"time"

	"github.com/talkincode/sshx/internal/textsafe"
)

// Long remote scans used to look like a hang: a 90 s SFTP window produced no
// output at all. The reporter narrates progress on stderr, which keeps stdout a
// single machine-readable JSON document for --json callers.
const (
	// textProgressGrace hides progress for quick scans.
	textProgressGrace = 3 * time.Second
	// textProgressInterval limits progress lines to one per second.
	textProgressInterval = time.Second
	// textSlowScanAdvice is the elapsed scan time worth advising the caller to
	// narrow the window.
	textSlowScanAdvice = 10 * time.Second
)

// textScanReporter writes bounded scan progress and closing advice to a single
// stream (stderr in production).
type textScanReporter struct {
	out      io.Writer
	pattern  bool
	start    time.Time
	lastLine time.Time
	sample   textsafe.ScanProgress

	grace    time.Duration
	interval time.Duration
	advice   time.Duration
}

func newTextScanReporter(out io.Writer, patternSet bool) *textScanReporter {
	return &textScanReporter{
		out:      out,
		pattern:  patternSet,
		start:    time.Now(),
		grace:    textProgressGrace,
		interval: textProgressInterval,
		advice:   textSlowScanAdvice,
	}
}

// Progress implements textsafe.ProgressObserver.
func (r *textScanReporter) Progress(p textsafe.ScanProgress) {
	r.sample = p
	now := time.Now()
	if now.Sub(r.start) < r.grace {
		return
	}
	if !r.lastLine.IsZero() && now.Sub(r.lastLine) < r.interval {
		return
	}
	r.lastLine = now
	fmt.Fprintln(r.out, r.progressLine(now))
}

func (r *textScanReporter) progressLine(now time.Time) string {
	p := r.sample
	line := fmt.Sprintf("sshx text: scanning %s", formatByteCount(p.Bytes))
	if p.FileSize > 0 {
		line += fmt.Sprintf(" of %s (%d%%)", formatByteCount(p.FileSize), percentOf(p.Bytes, p.FileSize))
	}
	line += fmt.Sprintf(" lines=%d elapsed=%s", p.Lines, formatSeconds(now.Sub(r.start)))
	if r.pattern {
		line += fmt.Sprintf(" matches=%d", p.MatchedLines)
	}
	return line
}

// Finish prints advice when a scan was slow or stopped at its byte budget, so
// partial results are never silently mistaken for complete ones.
func (r *textScanReporter) Finish(result textsafe.Result, elapsed time.Duration) {
	if r.out == nil {
		return
	}
	if result.Truncated && textsafe.HasTruncationReason(result.TruncatedReason, "max_scan_bytes") {
		fmt.Fprintf(r.out, "sshx text: warning: scan stopped at its --max-scan-bytes budget after %s (%s scanned, %s in window); results are partial "+
			"(total_hits_exact=false). Narrow with --offset=N or --tail=N, pre-filter with --pattern=..., or raise --max-scan-bytes=N.\n",
			formatSeconds(elapsed), formatByteCount(result.Stats.BytesScanned), formatByteCount(result.Stats.ExpectedScanBytes))
		return
	}
	if elapsed >= r.advice {
		fmt.Fprintf(r.out, "sshx text: notice: scan took %s for %s; narrow the window with --offset=N or --tail=N when a smaller window answers the question.\n",
			formatSeconds(elapsed), formatByteCount(result.Stats.BytesScanned))
	}
}

// formatByteCount renders a byte count as an exact integer with a binary unit.
func formatByteCount(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fGiB/%dB", float64(n)/(1<<30), n)
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMiB/%dB", float64(n)/(1<<20), n)
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKiB/%dB", float64(n)/(1<<10), n)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func percentOf(part, whole int64) int {
	if whole <= 0 {
		return 0
	}
	pct := part * 100 / whole
	if pct > 100 {
		return 100
	}
	return int(pct)
}

func formatSeconds(d time.Duration) string {
	return fmt.Sprintf("%.1fs", d.Seconds())
}
