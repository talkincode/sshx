package app

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/textsafe"
)

func newTestReporter(out *bytes.Buffer, patternSet bool) *textScanReporter {
	r := newTextScanReporter(out, patternSet)
	r.grace = 0
	r.interval = 0
	r.advice = time.Hour
	return r
}

// TestTextScanReporterStaysQuietDuringGrace: a fast scan must not print
// anything, so ordinary runs keep their output unchanged.
func TestTextScanReporterStaysQuietDuringGrace(t *testing.T) {
	var out bytes.Buffer
	reporter := newTextScanReporter(&out, true)
	reporter.Progress(textsafe.ScanProgress{Bytes: 4096, Lines: 10, FileSize: 1 << 20})
	assert.Empty(t, out.String())
}

// TestTextScanReporterPrintsBoundedProgress covers the monitored shape: one
// line per interval with bytes, percentage, lines, elapsed, and matches.
func TestTextScanReporterPrintsBoundedProgress(t *testing.T) {
	var out bytes.Buffer
	reporter := newTestReporter(&out, true)
	reporter.interval = time.Hour // only the first sample may print

	reporter.Progress(textsafe.ScanProgress{Bytes: 512 << 10, Lines: 2048, MatchedLines: 7, FileSize: 2 << 20})

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	require.Len(t, lines, 1, "progress must be throttled to one line per interval")
	assert.Contains(t, lines[0], "sshx text: scanning")
	assert.Contains(t, lines[0], "512.0KiB/524288B")
	assert.Contains(t, lines[0], " of 2.0MiB/2097152B")
	assert.Contains(t, lines[0], "(25%)")
	assert.Contains(t, lines[0], "lines=2048")
	assert.Contains(t, lines[0], "matches=7")

	reporter.Progress(textsafe.ScanProgress{Bytes: 1 << 20, Lines: 4096, FileSize: 2 << 20})
	assert.Len(t, strings.Split(strings.TrimRight(out.String(), "\n"), "\n"), 1)
}

// TestTextScanReporterOmitsMatchesWithoutPattern keeps the line honest for a
// preset-only scan, where no match count exists.
func TestTextScanReporterOmitsMatchesWithoutPattern(t *testing.T) {
	var out bytes.Buffer
	reporter := newTestReporter(&out, false)
	reporter.Progress(textsafe.ScanProgress{Bytes: 1 << 20, Lines: 10, FileSize: 1 << 20})
	assert.NotContains(t, out.String(), "matches=")
	assert.Contains(t, out.String(), "(100%)")
}

// TestTextScanReporterUnknownSizeOmitsPercentage: a journal scan has no file
// size, so progress must not invent a percentage.
func TestTextScanReporterUnknownSizeOmitsPercentage(t *testing.T) {
	var out bytes.Buffer
	reporter := newTestReporter(&out, false)
	reporter.Progress(textsafe.ScanProgress{Bytes: 1 << 20, Lines: 10})
	assert.NotContains(t, out.String(), "%")
	assert.Contains(t, out.String(), "1.0MiB/1048576B")
}

// TestTextScanReporterWarnsOnByteBudgetTruncation is the "partial results"
// guard: stopping at --max-scan-bytes must say so and name the narrower
// alternatives.
func TestTextScanReporterWarnsOnByteBudgetTruncation(t *testing.T) {
	var out bytes.Buffer
	reporter := newTestReporter(&out, false)
	reporter.Finish(textsafe.Result{
		Truncated:       true,
		TruncatedReason: "max_scan_bytes",
		Stats:           textsafe.Stats{BytesScanned: 1 << 20, ExpectedScanBytes: 1 << 20},
	}, 4*time.Second)

	line := out.String()
	assert.Contains(t, line, "warning")
	assert.Contains(t, line, "--max-scan-bytes")
	assert.Contains(t, line, "--offset")
	assert.Contains(t, line, "--tail")
	assert.Contains(t, line, "partial")
	assert.Contains(t, line, "total_hits_exact=false")
}

// TestTextScanReporterWarnsWhenReasonsAreJoined guards the multi-reason form of
// truncated_reason: a scan that also capped its hit list reports
// "max_scan_bytes,max_hits", and the byte-budget warning must still appear.
func TestTextScanReporterWarnsWhenReasonsAreJoined(t *testing.T) {
	var out bytes.Buffer
	reporter := newTestReporter(&out, false)
	reporter.Finish(textsafe.Result{
		Truncated:       true,
		TruncatedReason: "max_scan_bytes,max_hits",
		Stats:           textsafe.Stats{BytesScanned: 1 << 20, ExpectedScanBytes: 1 << 20},
	}, 4*time.Second)

	assert.Contains(t, out.String(), "warning")
	assert.Contains(t, out.String(), "--max-scan-bytes")
}

// TestTextScanReporterSkipsOtherTruncationReasons: a capped hit list is not a
// bounded scan, so it must not claim the window was cut short.
func TestTextScanReporterSkipsOtherTruncationReasons(t *testing.T) {
	var out bytes.Buffer
	reporter := newTestReporter(&out, false)
	reporter.Finish(textsafe.Result{
		Truncated:       true,
		TruncatedReason: "max_hits",
		Stats:           textsafe.Stats{BytesScanned: 1 << 20, ExpectedScanBytes: 1 << 20},
	}, 4*time.Second)

	assert.NotContains(t, out.String(), "warning")
}

// TestTextScanReporterAdvisesOnSlowScan covers the second trigger: a scan that
// covered its window but took long enough that a smaller window is worth
// suggesting next time.
func TestTextScanReporterAdvisesOnSlowScan(t *testing.T) {
	var out bytes.Buffer
	reporter := newTestReporter(&out, false)
	reporter.advice = time.Second
	reporter.Finish(textsafe.Result{Stats: textsafe.Stats{BytesScanned: 8 << 20}}, 12*time.Second)

	line := out.String()
	assert.Contains(t, line, "notice")
	assert.Contains(t, line, "8.0MiB/8388608B")
	assert.Contains(t, line, "--offset")
}

// TestTextScanReporterQuietOnFastCompleteScan: no warning, no notice.
func TestTextScanReporterQuietOnFastCompleteScan(t *testing.T) {
	var out bytes.Buffer
	reporter := newTestReporter(&out, false)
	reporter.advice = time.Minute
	reporter.Finish(textsafe.Result{Stats: textsafe.Stats{BytesScanned: 4096}}, 10*time.Millisecond)
	assert.Empty(t, out.String())
}

func TestTextProgressFormatters(t *testing.T) {
	assert.Equal(t, "512B", formatByteCount(512))
	assert.Equal(t, "1.5KiB/1536B", formatByteCount(1536))
	assert.Equal(t, "1.5MiB/1572864B", formatByteCount(1536<<10))
	assert.Equal(t, "2.0GiB/2147483648B", formatByteCount(2<<30))
	assert.Equal(t, 50, percentOf(1<<20, 2<<20))
	assert.Equal(t, 100, percentOf(9<<20, 2<<20))
	assert.Equal(t, 0, percentOf(10, 0))
	assert.Equal(t, "1.5s", formatSeconds(1500*time.Millisecond))
}

// TestReportSudoPromptFailureExplainsTheBoundary: when the remote refuses for
// want of a password that auto-fill never supplies, the run must say why.
func TestReportSudoPromptFailureExplainsTheBoundary(t *testing.T) {
	tests := []struct {
		name    string
		command string
		output  string
		want    bool
	}{
		{
			name:    "mid-command sudo refused",
			command: `cd /data/appdata/teamsacs && sudo docker compose up -d`,
			output:  "sudo: a password is required\n",
			want:    true,
		},
		{
			name:    "leading sudo is auto-filled",
			command: `sudo docker compose up -d`,
			output:  "sudo: a password is required\n",
			want:    false,
		},
		{
			name:    "mid-command sudo succeeded",
			command: `cd /srv && sudo systemctl restart api`,
			output:  "",
			want:    false,
		},
		{
			name:    "unrelated failure",
			command: `cd /srv && sudo systemctl restart api`,
			output:  "bash: systemctl: command not found\n",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			reportSudoPromptFailure(&out, tc.command, tc.output)
			if !tc.want {
				assert.Empty(t, out.String())
				return
			}
			assert.Contains(t, out.String(), "sudo is not the first token")
			assert.Contains(t, out.String(), `sudo sh -c`)
		})
	}
}

func TestReportRunSudoPromptFailuresPerTarget(t *testing.T) {
	command := `cd /data/appdata/teamsacs && sudo docker compose up -d`
	outcome := execution.RunOutcome{
		RunID: "run-test",
		Results: []execution.TargetResult{
			{
				Target: execution.ResolvedTarget{Alias: "prod-web", Address: "192.0.2.10"},
				Stderr: "sudo: a password is required\n",
			},
			{
				Target: execution.ResolvedTarget{Alias: "prod-edge", Address: "192.0.2.11"},
				Stderr: "container started\n",
			},
		},
	}

	_, stderr := captureStreams(t, func() {
		reportRunSudoPromptFailures(outcome, command)
	})

	// Only the target that actually hit the prompt is named.
	assert.Contains(t, string(stderr), "[prod-web]")
	assert.NotContains(t, string(stderr), "[prod-edge]")
	assert.Contains(t, string(stderr), "sudo is not the first token")
}

func TestReportRunSudoPromptFailuresStaysQuiet(t *testing.T) {
	refusal := execution.RunOutcome{
		RunID: "run-test",
		Results: []execution.TargetResult{{
			Target: execution.ResolvedTarget{Alias: "prod-web"},
			Stderr: "sudo: a password is required\n",
		}},
	}

	tests := []struct {
		name    string
		outcome execution.RunOutcome
		command string
	}{
		{name: "leading sudo is auto-filled", outcome: refusal, command: `sudo docker compose up -d`},
		{name: "no sudo at all", outcome: refusal, command: `docker compose ps`},
		{
			name: "no sudo prompt in the output",
			outcome: execution.RunOutcome{
				RunID: "run-test",
				Results: []execution.TargetResult{{
					Target: execution.ResolvedTarget{Alias: "prod-web"},
					Stderr: "bash: docker: command not found\n",
				}},
			},
			command: `cd /srv && sudo docker compose up -d`,
		},
		{name: "no targets ran", outcome: execution.RunOutcome{RunID: "run-test"}, command: `cd /srv && sudo id`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr := captureStreams(t, func() {
				reportRunSudoPromptFailures(tc.outcome, tc.command)
			})
			assert.Empty(t, string(stderr))
		})
	}
}
