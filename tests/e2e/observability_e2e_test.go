package e2e

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// textWindowResult captures the parts of sshx.text.v1 these tests assert on.
type textWindowResult struct {
	Success   bool   `json:"success"`
	ErrorKind string `json:"error_kind"`
	Truncated bool   `json:"truncated"`
	Reason    string `json:"truncated_reason"`
	Stats     struct {
		LinesScanned      int   `json:"lines_scanned"`
		BytesScanned      int64 `json:"bytes_scanned"`
		TotalHits         int   `json:"total_hits"`
		TotalHitsExact    bool  `json:"total_hits_exact"`
		FileSize          int64 `json:"file_size"`
		ExpectedScanBytes int64 `json:"expected_scan_bytes"`
	} `json:"stats"`
	Hits []struct {
		Text string `json:"text"`
	} `json:"hits"`
}

// writeRemoteLog builds a log file in the SFTP root with a unique marker on the
// requested line, so tests can prove read-ahead neither drops nor duplicates
// bytes at the end of a window.
func writeRemoteLog(t *testing.T, server *testSSHServer, name string, lines int, markerLine int, lineSize int) (string, int64) {
	t.Helper()
	var body strings.Builder
	padding := strings.Repeat("x", lineSize)
	for i := 1; i <= lines; i++ {
		if i == markerLine {
			body.WriteString("2026-01-01 INFO marker=SCANMARKER end-of-window\n")
			continue
		}
		body.WriteString("2026-01-01 INFO filler ")
		body.WriteString(padding)
		body.WriteString("\n")
	}
	path := filepath.Join(server.root, name)
	require.NoError(t, os.WriteFile(path, []byte(body.String()), 0o600))
	return filepath.ToSlash(path), int64(body.Len())
}

// TestTextLargeWindowScanIsCompleteOverSFTP covers the pipelined read path end
// to end: a multi-megabyte window must be read in full, with the marker on the
// last line present and the byte/line accounting matching the file.
func TestTextLargeWindowScanIsCompleteOverSFTP(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	remote, size := writeRemoteLog(t, server, "large.log", 12000, 12000, 256)

	got := runSSHX(t, t.TempDir(), []string{
		"text",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"--accept-unknown-host",
		"--path=" + remote,
		"--pattern=SCANMARKER",
		"--scan=start",
		"--max-scan-bytes=" + "16777216",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, got.exitCode, got.stderr+"\n"+got.stdout)

	var result textWindowResult
	require.NoError(t, json.Unmarshal([]byte(got.stdout), &result))
	assert.True(t, result.Success)
	require.Len(t, result.Hits, 1, "the marker on the final line must survive read-ahead")
	assert.Contains(t, result.Hits[0].Text, "SCANMARKER")
	assert.Equal(t, size, result.Stats.BytesScanned, "the whole window must be scanned")
	assert.Equal(t, size, result.Stats.FileSize)
	assert.Equal(t, size, result.Stats.ExpectedScanBytes)
	assert.False(t, result.Truncated)
}

// TestTextTruncationAdvisesOnStderrKeepsStdoutJSON is the monitoring contract:
// a scan stopped at its byte budget explains itself on stderr, while stdout
// stays exactly one JSON document.
func TestTextTruncationAdvisesOnStderrKeepsStdoutJSON(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	remote, _ := writeRemoteLog(t, server, "budget.log", 12000, 12000, 256)

	got := runSSHX(t, t.TempDir(), []string{
		"text",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"--accept-unknown-host",
		"--path=" + remote,
		"--pattern=SCANMARKER",
		"--scan=start",
		"--max-scan-bytes=262144",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, got.exitCode, got.stderr+"\n"+got.stdout)

	var result textWindowResult
	require.NoError(t, json.Unmarshal([]byte(got.stdout), &result), "stdout must stay a single JSON document: %q", got.stdout)
	assert.True(t, result.Truncated)
	assert.Equal(t, "max_scan_bytes", result.Reason)
	assert.False(t, result.Stats.TotalHitsExact)
	assert.Equal(t, int64(262144), result.Stats.ExpectedScanBytes, "stats must advertise the scan budget")
	assert.Equal(t, int64(262144), result.Stats.BytesScanned)

	stderr := got.stderr
	assert.Contains(t, stderr, "warning", "a partial scan must warn on stderr")
	assert.Contains(t, stderr, "--max-scan-bytes")
	assert.Contains(t, stderr, "--offset")
	assert.NotContains(t, got.stdout, "warning: scan stopped", "progress must never enter stdout")
}

// TestTextTruncationWarnsWhenReasonsAreJoined: a scan that also capped its hit
// list reports "max_scan_bytes,max_hits", and the byte-budget warning must
// still appear on stderr.
func TestTextTruncationWarnsWhenReasonsAreJoined(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	// Every line matches, so a 256 KiB scan overruns the hit cap before it
	// reaches the byte budget: truncated_reason becomes
	// "max_scan_bytes,max_hits" instead of a single reason.
	var body strings.Builder
	for i := 0; i < 40000; i++ {
		body.WriteString("2026-01-01 INFO marker=SCANMARKER\n")
	}
	path := filepath.Join(server.root, "joined.log")
	require.NoError(t, os.WriteFile(path, []byte(body.String()), 0o600))

	got := runSSHX(t, t.TempDir(), []string{
		"text",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"--accept-unknown-host",
		"--path=" + filepath.ToSlash(path),
		"--pattern=SCANMARKER",
		"--scan=start",
		"--max-scan-bytes=262144",
		"--max-hits=1",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, got.exitCode, got.stderr+"\n"+got.stdout)

	var result textWindowResult
	require.NoError(t, json.Unmarshal([]byte(got.stdout), &result), "stdout must stay a single JSON document: %q", got.stdout)
	assert.True(t, result.Truncated)
	assert.Contains(t, result.Reason, "max_scan_bytes")
	assert.Contains(t, result.Reason, "max_hits")
	assert.Contains(t, got.stderr, "warning", "a joined truncation reason must still warn about the byte budget")
	assert.Contains(t, got.stderr, "--max-scan-bytes")
}

// TestTextFastScanStaysQuietOnStderr: the reporter has a grace period, so small
// scans keep the output they had before monitoring existed.
func TestTextFastScanStaysQuietOnStderr(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	remote := filepath.Join(server.root, "small.log")
	require.NoError(t, os.WriteFile(remote, []byte("INFO boot\nINFO done\n"), 0o600))

	got := runSSHX(t, t.TempDir(), []string{
		"text",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"--accept-unknown-host",
		"--path=" + filepath.ToSlash(remote),
		"--scan=start",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, got.exitCode, got.stderr+"\n"+got.stdout)
	assert.NotContains(t, got.stderr, "sshx text: scanning")
}

// TestBlockedJSONExplainsItselfOnStderr is the regression guard for the
// silent-refusal report: a policy block keeps stdout machine-readable and
// states the reason and the guarded alternative on stderr.
func TestBlockedJSONExplainsItselfOnStderr(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()

	got := runSSHX(t, home, []string{
		"--json",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		`docker exec teamsacs_pgdb18 psql -U teamsacs -d teamsacs -At -c 'select 1'`,
	}, map[string]string{"SSH_PASSWORD": operatorPassword})

	require.Equal(t, 255, got.exitCode, got.stderr+"\n"+got.stdout)
	var result struct {
		ErrorKind string `json:"error_kind"`
		Phase     string `json:"phase"`
		Executed  *bool  `json:"executed"`
	}
	require.NoError(t, json.Unmarshal([]byte(got.stdout), &result), "stdout must stay a single JSON document: %q", got.stdout)
	assert.Equal(t, "blocked", result.ErrorKind)
	assert.Equal(t, "admission", result.Phase)
	require.NotNil(t, result.Executed)
	assert.False(t, *result.Executed)

	require.NotEmpty(t, got.stderr, "a blocked --json run must not look like a silent refusal")
	assert.Contains(t, got.stderr, "blocked by safety policy")
	assert.Contains(t, got.stderr, "phase=admission")
	assert.Contains(t, got.stderr, "error_kind=blocked")
	assert.Contains(t, got.stderr, "sshx sql", "the reason must keep the guarded SQL alternative")
	assert.Equal(t, 0, int(server.connections.Load()), "a blocked command must not reach the network")
}

// TestNonLeadingSudoWarnsBeforeRunning documents the sudo boundary: the stored
// password is only injected for a leading sudo, so a mid-command sudo is
// announced rather than failing with "a password is required".
func TestNonLeadingSudoWarnsBeforeRunning(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()

	got := runSSHX(t, home, []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"-pk=test-sudo-key",
		`cd /tmp && sudo id`,
	}, map[string]string{
		"SSH_PASSWORD":   operatorPassword,
		"SSHX_LOG_LEVEL": "info", // the pre-connect notice is a diagnostic log
	})

	assert.Contains(t, got.stderr, "sudo is not the first token")
	assert.Contains(t, got.stderr, `sudo sh -c`)
}

// TestNonLeadingSudoRefusalIsExplainedOnStderr covers the failure-time hint: the
// remote refusal is the only evidence a caller has, so sshx must name the cause
// and the fix even when diagnostics are quieted.
func TestNonLeadingSudoRefusalIsExplainedOnStderr(t *testing.T) {
	server := startSSHServer(t, serverOptions{
		execHandler: func(ch ssh.Channel, cmd string, role string) {
			_, _ = io.WriteString(ch.Stderr(), "sudo: a password is required\n") //nolint:errcheck
			sendExitStatus(ch, 1)
		},
	})

	got := runSSHX(t, t.TempDir(), []string{
		"--json",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"-pk=test-sudo-key",
		`cd /data/appdata/teamsacs && sudo docker compose up -d`,
	}, map[string]string{"SSH_PASSWORD": operatorPassword})

	require.NotEqual(t, 0, got.exitCode)
	assert.Contains(t, got.stderr, "sudo is not the first token")
	assert.Contains(t, got.stderr, `sudo sh -c`)
	assert.True(t, json.Valid([]byte(strings.TrimSpace(got.stdout))), "stdout must stay a JSON document: %q", got.stdout)
}

// TestRunNonLeadingSudoRefusalIsExplainedOnStderr covers the same boundary
// through `sshx run`, where the result document is the versioned run payload.
// The hint names the failing target so a multi-host run is unambiguous.
func TestRunNonLeadingSudoRefusalIsExplainedOnStderr(t *testing.T) {
	server := startSSHServer(t, serverOptions{
		execHandler: func(ch ssh.Channel, cmd string, role string) {
			_, _ = io.WriteString(ch.Stderr(), "sudo: a password is required\n") //nolint:errcheck
			sendExitStatus(ch, 1)
		},
	})

	got := runSSHX(t, t.TempDir(), []string{
		"run",
		"--address=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--json",
		"--",
		`cd /data/appdata/teamsacs && sudo docker compose up -d`,
	}, map[string]string{"SSH_PASSWORD": operatorPassword})

	require.NotEqual(t, 0, got.exitCode)
	assert.Contains(t, got.stderr, "sudo is not the first token")
	assert.Contains(t, got.stderr, `sudo sh -c`)
	assert.True(t, json.Valid([]byte(strings.TrimSpace(got.stdout))), "stdout must stay one JSON document: %q", got.stdout)
}
