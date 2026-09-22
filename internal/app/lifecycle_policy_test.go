package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/talkincode/sshx/internal/sshclient"
)

// captureStreams splits os.Stdout and os.Stderr into separate pipes so a test
// can assert on each stream independently.
func captureStreams(t *testing.T, fn func()) (stdout, stderr []byte) {
	t.Helper()

	oldStdout, oldStderr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	require.NoError(t, err)
	errR, errW, err := os.Pipe()
	require.NoError(t, err)

	type result struct {
		data []byte
		err  error
	}
	read := func(r *os.File) chan result {
		ch := make(chan result, 1)
		go func() {
			var buf bytes.Buffer
			_, copyErr := io.Copy(&buf, r)
			ch <- result{data: buf.Bytes(), err: copyErr}
		}()
		return ch
	}
	outCh, errCh := read(outR), read(errR)

	os.Stdout, os.Stderr = outW, errW
	func() {
		defer func() {
			os.Stdout, os.Stderr = oldStdout, oldStderr
			_ = outW.Close() //nolint:errcheck // test cleanup
			_ = errW.Close() //nolint:errcheck // test cleanup
		}()
		fn()
	}()

	outRes := <-outCh
	errRes := <-errCh
	require.NoError(t, outRes.err)
	require.NoError(t, errRes.err)
	require.NoError(t, outR.Close())
	require.NoError(t, errR.Close())
	return outRes.data, errRes.data
}

// TestReportPolicyRejectionMirrorsBlockedDecision is the regression guard for
// the silent-refusal report: a blocked admission decision must reach stderr,
// where callers that only print the streams can see it.
func TestReportPolicyRejectionMirrorsBlockedDecision(t *testing.T) {
	document := map[string]json.RawMessage{
		"error_kind": json.RawMessage(`"blocked"`),
		"phase":      json.RawMessage(`"admission"`),
		"executed":   json.RawMessage(`false`),
		"exit_code":  json.RawMessage(`-1`),
		"error":      json.RawMessage(`"⚠️  Dangerous command blocked\nCommand: docker exec c psql -c 'select 1'\nReason: bypasses the guarded SQL pipeline. Use: sshx sql -h=<host> --db=<name> [--docker=<container>] \"<SQL>\""`),
	}

	var out bytes.Buffer
	reportPolicyRejection(&out, document)
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	require.Len(t, lines, 2, "expected a decision line and a reason line")
	assert.Contains(t, lines[0], "blocked by safety policy")
	assert.Contains(t, lines[0], "phase=admission")
	assert.Contains(t, lines[0], "error_kind=blocked")
	assert.Contains(t, lines[0], "executed=false")
	assert.Contains(t, lines[0], "exit_code=-1")
	assert.Contains(t, lines[1], "bypasses the guarded SQL pipeline")
	assert.Contains(t, lines[1], "|", "multi-line reasons must be flattened to one line")
	assert.Contains(t, lines[1], "sshx sql", "the reason must keep the guarded alternative")
}

// TestReportPolicyRejectionIgnoresOtherFailures keeps the mirror narrow: only a
// policy block earns it, so ordinary remote failures are not annotated.
func TestReportPolicyRejectionIgnoresOtherFailures(t *testing.T) {
	for _, document := range []map[string]json.RawMessage{
		{"error_kind": json.RawMessage(`"remote_error"`), "error": json.RawMessage(`"boom"`)},
		{"error_kind": json.RawMessage(`""`)},
		{},
	} {
		var out bytes.Buffer
		reportPolicyRejection(&out, document)
		assert.Empty(t, out.String())
	}
}

// TestReportPolicyRejectionDefaultsMissingFields: a blocked decision without
// the optional projections still reads as "nothing ran".
func TestReportPolicyRejectionDefaultsMissingFields(t *testing.T) {
	var out bytes.Buffer
	reportPolicyRejection(&out, map[string]json.RawMessage{
		"error_kind": json.RawMessage(`"blocked"`),
	})
	line := out.String()
	assert.Contains(t, line, "phase=admission")
	assert.Contains(t, line, "executed=false")
	assert.Contains(t, line, "exit_code=-1")
	assert.Contains(t, line, "no remote command ran")
}

// TestBlockedJSONKeepsStdoutPureAndMirrorsStderr runs the real blocked
// admission path: stdout must stay exactly one JSON document while stderr
// carries the human-readable rejection.
func TestBlockedJSONKeepsStdoutPureAndMirrorsStderr(t *testing.T) {
	config := &sshclient.Config{
		Mode:       "ssh",
		Host:       "db1.example.net",
		Port:       "22",
		User:       "operator",
		Command:    `docker exec teamsacs_pgdb18 psql -U teamsacs -d teamsacs -At -c 'select 1'`,
		JSONOutput: true,
	}
	blocked := &sshclient.CommandBlockedError{
		Command: config.Command,
		Reason:  `Direct PostgreSQL client execution ("psql") bypasses the guarded SQL pipeline. Use: sshx sql -h=<host> --db=<name> [--docker=<container>] "<SQL>" (adds classification, backups, and audit)`,
	}

	var runErr error
	stdout, stderr := captureStreams(t, func() {
		runErr = reportSSHFailure(config, nil, sshclient.AuthMethodUnknown, "blocked", blocked)
	})
	require.ErrorIs(t, runErr, ErrReported)

	// stdout: exactly one JSON document, nothing else.
	assert.True(t, json.Valid(bytes.TrimSpace(stdout)), "stdout must be a single JSON document: %q", stdout)
	assert.Equal(t, 1, strings.Count(strings.TrimSpace(string(stdout)), "\n")+1, "stdout must hold one JSON line")

	var document map[string]any
	require.NoError(t, json.Unmarshal(stdout, &document))
	assert.Equal(t, "blocked", document["error_kind"])
	assert.Equal(t, "admission", document["phase"])
	assert.Equal(t, false, document["executed"])
	assert.EqualValues(t, -1, document["exit_code"])

	// stderr: the rejection a caller can print.
	require.NotEmpty(t, stderr, "a blocked --json run must explain itself on stderr")
	assert.Contains(t, string(stderr), "blocked by safety policy")
	assert.Contains(t, string(stderr), "phase=admission")
	assert.Contains(t, string(stderr), "sshx sql")
	assert.NotContains(t, string(stdout), "blocked by safety policy", "the mirror must not leak into stdout")
}

// TestNonBlockedJSONFailureHasNoMirror: a plain remote failure keeps today's
// behavior and writes nothing extra to stderr.
func TestNonBlockedJSONFailureHasNoMirror(t *testing.T) {
	config := &sshclient.Config{
		Mode:       "ssh",
		Host:       "db1.example.net",
		Port:       "22",
		User:       "operator",
		Command:    "systemctl restart api",
		JSONOutput: true,
	}

	var runErr error
	stdout, stderr := captureStreams(t, func() {
		runErr = reportSSHFailure(config, nil, sshclient.AuthMethodUnknown, "connect", errors.New("dial tcp: connection refused"))
	})
	require.ErrorIs(t, runErr, ErrReported)
	assert.NotContains(t, string(stderr), "blocked by safety policy")
	assert.True(t, json.Valid(bytes.TrimSpace(stdout)))
}
