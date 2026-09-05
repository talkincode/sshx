package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures freeze the v1 compatibility projection, not an exhaustive key
// set. New fields are allowed, but frozen fields cannot disappear or change type.
func TestContractGoldenJSON(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	for _, test := range []struct {
		name, command string
		run           bool
		exit          int
	}{
		{"command-success", "bothstreams", false, 0},
		{"command-remote-exit", "exit7", false, 7},
		{"command-auth-failure", "probe", false, 255},
		{"run-success", "probe", true, 0},
		{"run-auth-failure", "probe", true, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			args := []string{"-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key", "--accept-unknown-host", "--json"}
			if test.run {
				args[0] = "--address=" + server.host
				args = append([]string{"run"}, args...)
			}
			password := operatorPassword
			if strings.Contains(test.name, "auth-failure") {
				password = "wrong-password"
			}
			result := runSSHX(t, home, append(args, test.command), map[string]string{"SSH_PASSWORD": password})
			require.Equal(t, test.exit, result.exitCode, result.stdout+result.stderr)
			actual := decodeGoldenDocument(t, result.stdout)
			assertGoldenDocument(t, test.name+".json", actual)
			assert.NotContains(t, result.stdout, password)
		})
	}
}

func TestContractGoldenJSONL(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	for _, success := range []bool{true, false} {
		name := "run-success.jsonl"
		password, exit := operatorPassword, 0
		if !success {
			name, password, exit = "run-auth-failure.jsonl", "wrong-password", 1 // #nosec G101 -- rejected loopback fixture credential.
		}
		t.Run(name, func(t *testing.T) {
			result := runSSHX(t, t.TempDir(), []string{
				"run", "--address=" + server.host, "-p=" + server.port, "-u=operator",
				"--no-key", "--accept-unknown-host", "--concurrency=1", "--jsonl", "probe",
			}, map[string]string{"SSH_PASSWORD": password})
			require.Equal(t, exit, result.exitCode, result.stdout+result.stderr)
			expected, err := os.ReadFile(filepath.Join("testdata", "contract", name)) // #nosec G304 -- fixed package-local fixture names.
			require.NoError(t, err)
			wantLines := goldenLines(t, string(expected))
			gotLines := goldenLines(t, result.stdout)
			require.Len(t, gotLines, len(wantLines), "stream must contain exactly one terminal record per admitted target")
			var runID string
			for i, actual := range gotLines {
				event, ok := actual.(map[string]any)
				require.True(t, ok)
				if i == 0 {
					runID, ok = event["run_id"].(string)
					require.True(t, ok)
					require.NotEmpty(t, runID)
				}
				assert.Equal(t, runID, event["run_id"])
				assert.Equal(t, json.Number(strconv.Itoa(i+1)), event["sequence"])
				assert.Equal(t, wantLines[i], normalizeGolden(t, projectGolden(t, wantLines[i], actual, "$")))
			}
		})
	}
}

func decodeGoldenDocument(t *testing.T, text string) any {
	t.Helper()
	require.True(t, json.Valid([]byte(text)), "not exactly one JSON document: %s", text)
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var document any
	require.NoError(t, decoder.Decode(&document))
	return document
}

func goldenLines(t *testing.T, text string) []any {
	t.Helper()
	require.True(t, strings.HasSuffix(text, "\n"), "JSONL terminal record must end with newline")
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	var documents []any
	for scanner.Scan() {
		require.NotEmpty(t, scanner.Text(), "JSONL must not contain blank/noise lines")
		documents = append(documents, decodeGoldenDocument(t, scanner.Text()))
	}
	require.NoError(t, scanner.Err())
	return documents
}

func assertGoldenDocument(t *testing.T, filename string, actual any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "contract", filename)) // #nosec G304 -- fixed package-local golden fixture names.
	require.NoError(t, err)
	expected := decodeGoldenDocument(t, string(data))
	assert.Equal(t, expected, normalizeGolden(t, projectGolden(t, expected, actual, "$")))
}

func normalizeGolden(t *testing.T, value any) any {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		normalized := make(map[string]any, len(value))
		for key, item := range value {
			switch key {
			case "port":
				port, ok := item.(string)
				require.True(t, ok)
				number, err := strconv.Atoi(port)
				require.NoError(t, err)
				require.Positive(t, number)
				item = "<port>"
			case "run_id":
				id, ok := item.(string)
				require.True(t, ok)
				require.NotEmpty(t, id)
				item = "<run-id>"
			case "timestamp":
				stamp, ok := item.(string)
				require.True(t, ok)
				_, err := time.Parse(time.RFC3339Nano, stamp)
				require.NoError(t, err)
				item = "<timestamp>"
			case "duration_ms":
				duration, ok := item.(json.Number)
				require.True(t, ok)
				ms, err := duration.Int64()
				require.NoError(t, err)
				require.GreaterOrEqual(t, ms, int64(0))
				item = json.Number("0")
			case "error", "message":
				if message, ok := item.(string); ok && message != "" {
					item = "<diagnostic>"
				}
			}
			normalized[key] = normalizeGolden(t, item)
		}
		return normalized
	case []any:
		items := make([]any, len(value))
		for i, item := range value {
			items[i] = normalizeGolden(t, item)
		}
		return items
	default:
		return value
	}
}

func projectGolden(t *testing.T, expected, actual any, path string) any {
	t.Helper()
	switch want := expected.(type) {
	case map[string]any:
		got, ok := actual.(map[string]any)
		require.True(t, ok, "%s changed object type: %#v", path, actual)
		projected := make(map[string]any, len(want))
		for key, expectedValue := range want {
			value, exists := got[key]
			require.True(t, exists, "frozen field %s.%s disappeared: %#v", path, key, got)
			projected[key] = projectGolden(t, expectedValue, value, path+"."+key)
		}
		return projected
	case []any:
		got, ok := actual.([]any)
		require.True(t, ok, "%s changed array type", path)
		require.Len(t, got, len(want), "%s changed array length", path)
		projected := make([]any, len(want))
		for i := range want {
			projected[i] = projectGolden(t, want[i], got[i], fmt.Sprintf("%s[%d]", path, i))
		}
		return projected
	default:
		return actual
	}
}
