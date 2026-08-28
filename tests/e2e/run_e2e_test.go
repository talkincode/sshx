package e2e

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunScriptByteFidelity(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	// Use a quoted here-doc style body so remote sh prints literals without expanding them.
	script := "cat <<'EOF'\na b\n$HOME\n$(literal)\n你好\n*.log\nback\\slash\nEOF\n"
	scriptPath := filepath.Join(home, "payload.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o600))
	sum := sha256.Sum256([]byte(script))
	digest := hex.EncodeToString(sum[:])

	// Dry-run exposes digest without connecting.
	dry := runSSHX(t, home, []string{
		"run",
		"--address=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--script-file=" + scriptPath,
		"--dry-run",
		"--json",
	}, nil)
	require.Equal(t, 0, dry.exitCode, dry.stderr)
	var dryPlan map[string]any
	require.NoError(t, json.Unmarshal([]byte(dry.stdout), &dryPlan))
	assert.Equal(t, true, dryPlan["valid"])
	assert.Equal(t, true, dryPlan["would_connect"])
	// Dry-run must not read secrets; without SSH_PASSWORD/key refs it reports no secret read.
	assert.Equal(t, false, dryPlan["would_read_secret"])
	action, ok := dryPlan["action"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, digest, action["payload_sha256"])

	result := runSSHX(t, home, []string{
		"run",
		"--address=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--script-file=" + scriptPath,
		"--json",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, result.exitCode, "stderr=%s stdout=%s", result.stderr, result.stdout)
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload))
	assert.Equal(t, true, payload["success"])
	stdout, ok := payload["stdout"].(string)
	require.True(t, ok)
	assert.Contains(t, stdout, "a b")
	assert.Contains(t, stdout, "$HOME")
	assert.Contains(t, stdout, "$(literal)")
	assert.Contains(t, stdout, "你好")
	assert.Contains(t, stdout, "*.log")
	assert.Contains(t, stdout, `back\slash`)
	action2, ok := payload["action"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, digest, action2["payload_sha256"])
}

// A bash script must run under bash. Before shebang support the payload was
// always piped to `sh -s --`, so `set -o pipefail` aborted with
// "Illegal option -o pipefail" on dash/ash-provided /bin/sh.
func TestRunScriptHonorsShebangAndShellOverride(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available on this machine")
	}
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()

	script := "#!/usr/bin/env bash\nset -o pipefail\nprintf 'shell=%s\\n' \"${BASH_VERSION:+bash}\"\n"
	scriptPath := filepath.Join(home, "payload.bash")
	require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o600))

	base := []string{
		"run",
		"--address=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--script-file=" + scriptPath,
	}

	// The dry-run plan reports the interpreter before connecting.
	dry := runSSHX(t, home, append(append([]string{}, base...), "--dry-run", "--json"), nil)
	require.Equal(t, 0, dry.exitCode, dry.stderr)
	var plan map[string]any
	require.NoError(t, json.Unmarshal([]byte(dry.stdout), &plan))
	action, ok := plan["action"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "bash", action["script_runner"], "shebang must select the interpreter")

	result := runSSHX(t, home, append(append([]string{}, base...), "--accept-unknown-host", "--json"),
		map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, result.exitCode, "stderr=%s stdout=%s", result.stderr, result.stdout)
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload))
	assert.Equal(t, true, payload["success"])
	stdout, ok := payload["stdout"].(string)
	require.True(t, ok)
	assert.Contains(t, stdout, "shell=bash", "pipefail script must run under bash")

	// An explicit --shell wins over the shebang.
	shOverride := runSSHX(t, home, append(append([]string{}, base...), "--shell=sh", "--dry-run", "--json"), nil)
	require.Equal(t, 0, shOverride.exitCode, shOverride.stderr)
	var overridePlan map[string]any
	require.NoError(t, json.Unmarshal([]byte(shOverride.stdout), &overridePlan))
	overrideAction, ok := overridePlan["action"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "sh", overrideAction["script_runner"])

	// A non-shell interpreter is rejected locally instead of being run by sh.
	pyPath := filepath.Join(home, "payload.py")
	require.NoError(t, os.WriteFile(pyPath, []byte("#!/usr/bin/env python3\nprint(1)\n"), 0o600))
	before := server.connections.Load()
	py := runSSHX(t, home, []string{
		"run",
		"--address=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--script-file=" + pyPath,
		"--json",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 255, py.exitCode, py.stdout+py.stderr)
	assert.Contains(t, py.stdout+py.stderr, "unsupported script runner")
	assert.Equal(t, before, server.connections.Load(), "must not connect for an unsupported runner")
}

func TestRunMultiHostJSONLAndSelectors(t *testing.T) {
	const n = 8
	servers := make([]*testSSHServer, n)
	home := t.TempDir()
	hosts := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		servers[i] = startSSHServer(t, serverOptions{})
		name := fmt.Sprintf("node-%02d", i)
		group := "fleet"
		if i%2 == 0 {
			group = "even"
		}
		hosts = append(hosts, map[string]any{
			"name":   name,
			"host":   servers[i].host,
			"port":   servers[i].port,
			"user":   "operator",
			"groups": []string{group, "fleet"},
			"tags": map[string]string{
				"env":  "test",
				"role": fmt.Sprintf("r%d", i%2),
			},
		})
	}
	settingsPath := filepath.Join(home, ".sshx", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(settingsPath), 0o700))
	raw, err := json.MarshalIndent(map[string]any{"hosts": hosts}, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(settingsPath, raw, 0o600))

	// zero matches fails before connect
	zero := runSSHX(t, home, []string{
		"run", "--group=missing", "--json", "--", "probe",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 255, zero.exitCode, zero.stderr+zero.stdout)

	start := time.Now()
	result := runSSHX(t, home, []string{
		"run",
		"--group=fleet",
		"--tag=env=test",
		"--concurrency=4",
		"--failure-mode=continue",
		"--no-key",
		"--accept-unknown-host",
		"--jsonl",
		"--",
		"probe",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	elapsed := time.Since(start)
	require.Equal(t, 0, result.exitCode, "stderr=%s stdout=%s", result.stderr, result.stdout)

	events := parseJSONL(t, result.stdout)
	require.GreaterOrEqual(t, len(events), 2+n)
	assert.Equal(t, "run_started", events[0]["kind"])
	assert.Equal(t, "run_finished", events[len(events)-1]["kind"])
	// Sequence numbers are monotonic, but events may complete out of target-index order.
	seen := map[int64]bool{}
	var prev int64
	for i, ev := range events {
		s, ok := ev["sequence"].(float64)
		require.True(t, ok)
		seq := int64(s)
		require.False(t, seen[seq], "duplicate sequence %d", seq)
		seen[seq] = true
		if i > 0 {
			require.Greater(t, seq, prev, "sequence must increase in stream order")
		}
		prev = seq
	}
	finished := events[len(events)-1]
	counts, ok := finished["counts"].(map[string]any)
	require.True(t, ok)
	assert.EqualValues(t, n, counts["selected"])
	assert.EqualValues(t, n, counts["succeeded"])

	// Bounded fan-out should finish faster than serial sleep-equivalent; with
	// near-instant probe this is a smoke check that the path completes.
	assert.Less(t, elapsed, 15*time.Second)

	// tag AND filters to role=r0 (even indexes)
	filtered := runSSHX(t, home, []string{
		"run",
		"--group=fleet",
		"--tag=env=test",
		"--tag=role=r0",
		"--concurrency=4",
		"--no-key",
		"--accept-unknown-host",
		"--jsonl",
		"--",
		"probe",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, filtered.exitCode, filtered.stderr+filtered.stdout)
	fevents := parseJSONL(t, filtered.stdout)
	fc, ok := fevents[len(fevents)-1]["counts"].(map[string]any)
	require.True(t, ok)
	assert.EqualValues(t, n/2, fc["selected"])
}

func TestRunBoundedFanOutThirtyTwoHosts(t *testing.T) {
	const n = 32
	home := t.TempDir()
	servers := make([]*testSSHServer, n)
	hosts := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		servers[i] = startSSHServer(t, serverOptions{})
		hosts = append(hosts, map[string]any{
			"name":   fmt.Sprintf("bulk-%02d", i),
			"host":   servers[i].host,
			"port":   servers[i].port,
			"user":   "operator",
			"groups": []string{"bulk"},
		})
	}
	writeSettings(t, home, map[string]any{"hosts": hosts})

	for _, concurrency := range []int{1, 4, 8, 32} {
		concurrency := concurrency
		t.Run(fmt.Sprintf("c%d", concurrency), func(t *testing.T) {
			start := time.Now()
			result := runSSHX(t, home, []string{
				"run",
				"--group=bulk",
				fmt.Sprintf("--concurrency=%d", concurrency),
				"--no-key",
				"--accept-unknown-host",
				"--jsonl",
				"--",
				"probe",
			}, map[string]string{"SSH_PASSWORD": operatorPassword})
			elapsed := time.Since(start)
			require.Equal(t, 0, result.exitCode, result.stderr+result.stdout)
			events := parseJSONL(t, result.stdout)
			counts, ok := events[len(events)-1]["counts"].(map[string]any)
			require.True(t, ok)
			assert.EqualValues(t, n, counts["selected"])
			assert.EqualValues(t, n, counts["succeeded"])
			t.Logf("concurrency=%d elapsed=%s", concurrency, elapsed)
			if concurrency == 1 {
				// Store baseline wall time via t.Log; higher concurrency should not be dramatically slower.
				return
			}
			assert.Less(t, elapsed, 20*time.Second)
		})
	}
}

func TestRunFailFastAndPartialFailure(t *testing.T) {
	okServer := startSSHServer(t, serverOptions{})
	badHome := t.TempDir()
	// bad host points at closed port
	settings := map[string]any{
		"hosts": []map[string]any{
			{"name": "ok", "host": okServer.host, "port": okServer.port, "user": "operator", "groups": []string{"g"}},
			{"name": "bad", "host": "127.0.0.1", "port": "1", "user": "operator", "groups": []string{"g"}},
			{"name": "ok2", "host": okServer.host, "port": okServer.port, "user": "operator", "groups": []string{"g"}},
		},
	}
	writeSettings(t, badHome, settings)

	result := runSSHX(t, badHome, []string{
		"run",
		"--group=g",
		"--concurrency=1",
		"--failure-mode=fail_fast",
		"--no-key",
		"--accept-unknown-host",
		"--jsonl",
		"--",
		"probe",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 1, result.exitCode, result.stderr+result.stdout)
	events := parseJSONL(t, result.stdout)
	finished := events[len(events)-1]
	counts, ok := finished["counts"].(map[string]any)
	require.True(t, ok)
	assert.EqualValues(t, 3, counts["selected"])
	// At least one skipped or failed under fail_fast.
	failed, ok := counts["failed"].(float64)
	require.True(t, ok)
	skipped, ok := counts["skipped"].(float64)
	require.True(t, ok)
	assert.Greater(t, failed+skipped, 0.0)
}

func TestRunIgnoresHighRiskEnvAndDotenv(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	// Repository-local .env must not authorize force/safety bypass.
	require.NoError(t, os.WriteFile(filepath.Join(home, ".env"), []byte("SSH_FORCE=true\nSSH_NO_SAFETY_CHECK=true\n"), 0o600))

	blocked := runSSHX(t, home, []string{
		"run",
		"--address=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--json",
		"--",
		"rm -rf /",
	}, map[string]string{
		"SSH_PASSWORD":          operatorPassword,
		"SSH_FORCE":             "true",
		"SSH_NO_SAFETY_CHECK":   "true",
		"SSH_INSECURE_HOST_KEY": "true",
	})
	// Request-level blocked/config failure.
	require.NotEqual(t, 0, blocked.exitCode, blocked.stdout+blocked.stderr)
	assert.True(t,
		strings.Contains(blocked.stdout, "blocked") ||
			strings.Contains(blocked.stderr, "blocked") ||
			strings.Contains(blocked.stdout, "bypass"),
		"stdout=%s stderr=%s", blocked.stdout, blocked.stderr,
	)
}

func TestRunOversizedScriptFailsBeforeConnect(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	scriptPath := filepath.Join(home, "big.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte(strings.Repeat("x", 64)), 0o600))
	before := server.connections.Load()
	result := runSSHX(t, home, []string{
		"run",
		"--address=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--script-file=" + scriptPath,
		"--max-payload-bytes=16",
		"--json",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 255, result.exitCode, result.stdout+result.stderr)
	assert.Equal(t, before, server.connections.Load(), "must not connect for oversized payload")
}

func parseJSONL(t *testing.T, raw string) []map[string]any {
	t.Helper()
	var events []map[string]any
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &ev), line)
		events = append(events, ev)
	}
	require.NoError(t, sc.Err())
	return events
}

func writeSettings(t *testing.T, home string, settings map[string]any) {
	t.Helper()
	path := filepath.Join(home, ".sshx", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	raw, err := json.MarshalIndent(settings, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}
