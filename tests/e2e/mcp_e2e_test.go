package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mcpClient drives the compiled sshx binary in `sshx mcp` mode over stdio
// with newline-delimited JSON-RPC, the same way a real MCP client would.
type mcpClient struct {
	t         *testing.T
	cmd       *exec.Cmd
	stdin     *json.Encoder
	stdinPipe io.WriteCloser
	messages  chan mcpRead
	nextID    int
	waitOnce  sync.Once
	exited    chan struct{}
	waitErr   error
}

type mcpRead struct {
	line string
	err  error
}

func startMCPClient(t *testing.T, home string, extraEnv map[string]string) *mcpClient {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping compiled-binary E2E in short mode")
	}

	cmd := exec.Command(testBinary, "mcp") // #nosec G204 -- harness-built sshx binary.
	cmd.Dir = home
	cmd.Env = isolatedEnvironment(home, extraEnv)
	stdinPipe, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	client := &mcpClient{
		t: t, cmd: cmd, stdin: json.NewEncoder(stdinPipe), stdinPipe: stdinPipe,
		messages: make(chan mcpRead, 128), exited: make(chan struct{}),
	}
	stopReading := make(chan struct{})
	go func() {
		reader := bufio.NewReaderSize(stdoutPipe, 1<<20)
		for {
			line, err := reader.ReadString('\n')
			select {
			case client.messages <- mcpRead{line, err}:
			case <-stopReading:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(stopReading)
		_ = stdinPipe.Close() //nolint:errcheck // best-effort shutdown
		select {
		case <-client.wait():
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill() //nolint:errcheck // last-resort cleanup
			<-client.wait()
		}
	})

	client.initialize()
	return client
}

func (c *mcpClient) wait() <-chan struct{} {
	c.waitOnce.Do(func() {
		go func() {
			c.waitErr = c.cmd.Wait()
			close(c.exited)
		}()
	})
	return c.exited
}

func (c *mcpClient) readLine(deadline time.Time) (string, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case msg := <-c.messages:
		return msg.line, msg.err
	case <-timer.C:
		return "", fmt.Errorf("MCP read deadline exceeded")
	}
}

func (c *mcpClient) initialize() {
	c.t.Helper()
	response := c.call("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "sshx-e2e", "version": "0"},
	})
	serverInfo, ok := response["serverInfo"].(map[string]any)
	require.True(c.t, ok, "initialize response missing serverInfo: %v", response)
	require.Equal(c.t, "sshx", serverInfo["name"])
	c.notify("notifications/initialized", map[string]any{})
}

func (c *mcpClient) notify(method string, params map[string]any) {
	c.t.Helper()
	require.NoError(c.t, c.stdin.Encode(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}))
}

// call sends one request and blocks until its matching response arrives,
// skipping any server-initiated notifications.
func (c *mcpClient) callCollecting(method string, params map[string]any) (map[string]any, []map[string]any) {
	c.t.Helper()
	c.nextID++
	id := c.nextID
	require.NoError(c.t, c.stdin.Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}))

	var notes []map[string]any
	deadline := time.Now().Add(60 * time.Second)
	for {
		require.True(c.t, time.Now().Before(deadline), "timed out waiting for %s response", method)
		line, err := c.readLine(deadline)
		require.NoError(c.t, err, "read MCP response for %s", method)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var message map[string]any
		require.NoError(c.t, json.Unmarshal([]byte(line), &message), "parse MCP message: %s", line)
		rawID, hasID := message["id"]
		if !hasID {
			notes = append(notes, message)
			continue
		}
		gotID, ok := rawID.(float64)
		if !ok || int(gotID) != id {
			continue
		}
		if errObj, isErr := message["error"]; isErr {
			c.t.Fatalf("MCP %s returned protocol error: %v", method, errObj)
		}
		result, ok := message["result"].(map[string]any)
		require.True(c.t, ok, "MCP %s result is not an object: %s", method, line)
		return result, notes
	}
}

func (c *mcpClient) call(method string, params map[string]any) map[string]any {
	c.t.Helper()
	c.nextID++
	id := c.nextID
	require.NoError(c.t, c.stdin.Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}))

	deadline := time.Now().Add(60 * time.Second)
	for {
		require.True(c.t, time.Now().Before(deadline), "timed out waiting for %s response", method)
		line, err := c.readLine(deadline)
		require.NoError(c.t, err, "read MCP response for %s", method)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var message map[string]any
		require.NoError(c.t, json.Unmarshal([]byte(line), &message), "parse MCP message: %s", line)
		rawID, hasID := message["id"]
		if !hasID {
			continue // notification
		}
		gotID, ok := rawID.(float64)
		if !ok || int(gotID) != id {
			continue
		}
		if errObj, isErr := message["error"]; isErr {
			c.t.Fatalf("MCP %s returned protocol error: %v", method, errObj)
		}
		result, ok := message["result"].(map[string]any)
		require.True(c.t, ok, "MCP %s result is not an object: %s", method, line)
		return result
	}
}

// callTool invokes tools/call and returns isError plus the first text content.
func (c *mcpClient) callTool(name string, arguments map[string]any) (bool, string) {
	c.t.Helper()
	result := c.call("tools/call", map[string]any{"name": name, "arguments": arguments})
	isError, ok := result["isError"].(bool)
	if !ok {
		isError = false
	}
	content, ok := result["content"].([]any)
	require.True(c.t, ok, "tools/call %s returned no content: %v", name, result)
	require.NotEmpty(c.t, content)
	first, ok := content[0].(map[string]any)
	require.True(c.t, ok)
	text, ok := first["text"].(string)
	require.True(c.t, ok, "tools/call %s first content has no text: %v", name, first)
	return isError, text
}

func TestMCPServerContract(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	writeSettings(t, home, map[string]any{"hosts": []map[string]any{{
		"name": "mcp-target",
		"host": server.host,
		"port": server.port,
		"user": "operator",
	}}})

	// Pre-trust the harness host key once so MCP-originated child processes
	// connect with strict host-key verification and no trust relaxations.
	trust := runSSHX(t, home, []string{
		"-h=mcp-target", "--no-key", "--accept-unknown-host", "probe",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, trust.exitCode, "pre-trust failed: stderr=%s stdout=%s", trust.stderr, trust.stdout)

	client := startMCPClient(t, home, map[string]string{
		"SSH_PASSWORD":  operatorPassword,
		"SSHX_NO_AUDIT": "false",
	})

	t.Run("tools list exposes execution contract only", func(t *testing.T) {
		result := client.call("tools/list", map[string]any{})
		rawTools, ok := result["tools"].([]any)
		require.True(t, ok)
		names := make([]string, 0, len(rawTools))
		for _, raw := range rawTools {
			tool, ok := raw.(map[string]any)
			require.True(t, ok)
			name, ok := tool["name"].(string)
			require.True(t, ok, "tool entry missing name: %v", tool)
			names = append(names, name)
			if name != "sshx_host_list" {
				schema, ok := tool["inputSchema"].(map[string]any)
				require.True(t, ok)
				properties, ok := schema["properties"].(map[string]any)
				require.True(t, ok)
				for _, field := range []string{"expect_plan", "host_timeout_seconds", "global_timeout_seconds"} {
					assert.Contains(t, properties, field, "%s must expose %s", name, field)
				}
				if name == "sshx_run" {
					assert.Contains(t, properties, "max_failures")
					assert.Contains(t, properties, "fail_fast")
					assert.Contains(t, properties, "request_id")
				}
				if name == "sshx_sql" {
					assert.Contains(t, properties, "bypass_reason")
				}
			}
		}
		assert.ElementsMatch(t, []string{
			"sshx_run", "sshx_sql", "sshx_apply", "sshx_inspect",
			"sshx_sftp", "sshx_transfer", "sshx_host_list",
		}, names)
		for _, name := range names {
			assert.NotContains(t, name, "password", "secret management must not be exposed over MCP")
		}
	})

	t.Run("host list returns versioned JSON", func(t *testing.T) {
		isError, text := client.callTool("sshx_host_list", map[string]any{})
		assert.False(t, isError, "sshx_host_list failed: %s", text)
		var doc struct {
			SchemaVersion string `json:"schema_version"`
			Count         int    `json:"count"`
			Hosts         []struct {
				Name string `json:"name"`
			} `json:"hosts"`
		}
		require.NoError(t, json.Unmarshal([]byte(text), &doc), "host list output: %s", text)
		assert.Equal(t, "sshx.hosts.v1", doc.SchemaVersion)
		require.Equal(t, 1, doc.Count)
		assert.Equal(t, "mcp-target", doc.Hosts[0].Name)
	})

	t.Run("run dry-run previews without executing", func(t *testing.T) {
		before := server.connections.Load()
		isError, text := client.callTool("sshx_run", map[string]any{
			"targets": []any{"mcp-target"},
			"command": "probe",
			"dry_run": true,
		})
		assert.False(t, isError, "dry-run failed: %s", text)
		var plan map[string]any
		require.NoError(t, json.Unmarshal([]byte(text), &plan), "dry-run output: %s", text)
		assert.Equal(t, "sshx.request.v1", plan["schema_version"])
		assert.Equal(t, true, plan["valid"])
		assert.Equal(t, before, server.connections.Load(), "dry-run must not connect")
	})

	t.Run("run executes and audits with mcp entry", func(t *testing.T) {
		isError, text := client.callTool("sshx_run", map[string]any{
			"targets": []any{"mcp-target"},
			"command": "probe",
		})
		assert.False(t, isError, "run failed: %s", text)
		var result map[string]any
		require.NoError(t, json.Unmarshal([]byte(text), &result), "run output: %s", text)
		assert.Equal(t, "sshx.result.v1", result["schema_version"])
		assert.Equal(t, "succeeded", result["status"])

		auditDir := filepath.Join(home, ".sshx", "audit")
		entries, err := os.ReadDir(auditDir)
		require.NoError(t, err, "audit directory must exist for MCP child invocations")
		var found bool
		for _, entry := range entries {
			data, readErr := os.ReadFile(filepath.Join(auditDir, entry.Name())) // #nosec G304 -- isolated E2E audit fixture.
			require.NoError(t, readErr)
			if strings.Contains(string(data), `"entry":"mcp"`) {
				found = true
				break
			}
		}
		assert.True(t, found, "audit events must record entry=mcp for MCP-originated executions")
	})

	t.Run("safety gates hold over MCP", func(t *testing.T) {
		isError, text := client.callTool("sshx_run", map[string]any{
			"targets": []any{"mcp-target"},
			"command": "probe",
			"force":   true, // force without bypass_reason must be rejected
		})
		assert.True(t, isError, "force without bypass_reason must fail, got: %s", text)
		assert.Contains(t, text, "bypass", "error should explain the missing bypass reason: %s", text)
	})

	t.Run("invalid tool input is rejected locally", func(t *testing.T) {
		isError, text := client.callTool("sshx_run", map[string]any{
			"targets": []any{"mcp-target"},
		})
		assert.True(t, isError, "missing command and script must fail")
		assert.Contains(t, text, "exactly one of command or script", "got: %s", text)
	})

	t.Run("negative limits fail before connecting", func(t *testing.T) {
		before := server.connections.Load()
		for _, field := range []string{"timeout_seconds", "host_timeout_seconds", "global_timeout_seconds", "concurrency", "max_failures"} {
			isError, text := client.callTool("sshx_run", map[string]any{
				"targets": []any{"mcp-target"}, "command": "probe", field: -1,
			})
			assert.True(t, isError, "%s: %s", field, text)
		}
		assert.Equal(t, before, server.connections.Load())
	})

	t.Run("run plan matches CLI with lifecycle inputs", func(t *testing.T) {
		isError, text := client.callTool("sshx_run", map[string]any{
			"targets": []any{"mcp-target"}, "command": "probe", "dry_run": true,
			"host_timeout_seconds": 10, "global_timeout_seconds": 20, "max_failures": 2,
		})
		require.False(t, isError, text)
		cli := runSSHX(t, home, []string{"run", "--target=mcp-target", "--dry-run", "--json",
			"--host-timeout=10s", "--global-timeout=20s", "--max-failures=2", "--", "probe"},
			map[string]string{"SSH_PASSWORD": operatorPassword})
		require.Zero(t, cli.exitCode, cli.stdout+cli.stderr)
		var fromMCP, fromCLI map[string]any
		require.NoError(t, json.Unmarshal([]byte(text), &fromMCP))
		require.NoError(t, json.Unmarshal([]byte(cli.stdout), &fromCLI))
		require.NotEmpty(t, fromMCP["plan_hash"])
		assert.Equal(t, fromCLI["plan_hash"], fromMCP["plan_hash"])

		isError, text = client.callTool("sshx_run", map[string]any{
			"targets": []any{"mcp-target"}, "command": "probe",
			"expect_plan": "sha256:" + strings.Repeat("0", 64),
		})
		assert.True(t, isError, text)
		assert.Contains(t, text, "plan_mismatch")
	})

	t.Run("inline apply source path and empty bytes preserve plan hash", func(t *testing.T) {
		for _, content := range []string{"first\nsecond\n", ""} {
			path := filepath.Join(home, "apply-source")
			require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
			cli := runSSHX(t, home, []string{"apply", "-h=mcp-target", "--path=/mcp-config",
				"--from=" + path, "--json", "--dry-run"}, map[string]string{"SSH_PASSWORD": operatorPassword})
			require.Zero(t, cli.exitCode, cli.stdout+cli.stderr)
			isError, text := client.callTool("sshx_apply", map[string]any{
				"target": "mcp-target", "path": "/mcp-config", "content": content, "dry_run": true,
			})
			require.False(t, isError, text)
			var fromMCP, fromCLI map[string]any
			require.NoError(t, json.Unmarshal([]byte(text), &fromMCP))
			require.NoError(t, json.Unmarshal([]byte(cli.stdout), &fromCLI))
			require.NotEmpty(t, fromMCP["plan_hash"])
			assert.Equal(t, fromCLI["plan_hash"], fromMCP["plan_hash"])
		}
	})

	t.Run("single progress result preserves shared evidence", func(t *testing.T) {
		result, notes := client.callCollecting("tools/call", map[string]any{
			"name": "sshx_run",
			"arguments": map[string]any{
				"targets": []any{"mcp-target"}, "command": "probe", "request_id": "mcp-correlation",
			},
			"_meta": map[string]any{"progressToken": "single-progress"},
		})
		assert.NotEqual(t, true, result["isError"], "%v", result)
		contents, ok := result["content"].([]any)
		require.True(t, ok)
		require.NotEmpty(t, contents)
		first, ok := contents[0].(map[string]any)
		require.True(t, ok)
		content, ok := first["text"].(string)
		require.True(t, ok)
		var doc map[string]any
		require.NoError(t, json.Unmarshal([]byte(content), &doc), content)
		assert.Equal(t, "mcp-correlation", doc["request_id"])
		assert.Equal(t, "probe", doc["command"])
		for _, field := range []string{"plan_hash", "execution_id", "parent_execution_id", "execution_fingerprint", "risk", "change_state", "verification"} {
			assert.NotEmpty(t, doc[field], field)
		}
		assert.NotEmpty(t, notes)
	})

	t.Run("global timeout is a child semantic failure", func(t *testing.T) {
		isError, text := client.callTool("sshx_run", map[string]any{
			"targets": []any{"mcp-target"}, "command": "sleep",
			"timeout_seconds": 10, "global_timeout_seconds": 1,
		})
		require.True(t, isError, text)
		var doc map[string]any
		require.NoError(t, json.Unmarshal([]byte(text), &doc), text)
		assert.Equal(t, "timeout", doc["error_kind"])
		assert.Equal(t, false, doc["success"])
		assert.NotContains(t, text, "adapter failure")
	})

	t.Run("SFTP and transfer preserve real JSON outcomes", func(t *testing.T) {
		local := filepath.Join(home, "sftp-source")
		require.NoError(t, os.WriteFile(local, []byte("mcp-bytes\n"), 0o600))
		for _, arguments := range []map[string]any{
			{"target": "mcp-target", "action": "mkdir", "remote_path": "mcp-files"},
			{"target": "mcp-target", "action": "upload", "local_path": local, "remote_path": "mcp-files/source"},
			{"target": "mcp-target", "action": "list", "remote_path": "mcp-files"},
		} {
			isError, text := client.callTool("sshx_sftp", arguments)
			require.False(t, isError, text)
			var doc map[string]any
			require.NoError(t, json.Unmarshal([]byte(text), &doc), text)
			assert.Equal(t, "sshx.result.v1", doc["schema_version"])
			assert.Equal(t, true, doc["success"])
			assert.NotEmpty(t, doc["execution_id"])
		}
		isError, text := client.callTool("sshx_transfer", map[string]any{
			"source_host": "mcp-target", "source_path": "mcp-files/source",
			"dest_host": "mcp-target", "dest_path": "mcp-files/copied",
		})
		require.False(t, isError, text)
		var transfer map[string]any
		require.NoError(t, json.Unmarshal([]byte(text), &transfer), text)
		assert.Equal(t, "sshx.result.v1", transfer["schema_version"])
		assert.Equal(t, true, transfer["success"])
		bytes, err := os.ReadFile(filepath.Join(server.root, "mcp-files", "copied"))
		require.NoError(t, err)
		assert.Equal(t, "mcp-bytes\n", string(bytes))
	})
}

func TestMCPRunProgressMatchesTargetCount(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	writeSettings(t, home, map[string]any{"hosts": []map[string]any{
		{"name": "mcp-a", "host": server.host, "port": server.port, "user": "operator"},
		{"name": "mcp-b", "host": server.host, "port": server.port, "user": "operator"},
	}})
	trust := runSSHX(t, home, []string{
		"-h=mcp-a", "--no-key", "--accept-unknown-host", "probe",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, trust.exitCode, trust.stderr)

	client := startMCPClient(t, home, map[string]string{"SSH_PASSWORD": operatorPassword})
	result, notes := client.callCollecting("tools/call", map[string]any{
		"name": "sshx_run",
		"arguments": map[string]any{
			"targets": []any{"mcp-a", "mcp-b"},
			"command": "probe",
		},
		"_meta": map[string]any{"progressToken": "e2e-progress"},
	})
	isError := false
	if v, ok := result["isError"].(bool); ok {
		isError = v
	}
	assert.False(t, isError, "sshx_run with progress failed: %v", result)
	progress := 0
	for _, note := range notes {
		method, isString := note["method"].(string)
		if isString && method == "notifications/progress" {
			progress++
		}
	}
	assert.Equal(t, 2, progress, "progress notifications=%d notes=%v", progress, notes)
}

func mcpCancellationFixture(t *testing.T) (*mcpClient, *testSSHServer, string) {
	t.Helper()
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	writeSettings(t, home, map[string]any{"hosts": []map[string]any{
		{"name": "mcp-cancel", "host": server.host, "port": server.port, "user": "operator"},
	}})
	trust := runSSHX(t, home, []string{"-h=mcp-cancel", "--no-key", "--accept-unknown-host", "probe"},
		map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Zero(t, trust.exitCode, trust.stdout+trust.stderr)
	client := startMCPClient(t, home, map[string]string{"SSH_PASSWORD": operatorPassword, "SSHX_NO_AUDIT": "false"})
	return client, server, home
}

func startMCPSleep(t *testing.T, client *mcpClient, server *testSSHServer) int {
	t.Helper()
	before := server.connections.Load()
	client.nextID++
	id := client.nextID
	require.NoError(t, client.stdin.Encode(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": "sshx_run", "arguments": map[string]any{
			"targets": []any{"mcp-cancel"}, "command": "sleep", "timeout_seconds": 30,
			"request_id": "canceled-mcp-request",
		}},
	}))
	require.Eventually(t, func() bool { return server.connections.Load() > before }, 5*time.Second, 10*time.Millisecond)
	// The fixture sleeps for two seconds after acknowledging the exec request.
	time.Sleep(100 * time.Millisecond)
	return id
}

func TestMCPToolCancellationKeepsServerResponsive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cooperative console cancellation requires an attached Windows console")
	}
	client, server, _ := mcpCancellationFixture(t)
	id := startMCPSleep(t, client, server)
	client.notify("notifications/cancelled", map[string]any{"requestId": id, "reason": "test cancellation"}) //nolint:misspell // MCP protocol method.
	deadline := time.Now().Add(5 * time.Second)
	for {
		line, err := client.readLine(deadline)
		require.NoError(t, err)
		var message map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &message))
		if message["id"] != float64(id) {
			continue
		}
		assert.Contains(t, strings.ToLower(line), "cancel")
		assert.NotContains(t, line, `\"error_kind\":\"timeout\"`)
		break
	}
	result := client.call("tools/list", map[string]any{})
	assert.NotEmpty(t, result["tools"], "canceling one tool must not close the session")
}

func TestMCPRootCancellationAndDisconnect(t *testing.T) {
	for _, shutdown := range []string{"disconnect", "interrupt"} {
		t.Run(shutdown, func(t *testing.T) {
			if runtime.GOOS == "windows" && shutdown == "interrupt" {
				t.Skip("os.Interrupt cannot be sent to a Windows process without console APIs")
			}
			client, server, home := mcpCancellationFixture(t)
			startMCPSleep(t, client, server)
			if shutdown == "disconnect" {
				require.NoError(t, client.stdinPipe.Close())
			} else {
				require.NoError(t, client.cmd.Process.Signal(os.Interrupt))
			}
			select {
			case <-client.wait():
			case <-time.After(5 * time.Second):
				t.Fatal("MCP root shutdown did not reap its active child")
			}
			if runtime.GOOS == "windows" {
				return // Job escalation need not produce an unacknowledged semantic result.
			}
			entries, err := os.ReadDir(filepath.Join(home, ".sshx", "audit"))
			require.NoError(t, err)
			found := false
			for _, entry := range entries {
				raw, err := os.ReadFile(filepath.Join(home, ".sshx", "audit", entry.Name())) // #nosec G304 -- Enumerated audit file inside this test's isolated HOME.
				require.NoError(t, err)
				for _, line := range strings.Split(string(raw), "\n") {
					if strings.Contains(line, "canceled-mcp-request") &&
						(strings.Contains(line, `"error_kind":"cancelled"`) || strings.Contains(line, `"kind":"cancelled"`)) { //nolint:misspell // Released error kind.
						found = true
					}
				}
			}
			assert.True(t, found, "root shutdown must let the child persist cancellation evidence")
		})
	}
}

func TestMCPRejectsArguments(t *testing.T) {
	home := t.TempDir()
	result := runSSHX(t, home, []string{"mcp", "--port=1"}, nil)
	require.NotEqual(t, 0, result.exitCode)
	combined := result.stdout + result.stderr
	require.True(t, strings.Contains(combined, "accepts no arguments"),
		fmt.Sprintf("unexpected output: %s", combined))
}
