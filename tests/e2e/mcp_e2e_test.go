package e2e

import (
	"bufio"
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

// mcpClient drives the compiled sshx binary in `sshx mcp` mode over stdio
// with newline-delimited JSON-RPC, the same way a real MCP client would.
type mcpClient struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  *json.Encoder
	reader *bufio.Reader
	nextID int
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
		t:      t,
		cmd:    cmd,
		stdin:  json.NewEncoder(stdinPipe),
		reader: bufio.NewReaderSize(stdoutPipe, 1<<20),
	}
	t.Cleanup(func() {
		_ = stdinPipe.Close() //nolint:errcheck // best-effort shutdown
		done := make(chan struct{})
		go func() {
			_ = cmd.Wait() //nolint:errcheck // exit status is irrelevant at cleanup
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill() //nolint:errcheck // last-resort cleanup
			<-done
		}
	})

	client.initialize()
	return client
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
		line, err := c.reader.ReadString('\n')
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
		line, err := c.reader.ReadString('\n')
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

func TestMCPRejectsArguments(t *testing.T) {
	home := t.TempDir()
	result := runSSHX(t, home, []string{"mcp", "--port=1"}, nil)
	require.NotEqual(t, 0, result.exitCode)
	combined := result.stdout + result.stderr
	require.True(t, strings.Contains(combined, "accepts no arguments"),
		fmt.Sprintf("unexpected output: %s", combined))
}
