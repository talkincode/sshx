package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type textResult struct {
	SchemaVersion   string `json:"schema_version"`
	Success         bool   `json:"success"`
	ErrorKind       string `json:"error_kind"`
	Truncated       bool   `json:"truncated"`
	TruncatedReason string `json:"truncated_reason"`
	LineOrigin      string `json:"line_origin"`
	Redacted        bool   `json:"redacted"`
	Stats           struct {
		Returned        int `json:"returned"`
		TotalHits       int `json:"total_hits"`
		ExceptionBlocks int `json:"exception_blocks"`
	} `json:"stats"`
	Hits []struct {
		Kind      string `json:"kind"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
		Text      string `json:"text"`
	} `json:"hits"`
	Source struct {
		Kind string `json:"kind"`
		Path string `json:"path"`
	} `json:"source"`
}

func TestTextFindsExceptionBlockOverSFTP(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	remote := filepath.Join(server.root, "app.log")
	body := strings.Join([]string{
		"INFO boot",
		"Traceback (most recent call last):",
		`  File "app.py", line 1, in <module>`,
		`    raise ValueError("token=super-secret")`,
		"ValueError: token=super-secret",
		"INFO recovered",
	}, "\n") + "\n"
	require.NoError(t, os.WriteFile(remote, []byte(body), 0o600))

	got := runSSHX(t, home, []string{
		"text",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"--accept-unknown-host",
		"--path=" + filepath.ToSlash(remote),
		"--preset=exception",
		"--scan=start",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, got.exitCode, got.stderr+"\n"+got.stdout)

	var result textResult
	require.NoError(t, json.Unmarshal([]byte(got.stdout), &result))
	assert.True(t, result.Success)
	assert.Equal(t, "sshx.text.v1", result.SchemaVersion)
	assert.Equal(t, 1, result.Stats.ExceptionBlocks)
	require.NotEmpty(t, result.Hits)
	assert.Equal(t, "exception_block", result.Hits[0].Kind)
	assert.Contains(t, result.Hits[0].Text, "Traceback")
	assert.NotContains(t, result.Hits[0].Text, "super-secret")
	assert.True(t, result.Redacted)
	assert.Equal(t, "file", result.LineOrigin)
}

func TestTextDryRunDoesNotConnect(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	got := runSSHX(t, home, []string{
		"text",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"--dry-run",
		"--path=/var/log/app.log",
		"--preset=exception",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, got.exitCode, got.stderr+"\n"+got.stdout)
	assert.Contains(t, got.stdout, `"dry_run": true`)
	assert.Contains(t, got.stdout, `"would_connect": true`)
	assert.Contains(t, got.stdout, `"would_mutate_remote": false`)
	assert.Equal(t, int64(0), server.connections.Load())
}

func TestTextRejectsRelativePath(t *testing.T) {
	home := t.TempDir()
	got := runSSHX(t, home, []string{
		"text", "-h=127.0.0.1", "--json", "--path=var/log/app.log",
	}, nil)
	require.NotEqual(t, 0, got.exitCode)
	assert.Contains(t, got.stdout, `"error_kind":"config"`)
}

func TestTextJournalUsesOwnedArgv(t *testing.T) {
	var saw string
	server := startSSHServer(t, serverOptions{
		execHandler: func(channel ssh.Channel, command, _ string) {
			saw = command
			_, _ = channel.Write([]byte("2026-01-01T00:00:00Z nginx ERROR boom\n")) //nolint:errcheck // fixture
			sendExitStatus(channel, 0)
		},
	})
	home := t.TempDir()
	got := runSSHX(t, home, []string{
		"text",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"--accept-unknown-host",
		"--journal=nginx.service",
		"--since=1h",
		"--preset=error",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, got.exitCode, got.stderr+"\n"+got.stdout)
	assert.Contains(t, saw, "journalctl")
	assert.Contains(t, saw, "--unit='nginx.service'")
	assert.NotContains(t, saw, ";")
	var result textResult
	require.NoError(t, json.Unmarshal([]byte(got.stdout), &result))
	assert.True(t, result.Success)
	require.NotEmpty(t, result.Hits)
	assert.Equal(t, "error_line", result.Hits[0].Kind)
}

func TestTextHelpJSON(t *testing.T) {
	home := t.TempDir()
	got := runSSHX(t, home, []string{"text", "--help", "--json"}, nil)
	require.Equal(t, 0, got.exitCode, got.stderr+"\n"+got.stdout)
	assert.Contains(t, got.stdout, `"schema_version":"sshx.text.help.v1"`)
	assert.Contains(t, got.stdout, "preset=exception")
}
