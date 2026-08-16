package app

import (
	"strings"
	"testing"
)

func TestBuildRunArgsCommand(t *testing.T) {
	args, stdin, err := buildRunArgs(mcpRunInput{
		Targets:      []string{"web-1", "web-2"},
		Groups:       []string{"prod"},
		Tags:         []string{"env=prod"},
		Command:      "systemctl is-active nginx",
		TimeoutSecs:  30,
		Concurrency:  8,
		FailureMode:  "fail_fast",
		Intent:       "read",
		DryRun:       true,
		Force:        true,
		BypassReason: "maintenance window",
	})
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	if stdin != "" {
		t.Fatalf("stdin = %q, want empty for command mode", stdin)
	}
	want := []string{
		"run", "--json",
		"--target=web-1", "--target=web-2",
		"--group=prod",
		"--tag=env=prod",
		"--timeout=30s",
		"--concurrency=8",
		"--failure-mode=fail_fast",
		"--intent=read",
		"--dry-run",
		"--force",
		"--bypass-reason=maintenance window",
		"--", "systemctl is-active nginx",
	}
	assertArgs(t, args, want)
}

func TestBuildRunArgsScriptStdin(t *testing.T) {
	script := "#!/bin/sh\necho hello\n"
	args, stdin, err := buildRunArgs(mcpRunInput{Targets: []string{"web-1"}, Script: script})
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	if stdin != script {
		t.Fatalf("stdin = %q, want the byte-preserved script", stdin)
	}
	assertArgs(t, args, []string{"run", "--json", "--target=web-1", "--script-stdin"})
}

func TestBuildRunArgsRequiresExactlyOnePayload(t *testing.T) {
	if _, _, err := buildRunArgs(mcpRunInput{Targets: []string{"a"}}); err == nil {
		t.Fatal("expected error when neither command nor script is set")
	}
	if _, _, err := buildRunArgs(mcpRunInput{Targets: []string{"a"}, Command: "x", Script: "y"}); err == nil {
		t.Fatal("expected error when both command and script are set")
	}
}

func TestBuildSQLArgs(t *testing.T) {
	args, err := buildSQLArgs(mcpSQLInput{
		Target:        "db-1",
		Statement:     "SELECT count(*) FROM users",
		Engine:        "postgres",
		DB:            "app",
		DBUser:        "app",
		DBPasswordKey: "app-db",
		Explain:       true,
		RowThreshold:  500,
		DryRun:        true,
	})
	if err != nil {
		t.Fatalf("buildSQLArgs: %v", err)
	}
	want := []string{
		"sql", "--json", "-h=db-1",
		"--engine=postgres", "--db=app", "--db-user=app",
		"--db-password-key=app-db", "--explain", "--row-threshold=500",
		"--dry-run",
		"--", "SELECT count(*) FROM users",
	}
	assertArgs(t, args, want)
}

func TestBuildSQLArgsRequiredFields(t *testing.T) {
	if _, err := buildSQLArgs(mcpSQLInput{Statement: "SELECT 1"}); err == nil {
		t.Fatal("expected error without target")
	}
	if _, err := buildSQLArgs(mcpSQLInput{Target: "db-1"}); err == nil {
		t.Fatal("expected error without statement")
	}
}

func TestBuildApplyArgs(t *testing.T) {
	args, err := buildApplyArgs(mcpApplyInput{
		Target:       "prod",
		Path:         "/etc/nginx/nginx.conf",
		ExpectSHA256: "abc123",
		Sudo:         true,
		Force:        true,
		BypassReason: "planned change",
		TimeoutSecs:  45,
	}, "/tmp/payload")
	if err != nil {
		t.Fatalf("buildApplyArgs: %v", err)
	}
	want := []string{
		"apply", "--json", "-h=prod",
		"--path=/etc/nginx/nginx.conf", "--from=/tmp/payload",
		"--expect-sha256=abc123", "--sudo", "--force",
		"--bypass-reason=planned change", "--timeout=45s",
	}
	assertArgs(t, args, want)
}

func TestBuildApplyArgsRequiredFields(t *testing.T) {
	if _, err := buildApplyArgs(mcpApplyInput{Path: "/x"}, "/tmp/p"); err == nil {
		t.Fatal("expected error without target")
	}
	if _, err := buildApplyArgs(mcpApplyInput{Target: "h"}, "/tmp/p"); err == nil {
		t.Fatal("expected error without path")
	}
}

func TestBuildInspectArgs(t *testing.T) {
	args, err := buildInspectArgs(mcpInspectInput{
		Target:     "prod",
		Capability: "system.baseline",
		Cache:      "remote-prefer",
		MaxAge:     "30m",
		Sudo:       true,
	})
	if err != nil {
		t.Fatalf("buildInspectArgs: %v", err)
	}
	want := []string{
		"inspect", "--json", "-h=prod",
		"--cache=remote-prefer", "--max-age=30m", "--sudo",
		"system.baseline",
	}
	assertArgs(t, args, want)
}

func TestBuildSFTPArgs(t *testing.T) {
	cases := []struct {
		name  string
		in    mcpSFTPInput
		want  []string
		fails bool
	}{
		{
			name: "upload",
			in:   mcpSFTPInput{Target: "h", Action: "upload", LocalPath: "/l", RemotePath: "/r"},
			want: []string{"--json", "-h=h", "--upload=/l", "--to=/r"},
		},
		{
			name: "download",
			in:   mcpSFTPInput{Target: "h", Action: "download", LocalPath: "/l", RemotePath: "/r"},
			want: []string{"--json", "-h=h", "--download=/r", "--to=/l"},
		},
		{
			name: "list",
			in:   mcpSFTPInput{Target: "h", Action: "list", RemotePath: "/r"},
			want: []string{"--json", "-h=h", "--list=/r"},
		},
		{
			name: "mkdir",
			in:   mcpSFTPInput{Target: "h", Action: "mkdir", RemotePath: "/r"},
			want: []string{"--json", "-h=h", "--mkdir=/r"},
		},
		{
			name: "remove",
			in:   mcpSFTPInput{Target: "h", Action: "remove", RemotePath: "/r"},
			want: []string{"--json", "-h=h", "--rm=/r"},
		},
		{name: "upload without local path", in: mcpSFTPInput{Target: "h", Action: "upload", RemotePath: "/r"}, fails: true},
		{name: "unknown action", in: mcpSFTPInput{Target: "h", Action: "chmod", RemotePath: "/r"}, fails: true},
		{name: "missing target", in: mcpSFTPInput{Action: "list", RemotePath: "/r"}, fails: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, err := buildSFTPArgs(tc.in)
			if tc.fails {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildSFTPArgs: %v", err)
			}
			assertArgs(t, args, tc.want)
		})
	}
}

func TestBuildTransferArgs(t *testing.T) {
	args, err := buildTransferArgs(mcpTransferInput{
		SourceHost: "a", SourcePath: "/src", DestHost: "b", DestPath: "/dst", DryRun: true,
	})
	if err != nil {
		t.Fatalf("buildTransferArgs: %v", err)
	}
	assertArgs(t, args, []string{"--json", "--transfer=a:/src", "--to=b:/dst", "--dry-run"})

	if _, err := buildTransferArgs(mcpTransferInput{SourceHost: "a", SourcePath: "/s", DestHost: "b"}); err == nil {
		t.Fatal("expected error for missing dest_path")
	}
}

func TestParseMCPArgs(t *testing.T) {
	config := ParseArgs([]string{"sshx", "mcp"})
	if config.Mode != "mcp" {
		t.Fatalf("Mode = %q, want mcp", config.Mode)
	}
	if config.ArgumentError != "" {
		t.Fatalf("unexpected argument error: %s", config.ArgumentError)
	}

	config = ParseArgs([]string{"sshx", "mcp", "--port=8080"})
	if config.ArgumentError == "" {
		t.Fatal("expected argument error for unsupported mcp flag")
	}
}

func TestCurrentEntrySanitizes(t *testing.T) {
	cases := map[string]string{
		"mcp":                   "mcp",
		"ci-runner_1":           "ci-runner_1",
		"":                      "",
		"MCP":                   "",
		"mcp;rm -rf /":          "",
		strings.Repeat("a", 33): "",
		"with space":            "",
		"unicode-\u4f60\u597d":  "",
	}
	for input, want := range cases {
		t.Setenv("SSHX_ENTRY", input)
		if got := currentEntry(); got != want {
			t.Fatalf("currentEntry(%q) = %q, want %q", input, got, want)
		}
	}
}

func assertArgs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("args mismatch:\n got:  %q\n want: %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q\n got:  %q\n want: %q", i, got[i], want[i], got, want)
		}
	}
}
