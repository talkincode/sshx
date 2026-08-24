package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestParseArgs_LoginBasic(t *testing.T) {
	for _, args := range [][]string{
		{"sshx", "login", "prod-web", "--sudo"},
		{"sshx", "login", "-h=prod-web", "--sudo"},
		{"sshx", "login", "--target=prod-web", "--sudo"},
	} {
		config := ParseArgs(args)
		if config.Mode != "login" || config.Host != "prod-web" || !config.LoginUseSudo {
			t.Fatalf("unexpected login routing for %v: host=%q sudo=%v mode=%s err=%s",
				args, config.Host, config.LoginUseSudo, config.Mode, config.ArgumentError)
		}
	}
}

func TestParseArgs_LoginPositionalAndAddress(t *testing.T) {
	named := ParseArgs([]string{"sshx", "login", "prod-web"})
	if named.Host != "prod-web" || named.LoginLiteralHost {
		t.Fatalf("positional host should resolve via settings: %#v", named)
	}
	literal := ParseArgs([]string{"sshx", "login", "--address=10.0.0.8", "-u=root"})
	if literal.Host != "10.0.0.8" || !literal.LoginLiteralHost || literal.User != "root" {
		t.Fatalf("unexpected literal login: %#v", literal)
	}
}

func TestParseArgs_LoginRejectsAgentSurfaces(t *testing.T) {
	cases := [][]string{
		{"sshx", "login", "--target=prod", "--json"},
		{"sshx", "login", "--target=prod", "--group=web"},
		{"sshx", "login", "--target=prod", "--timeout=30s"},
		{"sshx", "login", "--target=prod", "--pty"},
		{"sshx", "login", "--target=a", "--address=1.2.3.4"},
		{"sshx", "login", "--target=prod", "--", "bash"},
	}
	for _, args := range cases {
		config := ParseArgs(args)
		if config.ArgumentError == "" {
			t.Fatalf("expected argument error for %v", args)
		}
	}
}

func TestParseArgs_LoginIgnoresSSHTimeout(t *testing.T) {
	t.Setenv("SSH_TIMEOUT", "30s")
	config := ParseArgs([]string{"sshx", "login", "--target=prod-web"})
	if config.Timeout != 0 {
		t.Fatalf("login must ignore SSH_TIMEOUT, got %s", config.Timeout)
	}
}

func TestValidateLoginConfig_RequiresHost(t *testing.T) {
	config := ParseArgs([]string{"sshx", "login"})
	err := validateLoginConfig(config)
	if err == nil || !errors.Is(err, execution.ErrConfig) {
		t.Fatalf("expected config error for missing host, got %v", err)
	}
}

func TestLoginDryRunPlan(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "login", "--address=10.1.2.3", "-u=deploy", "--sudo", "--dry-run", "--json",
	})
	plan := buildDryRunPlan(config)
	if !plan.Valid {
		t.Fatalf("expected valid login dry-run: %+v", plan.ConfigCheck)
	}
	if plan.Mode != "login" || plan.Action != "login-sudo" {
		t.Fatalf("unexpected plan identity: mode=%s action=%s", plan.Mode, plan.Action)
	}
	if plan.HostResolved != "10.1.2.3" || plan.HostResolution.Status != "direct" {
		t.Fatalf("literal address should not look up settings: %+v", plan.HostResolution)
	}
	if !plan.UsesSudo || !plan.WouldConnect || !plan.WouldReadSecret || !plan.WouldMutateRemote {
		t.Fatalf("unexpected login effects: %+v", plan)
	}
	if plan.Command != sshclient.PrivilegedLoginCommand {
		t.Fatalf("sudo plan command = %q", plan.Command)
	}
	joined := strings.Join(plan.Notes, "\n")
	if !strings.Contains(joined, "human-only") {
		t.Fatalf("dry-run notes should mark login as human-only: %s", joined)
	}
}

func TestHandleLogin_RejectsNonTTY(t *testing.T) {
	if !sshclient.InteractiveLoginSupported() {
		t.Skip("login session is not implemented on this platform")
	}
	if sshclient.StdinIsTerminal() {
		t.Skip("stdin is a TTY; cannot assert the non-TTY gate")
	}
	config := ParseArgs([]string{"sshx", "login", "--address=127.0.0.1", "--no-audit"})
	err := HandleLogin(config, nil)
	if !errors.Is(err, sshclient.ErrLoginNotTTY) {
		t.Fatalf("HandleLogin() = %v, want ErrLoginNotTTY", err)
	}
}
