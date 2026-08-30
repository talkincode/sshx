package sshclient

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPrivilegedLoginCommandUsesStdinSudo(t *testing.T) {
	cmd := PrivilegedLoginCommand
	if !strings.HasPrefix(cmd, "sudo -S -p ''") {
		t.Fatalf("privileged login must use sudo -S stdin injection, got %q", cmd)
	}
	if strings.Contains(cmd, "SudoPassword") || strings.Contains(cmd, "${") {
		t.Fatal("privileged login command must not interpolate secrets")
	}
	if !strings.Contains(cmd, "sudo -i") {
		t.Fatalf("privileged login must exec a login shell, got %q", cmd)
	}
}

func TestLoginRequiresConnection(t *testing.T) {
	client := &SSHClient{config: &Config{LoginUseSudo: true}}
	err := client.Login()
	if err == nil {
		t.Fatal("expected login without a connection to fail")
	}
	if errors.Is(err, ErrLoginNotTTY) {
		t.Fatalf("missing connection should fail before TTY checks, got %v", err)
	}
}

func TestLoginPtyModesInteractiveLooksLikeOpenSSH(t *testing.T) {
	modes := loginPtyModes(false)
	want := map[uint8]uint32{
		ssh.ECHO:    1,
		ssh.ECHOCTL: 1,
		ssh.IUTF8:   1,
		ssh.ICRNL:   1,
		ssh.ONLCR:   1,
		ssh.ICANON:  1,
		ssh.ISIG:    1,
		ssh.OPOST:   1,
		ssh.CS8:     1,
		ssh.VERASE:  127,
		ssh.VINTR:   3,
	}
	for key, val := range want {
		if modes[key] != val {
			t.Fatalf("loginPtyModes(false)[%d] = %d, want %d", key, modes[key], val)
		}
	}
}

func TestLoginPtyModesSudoDisablesEchoKeepsUTF8(t *testing.T) {
	modes := loginPtyModes(true)
	if modes[ssh.ECHO] != 0 || modes[ssh.ECHOCTL] != 0 {
		t.Fatalf("sudo login PTY must start with echo off, got ECHO=%d ECHOCTL=%d",
			modes[ssh.ECHO], modes[ssh.ECHOCTL])
	}
	if modes[ssh.IUTF8] != 1 || modes[ssh.ONLCR] != 1 {
		t.Fatalf("sudo login PTY must still be a UTF-8 cooked terminal, got IUTF8=%d ONLCR=%d",
			modes[ssh.IUTF8], modes[ssh.ONLCR])
	}
}

func TestLoginTermNameUsesTERM(t *testing.T) {
	t.Setenv("TERM", "xterm-ghostty")
	if got := loginTermName(); got != "xterm-ghostty" {
		t.Fatalf("loginTermName() = %q, want xterm-ghostty", got)
	}
	t.Setenv("TERM", "")
	if got := loginTermName(); got != "xterm-256color" {
		t.Fatalf("loginTermName() = %q, want xterm-256color", got)
	}
}

func TestLoginEnvVarsForwardsLocale(t *testing.T) {
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "C.UTF-8")
	t.Setenv("COLORTERM", "truecolor")
	got := loginEnvVars()
	want := [][2]string{
		{"LANG", "en_US.UTF-8"},
		{"LC_CTYPE", "C.UTF-8"},
		{"COLORTERM", "truecolor"},
	}
	if len(got) != len(want) {
		t.Fatalf("loginEnvVars() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("loginEnvVars()[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestLoginWithoutTTY(t *testing.T) {
	if !InteractiveLoginSupported() {
		t.Skip("login session is not implemented on this platform")
	}
	if StdinIsTerminal() {
		t.Skip("test stdin is a TTY; cannot assert the non-TTY gate here")
	}
	client := &SSHClient{config: &Config{}, client: &ssh.Client{}}
	err := client.loginSession()
	if !errors.Is(err, ErrLoginNotTTY) {
		t.Fatalf("loginSession() = %v, want ErrLoginNotTTY", err)
	}
}
