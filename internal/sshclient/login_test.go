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
