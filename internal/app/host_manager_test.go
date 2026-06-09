package app

import (
	"testing"
	"time"

	"github.com/talkincode/sshx/internal/sshclient"
)

func TestFormatAuthDescription(t *testing.T) {
	tests := []struct {
		method   sshclient.AuthMethod
		expected string
	}{
		{sshclient.AuthMethodKey, "SSH key"},
		{sshclient.AuthMethodPassword, "Password"},
		{sshclient.AuthMethodPasswordFallback, "Password (fallback after key failure)"},
		{sshclient.AuthMethodUnknown, "Unknown"},
	}

	for _, tt := range tests {
		if got := formatAuthDescription(tt.method); got != tt.expected {
			t.Errorf("formatAuthDescription(%s) = %q, expected %q", tt.method, got, tt.expected)
		}
	}
}

func TestBuildHostTestConfigDefaults(t *testing.T) {
	settings := &Settings{Key: "/custom/key"}
	host := &HostConfig{
		Name: "demo",
		Host: "demo.example.com",
	}
	base := &sshclient.Config{UseKeyAuth: true}

	cfg := buildHostTestConfig(host, settings, base)

	if cfg.Port != sshclient.DefaultSSHPort {
		t.Fatalf("expected default port %s, got %s", sshclient.DefaultSSHPort, cfg.Port)
	}
	if cfg.User != sshclient.DefaultSSHUser {
		t.Fatalf("expected default user %s, got %s", sshclient.DefaultSSHUser, cfg.User)
	}
	if cfg.KeyPath != settings.Key {
		t.Fatalf("expected key path %s, got %s", settings.Key, cfg.KeyPath)
	}
	if !cfg.UseKeyAuth {
		t.Fatalf("expected key auth to remain enabled")
	}
	if cfg.DialTimeout != hostTestDialTimeout {
		t.Fatalf("expected dial timeout %s, got %s", hostTestDialTimeout, cfg.DialTimeout)
	}
}

func TestBuildHostTestConfig_DisableKeyAuth(t *testing.T) {
	host := &HostConfig{Host: "demo"}
	base := &sshclient.Config{UseKeyAuth: false, KeyPath: "/tmp/key", Password: "secret", DialTimeout: 5 * time.Second}

	cfg := buildHostTestConfig(host, nil, base)

	if cfg.UseKeyAuth {
		t.Fatalf("expected key auth to be disabled")
	}
	if cfg.KeyPath != "" {
		t.Fatalf("expected key path to be cleared, got %s", cfg.KeyPath)
	}
	if cfg.Password != "secret" {
		t.Fatalf("expected password to propagate from base config")
	}
	if cfg.DialTimeout != base.DialTimeout {
		t.Fatalf("expected dial timeout override to persist (want %s, got %s)", base.DialTimeout, cfg.DialTimeout)
	}
}
