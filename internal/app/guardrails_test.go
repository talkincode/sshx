package app

import (
	"strings"
	"testing"
)

func TestApplyCommandModeBypassReason(t *testing.T) {
	args := []string{"sshx", "-h=host", "--force", "--bypass-reason=maintenance window", "sudo reboot"}
	config := ParseArgs(args)
	applyCommandModeBypassReason(config, args)
	if config.BypassReason != "maintenance window" {
		t.Fatalf("BypassReason=%q", config.BypassReason)
	}
	if config.Command != "sudo reboot" {
		t.Fatalf("Command=%q, want sudo reboot without leftover flag", config.Command)
	}
}

func TestRequireBypassReason(t *testing.T) {
	err := requireBypassReason(ParseArgs([]string{"sshx", "-h=host", "--force", "reboot"}))
	if err == nil || !strings.Contains(err.Error(), "--bypass-reason") {
		t.Fatalf("expected bypass-reason error, got %v", err)
	}
}
