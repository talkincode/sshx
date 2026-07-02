package app

import (
	"strings"
	"testing"

	"github.com/talkincode/sshx/internal/sshclient"
)

func TestParseArgs_TransferMode(t *testing.T) {
	args := []string{"sshx", "--transfer=hostA:/var/log/app.log", "--to=hostB:/backup/app.log"}
	config := ParseArgs(args)

	if config.Mode != "transfer" {
		t.Errorf("Expected mode 'transfer', got %s", config.Mode)
	}
	if config.TransferSrcHost != "hostA" {
		t.Errorf("Expected source host 'hostA', got %s", config.TransferSrcHost)
	}
	if config.TransferSrcPath != "/var/log/app.log" {
		t.Errorf("Expected source path '/var/log/app.log', got %s", config.TransferSrcPath)
	}
	if config.TransferDstHost != "hostB" {
		t.Errorf("Expected destination host 'hostB', got %s", config.TransferDstHost)
	}
	if config.TransferDstPath != "/backup/app.log" {
		t.Errorf("Expected destination path '/backup/app.log', got %s", config.TransferDstPath)
	}
}

func TestParseArgs_TransferToDoesNotAffectSftp(t *testing.T) {
	args := []string{"sshx", "-h=192.168.1.100", "--upload=local.txt", "--to=/tmp/remote.txt"}
	config := ParseArgs(args)

	if config.Mode != "sftp" {
		t.Errorf("Expected mode 'sftp', got %s", config.Mode)
	}
	if config.RemotePath != "/tmp/remote.txt" {
		t.Errorf("Expected remote path '/tmp/remote.txt', got %s", config.RemotePath)
	}
	if config.TransferDstHost != "" || config.TransferDstPath != "" {
		t.Errorf("Expected transfer destination to be empty, got %s:%s", config.TransferDstHost, config.TransferDstPath)
	}
}

func TestSplitHostPath(t *testing.T) {
	tests := []struct {
		spec     string
		wantHost string
		wantPath string
	}{
		{"hostA:/var/log", "hostA", "/var/log"},
		{"192.168.1.100:/tmp/file.txt", "192.168.1.100", "/tmp/file.txt"},
		{"hostA:relative/path", "hostA", "relative/path"},
		{"hostA:", "hostA", ""},
		{"hostA", "hostA", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		host, path := splitHostPath(tt.spec)
		if host != tt.wantHost || path != tt.wantPath {
			t.Errorf("splitHostPath(%q) = (%q, %q), want (%q, %q)", tt.spec, host, path, tt.wantHost, tt.wantPath)
		}
	}
}

func TestHandleTransfer_MissingSource(t *testing.T) {
	config := &sshclient.Config{Mode: "transfer", TransferDstHost: "hostB", TransferDstPath: "/tmp/x"}
	err := HandleTransfer(config)
	if err == nil || !strings.Contains(err.Error(), "--transfer=<host>:<path>") {
		t.Errorf("Expected missing source error, got %v", err)
	}
}

func TestHandleTransfer_MissingDestination(t *testing.T) {
	config := &sshclient.Config{Mode: "transfer", TransferSrcHost: "hostA", TransferSrcPath: "/tmp/x"}
	err := HandleTransfer(config)
	if err == nil || !strings.Contains(err.Error(), "--to=<host>:<path>") {
		t.Errorf("Expected missing destination error, got %v", err)
	}
}

func TestBuildDryRunPlan_Transfer(t *testing.T) {
	config := ParseArgs([]string{"sshx", "--transfer=10.0.0.1:/data/file", "--to=10.0.0.2:/data/file", "--dry-run"})
	plan := buildDryRunPlan(config)

	if plan.Mode != "transfer" {
		t.Errorf("Expected mode 'transfer', got %s", plan.Mode)
	}
	if plan.Action != "transfer" {
		t.Errorf("Expected action 'transfer', got %s", plan.Action)
	}
	if plan.TransferSource != "10.0.0.1:/data/file" {
		t.Errorf("Expected transfer source '10.0.0.1:/data/file', got %s", plan.TransferSource)
	}
	if plan.TransferDest != "10.0.0.2:/data/file" {
		t.Errorf("Expected transfer destination '10.0.0.2:/data/file', got %s", plan.TransferDest)
	}
	if !plan.Valid {
		t.Errorf("Expected plan to be valid")
	}
	if !plan.WouldConnect || !plan.WouldMutateRemote {
		t.Errorf("Expected WouldConnect and WouldMutateRemote to be true, got %t/%t", plan.WouldConnect, plan.WouldMutateRemote)
	}
}

func TestBuildDryRunPlan_TransferMissingDestination(t *testing.T) {
	config := ParseArgs([]string{"sshx", "--transfer=10.0.0.1:/data/file", "--dry-run"})
	plan := buildDryRunPlan(config)

	if plan.Valid {
		t.Errorf("Expected plan to be invalid without destination")
	}
	if plan.ConfigCheck.Status != "error" || plan.ConfigCheck.ErrorKind != "config" {
		t.Errorf("Expected config error, got %+v", plan.ConfigCheck)
	}
	if plan.WouldConnect {
		t.Errorf("Expected WouldConnect to be false for invalid plan")
	}
}
