package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseArgs_ApplyBasic(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "apply", "--target=prod", "--path=/etc/nginx/nginx.conf",
		"--from=./nginx.conf", "--expect-sha256=" + strings.Repeat("ab", 32),
		"--sudo", "--json",
	})
	if config.Mode != "apply" {
		t.Fatalf("expected mode apply, got %s", config.Mode)
	}
	if config.Host != "prod" || config.RemotePath != "/etc/nginx/nginx.conf" || config.LocalPath != "./nginx.conf" {
		t.Fatalf("unexpected apply routing: %#v", config)
	}
	if !config.ApplyUseSudo || !config.JSONOutput {
		t.Fatal("sudo/json flags were not parsed")
	}
	if config.ApplyExpectSHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("unexpected expect hash: %s", config.ApplyExpectSHA256)
	}
}

func TestParseArgs_ApplyUnknownOption(t *testing.T) {
	config := ParseArgs([]string{"sshx", "apply", "-h=prod", "--path=/tmp/a", "--from=./a", "--bogus"})
	if config.ArgumentError == "" {
		t.Fatal("expected an argument error for unknown option")
	}
}

func TestValidateApplyConfig_NoBackupRequiresForce(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "apply", "-h=prod", "--path=/tmp/app.conf", "--from=./app.conf", "--no-backup",
	})
	if err := validateApplyConfig(config); err == nil {
		t.Fatal("expected --no-backup without --force to fail")
	}
	config.Force = true
	if err := validateApplyConfig(config); err != nil {
		t.Fatalf("force should allow --no-backup: %v", err)
	}
}

func TestApplyPolicyBlocksPasswdWithoutBypass(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "apply", "-h=prod", "--path=/etc/passwd", "--from=./passwd",
	})
	if err := applyPolicy(config); err == nil {
		t.Fatal("expected /etc/passwd apply to be blocked")
	}
	config.Force = true
	config.BypassReason = "incident-restore"
	if err := applyPolicy(config); err != nil {
		t.Fatalf("force+bypass should allow the critical path: %v", err)
	}
}

func TestApplyDryRunDoesNotNeedHostConnection(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(local, []byte("payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := ParseArgs([]string{
		"sshx", "apply", "-h=prod", "--path=/tmp/app.conf", "--from=" + local, "--dry-run", "--json",
	})
	plan := buildDryRunPlan(config)
	if !plan.Valid {
		t.Fatalf("expected valid dry-run plan: %+v", plan.ConfigCheck)
	}
	if !plan.WouldConnect || !plan.WouldMutateRemote {
		t.Fatalf("unexpected effects: connect=%v mutate=%v", plan.WouldConnect, plan.WouldMutateRemote)
	}
	if plan.Apply == nil || plan.Apply.PayloadBytes != len("payload\n") || plan.Apply.Backup != "file" {
		t.Fatalf("unexpected apply plan: %+v", plan.Apply)
	}
}
