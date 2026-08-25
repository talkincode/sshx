package app

import (
	"strings"
	"testing"

	"github.com/talkincode/sshx/internal/sshclient"
)

func TestBuildDryRunPlan_BindLiteral(t *testing.T) {
	plan := buildDryRunPlan(&sshclient.Config{
		Mode:        "ssh",
		Host:        "203.0.113.1",
		Bind:        "192.0.2.10",
		BindSet:     true,
		Command:     "uptime",
		SafetyCheck: true,
		UseKeyAuth:  true,
	})
	if plan.Bind != "192.0.2.10" {
		t.Fatalf("bind = %q", plan.Bind)
	}
	if !strings.Contains(plan.BindResolved, "192.0.2.10") {
		t.Fatalf("bind_resolved = %q", plan.BindResolved)
	}
	if !plan.Valid || plan.ConfigCheck.ErrorKind != "" {
		t.Fatalf("unexpected plan: valid=%t config=%#v", plan.Valid, plan.ConfigCheck)
	}
}

func TestBuildDryRunPlan_InvalidBindIsConfig(t *testing.T) {
	plan := buildDryRunPlan(&sshclient.Config{
		Mode:        "ssh",
		Host:        "203.0.113.1",
		Bind:        "sshx-no-such-iface",
		BindSet:     true,
		Command:     "uptime",
		SafetyCheck: true,
		UseKeyAuth:  true,
	})
	if plan.Valid {
		t.Fatal("invalid bind must fail dry-run locally")
	}
	if plan.ConfigCheck.ErrorKind != "config" {
		t.Fatalf("error_kind = %q, want config", plan.ConfigCheck.ErrorKind)
	}
	if plan.WouldConnect {
		t.Fatal("invalid bind must not report would_connect")
	}
}

func TestBuildDryRunPlan_EmptyBindClearsHost(t *testing.T) {
	t.Setenv("SSHX_HOME", t.TempDir())
	if err := SaveSettings(&Settings{
		Hosts: []HostConfig{{Name: "edge", Host: "203.0.113.1", Port: "22", User: "root", Bind: "en0"}},
	}); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	plan := buildDryRunPlan(&sshclient.Config{
		Mode:        "ssh",
		Host:        "edge",
		Bind:        "",
		BindSet:     true,
		Command:     "uptime",
		SafetyCheck: true,
		UseKeyAuth:  true,
	})
	if plan.Bind != "" || plan.BindResolved != "" {
		t.Fatalf("empty --bind= must not inherit host bind: bind=%q resolved=%q", plan.Bind, plan.BindResolved)
	}
}

func TestClassifyError_InvalidBindIsConfig(t *testing.T) {
	if got := classifyError(sshclient.ErrInvalidBind); got != "config" {
		t.Fatalf("classifyError = %q, want config", got)
	}
}
