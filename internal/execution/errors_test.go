package execution

import (
	"fmt"
	"testing"

	"github.com/talkincode/sshx/internal/sshclient"
)

func TestClassify_InvalidBindIsConfig(t *testing.T) {
	if got := Classify(sshclient.ErrInvalidBind); got != ErrorKindConfig {
		t.Fatalf("Classify(ErrInvalidBind) = %q", got)
	}
	wrapped := fmt.Errorf("failed to dial: %w", sshclient.ErrInvalidBind)
	if got := Classify(wrapped); got != ErrorKindConfig {
		t.Fatalf("Classify(wrapped dial) = %q, want config not connect", got)
	}
}

func TestBuildDryRunPlan_InvalidBind(t *testing.T) {
	req := &Request{
		Action:  ActionSpec{Kind: ActionCommand, Command: "uptime", Intent: IntentRead},
		Targets: TargetSelector{Names: []string{"edge"}},
	}
	hosts := []HostRecord{{Name: "edge", Address: "203.0.113.1", Bind: "sshx-no-such-iface"}}
	plan := BuildDryRunPlan(req, hosts, HostRecord{}, nil)
	if plan.Valid {
		t.Fatal("invalid bind must fail dry-run")
	}
	if plan.Error == nil || plan.Error.Kind != ErrorKindConfig {
		t.Fatalf("error = %#v", plan.Error)
	}
	if plan.WouldConnect {
		t.Fatal("invalid bind must not connect")
	}
}
