package execution

import (
	"errors"
	"testing"

	"github.com/talkincode/sshx/internal/sshclient"
)

func sampleHosts() []HostRecord {
	return []HostRecord{
		{Name: "prod-web-1", Address: "10.0.1.11", Port: "22", User: "deploy", Groups: []string{"prod-web"}, Tags: map[string]string{"env": "prod", "role": "web"}},
		{Name: "prod-web-2", Address: "10.0.1.12", Port: "22", User: "deploy", Groups: []string{"prod-web"}, Tags: map[string]string{"env": "prod", "role": "web"}},
		{Name: "prod-db-1", Address: "10.0.2.11", Port: "22", User: "deploy", Groups: []string{"prod-db"}, Tags: map[string]string{"env": "prod", "role": "db"}},
		{Name: "stage-web-1", Address: "10.0.3.11", Port: "22", User: "deploy", Groups: []string{"stage-web"}, Tags: map[string]string{"env": "stage", "role": "web"}},
	}
}

func TestResolveTargets_GroupAndTagAND(t *testing.T) {
	snap, err := ResolveTargets(sampleHosts(), TargetSelector{
		Groups: []string{"prod-web"},
		Tags:   map[string]string{"env": "prod", "role": "web"},
	}, HostRecord{})
	if err != nil {
		t.Fatalf("ResolveTargets error: %v", err)
	}
	if snap.Count != 2 {
		t.Fatalf("expected 2 targets, got %d", snap.Count)
	}
	if snap.Targets[0].Alias != "prod-web-1" || snap.Targets[1].Alias != "prod-web-2" {
		t.Fatalf("expected stable alias sort, got %#v", snap.Targets)
	}
	if snap.SelectorDigest == "" {
		t.Fatal("expected selector digest")
	}
}

func TestResolveTargets_NamesUnionGroups(t *testing.T) {
	snap, err := ResolveTargets(sampleHosts(), TargetSelector{
		Names:  []string{"prod-db-1"},
		Groups: []string{"prod-web"},
	}, HostRecord{})
	if err != nil {
		t.Fatalf("ResolveTargets error: %v", err)
	}
	if snap.Count != 3 {
		t.Fatalf("expected 3 targets, got %d", snap.Count)
	}
}

func TestResolveTargets_ZeroMatches(t *testing.T) {
	_, err := ResolveTargets(sampleHosts(), TargetSelector{
		Groups: []string{"missing"},
	}, HostRecord{})
	if !errors.Is(err, ErrNoTargets) {
		t.Fatalf("expected ErrNoTargets, got %v", err)
	}
}

func TestResolveTargets_StrictAliasNoLiteralFallback(t *testing.T) {
	_, err := ResolveTargets(sampleHosts(), TargetSelector{
		Names: []string{"10.0.1.11"},
	}, HostRecord{})
	if err == nil {
		t.Fatal("expected error for literal IP in --target")
	}
}

func TestResolveTargets_LiteralAddress(t *testing.T) {
	snap, err := ResolveTargets(sampleHosts(), TargetSelector{
		Address: "192.0.2.10",
		Port:    "2222",
		User:    "ops",
	}, HostRecord{})
	if err != nil {
		t.Fatalf("ResolveTargets error: %v", err)
	}
	if snap.Count != 1 || !snap.Targets[0].Literal {
		t.Fatalf("unexpected snapshot: %#v", snap)
	}
	if snap.Targets[0].Address != "192.0.2.10" || snap.Targets[0].Port != "2222" {
		t.Fatalf("unexpected target: %#v", snap.Targets[0])
	}
}

func TestResolveTargets_MissingNameSkippedStillMatches(t *testing.T) {
	snap, err := ResolveTargets(sampleHosts(), TargetSelector{
		Names: []string{"prod-web-1", "missing-host"},
	}, HostRecord{})
	if err != nil {
		t.Fatalf("ResolveTargets error: %v", err)
	}
	if snap.Count != 1 {
		t.Fatalf("expected 1 target, got %d", snap.Count)
	}
	if len(snap.Skipped) != 1 || snap.Skipped[0].Alias != "missing-host" {
		t.Fatalf("expected missing-host skipped, got %#v", snap.Skipped)
	}
}

func TestResolveTargets_BindInheritOverrideAndClear(t *testing.T) {
	hosts := []HostRecord{
		{Name: "prod-web-1", Address: "10.0.1.11", Port: "22", User: "deploy", Bind: "en0"},
	}

	snap, err := ResolveTargets(hosts, TargetSelector{Names: []string{"prod-web-1"}}, HostRecord{})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Targets[0].Bind != "en0" {
		t.Fatalf("host bind = %q", snap.Targets[0].Bind)
	}
	hostDigest := snap.SelectorDigest

	snap, err = ResolveTargets(hosts, TargetSelector{Names: []string{"prod-web-1"}}, HostRecord{Bind: "192.0.2.10", BindSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Targets[0].Bind != "192.0.2.10" {
		t.Fatalf("cli bind = %q", snap.Targets[0].Bind)
	}
	if snap.SelectorDigest == hostDigest {
		t.Fatal("selector digest must change when bind changes")
	}

	snap, err = ResolveTargets(hosts, TargetSelector{Names: []string{"prod-web-1"}}, HostRecord{Bind: "", BindSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Targets[0].Bind != "" {
		t.Fatalf("empty BindSet must clear host bind, got %q", snap.Targets[0].Bind)
	}

	snap, err = ResolveTargets(hosts, TargetSelector{Address: "192.0.2.8"}, HostRecord{Bind: "en0", BindSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Targets[0].Literal || snap.Targets[0].Bind != "en0" {
		t.Fatalf("literal target bind = %#v", snap.Targets[0])
	}
}

// The sudo keyring reference is resolved once for the plan, the SSH client, and
// the keyring lookup: an explicit caller key wins, a host's configured
// sudo_password_key comes next, and the built-in default is the last resort
// (issue #78).
func TestSudoKeyForTargetPrecedence(t *testing.T) {
	tests := []struct {
		name      string
		policyKey string
		targetKey string
		want      string
	}{
		{"explicit caller key wins", "explicit-sudo", "host-sudo", "explicit-sudo"},
		{"host key beats the default", "", "host-sudo", "host-sudo"},
		{"host key fills a target without one", "", "", sshclient.DefaultSudoKey},
		{"explicit caller key fills a target without one", "explicit-sudo", "", "explicit-sudo"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := SudoKeyForTarget(test.policyKey, test.targetKey); got != test.want {
				t.Fatalf("SudoKeyForTarget(%q, %q) = %q, want %q", test.policyKey, test.targetKey, got, test.want)
			}
		})
	}
}
