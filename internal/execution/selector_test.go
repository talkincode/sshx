package execution

import (
	"errors"
	"testing"
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
