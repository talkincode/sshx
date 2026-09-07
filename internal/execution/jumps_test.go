package execution

import (
	"errors"
	"testing"
)

func jumpHosts() []HostRecord {
	return []HostRecord{
		{Name: "edge", Address: "10.0.0.1", Port: "22", User: "jump"},
		{Name: "mid", Address: "10.0.0.2", Port: "22", User: "jump", Via: "edge"},
		{Name: "app", Address: "10.0.0.3", Port: "22", User: "app", Via: "mid"},
		{Name: "loop-a", Address: "10.0.0.4", Port: "22", User: "app", Via: "loop-b"},
		{Name: "loop-b", Address: "10.0.0.5", Port: "22", User: "app", Via: "loop-a"},
		{Name: "deep1", Address: "10.0.1.1", Port: "22", User: "jump", Via: "deep2"},
		{Name: "deep2", Address: "10.0.1.2", Port: "22", User: "jump", Via: "deep3"},
		{Name: "deep3", Address: "10.0.1.3", Port: "22", User: "jump", Via: "deep4"},
		{Name: "deep4", Address: "10.0.1.4", Port: "22", User: "jump", Via: "deep5"},
		{Name: "deep5", Address: "10.0.1.5", Port: "22", User: "jump"},
		{Name: "self", Address: "10.0.1.9", Port: "22", User: "app", Via: "self"},
	}
}

func TestResolveJumps_Direct(t *testing.T) {
	got, err := ResolveJumps(jumpHosts(), ResolvedTarget{Alias: "edge", Address: "10.0.0.1", Via: ""}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Jumps != nil {
		t.Fatalf("direct host must have no jumps: %#v", got.Jumps)
	}
}

func TestResolveJumps_SingleHopOutermostFirst(t *testing.T) {
	got, err := ResolveJumps(jumpHosts(), ResolvedTarget{Alias: "app", Address: "10.0.0.3", Via: "mid"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Jumps) != 2 {
		t.Fatalf("expected edge->mid, got %#v", got.Jumps)
	}
	if got.Jumps[0].Alias != "edge" || got.Jumps[1].Alias != "mid" {
		t.Fatalf("outermost-first chain: %#v", got.Jumps)
	}
}

func TestResolveJumps_UnknownNamedHop(t *testing.T) {
	_, err := ResolveJumps(jumpHosts(), ResolvedTarget{Alias: "app", Via: "missing"}, nil)
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestResolveJumps_Cycle(t *testing.T) {
	_, err := ResolveJumps(jumpHosts(), ResolvedTarget{Alias: "loop-a", Via: "loop-b"}, nil)
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestResolveJumps_SelfVia(t *testing.T) {
	_, err := ResolveJumps(jumpHosts(), ResolvedTarget{Alias: "self", Via: "self"}, nil)
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestResolveJumps_DepthLimit(t *testing.T) {
	_, err := ResolveJumps(jumpHosts(), ResolvedTarget{Alias: "leaf", Address: "10.0.1.8", Via: "deep1"}, nil)
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestResolveJumps_OverrideClearsInventory(t *testing.T) {
	empty := ""
	got, err := ResolveJumps(jumpHosts(), ResolvedTarget{Alias: "app", Via: "mid"}, &empty)
	if err != nil {
		t.Fatal(err)
	}
	if got.Via != "" || got.Jumps != nil {
		t.Fatalf("empty override must force direct: %#v", got)
	}
}

func TestResolveJumps_OverrideReplacesInventory(t *testing.T) {
	via := "edge"
	got, err := ResolveJumps(jumpHosts(), ResolvedTarget{Alias: "app", Via: "mid"}, &via)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Jumps) != 1 || got.Jumps[0].Alias != "edge" {
		t.Fatalf("override should use edge only: %#v", got.Jumps)
	}
}
