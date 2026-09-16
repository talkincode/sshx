package ros

import (
	"testing"
)

func TestAllCommands(t *testing.T) {
	cmds := AllCommands()
	if len(cmds) == 0 {
		t.Fatal("expected non-empty static command catalog")
	}

	for _, cmd := range cmds {
		if len(cmd.CLIPath) == 0 {
			t.Errorf("command has empty CLI path")
		}
		if cmd.Action == "" {
			t.Errorf("command %v has empty action", cmd.CLIPath)
		}
		if cmd.RouterOSPath == "" {
			t.Errorf("command %v has empty ROS path", cmd.CLIPath)
		}
	}
}

func TestLookupCommand(t *testing.T) {
	tests := []struct {
		path   []string
		action string
		found  bool
	}{
		{[]string{"ip", "address"}, "print", true},
		{[]string{"ip", "address"}, "add", true},
		{[]string{"interface"}, "print", true},
		{[]string{"system", "resource"}, "print", true},
		{[]string{"raw"}, "raw", true},
		{[]string{"raw"}, "", true},
		{nil, "raw", true},
		{[]string{"command"}, "raw", true},
		{[]string{"unknown", "path"}, "print", false},
	}

	for _, tc := range tests {
		mapping, ok := LookupCommand(tc.path, tc.action)
		if ok != tc.found {
			t.Errorf("lookup %v %s: expected found=%v, got %v", tc.path, tc.action, tc.found, ok)
		}
		if tc.found && mapping == nil {
			t.Errorf("expected mapping not to be nil")
		}
	}
}

func TestParseInvocation(t *testing.T) {
	// 1. IP address print
	req, err := ParseInvocation([]string{"ip", "address", "print", "detail"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Action != "print" {
		t.Errorf("expected action print, got %s", req.Action)
	}
	if len(req.Flags) != 1 || req.Flags[0] != "detail" {
		t.Errorf("expected flags [detail], got %v", req.Flags)
	}

	cmdStr := BuildRouterOSCommand(req)
	if cmdStr != "/ip address print detail without-paging" {
		t.Errorf("expected '/ip address print detail without-paging', got %q", cmdStr)
	}

	// 2. IP address add
	reqAdd, err := ParseInvocation([]string{"ip", "address", "add", "address=192.168.88.1/24", "interface=ether1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqAdd.Args["address"] != "192.168.88.1/24" {
		t.Errorf("expected address arg, got %v", reqAdd.Args)
	}
	if reqAdd.Args["interface"] != "ether1" {
		t.Errorf("expected interface arg, got %v", reqAdd.Args)
	}

	// 3. Raw command
	reqRaw, err := ParseInvocation([]string{"raw", "/system/clock/print"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqRaw.Action != "raw" || reqRaw.RawCommand != "/system/clock/print" {
		t.Errorf("expected raw command, got %+v", reqRaw)
	}
	rawStr := BuildRouterOSCommand(reqRaw)
	if rawStr != "/system/clock/print without-paging" {
		t.Errorf("expected '/system/clock/print without-paging', got %q", rawStr)
	}

	// 4. Raw command with args and flags
	reqRawAdd, err := ParseInvocation([]string{"raw", "/ip/address/add", "address=10.0.0.1/24", "interface=ether2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqRawAdd.Args["address"] != "10.0.0.1/24" || reqRawAdd.Args["interface"] != "ether2" {
		t.Errorf("expected raw add args, got %+v", reqRawAdd.Args)
	}
	rawAddStr := BuildRouterOSCommand(reqRawAdd)
	if rawAddStr != "/ip/address/add address=10.0.0.1/24 interface=ether2" {
		t.Errorf("expected '/ip/address/add address=10.0.0.1/24 interface=ether2', got %q", rawAddStr)
	}
}
