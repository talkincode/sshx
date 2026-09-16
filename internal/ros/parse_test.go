package ros

import (
	"reflect"
	"testing"
)

func TestParseColonRecord(t *testing.T) {
	output := `
                   uptime: 1w3d4h20m
                  version: 7.14.3 (stable)
               build-time: Apr/18/2024 10:00:00
              free-memory: 245.2MiB
             total-memory: 256.0MiB
                cpu-count: 1
                 cpu-load: 5%
`
	res, ok := ParseRouterOSOutput(output)
	if !ok {
		t.Fatalf("expected colon record parsing to succeed")
	}

	record, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", res)
	}

	if record["version"] != "7.14.3 (stable)" {
		t.Errorf("expected version, got %v", record["version"])
	}
	if record["cpu-count"] != int64(1) {
		t.Errorf("expected cpu-count 1, got %v", record["cpu-count"])
	}
}

func TestParseItemRecords(t *testing.T) {
	output := `Flags: X - disabled, I - invalid, D - dynamic 
 0   ;;; defconf
     address=192.168.88.1/24 network=192.168.88.0 interface=bridge 
     actual-interface=bridge 

 1 D address=10.0.0.2/24 network=10.0.0.0 interface=ether1 
     actual-interface=ether1 
`
	res, ok := ParseRouterOSOutput(output)
	if !ok {
		t.Fatalf("expected item records parsing to succeed")
	}

	items, ok := res.([]map[string]any)
	if !ok {
		t.Fatalf("expected []map[string]any, got %T", res)
	}

	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	if items[0]["comment"] != "defconf" {
		t.Errorf("item 0 comment: got %v", items[0]["comment"])
	}
	if items[0]["address"] != "192.168.88.1/24" {
		t.Errorf("item 0 address: got %v", items[0]["address"])
	}
	if items[0]["interface"] != "bridge" {
		t.Errorf("item 0 interface: got %v", items[0]["interface"])
	}

	if items[1]["flags"] != "D" {
		t.Errorf("item 1 flags: got %v", items[1]["flags"])
	}
	if items[1]["address"] != "10.0.0.2/24" {
		t.Errorf("item 1 address: got %v", items[1]["address"])
	}
}

func TestParseJSONOutput(t *testing.T) {
	jsonStr := `[{"address":"192.168.88.1/24","interface":"bridge"}]`
	res, ok := ParseRouterOSOutput(jsonStr)
	if !ok {
		t.Fatalf("expected JSON parsing to succeed")
	}

	slice, ok := res.([]any)
	if !ok || len(slice) != 1 {
		t.Fatalf("expected []any of length 1, got %v", reflect.TypeOf(res))
	}
}
