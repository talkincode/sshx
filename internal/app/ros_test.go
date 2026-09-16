package app

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/talkincode/sshx/internal/sshclient"
)

func rosCaptureStdout(f func() error) (string, error) {
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		return "", pipeErr
	}
	os.Stdout = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r) //nolint:errcheck // fixture buffer copy
		outC <- buf.String()
	}()

	err := f()
	_ = w.Close() //nolint:errcheck // fixture pipe close
	os.Stdout = oldStdout
	out := <-outC
	return out, err
}

func TestParseROSArgs(t *testing.T) {
	config := &sshclient.Config{}
	args := []string{
		"-h=192.168.88.1",
		"-p=2222",
		"-u=custom_admin",
		"--json",
		"--dry-run",
		"--allow-write",
		"--force",
		"--raw",
		"--cleanup",
		"--compact",
		"--source=@./setup.rsc",
		"ip", "address", "print", "detail",
	}

	parseROSArgs(config, args)

	if config.Mode != "ros" {
		t.Errorf("expected Mode=ros, got %s", config.Mode)
	}
	if config.Host != "192.168.88.1" {
		t.Errorf("expected Host 192.168.88.1, got %s", config.Host)
	}
	if config.Port != "2222" {
		t.Errorf("expected Port 2222, got %s", config.Port)
	}
	if config.User != "custom_admin" {
		t.Errorf("expected User custom_admin, got %s", config.User)
	}
	if !config.JSONOutput {
		t.Errorf("expected JSONOutput=true")
	}
	if !config.DryRun {
		t.Errorf("expected DryRun=true")
	}
	if !config.ROSAllowWrite {
		t.Errorf("expected ROSAllowWrite=true")
	}
	if !config.Force {
		t.Errorf("expected Force=true")
	}
	if !config.ROSRaw {
		t.Errorf("expected ROSRaw=true")
	}
	if !config.ROSCleanup {
		t.Errorf("expected ROSCleanup=true")
	}
	if !config.ROSCompact {
		t.Errorf("expected ROSCompact=true")
	}
	if config.ROSSource != "./setup.rsc" {
		t.Errorf("expected ROSSource ./setup.rsc, got %s", config.ROSSource)
	}
	expectedTokens := []string{"ip", "address", "print", "detail"}
	if len(config.ROSTokens) != len(expectedTokens) {
		t.Fatalf("expected tokens %v, got %v", expectedTokens, config.ROSTokens)
	}
	for i := range expectedTokens {
		if config.ROSTokens[i] != expectedTokens[i] {
			t.Errorf("token %d: expected %s, got %s", i, expectedTokens[i], config.ROSTokens[i])
		}
	}
}

func TestHandleROS_Introspection(t *testing.T) {
	// 1. commands --json
	out, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "commands", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var cmdsPayload map[string]any
	if uErr := json.Unmarshal([]byte(out), &cmdsPayload); uErr != nil {
		t.Fatalf("invalid JSON for commands: %v\nOutput was: %s", uErr, out)
	}
	if cmdsPayload["schema_version"] != "roswire.commands.v1" {
		t.Errorf("expected schema_version roswire.commands.v1, got %v", cmdsPayload["schema_version"])
	}

	// 2. help --json
	outHelp, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "help", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var helpPayload map[string]any
	if uErr := json.Unmarshal([]byte(outHelp), &helpPayload); uErr != nil {
		t.Fatalf("invalid JSON for help: %v\nOutput: %s", uErr, outHelp)
	}
	if helpPayload["schema_version"] != "roswire.help.index.v1" {
		t.Errorf("expected schema_version roswire.help.index.v1, got %v", helpPayload["schema_version"])
	}

	// 3. help ip address add --json
	outHelpCmd, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "help", "ip", "address", "add", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var helpCmdPayload map[string]any
	if uErr := json.Unmarshal([]byte(outHelpCmd), &helpCmdPayload); uErr != nil {
		t.Fatalf("invalid JSON for help command: %v", uErr)
	}
	if helpCmdPayload["schema_version"] != "roswire.help.command.v1" {
		t.Errorf("expected schema_version roswire.help.command.v1, got %v", helpCmdPayload["schema_version"])
	}

	// 4. schema ip address add --json
	outSchema, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "schema", "ip", "address", "add", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var schemaPayload map[string]any
	if uErr := json.Unmarshal([]byte(outSchema), &schemaPayload); uErr != nil {
		t.Fatalf("invalid JSON for schema: %v", uErr)
	}
	if schemaPayload["schema_version"] != "roswire.schema.v1" {
		t.Errorf("expected schema_version roswire.schema.v1, got %v", schemaPayload["schema_version"])
	}

	// 5. explain-error USAGE_ERROR --json
	outExplain, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "explain-error", "USAGE_ERROR", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var explainPayload map[string]any
	if uErr := json.Unmarshal([]byte(outExplain), &explainPayload); uErr != nil {
		t.Fatalf("invalid JSON for explain-error: %v", uErr)
	}
	if explainPayload["schema_version"] != "roswire.explain_error.v1" {
		t.Errorf("expected schema_version roswire.explain_error.v1, got %v", explainPayload["schema_version"])
	}

	// 6. doctor --json
	outDoctor, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "doctor", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doctorPayload map[string]any
	if uErr := json.Unmarshal([]byte(outDoctor), &doctorPayload); uErr != nil {
		t.Fatalf("invalid JSON for doctor: %v", uErr)
	}
	if doctorPayload["schema_version"] != "roswire.doctor.v1" {
		t.Errorf("expected schema_version roswire.doctor.v1, got %v", doctorPayload["schema_version"])
	}

	// 7. help raw --json
	outHelpRaw, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "help", "raw", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var helpRawPayload map[string]any
	if uErr := json.Unmarshal([]byte(outHelpRaw), &helpRawPayload); uErr != nil {
		t.Fatalf("invalid JSON for help raw: %v", uErr)
	}
	if helpRawPayload["schema_version"] != "roswire.help.command.v1" {
		t.Errorf("expected schema_version roswire.help.command.v1, got %v", helpRawPayload["schema_version"])
	}

	// 8. schema command raw --json
	outSchemaRaw, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "schema", "command", "raw", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var schemaRawPayload map[string]any
	if err := json.Unmarshal([]byte(outSchemaRaw), &schemaRawPayload); err != nil {
		t.Fatalf("invalid JSON for schema raw: %v", err)
	}
	if schemaRawPayload["command"] != "raw" {
		t.Errorf("expected command 'raw', got %v", schemaRawPayload["command"])
	}
}

func TestHandleROS_DryRun(t *testing.T) {
	// 1. Read command dry-run
	out, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "-h=192.168.88.1", "ip", "address", "print", "--dry-run", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var plan map[string]any
	if uErr := json.Unmarshal([]byte(out), &plan); uErr != nil {
		t.Fatalf("invalid JSON plan: %v\nOutput was: %s", uErr, out)
	}
	if plan["schema_version"] != "roswire.command.plan.v1" {
		t.Errorf("expected schema_version roswire.command.plan.v1, got %v", plan["schema_version"])
	}
	modifyKey := "will_modify_routeros" //nolint:misspell // RouterOS domain key
	if plan[modifyKey] != false {
		t.Errorf("expected %s=false for print, got %v", modifyKey, plan[modifyKey])
	}

	// 2. Write command dry-run
	outWrite, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "-h=192.168.88.1", "ip", "address", "add", "address=192.168.88.1/24", "interface=ether1", "--dry-run", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var planWrite map[string]any
	if uErr := json.Unmarshal([]byte(outWrite), &planWrite); uErr != nil {
		t.Fatalf("invalid JSON plan: %v", uErr)
	}
	if planWrite[modifyKey] != true {
		t.Errorf("expected %s=true for add, got %v", modifyKey, planWrite[modifyKey])
	}

	// 3. Workflow dry-run
	outWf, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "-h=192.168.88.1", "file", "upload", "local.rsc", "flash/local.rsc", "--dry-run", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var planWf map[string]any
	if uErr := json.Unmarshal([]byte(outWf), &planWf); uErr != nil {
		t.Fatalf("invalid JSON plan: %v", uErr)
	}
	if planWf["operation"] != "file_upload" {
		t.Errorf("expected operation file_upload, got %v", planWf["operation"])
	}
	if planWf["transfer_backend"] != "ssh" {
		t.Errorf("expected transfer_backend ssh, got %v", planWf["transfer_backend"])
	}

	// 4. Raw command dry-run
	outRaw, err := rosCaptureStdout(func() error {
		cfg := ParseArgs([]string{"sshx", "ros", "-h=192.168.88.1", "raw", "/system/resource/print", "--dry-run", "--json"})
		return HandleROS(cfg, nil)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var planRaw map[string]any
	if err := json.Unmarshal([]byte(outRaw), &planRaw); err != nil {
		t.Fatalf("invalid JSON plan: %v", err)
	}
	if planRaw["action"] != "raw" || planRaw["routeros_path"] != "/system/resource/print" { //nolint:misspell // RouterOS domain key
		t.Errorf("expected raw plan, got %+v", planRaw)
	}
}

func TestHandleROS_Safety(t *testing.T) {
	// Dangerous command blocked without force
	cfg := ParseArgs([]string{"sshx", "ros", "-h=192.168.88.1", "raw", "/system/reset-configuration", "--json"})
	err := HandleROS(cfg, nil)
	if err == nil {
		t.Fatalf("expected dangerous command to be blocked")
	}
	// With JSON output, ErrReported is returned
	if !strings.Contains(err.Error(), "result already reported") && !strings.Contains(err.Error(), "dangerous RouterOS command blocked") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBuildROSArgs(t *testing.T) {
	in := mcpROSInput{
		Target:            "192.168.88.1",
		Port:              2222,
		User:              "admin",
		Command:           "ip address print detail",
		AllowWrite:        true,
		DryRun:            true,
		RouterOSVersion:   "v7",
		GlobalTimeoutSecs: 30,
	}

	args, err := buildROSArgs(in)
	if err != nil {
		t.Fatalf("unexpected error building ROS args: %v", err)
	}

	expectedPrefix := []string{
		"ros",
		"--json",
		"-h=192.168.88.1",
		"-p=2222",
		"-u=admin",
		"--allow-write",
		"--dry-run",
		"--routeros-version=v7", //nolint:misspell // RouterOS CLI flag
		"--timeout=30s",
		"ip",
		"address",
		"print",
		"detail",
	}

	if len(args) != len(expectedPrefix) {
		t.Fatalf("expected args length %d, got %d (%v)", len(expectedPrefix), len(args), args)
	}
	for i := range expectedPrefix {
		if args[i] != expectedPrefix[i] {
			t.Errorf("arg %d: expected %s, got %s", i, expectedPrefix[i], args[i])
		}
	}
}
