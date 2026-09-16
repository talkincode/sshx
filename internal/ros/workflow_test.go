package ros

import (
	"strings"
	"testing"
)

func TestParseWorkflowCommand(t *testing.T) {
	// 1. File upload
	spec, ok := ParseWorkflowCommand([]string{"file", "upload", "setup.rsc", "flash/setup.rsc"}, "")
	if !ok || spec.Type != WorkflowFileUpload {
		t.Fatalf("expected file upload workflow, got %v", spec)
	}
	if spec.LocalPath != "setup.rsc" || spec.RemotePath != "flash/setup.rsc" {
		t.Errorf("unexpected paths: %+v", spec)
	}

	// 2. File download
	specDown, ok := ParseWorkflowCommand([]string{"file", "download", "flash/setup.rsc", "local.rsc"}, "")
	if !ok || specDown.Type != WorkflowFileDownload {
		t.Fatalf("expected file download workflow, got %v", specDown)
	}

	// 3. Import
	specImp, ok := ParseWorkflowCommand([]string{"import", "config.rsc"}, "")
	if !ok || specImp.Type != WorkflowImport {
		t.Fatalf("expected import workflow, got %v", specImp)
	}

	// 4. Script put
	specScript, ok := ParseWorkflowCommand([]string{"script", "put", "bootstrap"}, "@./local.rsc")
	if !ok || specScript.Type != WorkflowScriptPut {
		t.Fatalf("expected script put workflow, got %v", specScript)
	}
	if specScript.ScriptName != "bootstrap" || specScript.LocalPath != "./local.rsc" {
		t.Errorf("unexpected script spec: %+v", specScript)
	}
}

func TestRenderWorkflowPlanJSON(t *testing.T) {
	spec := &WorkflowSpec{
		Type:       WorkflowScriptPut,
		ScriptName: "my_script",
		LocalPath:  "/path/to/my_script.rsc",
	}

	jsonPlan, err := RenderWorkflowPlanJSON(spec)
	if err != nil {
		t.Fatalf("unexpected error rendering plan: %v", err)
	}

	if !strings.Contains(jsonPlan, "roswire.workflow.script.put.plan.v1") {
		t.Errorf("expected script put plan schema, got %s", jsonPlan)
	}
	if !strings.Contains(jsonPlan, "***REDACTED***/my_script.rsc") {
		t.Errorf("expected redacted local path, got %s", jsonPlan)
	}
}
