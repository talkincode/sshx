package app

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/talkincode/sshx/internal/execution"
	pluginpkg "github.com/talkincode/sshx/internal/plugin"
	"github.com/talkincode/sshx/internal/sshclient"
)

func localRiskDocument(t *testing.T, emit func() error) map[string]json.RawMessage {
	t.Helper()
	var emitErr error
	raw := captureStdout(t, func() { emitErr = emit() })
	if emitErr != nil {
		t.Fatalf("emit local result: %v", emitErr)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode local result: %v: %s", err, raw)
	}
	return document
}

func assertLocalRiskDocument(t *testing.T, document map[string]json.RawMessage, mode, action string) {
	t.Helper()
	risk, effects, ok := execution.ClassifyLocalRisk(mode, action)
	if !ok {
		t.Fatalf("test action has no local risk classification: %s/%s", mode, action)
	}
	var gotRisk execution.Risk
	if err := json.Unmarshal(document["risk"], &gotRisk); err != nil {
		t.Fatal(err)
	}
	var gotEffects execution.Effects
	if err := json.Unmarshal(document["effects"], &gotEffects); err != nil {
		t.Fatal(err)
	}
	if gotRisk != risk || gotEffects != effects || gotEffects.RemoteWrite {
		t.Fatalf("local result risk = %s %+v, want %s %+v", gotRisk, gotEffects, risk, effects)
	}
	for _, key := range []string{"execution_id", "execution_fingerprint", "verified", "executed", "change_state"} {
		if _, exists := document[key]; exists {
			t.Fatalf("risk-only projection must not claim %s", key)
		}
	}
}

func TestLocalManagementJSONEmittersPreserveLegacyEnvelopes(t *testing.T) {
	for _, tt := range []struct {
		mode, actions string
	}{
		{"host", "add update import remove"},
		{"password", "set delete check list"},
		{"plugin", "create trust remove list show validate test"},
		{"skill", "install"},
	} {
		for _, action := range strings.Fields(tt.actions) {
			for _, success := range []bool{false, true} {
				name := tt.mode + "/" + action + "/failure"
				if success {
					name = tt.mode + "/" + action + "/success"
				}
				t.Run(name, func(t *testing.T) {
					document := localRiskDocument(t, func() error {
						config := &sshclient.Config{JSONOutput: true}
						switch tt.mode {
						case "host":
							return emitHostActionJSON(hostActionJSON{Success: success, Action: action})
						case "password":
							return emitSecretsJSON(secretsJSONResult{Success: success, Action: action, Backend: "fixture"})
						case "plugin":
							return emitPluginResult(config, pluginpkg.ActionResult{Success: success, Action: action, PluginID: "demo"})
						default:
							return emitSkillResult(config, skillActionResult{Success: success, Action: action, Status: "current"})
						}
					})
					assertLocalRiskDocument(t, document, tt.mode, action)
					var gotSuccess bool
					if err := json.Unmarshal(document["success"], &gotSuccess); err != nil || gotSuccess != success {
						t.Fatalf("legacy success changed: %s, err=%v", document["success"], err)
					}
					if string(document["action"]) != `"`+action+`"` {
						t.Fatalf("legacy action changed: %s", document["action"])
					}
					switch tt.mode {
					case "host":
						if string(document["schema_version"]) != `"sshx.hosts.v1"` {
							t.Fatalf("host schema changed: %s", document["schema_version"])
						}
					case "password":
						if string(document["schema_version"]) != `"sshx.secrets.v1"` || string(document["backend"]) != `"fixture"` {
							t.Fatal("secret schema or backend changed")
						}
					case "plugin", "skill":
						if _, exists := document["schema_version"]; exists {
							t.Fatal("legacy unversioned envelope must not acquire a different schema claim")
						}
					}
				})
			}
		}
	}
}

func TestLocalHostListPreservesLegacyShape(t *testing.T) {
	document := localRiskDocument(t, func() error { return printHostListJSON(nil) })
	assertLocalRiskDocument(t, document, "host", "list")
	if string(document["hosts"]) != "[]" || string(document["count"]) != "0" ||
		string(document["schema_version"]) != `"sshx.hosts.v1"` {
		t.Fatalf("host-list shape changed: %+v", document)
	}
	if _, exists := document["success"]; exists {
		t.Fatal("host-list must retain its legacy shape without success")
	}
}

func TestLocalManagementProjectionExcludesRemoteAndUnknownActions(t *testing.T) {
	for _, action := range []string{"test", "test-all", "unknown"} {
		document := localRiskDocument(t, func() error {
			return emitHostActionJSON(hostActionJSON{Action: action, Success: false})
		})
		for _, key := range []string{"risk", "effects"} {
			if _, exists := document[key]; exists {
				t.Fatalf("host %s must not claim local-only %s", action, key)
			}
		}
	}
}

func TestLocalManagementJSONAuditRiskParity(t *testing.T) {
	for _, mode := range []string{"host", "password", "plugin", "skill"} {
		t.Run(mode, func(t *testing.T) {
			setTestHome(t, t.TempDir())
			withAppVault(t)
			t.Setenv("SSHX_NO_AUDIT", "false")
			auditDir := filepath.Join(t.TempDir(), "audit")
			var args []string
			action := ""
			switch mode {
			case "host":
				args = []string{"sshx", "--host-add", "--host-name=local-risk", "--host=192.0.2.1"}
				action = "add"
			case "password":
				args = []string{"sshx", "--password-set=local-risk:local-risk-test-value"}
				action = "set"
			case "plugin":
				args = []string{"sshx", "plugin", "create", "local-risk"}
				action = "create"
			case "skill":
				args = []string{"sshx", "skill", "install", "--dir=" + t.TempDir()}
				action = "install"
			}
			args = append(args, "--json", "--audit-output="+auditDir)
			document := localRiskDocument(t, func() error { return Run(args) })
			assertLocalRiskDocument(t, document, mode, action)
			event := readSingleAuditEvent(t, auditDir)
			var effects execution.Effects
			if err := json.Unmarshal(document["effects"], &effects); err != nil {
				t.Fatal(err)
			}
			var risk string
			if err := json.Unmarshal(document["risk"], &risk); err != nil {
				t.Fatal(err)
			}
			eventEffects, err := json.Marshal(event["effects"])
			if err != nil {
				t.Fatal(err)
			}
			var audited execution.Effects
			if decodeErr := json.Unmarshal(eventEffects, &audited); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if event["risk"] != risk || !reflect.DeepEqual(effects, audited) ||
				event["would_write_local_state"] != true || event["would_mutate_remote"] != false {
				t.Fatalf("local JSON/audit risk mismatch: result=%s %s audit=%+v", document["risk"], document["effects"], event)
			}
			outcome, ok := event["outcome"].(map[string]any)
			if !ok || outcome["status"] != "success" {
				t.Fatalf("legacy audit status changed: %+v", event["outcome"])
			}
		})
	}
}

func TestLocalManagementHumanEmittersUnchanged(t *testing.T) {
	var emitErr error
	pluginOutput := captureStdout(t, func() {
		emitErr = emitPluginResult(&sshclient.Config{}, pluginpkg.ActionResult{
			Action: "create", PluginID: "demo", Path: "/plugins/demo",
		})
	})
	if emitErr != nil || string(pluginOutput) != "plugin create: demo (/plugins/demo)\n" {
		t.Fatalf("plugin human output changed: %q err=%v", pluginOutput, emitErr)
	}
	skillOutput := captureStdout(t, func() {
		emitErr = emitSkillResult(&sshclient.Config{}, skillActionResult{Status: "current", Path: "/skills/demo"})
	})
	if emitErr != nil || string(skillOutput) != "Agent skill is current: /skills/demo\n" {
		t.Fatalf("skill human output changed: %q err=%v", skillOutput, emitErr)
	}
}
