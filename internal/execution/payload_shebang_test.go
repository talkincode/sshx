package execution

import (
	"strings"
	"testing"
)

func TestParseShebang(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"no shebang", "echo hi\n", ""},
		{"absolute bash", "#!/bin/bash\nset -o pipefail\n", "bash"},
		{"absolute sh", "#!/bin/sh\nset -eu\n", "sh"},
		{"usr bin bash", "#!/usr/bin/bash\n", "bash"},
		{"env bash", "#!/usr/bin/env bash\nset -o pipefail\n", "bash"},
		{"env with option", "#!/usr/bin/env -S bash -e\n", "bash"},
		{"env with assignment", "#!/usr/bin/env LC_ALL=C bash\n", "bash"},
		{"env alone", "#!/usr/bin/env\n", ""},
		{"zsh", "#!/bin/zsh\n", "zsh"},
		{"python", "#!/usr/bin/env python3\nprint(1)\n", "python3"},
		{"shebang with args", "#!/bin/bash -e\n", "bash"},
		{"crlf line ending", "#!/bin/bash\r\necho hi\r\n", "bash"},
		{"only shebang line", "#!/bin/bash", "bash"},
		{"hash but not shebang", "# not a shebang\n", ""},
		{"too short", "#!", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseShebang([]byte(tt.body)); got != tt.want {
				t.Errorf("parseShebang(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

func TestDigestPayloadCapturesShebang(t *testing.T) {
	p, err := digestPayload([]byte("#!/usr/bin/env bash\nset -o pipefail\n"), DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	if p.Shebang != "bash" {
		t.Errorf("Shebang = %q, want bash", p.Shebang)
	}
	if p.Size == 0 || p.SHA256 == "" {
		t.Error("payload digest metadata missing")
	}
}

// A bash script must not be silently executed by sh: `set -o pipefail` fails
// with "Illegal option -o pipefail" under dash/ash, which is a confusing
// remote-exit failure rather than a clear local one.
func TestNormalizeRequestAcceptsShellFamilyRunners(t *testing.T) {
	for _, runner := range []string{"sh", "bash", "zsh", "dash", "ksh", "ash"} {
		t.Run(runner, func(t *testing.T) {
			req := scriptRequest(runner)
			if err := NormalizeRequest(req); err != nil {
				t.Fatalf("runner %q should be accepted: %v", runner, err)
			}
			if req.Action.ScriptRunner != runner {
				t.Errorf("ScriptRunner = %q, want %q", req.Action.ScriptRunner, runner)
			}
		})
	}
}

func TestNormalizeRequestRejectsUnsupportedRunner(t *testing.T) {
	req := scriptRequest("python3")
	err := NormalizeRequest(req)
	if err == nil {
		t.Fatal("expected an error for an unsupported script runner")
	}
	if !strings.Contains(err.Error(), "unsupported script runner") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNormalizeRequestDefaultsRunnerToSh(t *testing.T) {
	req := scriptRequest("")
	if err := NormalizeRequest(req); err != nil {
		t.Fatal(err)
	}
	if req.Action.ScriptRunner != ScriptRunnerSH {
		t.Errorf("ScriptRunner = %q, want sh", req.Action.ScriptRunner)
	}
}

func scriptRequest(runner string) *Request {
	return &Request{
		SchemaVersion: RequestSchemaVersion,
		Targets:       TargetSelector{Names: []string{"host-a"}},
		Action: ActionSpec{
			Kind:         ActionScript,
			Intent:       IntentRead,
			ScriptPath:   "/tmp/script.sh",
			ScriptRunner: runner,
		},
		Policy: Policy{SafetyCheckEnabled: true},
	}
}
