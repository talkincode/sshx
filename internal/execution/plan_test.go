package execution

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlanCanonicalSerialization(t *testing.T) {
	plan := Plan{Action: "command", Risk: RiskRead, Inputs: map[string]string{"z": "last", "a": "<&"},
		Targets: []PlanTarget{{Role: "target", Address: "127.0.0.1", Port: "22", User: "worker"}}}
	require.NoError(t, plan.Seal())
	raw, err := plan.CanonicalBytes()
	require.NoError(t, err)
	require.JSONEq(t, `{"schema_version":"sshx.plan.v1","semantics":"sshx.execution.v1","action":"command","targets":[{"role":"target","address":"127.0.0.1","port":"22","user":"worker"}],"inputs":{"a":"<&","z":"last"},"risk":"read","effects":{"unknown":false,"remote_write":false,"local_write":false,"privileged":false,"destructive":false}}`, string(raw))
	require.Contains(t, string(raw), `"inputs":{"a":"\u003c\u0026","z":"last"}`)
	before := plan.PlanHash
	plan.Inputs = map[string]string{"a": "<&", "z": "last"}
	require.NoError(t, plan.Seal())
	require.Equal(t, before, plan.PlanHash)
	require.NoError(t, plan.CheckExpected(before))
	require.Equal(t, "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		Digest([]byte("abc")))
}

func TestPlanChangedInputsAndUnresolvedIdentity(t *testing.T) {
	original := Plan{Action: "apply", Risk: RiskMutation, Inputs: map[string]string{"payload": "a"},
		Targets: []PlanTarget{{Role: "target", Address: "127.0.0.1", Port: "22", User: "worker"}}}
	require.NoError(t, original.Seal())
	for name, mutate := range map[string]func(*Plan){
		"payload":    func(p *Plan) { p.Inputs["payload"] = "b" },
		"target":     func(p *Plan) { p.Targets[0].Address = "127.0.0.2" },
		"user":       func(p *Plan) { p.Targets[0].User = "root" },
		"credential": func(p *Plan) { p.Targets[0].SSHPasswordKey = "other" },
		"trust":      func(p *Plan) { p.Targets[0].TrustSHA256 = "other" },
		"bypass":     func(p *Plan) { p.Inputs["force"] = "true" },
		"risk":       func(p *Plan) { p.Risk = RiskPrivileged },
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(original)
			require.NoError(t, err)
			var changed Plan
			require.NoError(t, json.Unmarshal(raw, &changed))
			mutate(&changed)
			require.NoError(t, changed.Seal())
			var boundary *BoundaryError
			require.ErrorAs(t, changed.CheckExpected(original.PlanHash), &boundary)
			require.Equal(t, "plan_mismatch", boundary.Kind)
		})
	}
	original.Unresolved = []string{"missing public identity"}
	require.NoError(t, original.Seal())
	var boundary *BoundaryError
	require.True(t, errors.As(original.CheckExpected(original.PlanHash), &boundary))
	require.Equal(t, "plan_unresolved", boundary.Kind)
	require.NoError(t, original.CheckExpected(""))
	for _, input := range []string{"a", "sha256:", "sha256:" + string(make([]byte, 64))} {
		require.Error(t, ValidatePlanHash(input))
	}
}

func TestExecutionFingerprintIgnoresPresentationAndChangesWithEvidence(t *testing.T) {
	plan := Plan{Action: "apply", Risk: RiskMutation}
	require.NoError(t, plan.Seal())
	a := NewMetadata(&plan, "run-one")
	a.ChangeState, a.Verified, a.Verification = "changed", true, "passed"
	a.Finish("succeeded", "complete", CompletionCompleted, 0, "")
	b := a
	b.StartedAt = "different"
	b.Finish("succeeded", "complete", CompletionCompleted, 0, "")
	require.Equal(t, a.ExecutionFingerprint, b.ExecutionFingerprint)
	b.Verified = false
	b.Finish("failed", "verify", CompletionCompleted, -1, "verification_failed")
	require.NotEqual(t, a.ExecutionFingerprint, b.ExecutionFingerprint)
}
