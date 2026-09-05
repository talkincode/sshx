package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const PlanSchemaVersion = "sshx.plan.v1"

// BoundaryError has a stable machine category independent of diagnostic text.
type BoundaryError struct {
	Kind    string
	Message string
}

func (e *BoundaryError) Error() string     { return e.Message }
func (e *BoundaryError) ErrorKind() string { return e.Kind }

type PlanTarget struct {
	Role           string `json:"role"`
	Alias          string `json:"alias,omitempty"`
	Address        string `json:"address"`
	Port           string `json:"port"`
	User           string `json:"user"`
	Bind           string `json:"bind,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	TrustSHA256    string `json:"trust_sha256,omitempty"`
	SSHPasswordKey string `json:"ssh_password_key,omitempty"`
	SudoKey        string `json:"sudo_key,omitempty"`
}

// Plan contains public semantic inputs only. Payloads and credentials are
// held separately by the caller and must not be reconstructed from this view.
type Plan struct {
	SchemaVersion string            `json:"schema_version"`
	Semantics     string            `json:"semantics"`
	Action        string            `json:"action"`
	Targets       []PlanTarget      `json:"targets"`
	Inputs        map[string]string `json:"inputs"`
	Risk          Risk              `json:"risk"`
	Effects       Effects           `json:"effects"`
	Bindable      bool              `json:"bindable"`
	Unresolved    []string          `json:"unresolved,omitempty"`
	PlanHash      string            `json:"plan_hash"`
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CanonicalBytes excludes display metadata and the digest itself. Go's JSON
// encoder sorts string map keys; target order is normalized by Seal.
func (p Plan) CanonicalBytes() ([]byte, error) {
	return json.Marshal(struct {
		SchemaVersion string            `json:"schema_version"`
		Semantics     string            `json:"semantics"`
		Action        string            `json:"action"`
		Targets       []PlanTarget      `json:"targets"`
		Inputs        map[string]string `json:"inputs"`
		Risk          Risk              `json:"risk"`
		Effects       Effects           `json:"effects"`
	}{
		p.SchemaVersion, p.Semantics, p.Action, p.Targets, p.Inputs, p.Risk, p.Effects,
	})
}

func (p *Plan) Seal() error {
	p.SchemaVersion = PlanSchemaVersion
	p.Semantics = "sshx.execution.v1"
	if p.Inputs == nil {
		p.Inputs = map[string]string{}
	}
	if p.Targets == nil {
		p.Targets = []PlanTarget{}
	}
	sort.Slice(p.Targets, func(i, j int) bool {
		a, b := p.Targets[i], p.Targets[j]
		return strings.Join([]string{a.Role, a.Alias, a.Address, a.Port, a.User}, "\x00") <
			strings.Join([]string{b.Role, b.Alias, b.Address, b.Port, b.User}, "\x00")
	})
	sort.Strings(p.Unresolved)
	p.Bindable = len(p.Unresolved) == 0
	raw, err := p.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("serialize execution plan: %w", err)
	}
	p.PlanHash = Digest(raw)
	return nil
}

func ValidatePlanHash(value string) error {
	if value == "" {
		return nil
	}
	raw := strings.TrimPrefix(value, "sha256:")
	if len(raw) != 64 || raw == value || strings.ToLower(raw) != raw {
		return &BoundaryError{Kind: "config", Message: "--expect-plan requires sha256: followed by 64 lowercase hex characters"}
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return &BoundaryError{Kind: "config", Message: "invalid --expect-plan digest"}
	}
	return nil
}

func (p Plan) CheckExpected(expected string) error {
	if err := ValidatePlanHash(expected); err != nil {
		return err
	}
	if expected == "" {
		return nil
	}
	if expected != p.PlanHash {
		return &BoundaryError{Kind: "plan_mismatch", Message: "execution inputs differ from the reviewed plan"}
	}
	if !p.Bindable {
		return &BoundaryError{Kind: "plan_unresolved", Message: "plan has unresolved identity: " + strings.Join(p.Unresolved, "; ")}
	}
	return nil
}
