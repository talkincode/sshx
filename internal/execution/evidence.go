package execution

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

type Condition struct {
	Kind     string `json:"kind"`
	Subject  string `json:"subject,omitempty"`
	Expected string `json:"expected,omitempty"`
	Observed string `json:"observed,omitempty"`
	Status   string `json:"status"`
}

type PeerIdentity struct {
	Role               string `json:"role"`
	Address            string `json:"address,omitempty"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	AuthMethod         string `json:"auth_method,omitempty"`
	User               string `json:"user,omitempty"`
	SSHPasswordKey     string `json:"ssh_password_key,omitempty"`
	SudoPasswordKey    string `json:"sudo_password_key,omitempty"`
}

type Metadata struct {
	PlanHash             string         `json:"plan_hash,omitempty"`
	Risk                 Risk           `json:"risk,omitempty"`
	Effects              Effects        `json:"effects"`
	ExecutionID          string         `json:"execution_id,omitempty"`
	ParentExecutionID    string         `json:"parent_execution_id,omitempty"`
	ExecutionFingerprint string         `json:"execution_fingerprint,omitempty"`
	TargetFingerprints   []string       `json:"target_fingerprints,omitempty"`
	Peers                []PeerIdentity `json:"peers,omitempty"`
	CancellationCause    string         `json:"cancellation_cause,omitempty"`
	DeadlineScope        string         `json:"deadline_scope,omitempty"`
	StartedAt            string         `json:"started_at,omitempty"`
	FinishedAt           string         `json:"finished_at,omitempty"`
	ChangeState          string         `json:"change_state"`
	Executed             *bool          `json:"executed"`
	Verified             bool           `json:"verified"`
	Verification         string         `json:"verification"`
	Preconditions        []Condition    `json:"preconditions,omitempty"`
	Postconditions       []Condition    `json:"postconditions,omitempty"`
}

type deadlineScopeKey struct{}

// WithScopedTimeout keeps the scope of the earliest effective deadline.
func WithScopedTimeout(parent context.Context, timeout time.Duration, scope string) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(timeout)
	if prior, ok := parent.Deadline(); !ok || deadline.Before(prior) {
		parent = context.WithValue(parent, deadlineScopeKey{}, scope)
	}
	return context.WithDeadline(parent, deadline)
}

func (m *Metadata) ObserveContext(ctx context.Context) {
	if ctx == nil || ctx.Err() == nil {
		return
	}
	if ctx.Err() == context.DeadlineExceeded {
		m.CancellationCause = "deadline_exceeded"
		if scope, ok := ctx.Value(deadlineScopeKey{}).(string); ok {
			m.DeadlineScope = scope
		}
	} else {
		m.CancellationCause = ErrorKindCancelled
	}
}

func NewMetadata(plan *Plan, id string) Metadata {
	m := Metadata{
		ExecutionID: id, StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ChangeState: "unknown", Verification: "not_performed",
	}
	if plan != nil {
		m.PlanHash, m.Risk, m.Effects = plan.PlanHash, plan.Risk, plan.Effects
	}
	return m
}

// Finish hashes redacted outcome facts, never stdout, stderr or raw errors.
func (m *Metadata) Finish(status, phase, completion string, exitCode int, errorKind string) {
	m.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if len(m.TargetFingerprints) > 0 {
		m.TargetFingerprints = append([]string(nil), m.TargetFingerprints...)
		sort.Strings(m.TargetFingerprints)
	}
	if completion == CompletionNotStarted {
		no := false
		m.Executed = &no
		m.ChangeState = "unchanged"
	} else if completion == CompletionCompleted && m.Executed == nil {
		yes := true
		m.Executed = &yes
	}
	facts := struct {
		Metadata
		Version    string `json:"fingerprint_version"`
		Status     string `json:"status"`
		Phase      string `json:"phase"`
		Completion string `json:"completion"`
		ExitCode   int    `json:"exit_code"`
		ErrorKind  string `json:"error_kind,omitempty"`
	}{*m, "sshx.execution.v1", status, phase, completion, exitCode, errorKind}
	facts.ExecutionFingerprint = ""
	facts.StartedAt, facts.FinishedAt = "", ""
	// This projection contains no values with fallible JSON encodings.
	data, err := json.Marshal(facts)
	if err != nil {
		panic(err)
	}
	m.ExecutionFingerprint = Digest(data)
}
