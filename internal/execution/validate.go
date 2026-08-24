package execution

import (
	"fmt"
	"strings"

	"github.com/talkincode/sshx/internal/sshclient"
)

// NormalizeRequest fills defaults and validates the internal request shape.
// It does not resolve hosts or read secrets.
func NormalizeRequest(req *Request) error {
	if req == nil {
		return fmt.Errorf("%w: request is nil", ErrConfig)
	}
	if req.SchemaVersion == "" {
		req.SchemaVersion = RequestSchemaVersion
	}
	if req.SchemaVersion != RequestSchemaVersion {
		return fmt.Errorf("%w: unsupported request schema %q", ErrConfig, req.SchemaVersion)
	}

	if req.Limits.Concurrency <= 0 {
		req.Limits.Concurrency = DefaultConcurrency
	}
	if req.Limits.Concurrency > MaxConcurrency {
		return fmt.Errorf("%w: concurrency %d exceeds hard maximum %d", ErrConfig, req.Limits.Concurrency, MaxConcurrency)
	}
	if req.Limits.MaxOutputBytesPerTarget <= 0 {
		req.Limits.MaxOutputBytesPerTarget = DefaultMaxOutput
	}
	if req.Limits.MaxPayloadBytes <= 0 {
		req.Limits.MaxPayloadBytes = DefaultMaxPayload
	}
	if req.Policy.FailureMode == "" {
		req.Policy.FailureMode = FailureContinue
	}
	switch req.Policy.FailureMode {
	case FailureContinue, FailureFailFast:
	default:
		return fmt.Errorf("%w: invalid failure mode %q", ErrConfig, req.Policy.FailureMode)
	}

	if req.Action.Kind == "" {
		return fmt.Errorf("%w: action kind is required", ErrConfig)
	}
	switch req.Action.Kind {
	case ActionCommand, ActionScript, ActionInspect, ActionSFTP, ActionTransfer:
	default:
		return fmt.Errorf("%w: unsupported action kind %q", ErrConfig, req.Action.Kind)
	}

	if req.Action.Intent == "" {
		req.Action.Intent = IntentUnknown
	}
	switch req.Action.Intent {
	case IntentRead, IntentChange, IntentUnknown:
	default:
		return fmt.Errorf("%w: invalid action intent %q", ErrConfig, req.Action.Intent)
	}

	sources := 0
	if strings.TrimSpace(req.Action.Command) != "" {
		sources++
	}
	if req.Action.ScriptPath != "" {
		sources++
	}
	if req.Action.ScriptFromStdin {
		sources++
	}
	switch req.Action.Kind {
	case ActionCommand:
		if strings.TrimSpace(req.Action.Command) == "" {
			return fmt.Errorf("%w: command action requires a command", ErrConfig)
		}
		if req.Action.ScriptPath != "" || req.Action.ScriptFromStdin {
			return fmt.Errorf("%w: command action cannot combine with script input", ErrConfig)
		}
	case ActionScript:
		if sources != 1 || strings.TrimSpace(req.Action.Command) != "" {
			// script must have exactly one of file/stdin and no command text
			n := 0
			if req.Action.ScriptPath != "" {
				n++
			}
			if req.Action.ScriptFromStdin {
				n++
			}
			if n != 1 {
				return fmt.Errorf("%w: script action requires exactly one of --script-file or --script-stdin", ErrConfig)
			}
			if strings.TrimSpace(req.Action.Command) != "" {
				return fmt.Errorf("%w: script action cannot combine with positional command input", ErrConfig)
			}
		}
		if req.Action.ScriptRunner == "" {
			req.Action.ScriptRunner = ScriptRunnerSH
		}
		if req.Action.ScriptRunner != ScriptRunnerSH {
			return fmt.Errorf("%w: unsupported script runner %q (required: sh)", ErrConfig, req.Action.ScriptRunner)
		}
	}

	if req.Policy.SafetyBypass || !req.Policy.SafetyCheckEnabled {
		if strings.TrimSpace(req.Policy.BypassReason) == "" {
			return fmt.Errorf("%w: safety bypass requires a non-empty --bypass-reason", ErrConfig)
		}
		req.Policy.SafetyBypass = true
		req.Policy.SafetyCheckEnabled = false
	}

	return nil
}

// SafetyCheck evaluates command/script safety without connecting.
func SafetyCheck(req *Request, payload []byte) error {
	if req.Policy.SafetyBypass || !req.Policy.SafetyCheckEnabled {
		return nil
	}
	switch req.Action.Kind {
	case ActionCommand:
		if err := sshclient.ValidateCommand(req.Action.Command); err != nil {
			return fmt.Errorf("%w: %v", ErrBlocked, err)
		}
	case ActionScript:
		// Best-effort scan of script text for the same destructive patterns.
		if err := sshclient.ValidateCommand(string(payload)); err != nil {
			return fmt.Errorf("%w: %v", ErrBlocked, err)
		}
	}
	return nil
}

// BuildDryRunPlan resolves selectors and reports effects without secrets/network.
func BuildDryRunPlan(req *Request, hosts []HostRecord, defaults HostRecord, payload *Payload) DryRunPlan {
	plan := DryRunPlan{
		SchemaVersion: RequestSchemaVersion,
		DryRun:        true,
		Valid:         true,
		RequestID:     req.RequestID,
		Action:        req.Action,
		Limits:        req.Limits,
		Policy:        PublicPolicy(req.Policy),
		Notes: []string{
			"dry-run does not connect, execute, read secrets, mutate known_hosts, or write local/remote state",
		},
	}

	if err := NormalizeRequest(req); err != nil {
		plan.Valid = false
		plan.Error = BuildError(err, ErrorKindConfig, req.Action.Intent, CompletionNotStarted)
		return plan
	}
	plan.Action = req.Action
	plan.Limits = req.Limits
	plan.Policy = PublicPolicy(req.Policy)

	if payload != nil {
		plan.Action.PayloadSHA256 = payload.SHA256
		plan.Action.PayloadBytes = payload.Size
	}

	snap, err := ResolveTargets(hosts, req.Targets, defaults)
	if err != nil {
		plan.Valid = false
		plan.Snapshot = snap
		plan.Error = BuildError(err, ErrorKindConfig, req.Action.Intent, CompletionNotStarted)
		return plan
	}
	plan.Snapshot = snap

	if err := SafetyCheck(req, payloadBytes(payload)); err != nil {
		plan.Valid = false
		plan.Error = BuildError(err, ErrorKindBlocked, req.Action.Intent, CompletionNotStarted)
		// still report resolved snapshot for inspection
	}

	plan.WouldConnect = plan.Valid && snap.Count > 0
	plan.WouldExecute = plan.WouldConnect
	plan.WouldReadSecret = plan.WouldConnect && wouldReadSecret(req, snap)
	plan.WouldMutateRemote = plan.WouldConnect && req.Action.Intent == IntentChange
	plan.MayMutateKnownHosts = plan.WouldConnect && req.Policy.AcceptUnknownHost
	plan.WouldWriteLocal = false
	return plan
}

func payloadBytes(p *Payload) []byte {
	if p == nil {
		return nil
	}
	return p.Bytes
}

func wouldReadSecret(req *Request, snap TargetSnapshot) bool {
	if req.Policy.SSHPasswordKey != "" || req.Policy.SSHPassword != "" {
		return true
	}
	needSudo := req.Action.UseSudo || (req.Action.Kind == ActionCommand && sshclient.CommandUsesSudo(req.Action.Command))
	if !needSudo {
		return false
	}
	if req.Policy.SudoPasswordKey != "" {
		return true
	}
	for _, t := range snap.Targets {
		if t.SudoPasswordKey != "" {
			return true
		}
	}
	return false
}
