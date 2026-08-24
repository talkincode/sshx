package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/keyringstore"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/logger"
)

// keyringSecrets adapts the OS keyring to typed credential roles.
type keyringSecrets struct{}

func (keyringSecrets) GetSSHPassword(key string) (string, error) {
	return sshclient.GetSudoPassword(key) // same keyring service; role is caller-enforced
}

func (keyringSecrets) GetSudoPassword(key string) (string, error) {
	return sshclient.GetSudoPassword(key)
}

// HandleRun executes the versioned sshx run contract.
func HandleRun(config *sshclient.Config, audit *auditRecorder) error {
	req, payload, buildErr := buildRunRequest(config)
	if buildErr != nil {
		return reportRunRequestFailure(config, audit, buildErr)
	}

	hosts, defaults, loadErr := loadHostRecords(config)
	if loadErr != nil {
		return reportRunRequestFailure(config, audit, loadErr)
	}

	if config.DryRun {
		plan := execution.BuildDryRunPlan(req, hosts, defaults, payload)
		attachRunSecretBackend(&plan)
		return emitRunDryRun(config, plan)
	}

	if normErr := execution.NormalizeRequest(req); normErr != nil {
		return reportRunRequestFailure(config, audit, normErr)
	}
	if safetyErr := execution.SafetyCheck(req, payloadBytes(payload)); safetyErr != nil {
		return reportRunRequestFailure(config, audit, safetyErr)
	}

	snap, resolveErr := execution.ResolveTargets(hosts, req.Targets, defaults)
	if resolveErr != nil {
		return reportRunRequestFailure(config, audit, resolveErr)
	}

	ctx := context.Background()
	if req.Limits.Timeout > 0 {
		// Overall run budget: per-target timeout still applies inside sessions.
		// Use a generous multiple so fan-out can complete under continue mode.
		budget := req.Limits.Timeout * time.Duration(max(1, (snap.Count+req.Limits.Concurrency-1)/req.Limits.Concurrency))
		budget += 5 * time.Second
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}

	var events execution.EventWriter
	switch {
	case req.JSONLOutput:
		events = &execution.JSONLWriter{W: os.Stdout}
	case req.JSONOutput && snap.Count == 1:
		events = executionNoopEvents{}
	case req.JSONOutput && snap.Count > 1:
		// Multi-target JSON mode defaults to JSONL stream.
		events = &execution.JSONLWriter{W: os.Stdout}
		req.JSONLOutput = true
	default:
		events = &execution.HumanWriter{W: os.Stdout}
	}

	outcome, execErr := execution.Execute(ctx, execution.RunOptions{
		Request:  req,
		Snapshot: snap,
		Payload:  payload,
		Secrets:  keyringSecrets{},
		Events:   events,
	})
	if execErr != nil {
		return reportRunRequestFailure(config, audit, execErr)
	}

	recordRunAudit(audit, config, req, snap, outcome)

	// Single-target --json emits one versioned result document.
	if req.JSONOutput && !req.JSONLOutput && outcome.Single != nil {
		if err := encodeJSON(outcome.Single); err != nil {
			logger.GetLogger().Error("failed to encode run result: %v", err)
		}
	}

	code := execution.ProcessExitCode(outcome.Counts, nil)
	switch code {
	case 0:
		return nil
	case 255:
		return fmt.Errorf("run failed")
	default:
		return &ExitError{Code: code}
	}
}

type executionNoopEvents struct{}

func (executionNoopEvents) WriteEvent(execution.Event) error { return nil }

func emitRunDryRun(config *sshclient.Config, plan execution.DryRunPlan) error {
	if config.JSONOutput || config.JSONLOutput {
		return encodeJSON(plan)
	}
	fmt.Println("=== sshx run dry-run ===")
	fmt.Printf("Valid: %t\n", plan.Valid)
	fmt.Printf("Action: %s intent=%s\n", plan.Action.Kind, plan.Action.Intent)
	if plan.Action.PayloadSHA256 != "" {
		fmt.Printf("Payload: sha256=%s bytes=%d\n", plan.Action.PayloadSHA256, plan.Action.PayloadBytes)
	}
	if plan.Action.Command != "" {
		fmt.Printf("Command: %s\n", plan.Action.Command)
	}
	fmt.Printf("Targets: %d digest=%s\n", plan.Snapshot.Count, plan.Snapshot.SelectorDigest)
	for _, t := range plan.Snapshot.Targets {
		alias := t.Alias
		if alias == "" {
			alias = "(literal)"
		}
		fmt.Printf("  - [%d] %s %s@%s:%s sudo_key=%s ssh_pw_key=%s\n",
			t.Index, alias, t.User, t.Address, t.Port, t.SudoPasswordKey, t.SSHPasswordKey)
	}
	for _, s := range plan.Snapshot.Skipped {
		fmt.Printf("  skip %s: %s\n", s.Alias, s.Reason)
	}
	fmt.Printf("Concurrency: %d failure_mode=%s\n", plan.Limits.Concurrency, plan.Policy.FailureMode)
	if plan.SecretBackend != "" {
		fmt.Printf("Secret backend: %s", plan.SecretBackend)
		if plan.SecretUnlock != "" {
			fmt.Printf(" unlock=%s", plan.SecretUnlock)
		}
		fmt.Println()
	}
	fmt.Printf("Would connect/execute/read_secret/mutate_remote: %t/%t/%t/%t\n",
		plan.WouldConnect, plan.WouldExecute, plan.WouldReadSecret, plan.WouldMutateRemote)
	if plan.Error != nil {
		fmt.Printf("Error: kind=%s message=%s\n", plan.Error.Kind, plan.Error.Message)
	}
	return nil
}

func attachRunSecretBackend(plan *execution.DryRunPlan) {
	status := keyringstore.Inspect()
	plan.SecretBackend = status.Backend
	if status.Unlock != keyringstore.UnlockNone {
		plan.SecretUnlock = status.Unlock
	}
	if _, err := keyringstore.Backend(); err != nil && plan.Valid {
		plan.Valid = false
		plan.WouldConnect = false
		plan.WouldExecute = false
		plan.WouldReadSecret = false
		plan.WouldMutateRemote = false
		plan.Error = execution.BuildError(err, execution.ErrorKindConfig, plan.Action.Intent, execution.CompletionNotStarted)
	}
}

func reportRunRequestFailure(config *sshclient.Config, audit *auditRecorder, err error) error {
	kind := execution.Classify(err)
	if kind == "" {
		kind = execution.ErrorKindConfig
	}
	if audit != nil {
		audit.recordFailure(config, sshclient.AuthMethodUnknown, kind, err)
	}
	if config.JSONOutput || config.JSONLOutput {
		res := execution.Result{
			SchemaVersion: execution.ResultSchemaVersion,
			Status:        execution.StatusFailed,
			Phase:         execution.PhaseResolve,
			Completion:    execution.CompletionNotStarted,
			ExitCode:      -1,
			Success:       false,
			Error:         execution.BuildError(err, kind, execution.IntentUnknown, execution.CompletionNotStarted),
			ErrorKind:     kind,
		}
		if encErr := encodeJSON(res); encErr != nil {
			logger.GetLogger().Error("failed to encode run failure: %v", encErr)
		}
		return ErrReported
	}
	return err
}

func encodeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func payloadBytes(p *execution.Payload) []byte {
	if p == nil {
		return nil
	}
	return p.Bytes
}

func loadHostRecords(config *sshclient.Config) ([]execution.HostRecord, execution.HostRecord, error) {
	settings, err := LoadSettings()
	if err != nil {
		return nil, execution.HostRecord{}, fmt.Errorf("%w: load settings: %v", execution.ErrConfig, err)
	}
	hosts := make([]execution.HostRecord, 0, len(settings.Hosts))
	for _, h := range settings.Hosts {
		hosts = append(hosts, hostToRecord(h))
	}
	defaults := execution.HostRecord{
		Port:            firstNonEmptyStr(config.Port, sshclient.DefaultSSHPort),
		User:            firstNonEmptyStr(config.User, sshclient.DefaultSSHUser),
		KeyPath:         firstNonEmptyStr(config.KeyPath, settings.Key),
		SSHPasswordKey:  config.SSHPasswordKey,
		SudoPasswordKey: config.SudoKey,
	}
	return hosts, defaults, nil
}

func hostToRecord(h HostConfig) execution.HostRecord {
	return execution.HostRecord{
		Name:            h.Name,
		Address:         h.Host,
		Port:            h.Port,
		User:            h.User,
		KeyPath:         h.Key,
		SSHPasswordKey:  h.EffectiveSSHPasswordKey(),
		SudoPasswordKey: h.EffectiveSudoPasswordKey(),
		Groups:          append([]string(nil), h.Groups...),
		Tags:            cloneTags(h.Tags),
	}
}

func cloneTags(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func buildRunRequest(config *sshclient.Config) (*execution.Request, *execution.Payload, error) {
	req := &execution.Request{
		SchemaVersion: execution.RequestSchemaVersion,
		RequestID:     config.RequestID,
		Targets: execution.TargetSelector{
			Names:    append([]string(nil), config.RunTargets...),
			Groups:   append([]string(nil), config.RunGroups...),
			Tags:     cloneTags(config.RunTags),
			AllHosts: config.RunAllHosts,
			Address:  config.RunAddress,
			Port:     config.Port,
			User:     config.User,
		},
		Action: execution.ActionSpec{
			Kind:            config.RunActionKind,
			Intent:          config.RunIntent,
			Command:         config.Command,
			ScriptPath:      config.ScriptFile,
			ScriptFromStdin: config.ScriptStdin,
			ScriptRunner:    execution.ScriptRunnerSH,
			UseSudo:         config.RunUseSudo,
		},
		Limits: execution.Limits{
			Concurrency:             config.RunConcurrency,
			Timeout:                 config.Timeout,
			MaxOutputBytesPerTarget: config.MaxOutputBytes,
			MaxPayloadBytes:         config.MaxPayloadBytes,
		},
		Policy: execution.Policy{
			FailureMode:          config.FailureMode,
			SafetyCheckEnabled:   config.SafetyCheck,
			SafetyBypass:         config.Force || !config.SafetyCheck,
			BypassReason:         config.BypassReason,
			AcceptUnknownHost:    config.AcceptUnknownHost,
			AllowInsecureHostKey: config.AllowInsecureHostKey,
			KnownHostsPath:       config.KnownHostsPath,
			UseKeyAuth:           config.UseKeyAuth,
			KeyPath:              config.KeyPath,
			SSHPasswordKey:       config.SSHPasswordKey,
			SudoPasswordKey:      config.SudoKey,
			SSHPassword:          config.Password,
		},
		JSONOutput:   config.JSONOutput,
		JSONLOutput:  config.JSONLOutput,
		DryRun:       config.DryRun,
		AuditEnabled: config.AuditEnabled,
		AuditOutput:  config.AuditOutput,
	}

	// Infer action kind when not set explicitly.
	if req.Action.Kind == "" {
		switch {
		case config.ScriptFile != "" || config.ScriptStdin:
			req.Action.Kind = execution.ActionScript
		default:
			req.Action.Kind = execution.ActionCommand
		}
	}
	if req.Action.Intent == "" {
		if req.Action.UseSudo || sshclient.CommandUsesSudo(req.Action.Command) {
			req.Action.Intent = execution.IntentChange
		} else {
			req.Action.Intent = execution.IntentRead
		}
	}
	if req.Policy.FailureMode == "" {
		req.Policy.FailureMode = execution.FailureContinue
	}
	if req.Limits.Concurrency == 0 {
		req.Limits.Concurrency = execution.DefaultConcurrency
	}

	// Compatibility: single --target from -h when using run with host alias flag mapping.
	if len(req.Targets.Names) == 0 && req.Targets.Address == "" && !req.Targets.AllHosts &&
		len(req.Targets.Groups) == 0 && len(req.Targets.Tags) == 0 && config.Host != "" {
		// In run mode -h is treated as strict alias unless --address was set.
		req.Targets.Names = []string{config.Host}
	}

	if err := execution.NormalizeRequest(req); err != nil {
		return nil, nil, err
	}

	var payload *execution.Payload
	if req.Action.Kind == execution.ActionScript {
		var err error
		if req.Action.ScriptFromStdin {
			p, loadErr := execution.LoadScriptStdin(os.Stdin, req.Limits.MaxPayloadBytes)
			if loadErr != nil {
				return nil, nil, loadErr
			}
			payload = &p
		} else {
			p, loadErr := execution.LoadScriptFile(req.Action.ScriptPath, req.Limits.MaxPayloadBytes)
			if loadErr != nil {
				return nil, nil, loadErr
			}
			payload = &p
		}
		req.Action.PayloadSHA256 = payload.SHA256
		req.Action.PayloadBytes = payload.Size
		_ = err
	}

	return req, payload, nil
}

func recordRunAudit(audit *auditRecorder, config *sshclient.Config, req *execution.Request, snap execution.TargetSnapshot, outcome execution.RunOutcome) {
	if audit == nil {
		return
	}
	audit.event.Mode = "run"
	audit.event.Action = req.Action.Kind
	audit.event.RunID = outcome.RunID
	audit.event.RequestID = req.RequestID
	audit.event.SelectorDigest = snap.SelectorDigest
	audit.event.PayloadSHA256 = req.Action.PayloadSHA256
	audit.event.ActionIntent = req.Action.Intent
	audit.event.BypassReason = req.Policy.BypassReason
	audit.event.Concurrency = req.Limits.Concurrency
	audit.event.FailureMode = req.Policy.FailureMode
	audit.event.TargetCount = snap.Count
	if outcome.Counts.Succeeded == outcome.Counts.Selected && outcome.Counts.Failed == 0 {
		code := 0
		audit.event.ExitCode = &code
		audit.event.Outcome = auditStatus{Status: "succeeded"}
	} else {
		code := 1
		audit.event.ExitCode = &code
		audit.event.Outcome = auditStatus{Status: "failed", ErrorKind: "aggregate", Message: fmt.Sprintf("succeeded=%d failed=%d skipped=%d uncertain=%d", outcome.Counts.Succeeded, outcome.Counts.Failed, outcome.Counts.Skipped, outcome.Counts.Uncertain)}
	}
	// Per-target audit lines are best-effort additional records.
	for _, tr := range outcome.Results {
		if auditErr := writeTargetAudit(config, outcome.RunID, req, tr); auditErr != nil {
			logger.GetLogger().Error("failed to write target audit event: %v", auditErr)
		}
	}
}

func writeTargetAudit(config *sshclient.Config, runID string, req *execution.Request, tr execution.TargetResult) error {
	if config == nil || !config.AuditEnabled || config.DryRun {
		return nil
	}
	rec := newAuditRecorder(config)
	if rec == nil {
		return nil
	}
	rec.event.Mode = "run"
	rec.event.Action = req.Action.Kind
	rec.event.RunID = runID
	rec.event.RequestID = req.RequestID
	rec.event.HostInput = tr.Target.Alias
	rec.event.HostResolved = tr.Target.Address
	rec.event.Port = tr.Target.Port
	rec.event.User = tr.Target.User
	rec.event.Command = redactSensitiveText(req.Action.Command)
	rec.event.PayloadSHA256 = req.Action.PayloadSHA256
	rec.event.ActionIntent = req.Action.Intent
	rec.event.BypassReason = req.Policy.BypassReason
	rec.event.TargetIndex = &tr.Target.Index
	rec.event.Completion = tr.Completion
	rec.event.Phase = tr.Phase
	rec.event.AuthMethod = tr.AuthMethod
	code := tr.ExitCode
	rec.event.ExitCode = &code
	rec.event.DurationMs = tr.DurationMs
	if tr.Status == execution.StatusSucceeded {
		rec.event.Outcome = auditStatus{Status: "succeeded"}
	} else if tr.Error != nil {
		rec.event.Outcome = auditStatus{Status: "failed", ErrorKind: tr.Error.Kind, Message: redactSensitiveText(tr.Error.Message)}
	} else {
		rec.event.Outcome = auditStatus{Status: "failed"}
	}
	return rec.finish(config, nil)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
