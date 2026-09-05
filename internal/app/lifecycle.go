package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sqlsafe"
	"github.com/talkincode/sshx/internal/sshclient"
)

func recordConnectedPeer(config *sshclient.Config, client *sshclient.SSHClient, role string) {
	p := preparedFrom(config)
	if p == nil {
		return
	}
	if p.audit != nil && role == "target" {
		p.audit.recordPeer(client)
	}
	p.meta.Peers = append(p.meta.Peers, execution.PeerIdentity{
		Role: role, Address: client.PeerAddress(), HostKeyFingerprint: client.HostKeyFingerprint(),
		AuthMethod: string(client.AuthMethodUsed()), User: config.User,
		SSHPasswordKey: config.SSHPasswordKey, SudoPasswordKey: config.SudoKey,
	})
}

func resolveSSHCredential(config *sshclient.Config) error {
	if config.Password != "" || config.SSHPasswordKey == "" {
		return nil
	}
	password, err := sshclient.GetSudoPassword(config.SSHPasswordKey)
	if err != nil {
		return &execution.BoundaryError{Kind: "auth", Message: fmt.Sprintf("resolve SSH password role %q: %v", config.SSHPasswordKey, err)}
	}
	config.Password = password
	return nil
}

func reportPlanFailure(config *sshclient.Config, audit *auditRecorder, err error) error {
	if preparedFrom(config) == nil {
		attachPrepared(config, &preparedOperation{meta: execution.NewMetadata(nil, config.ExecutionID), audit: audit})
	}
	kind := execution.Classify(err)
	if audit != nil {
		audit.recordFailure(config, sshclient.AuthMethodUnknown, kind, err)
	}
	result := map[string]any{
		"schema_version": execution.ResultSchemaVersion, "success": false, "status": "failed",
		"host": config.Host, "port": config.Port, "user": config.User,
		"action": config.Mode, "phase": "admission", "completion": execution.CompletionNotStarted,
		"exit_code": -1, "error_kind": kind, "error": redactError(err),
		"duration_ms": int64(0), "auth_method": "unknown", "stdout": "", "stderr": "",
	}
	if config.Mode == "ssh" {
		result["command"] = redactSensitiveText(config.Command)
	}
	var value any = result
	switch config.Mode {
	case "apply":
		run := &applyRun{config: config, start: time.Now(), phase: "classify", payload: config.PreparedPayload}
		value = run.baseResult(false, -1, kind, err)
	case "sql":
		run := &sqlRun{config: config, start: time.Now(), phase: "classify"}
		if classification, classifyErr := sqlsafe.ClassifyFor(config.SQLEngine, config.SQLStatement); classifyErr == nil {
			run.cls = classification
		}
		failure := run.baseResult()
		failure.ExitCode, failure.ErrorKind, failure.Error = -1, kind, redactError(err)
		value = failure
	case "inspect":
		result["capability"] = config.InspectCapability
	}
	if !config.JSONOutput && !config.JSONLOutput {
		if _, finalizeErr := finalizeLifecycle(config, value); finalizeErr != nil {
			return finalizeErr
		}
		return err
	}
	if emitErr := emitLifecycleJSON(config, value); emitErr != nil {
		return emitErr
	}
	return ErrReported
}

// emitLifecycleJSON projects shared evidence additively onto legacy envelopes.
// It never changes existing field types or includes raw output in the digest.
func emitLifecycleJSON(config *sshclient.Config, value any) error {
	document, err := finalizeLifecycle(config, value)
	if err != nil {
		return err
	}
	if err := encodeJSON(document); err != nil {
		return fmt.Errorf("%w: deliver execution result: %w", execution.ErrLocalIO, err)
	}
	return nil
}

func finalizeLifecycle(config *sshclient.Config, value any) (map[string]json.RawMessage, error) {
	data, err := marshalLifecycleValue(value)
	if err != nil {
		return nil, fmt.Errorf("encode execution result: %w", err)
	}
	var document map[string]json.RawMessage
	if decodeErr := json.Unmarshal(data, &document); decodeErr != nil {
		return nil, fmt.Errorf("decode execution result envelope: %w", decodeErr)
	}
	if document == nil {
		return nil, fmt.Errorf("execution result must be an object")
	}
	p := preparedFrom(config)
	meta := execution.NewMetadata(nil, config.ExecutionID)
	if p != nil {
		meta = p.meta
		if meta.ExecutionID == "" {
			meta = execution.NewMetadata(p.plan, config.ExecutionID)
		}
	}
	if meta.Risk == "" {
		action := config.Mode
		if action == "ssh" {
			action = "command"
		}
		if action == "sftp" {
			action = config.SftpAction
		}
		meta.Risk, meta.Effects = execution.ClassifyRisk(action, config.Command, false)
	}
	for key, dst := range map[string]any{
		"change_state": &meta.ChangeState, "executed": &meta.Executed, "verified": &meta.Verified,
		"verification": &meta.Verification, "preconditions": &meta.Preconditions, "postconditions": &meta.Postconditions,
	} {
		if raw, ok := document[key]; ok {
			if decodeErr := json.Unmarshal(raw, dst); decodeErr != nil {
				return nil, fmt.Errorf("decode result %s: %w", key, decodeErr)
			}
		}
	}
	stringField := func(key string) string {
		var text string
		if raw, ok := document[key]; ok {
			_ = json.Unmarshal(raw, &text) //nolint:errcheck // only reads optional string projections
		}
		return text
	}
	code := -1
	if raw, ok := document["exit_code"]; ok {
		if decodeErr := json.Unmarshal(raw, &code); decodeErr != nil {
			return nil, fmt.Errorf("decode result exit_code: %w", decodeErr)
		}
	}
	status, phase, completion := stringField("status"), stringField("phase"), stringField("completion")
	if status != execution.StatusSucceeded && status != execution.StatusFailed && status != execution.StatusSkipped {
		status = "failed"
		if code == 0 && stringField("error_kind") == "" {
			status = "succeeded"
		}
	}
	if completion == "" {
		if code >= 0 {
			completion = execution.CompletionCompleted
		} else {
			completion = execution.CompletionUnknown
		}
	}
	if !meta.Effects.Unknown && !meta.Effects.RemoteWrite && !meta.Effects.LocalWrite {
		meta.ChangeState = "unchanged"
	}
	if observed := stringField("after_sha256"); observed != "" && len(meta.Postconditions) == 0 {
		meta.Postconditions = append(meta.Postconditions, execution.Condition{
			Kind: "sha256", Subject: config.RemotePath, Expected: stringField("payload_sha256"),
			Observed: observed, Status: meta.Verification,
		})
	}
	meta.ObserveContext(config.Context)
	meta.Finish(status, phase, completion, code, stringField("error_kind"))
	if p != nil {
		p.meta = meta
	}
	fields, err := marshalLifecycleValue(meta)
	if err != nil {
		return nil, fmt.Errorf("encode execution metadata: %w", err)
	}
	var additions map[string]json.RawMessage
	if decodeErr := json.Unmarshal(fields, &additions); decodeErr != nil {
		return nil, decodeErr
	}
	for key, raw := range additions {
		document[key] = raw
	}
	if _, ok := document["schema_version"]; !ok {
		document["schema_version"] = json.RawMessage(`"sshx.result.v1"`)
	}
	persistenceStatus := "disabled"
	if p != nil && p.audit != nil {
		p.audit.event.Metadata = meta
		p.audit.event.CancellationCause, p.audit.event.DeadlineScope = meta.CancellationCause, meta.DeadlineScope
		p.audit.event.Phase, p.audit.event.Completion = phase, completion
		p.audit.event.ExitCode = &code
		if p.audit.event.Outcome.Status == "" {
			auditOutcome := "failure"
			if status == execution.StatusSucceeded {
				auditOutcome = "success"
			}
			p.audit.event.Outcome = auditStatus{Status: auditOutcome, ErrorKind: stringField("error_kind"), Message: redactSensitiveText(stringField("error"))}
		}
		if auditErr := p.audit.finish(config, nil); auditErr != nil {
			persistenceStatus = "failed"
		} else {
			persistenceStatus = "written"
		}
	}
	statusJSON, err := json.Marshal(persistenceStatus)
	if err != nil {
		return nil, err
	}
	document["audit_status"] = statusJSON
	return document, nil
}

func finishOperation(config *sshclient.Config, audit *auditRecorder, result any, operationErr error) error {
	if audit != nil && operationErr != nil {
		audit.recordFailure(config, sshclient.AuthMethodUnknown, execution.Classify(operationErr), operationErr)
	}
	if config.JSONOutput {
		if err := emitLifecycleJSON(config, result); err != nil {
			return err
		}
		if operationErr != nil {
			return ErrReported
		}
		return nil
	}
	if _, err := finalizeLifecycle(config, result); err != nil {
		return err
	}
	return operationErr
}

func operationContextError(config *sshclient.Config) error {
	if config.Context == nil {
		return nil
	}
	if err := config.Context.Err(); err != nil {
		return err
	}
	return nil
}

func marshalLifecycleValue(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
