package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/ros"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
)

// rosJSONResult is the machine-readable result emitted in --json mode for RouterOS commands.
type rosJSONResult struct {
	SchemaVersion  string `json:"schema_version,omitempty"`
	Status         string `json:"status"` // "ok" or "error"
	Host           string `json:"host,omitempty"`
	Port           string `json:"port,omitempty"`
	User           string `json:"user,omitempty"`
	Command        string `json:"command"`
	Action         string `json:"action,omitempty"`
	RouterOSPath   string `json:"routeros_path,omitempty"` //nolint:misspell // RouterOS domain term
	Stdout         string `json:"stdout,omitempty"`
	Stderr         string `json:"stderr,omitempty"`
	Data           any    `json:"data,omitempty"`
	ExitCode       int    `json:"exit_code"`
	Success        bool   `json:"success"`
	DurationMs     int64  `json:"duration_ms"`
	AuthMethod     string `json:"auth_method,omitempty"`
	ErrorKind      string `json:"error_kind,omitempty"`
	Error          string `json:"error,omitempty"`
	Phase          string `json:"phase"`
	Completion     string `json:"completion"`
	Executed       *bool  `json:"executed,omitempty"`
	ChangeState    string `json:"change_state,omitempty"`
	RemoteExitCode *int   `json:"remote_exit_code,omitempty"`
}

// HandleROS manages RouterOS command execution and workflows strictly over SSH.
func HandleROS(config *sshclient.Config, audit *auditRecorder) (err error) {
	start := time.Now()
	if config.Context == nil {
		config.Context = context.Background()
	}
	attachPrepared(config, &preparedOperation{meta: execution.NewMetadata(nil, config.ExecutionID), audit: audit})
	setROSOperation(config, "introspect", strings.Join(config.ROSTokens, " "), false, false, false)
	if config.HostTimeout > 0 {
		ctx, cancel := execution.WithScopedTimeout(config.Context, config.HostTimeout, "host")
		defer cancel()
		config.Context = ctx
	}

	if config.ArgumentError != "" {
		return reportROSFailure(config, audit, "config", fmt.Errorf("%s", config.ArgumentError), start)
	}

	tokens := config.ROSTokens
	if len(tokens) == 0 {
		return reportROSFailure(config, audit, "usage", ros.NewUsageError("missing RouterOS command", "run `sshx ros help` or `sshx ros commands` to list commands"), start)
	}

	// 1. Introspection commands (can run entirely locally without host)
	switch tokens[0] {
	case "commands":
		payload, rErr := ros.RenderCommandsJSON()
		if rErr != nil {
			return reportROSFailure(config, audit, "internal", rErr, start)
		}
		if config.JSONOutput {
			fmt.Println(payload)
			return nil
		}
		// Human output
		cmds := ros.AllCommands()
		fmt.Printf("Supported RouterOS Commands (%d):\n\n", len(cmds))
		for _, c := range cmds {
			fmt.Printf("  %-35s %s\n", strings.Join(c.CLIPath, " ")+" "+c.Action, c.Summary)
		}
		return nil

	case "help":
		payload, rErr := ros.RenderHelpJSON(tokens[1:])
		if rErr != nil {
			return reportROSFailure(config, audit, "usage", rErr, start)
		}
		fmt.Println(payload)
		return nil

	case "schema":
		payload, rErr := ros.RenderSchemaJSON(tokens[1:])
		if rErr != nil {
			return reportROSFailure(config, audit, "usage", rErr, start)
		}
		fmt.Println(payload)
		return nil

	case "explain-error":
		code := ""
		if len(tokens) > 1 {
			code = tokens[1]
		}
		payload, exErr := ros.RenderExplainErrorJSON(code)
		if exErr != nil {
			return reportROSFailure(config, audit, "usage", exErr, start)
		}
		fmt.Println(payload)
		return nil

	case "doctor":
		return handleDoctor(config, audit, start)
	}

	// 2. File and script workflows
	if wfSpec, isWf := ros.ParseWorkflowCommand(tokens, config.ROSSource); isWf {
		rosWorkflowIntent(config, wfSpec)
		if config.DryRun {
			planJSON, pErr := ros.RenderWorkflowPlanJSON(wfSpec)
			if pErr != nil {
				return reportROSFailure(config, audit, "internal", pErr, start)
			}
			fmt.Println(planJSON)
			return nil
		}
		return handleWorkflow(config, audit, wfSpec, start)
	}

	// 3. Command execution
	req, parseErr := ros.ParseInvocation(tokens)
	if parseErr != nil {
		return reportROSFailure(config, audit, "usage", parseErr, start)
	}

	setROSOperation(config, strings.Join(req.Path, "/")+"/"+req.Action, ros.BuildRouterOSCommand(req), !ros.ReadOnly(req), false, !ros.ReadOnly(req))
	// Check dry-run
	if config.DryRun {
		plan := &ros.ROSPlan{
			SchemaVersion:      "roswire.command.plan.v1",
			DryRun:             true,
			Command:            strings.Join(tokens, " "),
			RouterOSPath:       req.Mapping.RouterOSPath,
			Action:             req.Action,
			ResolvedArgs:       req.Args,
			Flags:              req.Flags,
			SideEffects:        req.Mapping.SideEffects,
			Idempotency:        req.Mapping.Idempotency,
			WillConnect:        false,
			WillModifyRouterOS: !ros.ReadOnly(req),
		}
		if req.Mapping.IsRaw() {
			plan.RawCommand = req.RawCommand
			plan.ResolvedArgs = map[string]string{}
			plan.Flags = []string{}
		}
		b, mErr := json.MarshalIndent(plan, "", "  ")
		if mErr != nil {
			return reportROSFailure(config, audit, "internal", mErr, start)
		}
		fmt.Println(string(b))
		return nil
	}

	// Check safety guardrails
	if safeErr := ros.ValidateSafety(req, config.ROSAllowWrite, config.Force); safeErr != nil {
		return reportROSFailure(config, audit, "blocked", safeErr, start)
	}

	// Require host
	if config.Host == "" {
		return reportROSFailure(config, audit, "config", ros.NewConfigError("host is required (use -h=<host>)", "specify -h=<router-ip>"), start)
	}

	// Resolve named host
	if !isIPAddress(config.Host) {
		if resolveErr := resolveHostFromSettings(config); resolveErr != nil {
			logger.GetLogger().Info("Note: Could not find host '%s' in settings, using as hostname directly", config.Host)
		}
	}

	client, cliErr := newROSClient(config)
	if cliErr != nil {
		return reportROSFailure(config, audit, "config", fmt.Errorf("failed to create SSH client: %w", cliErr), start)
	}
	defer errutil.HandleCloseError(&err, client)

	if connErr := client.Connect(); connErr != nil {
		audit.recordPeer(client)
		return reportROSFailure(config, audit, classifyError(connErr), fmt.Errorf("failed to connect over SSH: %w", connErr), start)
	}
	audit.recordPeer(client)
	recordConnectedHops(config, client)

	rosCmd := ros.BuildRouterOSCommand(req)
	logger.GetLogger().Debug("executing RouterOS command over SSH: %s", rosCmd)

	res, execErr := runROSCommand(client, rosCmd)
	if execErr != nil {
		return reportROSFailureWithExit(config, audit, classifyError(execErr), res, execErr, start)
	}

	if res.ExitCode != 0 {
		return reportROSFailureWithExit(config, audit, "ros_exit_error", res, fmt.Errorf("RouterOS command failed with exit code %d: %s", res.ExitCode, firstNonEmpty(res.Stderr, res.Stdout)), start)
	}

	// Success reporting
	durationMs := time.Since(start).Milliseconds()
	if audit != nil {
		audit.recordCommandResult(config, client.AuthMethodUsed(), res, time.Since(start), "", nil)
	}

	var data any
	if !config.ROSRaw {
		if parsed, ok := ros.ParseRouterOSOutput(res.Stdout); ok {
			data = parsed
		}
	}

	result := rosJSONResult{
		SchemaVersion: "roswire.write.v1",
		Status:        "ok",
		Host:          config.Host,
		Port:          config.Port,
		User:          config.User,
		Command:       redactSensitiveText(config.Command),
		Action:        req.Action,
		RouterOSPath:  req.Mapping.RouterOSPath,
		Stdout:        res.Stdout,
		Stderr:        res.Stderr,
		Data:          data,
		ExitCode:      0,
		Success:       true,
		DurationMs:    durationMs,
		AuthMethod:    string(client.AuthMethodUsed()),
		Phase:         "complete",
		Completion:    execution.CompletionCompleted,
	}

	if config.JSONOutput {
		return emitROSJSON(config, result)
	}

	if _, finalizeErr := finalizeLifecycle(config, result); finalizeErr != nil {
		return finalizeErr
	}
	// Human output: print stdout cleanly
	if strings.TrimSpace(res.Stdout) != "" {
		fmt.Print(res.Stdout)
		if !strings.HasSuffix(res.Stdout, "\n") {
			fmt.Println()
		}
	} else if req.Mapping.ActionKind != ros.ActionPrint {
		logger.GetLogger().Success("RouterOS command %s completed successfully", strings.Join(tokens, " "))
	}
	return nil
}

func handleWorkflow(config *sshclient.Config, audit *auditRecorder, spec *ros.WorkflowSpec, start time.Time) (err error) {
	if config.Host == "" {
		return reportROSFailure(config, audit, "config", ros.NewConfigError("host is required for workflow (use -h=<host>)", "specify -h=<router-ip>"), start)
	}
	if !isIPAddress(config.Host) {
		_ = resolveHostFromSettings(config) //nolint:errcheck // best-effort settings lookup
	}

	client, cliErr := newROSClient(config)
	if cliErr != nil {
		return reportROSFailure(config, audit, "config", fmt.Errorf("failed to create SSH client: %w", cliErr), start)
	}
	defer errutil.HandleCloseError(&err, client)

	if connErr := client.Connect(); connErr != nil {
		audit.recordPeer(client)
		return reportROSFailure(config, audit, classifyError(connErr), connErr, start)
	}
	audit.recordPeer(client)
	recordConnectedHops(config, client)

	sftpClient, sftpErr := client.NewSFTPClient()
	if sftpErr != nil {
		return reportROSFailure(config, audit, "sftp_error", fmt.Errorf("failed to open SFTP session on RouterOS: %w", sftpErr), start)
	}
	defer func() { _ = sftpClient.Close() }() //nolint:errcheck // best-effort close

	var outputMsg string
	var resultData any

	switch spec.Type {
	case ros.WorkflowFileUpload:
		return finishROSFile(config, audit, client, "upload", spec.LocalPath, spec.RemotePath, start)

	case ros.WorkflowFileDownload:
		return finishROSFile(config, audit, client, "download", spec.LocalPath, spec.RemotePath, start)

	case ros.WorkflowFileList:
		entries, listErr := sftpClient.ReadDir(spec.RemotePath)
		if listErr != nil {
			return reportROSFailure(config, audit, "file_transfer_failed", listErr, start)
		}
		var fileList []map[string]any
		for _, e := range entries {
			fileList = append(fileList, map[string]any{
				"name":     e.Name(),
				"size":     e.Size(),
				"is_dir":   e.IsDir(),
				"mod_time": e.ModTime().Format(time.RFC3339),
			})
		}
		resultData = fileList
		outputMsg = fmt.Sprintf("Found %d file(s) in %s", len(fileList), spec.RemotePath)

	case ros.WorkflowScriptPut:
		content, readErr := os.ReadFile(spec.LocalPath)
		if readErr != nil {
			return reportROSFailure(config, audit, "usage", fmt.Errorf("read script file %s: %w", spec.LocalPath, readErr), start)
		}
		if valErr := ros.ValidateScriptSource(content, spec.LocalPath); valErr != nil {
			return reportROSFailure(config, audit, "usage", valErr, start)
		}
		escapedSource := ros.QuoteValue(string(content))
		cmd := fmt.Sprintf(`/system script add name=%s source=%s`, ros.QuoteValue(spec.ScriptName), escapedSource)
		res, execErr := runROSCommand(client, cmd)
		if execErr != nil || res.ExitCode != 0 {
			// Only a positively observed duplicate-name diagnostic authorizes set;
			// an unknown outcome must not silently trigger a second mutation.
			message := strings.ToLower(res.Stdout + res.Stderr)
			if !res.ExitObserved || (!strings.Contains(message, "already have such name") && !strings.Contains(message, "already exists")) {
				return reportROSFailureWithExit(config, audit, "ros_exec_error", res, fmt.Errorf("failed to add script: %s", redactSensitiveText(message)), start)
			}
			cmdSet := fmt.Sprintf(`/system script set [find name=%s] source=%s`, ros.QuoteValue(spec.ScriptName), escapedSource)
			resSet, execSetErr := runROSCommand(client, cmdSet)
			if execSetErr != nil || resSet.ExitCode != 0 {
				return reportROSFailure(config, audit, "ros_exec_error", fmt.Errorf("failed to put script: %s", firstNonEmpty(res.Stderr, resSet.Stderr)), start)
			}
		}
		outputMsg = fmt.Sprintf("Installed script %q (%d bytes)", spec.ScriptName, len(content))
		resultData = map[string]any{"name": spec.ScriptName, "bytes": len(content)}

	case ros.WorkflowImport:
		// 1. Upload script
		_, uploadErr := copyROSFile(client, config, "upload", spec.LocalPath, spec.RemotePath)
		if uploadErr != nil {
			return reportROSFailure(config, audit, "file_transfer_failed", uploadErr, start)
		}
		// 2. Run /import
		importCmd := "/import file-name=" + ros.QuoteValue(spec.RemotePath)
		res, execErr := runROSCommand(client, importCmd)
		// 3. Cleanup if requested
		if config.ROSCleanup {
			_ = sftpClient.Remove(spec.RemotePath) //nolint:errcheck // best-effort remote file cleanup
		}
		if execErr != nil || res.ExitCode != 0 {
			return reportROSFailure(config, audit, "ros_exec_error", fmt.Errorf("import failed: %s", firstNonEmpty(res.Stderr, res.Stdout)), start)
		}
		outputMsg = fmt.Sprintf("Imported %s into RouterOS", spec.LocalPath)
		resultData = map[string]any{"imported": spec.LocalPath, "output": res.Stdout}

	case ros.WorkflowExportDownload:
		tempFile := "sshx_export_" + newAuditEventID() + ".rsc"
		compactFlag := ""
		if config.ROSCompact {
			compactFlag = "compact"
		}
		exportCmd := fmt.Sprintf("/export %s file=%s", compactFlag, tempFile)
		res, execErr := runROSCommand(client, exportCmd)
		if execErr != nil || res.ExitCode != 0 {
			return reportROSFailure(config, audit, "ros_exec_error", fmt.Errorf("export failed: %s", firstNonEmpty(res.Stderr, res.Stdout)), start)
		}
		// Wait for file
		if waitErr := ros.WaitForRemoteFile(sftpClient, tempFile, 15*time.Second); waitErr != nil {
			return reportROSFailure(config, audit, "file_transfer_failed", waitErr, start)
		}
		// Download file
		n, dlErr := copyROSFile(client, config, "download", spec.LocalPath, tempFile)
		if config.ROSCleanup {
			_ = sftpClient.Remove(tempFile) //nolint:errcheck // best-effort remote file cleanup
		}
		if dlErr != nil {
			return reportROSFailure(config, audit, "file_transfer_failed", dlErr, start)
		}
		outputMsg = fmt.Sprintf("Exported configuration downloaded to %s (%d bytes)", spec.LocalPath, n)
		resultData = map[string]any{"exported_to": spec.LocalPath, "bytes": n}

	case ros.WorkflowBackupDownload:
		backupName := config.ROSBackupName
		if backupName == "" {
			backupName = "sshx_backup_" + newAuditEventID()
		}
		backupFile := backupName + ".backup"
		backupCmd := "/system backup save name=" + ros.QuoteValue(backupName)
		res, execErr := runROSCommand(client, backupCmd)
		if execErr != nil || res.ExitCode != 0 {
			return reportROSFailure(config, audit, "ros_exec_error", fmt.Errorf("backup failed: %s", firstNonEmpty(res.Stderr, res.Stdout)), start)
		}
		// Wait for file
		if waitErr := ros.WaitForRemoteFile(sftpClient, backupFile, 20*time.Second); waitErr != nil {
			return reportROSFailure(config, audit, "file_transfer_failed", waitErr, start)
		}
		// Download file
		n, dlErr := copyROSFile(client, config, "download", spec.LocalPath, backupFile)
		if config.ROSCleanup {
			_ = sftpClient.Remove(backupFile) //nolint:errcheck // best-effort remote file cleanup
		}
		if dlErr != nil {
			return reportROSFailure(config, audit, "file_transfer_failed", dlErr, start)
		}
		outputMsg = fmt.Sprintf("Backup downloaded to %s (%d bytes)", spec.LocalPath, n)
		resultData = map[string]any{"backup_file": spec.LocalPath, "bytes": n}
	}

	durationMs := time.Since(start).Milliseconds()
	if audit != nil {
		audit.recordCommandResult(config, client.AuthMethodUsed(), sshclient.ExecResult{ExitCode: 0}, time.Since(start), "", nil)
	}

	result := rosJSONResult{
		SchemaVersion: "roswire.write.v1",
		Status:        "ok",
		Host:          config.Host,
		Port:          config.Port,
		User:          config.User,
		Command:       string(spec.Type),
		Data:          resultData,
		ExitCode:      0,
		Success:       true,
		DurationMs:    durationMs,
		AuthMethod:    string(client.AuthMethodUsed()),
		Phase:         "complete",
		Completion:    execution.CompletionCompleted,
	}

	if config.JSONOutput {
		return emitROSJSON(config, result)
	}

	if _, finalizeErr := finalizeLifecycle(config, result); finalizeErr != nil {
		return finalizeErr
	}
	logger.GetLogger().Success("%s", outputMsg)
	return nil
}

func handleDoctor(config *sshclient.Config, audit *auditRecorder, start time.Time) error {
	home, _ := os.UserHomeDir() //nolint:errcheck // fallback to relative if unavailable
	sshDir := filepath.Join(home, ".ssh")
	_, errSSH := os.Stat(sshDir)

	settingsPath := filepath.Join(home, ".sshx", "settings.json")
	_, errSettings := os.Stat(settingsPath)

	var keysFound []string
	commonKeys := []string{"id_rsa", "id_ed25519", "id_ecdsa"}
	for _, k := range commonKeys {
		if _, err := os.Stat(filepath.Join(sshDir, k)); err == nil {
			keysFound = append(keysFound, k)
		}
	}

	localDoc := ros.LocalDoctor{
		HomeExists:    true,
		ConfigExists:  errSettings == nil,
		PermissionsOK: true,
		SSHKeysFound:  keysFound,
		Dependencies: map[string]string{
			"transport": "ssh (built-in crypto/ssh)",
			"file":      "sftp (built-in pkg/sftp)",
		},
		Warnings: nil,
	}
	if errSSH != nil {
		localDoc.Warnings = append(localDoc.Warnings, "local ~/.ssh directory not found")
	}

	docPayload := ros.DoctorPayload{
		SchemaVersion:    "roswire.doctor.v1",
		Local:            localDoc,
		SelectedProtocol: "ssh",
	}

	if config.ROSIncludeRemote && config.Host != "" && !config.DryRun {
		if !isIPAddress(config.Host) {
			_ = resolveHostFromSettings(config) //nolint:errcheck // best-effort settings lookup
		}
		client, cliErr := newROSClient(config)
		if cliErr == nil {
			defer func() { _ = client.Close() }() //nolint:errcheck // best-effort close
			if connErr := client.Connect(); connErr == nil {
				res, _ := runROSCommand(client, "/system resource print") //nolint:errcheck // doctor probe ignores exec failure
				remoteDoc := &ros.RemoteDoctor{
					Status: "connected",
				}
				if parsed, ok := ros.ParseRouterOSOutput(res.Stdout); ok {
					if rec, isRec := parsed.(map[string]any); isRec {
						if v, ok := rec["version"].(string); ok {
							remoteDoc.RouterOSVersion = v
							docPayload.RouterOSVersion = v
						}
						if a, ok := rec["architecture-name"].(string); ok {
							remoteDoc.Architecture = a
						}
						if b, ok := rec["board-name"].(string); ok {
							remoteDoc.BoardName = b
						}
						if u, ok := rec["uptime"].(string); ok {
							remoteDoc.Uptime = u
						}
					}
				}
				docPayload.Remote = remoteDoc
			} else {
				docPayload.Remote = &ros.RemoteDoctor{
					Status:   "connection_failed",
					Warnings: []string{connErr.Error()},
				}
			}
		}
	}

	b, err := json.MarshalIndent(docPayload, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func emitROSJSON(config *sshclient.Config, result rosJSONResult) error {
	return emitLifecycleJSON(config, result)
}

func reportROSFailure(config *sshclient.Config, audit *auditRecorder, kind string, err error, start time.Time) error {
	return reportROSFailureWithExit(config, audit, kind, sshclient.ExecResult{ExitCode: -1}, err, start)
}

func reportROSFailureWithExit(config *sshclient.Config, audit *auditRecorder, kind string, res sshclient.ExecResult, err error, start time.Time) error {
	if audit != nil {
		audit.recordFailure(config, sshclient.AuthMethodUnknown, kind, err)
	}

	result := rosJSONResult{
		Status:     "error",
		Host:       config.Host,
		Port:       config.Port,
		User:       config.User,
		Command:    redactSensitiveText(config.Command),
		ExitCode:   res.ExitCode,
		Success:    false,
		DurationMs: time.Since(start).Milliseconds(),
		ErrorKind:  kind,
		Error:      redactError(err),
		Phase:      execution.PhaseExecute,
		Completion: execution.CompletionForAttempt(execution.PhaseExecute, kind, res.StartAttempted, res.Started, res.ExitObserved),
	}
	if p := preparedFrom(config); p != nil {
		result.Executed, result.ChangeState = p.meta.Executed, p.meta.ChangeState
	}
	if kind == "ros_command_error" && res.ExitObserved {
		observed := res.ExitCode
		result.RemoteExitCode = &observed
		result.ExitCode = -1
	}
	if result.Executed != nil && *result.Executed && !res.StartAttempted {
		result.Completion = execution.CompletionPartial
	}
	if res.Started || res.ExitObserved {
		value := true
		result.Executed = &value
	} else if !res.StartAttempted && result.Executed == nil {
		value := false
		result.Executed = &value
		result.Phase = execution.PhaseAdmission
	}
	if config.JSONOutput {
		if emitErr := emitROSJSON(config, result); emitErr != nil {
			return emitErr
		}
		return ErrReported
	}

	return err
}
