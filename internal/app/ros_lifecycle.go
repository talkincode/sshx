package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/ros"
	"github.com/talkincode/sshx/internal/sshclient"
)

func runROSCommand(client *sshclient.SSHClient, command string) (sshclient.ExecResult, error) {
	result, err := client.RunCommandWithInput(command, nil)
	if err == nil && (ros.CommandDiagnostic(result.Stdout) || ros.CommandDiagnostic(result.Stderr)) {
		err = &execution.BoundaryError{Kind: "ros_command_error", Message: "RouterOS rejected the command: " + redactSensitiveText(firstNonEmpty(result.Stderr, result.Stdout))}
	}
	return result, err
}

func setROSOperation(config *sshclient.Config, action, command string, remoteWrite, localWrite, unknown bool) {
	config.ROSAction, config.Command = action, command
	if p := preparedFrom(config); p != nil {
		p.meta.Effects = execution.Effects{RemoteWrite: remoteWrite, LocalWrite: localWrite, Unknown: unknown}
		p.meta.Risk = execution.RiskRead
		if remoteWrite || unknown {
			p.meta.Risk = execution.RiskMutation
		}
		p.preview.LocalPath = config.LocalPath
	}
}

func newROSClient(config *sshclient.Config) (*sshclient.SSHClient, error) {
	settings, err := LoadSettings()
	if err != nil {
		return nil, err
	}
	if err := materializeJumpChain(config, settings); err != nil {
		return nil, err
	}
	if err := resolveSSHCredential(config); err != nil {
		return nil, err
	}
	if err := resolveJumpSecrets(config); err != nil {
		return nil, err
	}
	return sshclient.NewSSHClient(config)
}

func rosWorkflowIntent(config *sshclient.Config, spec *ros.WorkflowSpec) {
	config.LocalPath, config.RemotePath = spec.LocalPath, spec.RemotePath
	remoteWrite := spec.Type != ros.WorkflowFileDownload && spec.Type != ros.WorkflowFileList
	localWrite := spec.Type == ros.WorkflowFileDownload || spec.Type == ros.WorkflowExportDownload || spec.Type == ros.WorkflowBackupDownload
	setROSOperation(config, string(spec.Type), strings.Join(config.ROSTokens, " "), remoteWrite, localWrite, remoteWrite)
}

func finishROSFile(config *sshclient.Config, audit *auditRecorder, client *sshclient.SSHClient, action, local, remote string, start time.Time) error {
	outcome, operationErr := client.CopyFile(action, local, remote)
	result, err := fileOperationResult(config, outcome, start, operationErr)
	if err != nil {
		return err
	}
	result["schema_version"] = "roswire.write.v1"
	result["command"] = config.ROSAction
	result["status"] = "ok"
	if operationErr != nil {
		result["status"] = "error"
	}
	data := map[string]any{"local": local, "remote": remote, "bytes": int64(0)}
	if outcome != nil {
		data["bytes"] = outcome.BytesTransferred
	}
	result["data"] = data
	if audit != nil && operationErr == nil {
		audit.recordCommandResult(config, client.AuthMethodUsed(), sshclient.ExecResult{ExitCode: 0}, time.Since(start), "", nil)
	}
	if err := finishOperation(config, audit, result, operationErr); err != nil {
		return err
	}
	if !config.JSONOutput {
		fmt.Printf("SFTP %s: %s (%d bytes)\n", action, outcome.Completion, outcome.BytesTransferred)
	}
	return nil
}

func copyROSFile(client *sshclient.SSHClient, config *sshclient.Config, action, local, remote string) (int64, error) {
	out, err := client.CopyFile(action, local, remote)
	if out == nil {
		return 0, err
	}
	if p := preparedFrom(config); p != nil {
		p.meta.Executed, p.meta.ChangeState = out.Executed, out.ChangeState
	}
	return out.BytesTransferred, err
}
