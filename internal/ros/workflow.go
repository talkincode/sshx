package ros

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

// WorkflowType identifies the kind of RouterOS file/script workflow.
type WorkflowType string

const (
	WorkflowFileUpload     WorkflowType = "file_upload"
	WorkflowFileDownload   WorkflowType = "file_download"
	WorkflowFileList       WorkflowType = "file_list"
	WorkflowScriptPut      WorkflowType = "script_put"
	WorkflowImport         WorkflowType = "import"
	WorkflowExportDownload WorkflowType = "export_download"
	WorkflowBackupDownload WorkflowType = "backup_download"
)

// WorkflowSpec defines the parameters for a workflow execution.
type WorkflowSpec struct {
	Type       WorkflowType `json:"type"`
	LocalPath  string       `json:"local_path,omitempty"`
	RemotePath string       `json:"remote_path,omitempty"`
	ScriptName string       `json:"script_name,omitempty"`
	BackupName string       `json:"backup_name,omitempty"`
	Compact    bool         `json:"compact,omitempty"`
	Cleanup    bool         `json:"cleanup,omitempty"`
}

// ParseWorkflowCommand detects if the CLI tokens form a workflow command.
func ParseWorkflowCommand(tokens []string, sourceFlag string) (*WorkflowSpec, bool) {
	if len(tokens) == 0 {
		return nil, false
	}

	switch tokens[0] {
	case "file":
		if len(tokens) >= 3 && tokens[1] == "upload" {
			return &WorkflowSpec{
				Type:       WorkflowFileUpload,
				LocalPath:  tokens[2],
				RemotePath: getOptionalToken(tokens, 3, filepath.Base(tokens[2])),
			}, true
		}
		if len(tokens) >= 3 && tokens[1] == "download" {
			return &WorkflowSpec{
				Type:       WorkflowFileDownload,
				RemotePath: tokens[2],
				LocalPath:  getOptionalToken(tokens, 3, filepath.Base(tokens[2])),
			}, true
		}
		if len(tokens) >= 2 && (tokens[1] == "list" || tokens[1] == "ls") {
			remoteDir := "/"
			if len(tokens) >= 3 {
				remoteDir = tokens[2]
			}
			return &WorkflowSpec{
				Type:       WorkflowFileList,
				RemotePath: remoteDir,
			}, true
		}
	case "script":
		if len(tokens) >= 3 && tokens[1] == "put" {
			name := tokens[2]
			srcPath := strings.TrimPrefix(sourceFlag, "@")
			return &WorkflowSpec{
				Type:       WorkflowScriptPut,
				ScriptName: name,
				LocalPath:  srcPath,
			}, true
		}
	case "import":
		if len(tokens) >= 2 {
			localPath := tokens[1]
			remotePath := getOptionalToken(tokens, 2, "sshx_import_temp_"+filepath.Base(localPath))
			return &WorkflowSpec{
				Type:       WorkflowImport,
				LocalPath:  localPath,
				RemotePath: remotePath,
			}, true
		}
	case "export":
		if len(tokens) >= 3 && tokens[1] == "download" {
			return &WorkflowSpec{
				Type:      WorkflowExportDownload,
				LocalPath: tokens[2],
			}, true
		}
	case "backup":
		if len(tokens) >= 3 && tokens[1] == "download" {
			return &WorkflowSpec{
				Type:       WorkflowBackupDownload,
				LocalPath:  tokens[2],
				BackupName: "sshx_backup_temp",
			}, true
		}
	}

	return nil, false
}

func getOptionalToken(tokens []string, idx int, defaultVal string) string {
	if idx < len(tokens) && tokens[idx] != "" && !strings.HasPrefix(tokens[idx], "-") {
		return tokens[idx]
	}
	return defaultVal
}

// RenderWorkflowPlanJSON creates a dry-run plan for file/script workflows.
func RenderWorkflowPlanJSON(spec *WorkflowSpec) (string, error) {
	plan := map[string]any{
		"dry_run":          true,
		"operation":        string(spec.Type),
		"transfer_backend": "ssh",
		"local_path":       redactPath(spec.LocalPath),
		"remote_path":      spec.RemotePath,
	}

	switch spec.Type {
	case WorkflowScriptPut:
		plan["schema_version"] = "roswire.workflow.script.put.plan.v1"
		plan["script_name"] = spec.ScriptName
		plan["routeros_command"] = "/system/script/add" //nolint:misspell // RouterOS domain key
		plan["side_effects"] = []string{"creates-ros-script"}
		plan["routeros_file_created"] = false //nolint:misspell // RouterOS domain key
		plan["content_redacted"] = true
	case WorkflowImport:
		plan["schema_version"] = "roswire.workflow.import.plan.v1"
		plan["cleanup"] = spec.Cleanup
		plan["routeros_command"] = "/import file-name=" + spec.RemotePath //nolint:misspell // RouterOS domain key
	case WorkflowExportDownload:
		plan["schema_version"] = "roswire.workflow.export.plan.v1"
		plan["compact"] = spec.Compact
		plan["routeros_command"] = "/export" //nolint:misspell // RouterOS domain key
	case WorkflowBackupDownload:
		plan["schema_version"] = "roswire.workflow.backup.plan.v1"
		plan["backup_name"] = spec.BackupName
		plan["routeros_command"] = "/system backup save" //nolint:misspell // RouterOS domain key
		plan["cleanup"] = spec.Cleanup
	default:
		plan["schema_version"] = "roswire.workflow.file.plan.v1"
	}

	b, err := json.MarshalIndent(plan, "", "  ")
	return string(b), err
}

func redactPath(p string) string {
	if p == "" {
		return ""
	}
	return "***REDACTED***/" + filepath.Base(p)
}

// ExecuteSFTPUpload copies a local file to remote RouterOS using SFTP.
func ExecuteSFTPUpload(sftpClient *sftp.Client, localPath, remotePath string) (int64, error) {
	srcFile, err := os.Open(filepath.Clean(localPath)) // #nosec G304 -- local file path provided via CLI flag
	if err != nil {
		return 0, fmt.Errorf("open local file: %w", err)
	}
	defer func() { _ = srcFile.Close() }() //nolint:errcheck // best-effort file close

	stat, err := srcFile.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat local file: %w", err)
	}

	dstFile, err := sftpClient.Create(remotePath)
	if err != nil {
		return 0, fmt.Errorf("create remote SFTP file %q: %w", remotePath, err)
	}
	defer func() { _ = dstFile.Close() }() //nolint:errcheck // best-effort file close

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return n, fmt.Errorf("copy to remote SFTP file: %w", err)
	}
	if n != stat.Size() {
		return n, fmt.Errorf("partial transfer: copied %d of %d bytes", n, stat.Size())
	}
	return n, nil
}

// ExecuteSFTPDownload copies a remote file on RouterOS to local filesystem using SFTP.
func ExecuteSFTPDownload(sftpClient *sftp.Client, remotePath, localPath string) (int64, error) {
	srcFile, err := sftpClient.Open(remotePath)
	if err != nil {
		return 0, fmt.Errorf("open remote SFTP file %q: %w", remotePath, err)
	}
	defer func() { _ = srcFile.Close() }() //nolint:errcheck // best-effort file close

	if mkdirErr := os.MkdirAll(filepath.Dir(localPath), 0750); mkdirErr != nil {
		return 0, fmt.Errorf("create local directory: %w", mkdirErr)
	}

	dstFile, err := os.Create(filepath.Clean(localPath)) // #nosec G304 -- local target path provided via CLI flag
	if err != nil {
		return 0, fmt.Errorf("create local file %q: %w", localPath, err)
	}
	defer func() { _ = dstFile.Close() }() //nolint:errcheck // best-effort file close

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return n, fmt.Errorf("copy from remote SFTP file: %w", err)
	}
	return n, nil
}

// WaitForRemoteFile polls remote path via SFTP until it exists or deadline is exceeded.
func WaitForRemoteFile(sftpClient *sftp.Client, remotePath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := sftpClient.Stat(remotePath); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for remote file %q (%v)", remotePath, timeout)
}
