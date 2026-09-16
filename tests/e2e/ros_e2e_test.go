package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestROSE2E_Introspection verifies the self-describing introspection commands
// (commands, help, schema, doctor, explain-error) across the compiled sshx binary.
func TestROSE2E_Introspection(t *testing.T) {
	home := t.TempDir()

	// 1. sshx ros commands --json
	res := runSSHX(t, home, []string{"ros", "commands", "--json"}, nil)
	require.Equal(t, 0, res.exitCode, res.stderr)
	var cmds map[string]any
	require.NoError(t, json.Unmarshal([]byte(res.stdout), &cmds))
	assert.Equal(t, "roswire.commands.v1", cmds["schema_version"])
	rawFound := false
	if list, ok := cmds["commands"].([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok && m["name"] == "raw" {
				rawFound = true
				assert.Equal(t, "raw-routeros-command", m["kind"]) //nolint:misspell // RouterOS domain kind
				break
			}
		}
	}
	assert.True(t, rawFound, "commands must contain raw")

	// 2. sshx ros help --json
	resHelp := runSSHX(t, home, []string{"ros", "help", "--json"}, nil)
	require.Equal(t, 0, resHelp.exitCode, resHelp.stderr)
	var helpIndex map[string]any
	require.NoError(t, json.Unmarshal([]byte(resHelp.stdout), &helpIndex))
	assert.Equal(t, "roswire.help.index.v1", helpIndex["schema_version"])

	// 3. sshx ros help raw --json
	resHelpRaw := runSSHX(t, home, []string{"ros", "help", "raw", "--json"}, nil)
	require.Equal(t, 0, resHelpRaw.exitCode, resHelpRaw.stderr)
	var helpRaw map[string]any
	require.NoError(t, json.Unmarshal([]byte(resHelpRaw.stdout), &helpRaw))
	assert.Equal(t, "roswire.help.command.v1", helpRaw["schema_version"])

	// 4. sshx ros schema raw --json & sshx ros schema command raw --json
	resSchemaRaw := runSSHX(t, home, []string{"ros", "schema", "raw", "--json"}, nil)
	require.Equal(t, 0, resSchemaRaw.exitCode, resSchemaRaw.stderr)
	var schemaRaw map[string]any
	require.NoError(t, json.Unmarshal([]byte(resSchemaRaw.stdout), &schemaRaw))
	assert.Equal(t, "raw", schemaRaw["command"])

	resSchemaCmdRaw := runSSHX(t, home, []string{"ros", "schema", "command", "raw", "--json"}, nil)
	require.Equal(t, 0, resSchemaCmdRaw.exitCode, resSchemaCmdRaw.stderr)

	// 5. sshx ros doctor --json
	resDoctor := runSSHX(t, home, []string{"ros", "doctor", "--json"}, nil)
	require.Equal(t, 0, resDoctor.exitCode, resDoctor.stderr)
	var doctor map[string]any
	require.NoError(t, json.Unmarshal([]byte(resDoctor.stdout), &doctor))
	assert.Equal(t, "roswire.doctor.v1", doctor["schema_version"])

	// 6. sshx ros explain-error DANGEROUS_COMMAND_BLOCKED --json
	resExplain := runSSHX(t, home, []string{"ros", "explain-error", "DANGEROUS_COMMAND_BLOCKED", "--json"}, nil)
	require.Equal(t, 0, resExplain.exitCode, resExplain.stderr)
	var explain map[string]any
	require.NoError(t, json.Unmarshal([]byte(resExplain.stdout), &explain))
	assert.Equal(t, "roswire.explain_error.v1", explain["schema_version"])
	assert.Equal(t, "DANGEROUS_COMMAND_BLOCKED", explain["error_code"])
}

// TestROSE2E_DryRun verifies the client execution plans without connecting over SSH.
func TestROSE2E_DryRun(t *testing.T) {
	home := t.TempDir()

	// 1. Catalog print dry-run
	resPrint := runSSHX(t, home, []string{
		"ros", "-h=192.168.88.1", "ip", "address", "print", "--dry-run", "--json",
	}, nil)
	require.Equal(t, 0, resPrint.exitCode, resPrint.stderr)
	var planPrint map[string]any
	require.NoError(t, json.Unmarshal([]byte(resPrint.stdout), &planPrint))
	assert.Equal(t, "roswire.command.plan.v1", planPrint["schema_version"])
	assert.Equal(t, false, planPrint["will_modify_routeros"]) //nolint:misspell // RouterOS domain key
	assert.Equal(t, "read-only", planPrint["idempotency"])

	// 2. Raw print with flags dry-run
	resRawPrint := runSSHX(t, home, []string{
		"ros", "-h=192.168.88.1", "raw", "/interface/print", "detail", "--dry-run", "--json",
	}, nil)
	require.Equal(t, 0, resRawPrint.exitCode, resRawPrint.stderr)
	var planRawPrint map[string]any
	require.NoError(t, json.Unmarshal([]byte(resRawPrint.stdout), &planRawPrint))
	assert.Equal(t, "raw", planRawPrint["action"])
	assert.Equal(t, "/interface/print", planRawPrint["routeros_path"]) //nolint:misspell // RouterOS domain key
	assert.Equal(t, false, planRawPrint["will_modify_routeros"])       //nolint:misspell // RouterOS domain key

	// 3. Raw write dry-run
	resRawWrite := runSSHX(t, home, []string{
		"ros", "-h=192.168.88.1", "raw", "/ip/address/add", "address=10.0.0.1/24", "interface=ether2", "--dry-run", "--json",
	}, nil)
	require.Equal(t, 0, resRawWrite.exitCode, resRawWrite.stderr)
	var planRawWrite map[string]any
	require.NoError(t, json.Unmarshal([]byte(resRawWrite.stdout), &planRawWrite))
	assert.Equal(t, true, planRawWrite["will_modify_routeros"]) //nolint:misspell // RouterOS domain key
	resolvedArgs, ok := planRawWrite["resolved_args"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.1/24", resolvedArgs["address"])
	assert.Equal(t, "ether2", resolvedArgs["interface"])

	// 4. Workflow dry-run
	resWf := runSSHX(t, home, []string{
		"ros", "-h=192.168.88.1", "backup", "download", "my.backup", "--dry-run", "--json",
	}, nil)
	require.Equal(t, 0, resWf.exitCode, resWf.stderr)
	var planWf map[string]any
	require.NoError(t, json.Unmarshal([]byte(resWf.stdout), &planWf))
	assert.Equal(t, "roswire.workflow.backup.plan.v1", planWf["schema_version"])
	assert.Equal(t, "backup_download", planWf["operation"])
	assert.Equal(t, "ssh", planWf["transfer_backend"])
}

// TestROSE2E_SafetyGuardrails verifies dangerous command blocking and raw mutation guards.
func TestROSE2E_SafetyGuardrails(t *testing.T) {
	home := t.TempDir()

	// 1. Dangerous command blocked without force
	resDangerous := runSSHX(t, home, []string{
		"ros", "-h=192.168.88.1", "raw", "/system/reset-configuration",
	}, nil)
	assert.NotEqual(t, 0, resDangerous.exitCode)
	assert.Contains(t, resDangerous.stderr, "DANGEROUS_COMMAND_BLOCKED")

	// 2. Raw mutation blocked without --allow-write
	resRawMut := runSSHX(t, home, []string{
		"ros", "-h=192.168.88.1", "raw", "/ip/address/add", "address=10.0.0.1/24", "interface=ether1",
	}, nil)
	assert.NotEqual(t, 0, resRawMut.exitCode)
	assert.Contains(t, resRawMut.stderr, "require --allow-write")
}

// TestROSE2E_LiveSSHExecution verifies actual network command execution, RouterOS CLI parsing,
// and --raw flag behavior against a mock RouterOS SSH server.
func TestROSE2E_LiveSSHExecution(t *testing.T) {
	mockDetailOutput := " 0   address=192.168.88.1/24 network=192.168.88.0 interface=ether1 actual-interface=ether1 invalid=no dynamic=no disabled=no\n"
	mockResourceOutput := "             uptime: 2w4d12h\n            version: 7.16.1 (stable)\n         build-time: 2024-10-15 08:30:00\n        free-memory: 245.5MiB\n       total-memory: 512.0MiB\n                cpu: MIPS\n          cpu-count: 2\n      cpu-frequency: 880MHz\n           cpu-load: 3%\n"

	var executedCommands []string
	server := startSSHServer(t, serverOptions{
		execHandler: func(ch ssh.Channel, cmd string, role string) {
			executedCommands = append(executedCommands, cmd)
			switch {
			case strings.Contains(cmd, "/ip address print detail"):
				_, _ = io.WriteString(ch, mockDetailOutput) //nolint:errcheck
				sendExitStatus(ch, 0)
			case strings.Contains(cmd, "/system/resource/print") || strings.Contains(cmd, "/system resource print"):
				_, _ = io.WriteString(ch, mockResourceOutput) //nolint:errcheck
				sendExitStatus(ch, 0)
			case strings.Contains(cmd, "/ip/address/add") || strings.Contains(cmd, "/ip address add"):
				// Successful mutation returns empty output in RouterOS CLI
				sendExitStatus(ch, 0)
			case strings.Contains(cmd, "/system/reset-configuration"):
				_, _ = io.WriteString(ch, "configuration reset scheduled\n") //nolint:errcheck
				sendExitStatus(ch, 0)
			default:
				_, _ = io.WriteString(ch.Stderr(), "syntax error\n") //nolint:errcheck
				sendExitStatus(ch, 1)
			}
			_ = ch.Close() //nolint:errcheck
		},
	})
	home := t.TempDir()
	env := map[string]string{"SSH_PASSWORD": operatorPassword}
	base := []string{
		"ros",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
	}

	// 1. Execute print query with structured JSON output
	resPrint := runSSHX(t, home, append(append([]string{}, base...),
		"ip", "address", "print", "detail", "--json",
	), env)
	require.Equal(t, 0, resPrint.exitCode, "stderr=%s stdout=%s", resPrint.stderr, resPrint.stdout)
	var printJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(resPrint.stdout), &printJSON))
	assert.Equal(t, "ok", printJSON["status"])
	assert.Equal(t, true, printJSON["success"])
	dataList, ok := printJSON["data"].([]any)
	require.True(t, ok, "expected data array in json: %v", printJSON["data"])
	require.Len(t, dataList, 1)
	record, ok := dataList[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "192.168.88.1/24", record["address"])
	assert.Equal(t, "ether1", record["interface"])

	// 2. Execute raw read command with colon record parsing
	resRaw := runSSHX(t, home, append(append([]string{}, base...),
		"raw", "/system/resource/print", "--json",
	), env)
	require.Equal(t, 0, resRaw.exitCode, "stderr=%s stdout=%s", resRaw.stderr, resRaw.stdout)
	var rawJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(resRaw.stdout), &rawJSON))
	assert.Equal(t, "ok", rawJSON["status"])
	resMap, ok := rawJSON["data"].(map[string]any)
	require.True(t, ok, "expected parsed data map for colon records")
	assert.Equal(t, "7.16.1 (stable)", resMap["version"])
	assert.Equal(t, "2", fmt.Sprintf("%v", resMap["cpu-count"]))

	// 3. Raw command with --raw flag suppresses output parsing
	resRawSuppressed := runSSHX(t, home, append(append([]string{}, base...),
		"raw", "/system/resource/print", "--raw", "--json",
	), env)
	require.Equal(t, 0, resRawSuppressed.exitCode, resRawSuppressed.stderr)
	var rawSupJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(resRawSuppressed.stdout), &rawSupJSON))
	assert.Nil(t, rawSupJSON["data"], "data should be nil when --raw flag is specified")
	rawOut, ok := rawSupJSON["stdout"].(string)
	require.True(t, ok)
	assert.Contains(t, rawOut, "7.16.1 (stable)")

	// 4. Raw mutative command with --allow-write succeeds
	resRawAdd := runSSHX(t, home, append(append([]string{}, base...),
		"raw", "/ip/address/add", "address=10.0.0.1/24", "interface=ether2", "--allow-write", "--json",
	), env)
	require.Equal(t, 0, resRawAdd.exitCode, "stderr=%s stdout=%s", resRawAdd.stderr, resRawAdd.stdout)
	var addJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(resRawAdd.stdout), &addJSON))
	assert.Equal(t, "ok", addJSON["status"])

	// 5. Dangerous command with --force succeeds
	resForce := runSSHX(t, home, append(append([]string{}, base...),
		"raw", "/system/reset-configuration", "--force", "--json",
	), env)
	require.Equal(t, 0, resForce.exitCode, "stderr=%s stdout=%s", resForce.stderr, resForce.stdout)
	var forceJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(resForce.stdout), &forceJSON))
	assert.Equal(t, "ok", forceJSON["status"])

	// Verify command strings dispatched over SSH
	assert.Contains(t, executedCommands[0], "without-paging")
}

// TestROSE2E_LiveWorkflows verifies SFTP file operations, backup, export, and script workflows
// against the mock server's real SFTP filesystem backend.
func TestROSE2E_LiveWorkflows(t *testing.T) {
	var executedCommands []string
	var serverRoot string

	server := startSSHServer(t, serverOptions{
		execHandler: func(ch ssh.Channel, cmd string, role string) {
			executedCommands = append(executedCommands, cmd)
			switch {
			case strings.Contains(cmd, "backup") && strings.Contains(cmd, "save"):
				name := "test_backup"
				if idx := strings.Index(cmd, "name="); idx != -1 {
					name = strings.Fields(cmd[idx+5:])[0]
				}
				backupFile := filepath.Join(serverRoot, name+".backup")
				_ = os.WriteFile(backupFile, []byte("ROUTEROS-BINARY-BACKUP-PAYLOAD"), 0o600)                                          //nolint:errcheck,misspell // fixture backup file
				_, _ = io.WriteString(ch, fmt.Sprintf("Saving system configuration\nConfiguration backup saved to %s.backup\n", name)) //nolint:errcheck
				sendExitStatus(ch, 0)
			case strings.HasPrefix(cmd, "/export"):
				for _, part := range strings.Fields(cmd) {
					if strings.HasPrefix(part, "file=") {
						name := strings.TrimPrefix(part, "file=")
						exportFile := filepath.Join(serverRoot, name)
						_ = os.WriteFile(exportFile, []byte("# RouterOS export script\n/ip address add address=192.168.88.1/24\n"), 0o600) //nolint:errcheck // fixture export file
						break
					}
				}
				sendExitStatus(ch, 0)
			case strings.Contains(cmd, "script") && (strings.Contains(cmd, "add") || strings.Contains(cmd, "set")):
				sendExitStatus(ch, 0)
			case strings.Contains(cmd, "/file"):
				sendExitStatus(ch, 0)
			default:
				sendExitStatus(ch, 0)
			}
			_ = ch.Close() //nolint:errcheck
		},
	})
	serverRoot = server.root

	home := t.TempDir()
	env := map[string]string{"SSH_PASSWORD": operatorPassword}
	base := []string{
		"ros",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
	}

	// 1. file upload via SFTP
	localUpload := filepath.Join(home, "upload.rsc")
	require.NoError(t, os.WriteFile(localUpload, []byte("/system identity set name=test-router\n"), 0o600))
	resUpload := runSSHX(t, home, append(append([]string{}, base...),
		"file", "upload", localUpload, "upload.rsc", "--json",
	), env)
	require.Equal(t, 0, resUpload.exitCode, "upload stderr=%s", resUpload.stderr)
	uploadedContent, err := os.ReadFile(filepath.Clean(filepath.Join(server.root, "upload.rsc"))) // #nosec G304 -- test file verification
	require.NoError(t, err)
	assert.Equal(t, "/system identity set name=test-router\n", string(uploadedContent))

	// 2. file download via SFTP
	remoteFile := filepath.Join(server.root, "download_test.txt")
	require.NoError(t, os.WriteFile(remoteFile, []byte("remote-router-config\n"), 0o600))
	localDownload := filepath.Join(home, "downloaded.txt")
	resDownload := runSSHX(t, home, append(append([]string{}, base...),
		"file", "download", "download_test.txt", localDownload, "--json",
	), env)
	require.Equal(t, 0, resDownload.exitCode, "download stderr=%s", resDownload.stderr)
	downloadedContent, err := os.ReadFile(filepath.Clean(localDownload)) // #nosec G304 -- test file verification
	require.NoError(t, err)
	assert.Equal(t, "remote-router-config\n", string(downloadedContent))

	// 3. backup download with --cleanup
	localBackup := filepath.Join(home, "router.backup")
	resBackup := runSSHX(t, home, append(append([]string{}, base...),
		"backup", "download", localBackup, "--name=test_backup", "--cleanup", "--json",
	), env)
	require.Equal(t, 0, resBackup.exitCode, "backup stderr=%s", resBackup.stderr)
	backupBytes, err := os.ReadFile(filepath.Clean(localBackup)) // #nosec G304 -- test file verification
	require.NoError(t, err)
	assert.Equal(t, "ROUTEROS-BINARY-BACKUP-PAYLOAD", string(backupBytes)) //nolint:misspell // test payload token

	// 4. export download with --compact and --cleanup
	localExport := filepath.Join(home, "export.rsc")
	resExport := runSSHX(t, home, append(append([]string{}, base...),
		"export", "download", localExport, "--compact", "--cleanup", "--json",
	), env)
	require.Equal(t, 0, resExport.exitCode, "export stderr=%s", resExport.stderr)
	exportBytes, err := os.ReadFile(filepath.Clean(localExport)) // #nosec G304 -- test file verification
	require.NoError(t, err)
	assert.Contains(t, string(exportBytes), "/ip address add")

	// 5. script put with --source
	localScript := filepath.Join(home, "my_script.rsc")
	require.NoError(t, os.WriteFile(localScript, []byte(":log info \"hello ros\"\n"), 0o600))
	resScript := runSSHX(t, home, append(append([]string{}, base...),
		"script", "put", "my-script", "--source=@"+localScript, "--json",
	), env)
	require.Equal(t, 0, resScript.exitCode, "script put stderr=%s", resScript.stderr)
	var scriptJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(resScript.stdout), &scriptJSON))
	assert.Equal(t, "ok", scriptJSON["status"])
}

// TestROSE2E_MCPToolCall verifies AI agent invocation of the sshx_ros MCP tool.
func TestROSE2E_MCPToolCall(t *testing.T) {
	server := startSSHServer(t, serverOptions{
		execHandler: func(ch ssh.Channel, cmd string, role string) {
			if strings.Contains(cmd, "/system/resource/print") {
				_, _ = io.WriteString(ch, "  uptime: 10d\n  version: 7.16\n") //nolint:errcheck
				sendExitStatus(ch, 0)
			} else {
				sendExitStatus(ch, 0)
			}
			_ = ch.Close() //nolint:errcheck
		},
	})
	home := t.TempDir()
	env := map[string]string{
		"SSH_PASSWORD": operatorPassword,
	}

	client := startMCPClient(t, home, env)

	// Dry run tool call over MCP stdio
	isErr, out := client.callTool("sshx_ros", map[string]any{
		"target":  server.host,
		"port":    22,
		"user":    "operator",
		"command": "raw /system/resource/print",
		"dry_run": true,
	})
	require.False(t, isErr, "MCP callTool returned error: %s", out)
	var plan map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &plan))
	assert.Equal(t, "roswire.command.plan.v1", plan["schema_version"])
	assert.Equal(t, "raw", plan["action"])
	assert.Equal(t, "/system/resource/print", plan["routeros_path"]) //nolint:misspell // RouterOS domain key
}
