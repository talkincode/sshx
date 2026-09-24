package app

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/talkincode/sshx/internal/sshclient"
)

func TestPrintUsage(t *testing.T) {
	// Call PrintUsage and capture its output.
	output := string(captureStdout(t, PrintUsage))

	// Verify output contains key sections
	expectedSections := []string{
		"SSHX — Agent-native remote host execution over SSH",
		"Usage:",
		"SSH Options:",
		"Sudo Auto-fill:",
		"Dry-run Plan Preview:",
		"Bound Plan Admission:",
		"Shared Execution Evidence:",
		"Audit Trail:",
		"Safety Options:",
		"SFTP Options:",
		"Password Management",
		"Inspection Capabilities:",
		"Guarded SQL Execution:",
		"Guarded File Apply:",
		"Text Dissection:",
		"Interactive Login:",
		"Plugin Management:",
		"Agent Skill Installation:",
		"Environment Variables",
		"SSH Examples:",
		"SFTP Examples:",
		"Password Management Examples:",
	}

	for _, section := range expectedSections {
		if !strings.Contains(output, section) {
			t.Errorf("Expected output to contain section: %s", section)
		}
	}

	// Verify important commands are documented
	importantCommands := []string{
		"sshx -h=",
		"--upload=",
		"--download=",
		"--password-set=",
		"--password-get=",
		"--dry-run",
		"--expect-plan=",
		"--host-timeout=",
		"--global-timeout=",
		"--fail-fast",
		"--max-failures=",
		"--execution-id=",
		"--bind=",
		"--audit-output",
		"--force",
		"--no-safety-check",
		"--bypass-reason",
		"sshx inspect",
		"sshx apply",
		"sshx text",
		"sshx login",
		"sshx plugin create",
		"sshx skill install",
		"SSHX_HOME",
		"SSHX_SECRET_BACKEND",
		"local vault",
	}

	for _, cmd := range importantCommands {
		if !strings.Contains(output, cmd) {
			t.Errorf("Expected output to contain command: %s", cmd)
		}
	}

	// Verify platform mentions
	platforms := []string{"macOS", "Linux", "Windows"}
	for _, platform := range platforms {
		if !strings.Contains(output, platform) {
			t.Errorf("Expected output to mention platform: %s", platform)
		}
	}

	// Verify safety warnings
	safetyKeywords := []string{
		"rm -rf /",
		"BLOCKED",
		"safety check",
		"remote command starts with sudo",
		"Non-leading sudo is not auto-filled",
		"Dry-run never connects",
		"Audit events are JSONL",
		"sshx.plan.v1",
		"plan_mismatch",
		"plan_unresolved",
		"execution_fingerprint",
		"change_state",
		"executed (nullable)",
		"verification_failed",
		"Failure thresholds stop admission only",
		"not guaranteed remote termination",
		"not arbitrary-writer CAS",
		"Row counts are engine-specific",
		"evidence.verification=protocol_verified",
		"Mutation state_change stays unknown",
		"SSHX_MYSQL_HEX_ROWS_V1",
		"Whole-file .backup uses a second",
		"persistence status separate from execution",
	}

	for _, keyword := range safetyKeywords {
		if !strings.Contains(output, keyword) {
			t.Errorf("Expected output to contain safety keyword: %s", keyword)
		}
	}

	// Verify output is not empty
	if len(output) < 100 {
		t.Errorf("Expected longer usage output, got %d characters", len(output))
	}
}

func TestPrintUsage_OutputFormat(t *testing.T) {
	output := string(captureStdout(t, PrintUsage))

	// Verify output starts with newline (for proper formatting)
	if !strings.HasPrefix(output, "\n") {
		t.Error("Expected output to start with newline for formatting")
	}

	// Verify there are multiple lines
	lines := strings.Split(output, "\n")
	if len(lines) < 50 {
		t.Errorf("Expected at least 50 lines of usage text, got %d", len(lines))
	}
}

func TestPrintUsage_Examples(t *testing.T) {
	output := string(captureStdout(t, PrintUsage))

	// Verify practical examples exist
	examples := []string{
		`sshx -h=192.168.1.100 "uptime"`,
		`sshx -h=192.168.1.100 "sudo systemctl status docker"`,
		`sshx --password-set=master`,
		`--upload=local.txt --to=/tmp/remote.txt`,
		`--download=/var/log/app.log`,
		`--audit-output=./.sshx-audit`,
		`sshx inspect -h=prod-web system.baseline --json`,
		`sshx plugin create docker.environment --template=docker`,
		`sshx skill install`,
		`sshx login prod-web`,
	}

	for _, example := range examples {
		if !strings.Contains(output, example) {
			t.Errorf("Expected output to contain example: %s", example)
		}
	}
}

// Every subcommand renders its own usage document, and sshx.help.v1 carries the
// same blocks in machine-readable form. The global help points at both.
func TestPrintVerbUsage(t *testing.T) {
	// sshx text keeps its own Agent-facing document rather than the generic
	// section rendering, in both the human and the JSON variant.
	t.Run("text", func(t *testing.T) {
		output := string(captureStdout(t, func() {
			require.NoError(t, PrintVerbUsage(&sshclient.Config{HelpVerb: "text"}))
		}))
		require.Contains(t, output, "bounded remote text and log dissection")
		require.Contains(t, output, "sshx.text.v1")
	})
	for _, verb := range helpVerbs {
		if verb == "text" {
			continue
		}
		t.Run(verb, func(t *testing.T) {
			var printErr error
			output := string(captureStdout(t, func() {
				printErr = PrintVerbUsage(&sshclient.Config{HelpVerb: verb})
			}))
			require.NoError(t, printErr)
			require.Contains(t, output, "sshx "+verb+" — ")
			require.Contains(t, output, "SSH Options:")
			require.Contains(t, output, "sshx "+verb+" --help --json")
			for _, section := range usageSections() {
				if section.verb == verb {
					require.Contains(t, output, section.title+":")
				}
			}
		})
	}

	unknown := PrintVerbUsage(&sshclient.Config{HelpVerb: "no-such-verb"})
	require.Error(t, unknown)
}

func TestPrintVerbUsageJSON(t *testing.T) {
	for _, verb := range helpVerbs {
		if verb == "text" {
			continue // covered by TestTextHelpJSON in the compiled-binary E2E suite
		}
		t.Run(verb, func(t *testing.T) {
			output := captureStdout(t, func() {
				require.NoError(t, PrintVerbUsage(&sshclient.Config{HelpVerb: verb, JSONOutput: true}))
			})
			var document verbHelpDocument
			require.NoError(t, json.Unmarshal(output, &document))
			require.Equal(t, helpSchemaVersion, document.SchemaVersion)
			require.Equal(t, verb, document.Verb)
			require.NotEmpty(t, document.Summary)
			require.NotEmpty(t, document.Usage)
			for _, section := range document.Usage {
				require.NotEmpty(t, section.Title)
				require.NotEmpty(t, section.Text)
			}
		})
	}
}

func TestSQLHelpDocumentsTargetHostSelector(t *testing.T) {
	output := string(captureStdout(t, func() {
		require.NoError(t, PrintVerbUsage(&sshclient.Config{HelpVerb: "sql"}))
	}))
	require.Contains(t, output, "--target=NAME")
	require.Contains(t, output, "Host selectors --target=NAME, --host=NAME, and -h=NAME are equivalent")
}

func TestRunHelpExplainsSudoScriptPayloads(t *testing.T) {
	output := string(captureStdout(t, func() {
		require.NoError(t, PrintVerbUsage(&sshclient.Config{HelpVerb: "run"}))
	}))
	require.Contains(t, output, "--sudo")
	require.Contains(t, output, "run the selected script interpreter via sudo")
	require.Contains(t, output, "Do not embed sudo")
	require.Contains(t, output, "its stdin is occupied by the script")
	require.Contains(t, output, "inject the password for a nested sudo command")
}

func TestSQLHelpDocumentsFullTableBackupOptIn(t *testing.T) {
	output := string(captureStdout(t, func() {
		require.NoError(t, PrintVerbUsage(&sshclient.Config{HelpVerb: "sql"}))
	}))
	require.Contains(t, output, "--allow-full-table-backup")
	require.Contains(t, output, "full-table backup")
	require.Contains(t, output, "blocked by default")
}

func TestPrintUsageAdvertisesHelpSurfaces(t *testing.T) {
	output := string(captureStdout(t, PrintUsage))
	require.Contains(t, output, "sshx <verb> --help")
	require.Contains(t, output, "--quiet, --no-notices")
	require.Contains(t, output, "should pass --quiet")
}
