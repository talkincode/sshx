package app

import (
	"fmt"
	"strings"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sshclient"
)

// Version is the sshx build version, set by the main package at startup
// (injected via -ldflags). Defaults to "dev" for go test / go run builds.
var Version = "dev"

// helpSchemaVersion is the schema of the generic per-verb help document.
const helpSchemaVersion = "sshx.help.v1"

// usageSection is one titled block of the sshx help surface. `sshx --help`
// prints every block in order; `sshx <verb> --help` prints that verb's blocks
// plus the shared option blocks. The text is defined once, in
// usage_sections.go, so the per-verb help cannot drift from the global help.
type usageSection struct {
	title   string
	verb    string // empty for blocks that no single verb owns
	summary string // one line, emitted by sshx.help.v1
	text    string
}

// helpVerbs are the subcommands that answer `sshx <verb> --help`.
var helpVerbs = []string{"run", "apply", "sql", "text", "inspect", "plugin", "skill", "audit", "login", "mcp", "ros"}

// verbSharedSections are the blocks every remote verb accepts, repeated in each
// per-verb help so one call answers "what may I pass here?".
var verbSharedSections = []string{
	"SSH Options",
	"Agent / Scripting Mode",
	"Sudo Auto-fill",
	"Dry-run Plan Preview",
	"Audit Trail",
	"Safety Options",
}

// usageSections returns every help block in global-help order.
func usageSections() []usageSection {
	return []usageSection{
		{title: "Usage", verb: "", summary: "", text: usageIntro},
		{title: "SSH Options", verb: "", summary: "", text: usageSSHOptions},
		{title: "Run Contract (preferred for Agents)", verb: "run", summary: "Execute one command or script across selected hosts with the versioned sshx.run contract.", text: usageRun},
		{title: "Agent / Scripting Mode", verb: "", summary: "", text: usageAgentMode},
		{title: "Sudo Auto-fill", verb: "", summary: "", text: usageSudoAutoFill},
		{title: "Dry-run Plan Preview", verb: "", summary: "", text: usageDryRun},
		{title: "Audit Trail", verb: "", summary: "", text: usageAuditTrail},
		{title: "Audit Query and Export", verb: "audit", summary: "Query or export the local structured audit trail without connecting or writing.", text: usageAuditQuery},
		{title: "Safety Options", verb: "", summary: "", text: usageSafety},
		{title: "SFTP Options", verb: "", summary: "", text: usageSFTP},
		{title: "Server-to-Server Transfer", verb: "", summary: "", text: usageTransfer},
		{title: "Password Management (Cross-Platform)", verb: "", summary: "", text: usagePassword},
		{title: "Host Management", verb: "", summary: "", text: usageHost},
		{title: "Inspection Capabilities", verb: "inspect", summary: "Collect or reuse one structured host observation from a built-in or local capability.", text: usageInspect},
		{title: "Guarded SQL Execution", verb: "sql", summary: "Run one guarded SQL statement through the database client already present on the remote host.", text: usageSQL},
		{title: "MikroTik RouterOS (ROS) over SSH", verb: "ros", summary: "Manage MikroTik RouterOS devices over SSH and SFTP with structured commands.", text: usageROS},
		{title: "Guarded File Apply", verb: "apply", summary: "Replace one remote regular file with a precondition, backup, and post-write verification pipeline.", text: usageApply},
		{title: "Text Dissection", verb: "", summary: "", text: usageText},
		{title: "Interactive Login", verb: "login", summary: "Open one human interactive TTY session on a host already known to sshx.", text: usageLogin},
		{title: "Plugin Management", verb: "plugin", summary: "Install, create, list, validate, trust, and remove local inspection plugins.", text: usagePlugin},
		{title: "Agent Skill Installation", verb: "skill", summary: "Install or update the sshx Agent skill embedded in the binary.", text: usageSkill},
		{title: "MCP Server (stdio)", verb: "mcp", summary: "Serve the sshx execution contract over stdio to an MCP client.", text: usageMCP},
		{title: "Environment Variables (.env)", verb: "", summary: "", text: usageEnv},
		{title: "SSH Examples", verb: "", summary: "", text: usageSSHExamples},
		{title: "Inspection Examples", verb: "inspect", summary: "", text: usageInspectExamples},
		{title: "Agent Skill Example", verb: "skill", summary: "", text: usageSkillExample},
		{title: "SFTP Examples", verb: "", summary: "", text: usageSFTPExamples},
		{title: "Server-to-Server Transfer Examples", verb: "", summary: "", text: usageTransferExamples},
		{title: "Password Management Examples", verb: "", summary: "", text: usagePasswordExamples},
		{title: "Host Management Examples", verb: "", summary: "", text: usageHostExamples},
		{title: "Note", verb: "", summary: "", text: usageNotes},
	}
}

// PrintUsage prints the global sshx help surface.
func PrintUsage() {
	fmt.Printf("\nSSHX — Agent-native remote host execution over SSH\nVersion: %s\n", Version)
	for _, section := range usageSections() {
		fmt.Print(section.text)
	}
	fmt.Println()
}

// PrintVerbUsage answers `sshx <verb> --help`: the verb's own blocks, the
// shared option blocks, and a pointer to the global surface. With --json it
// emits the sshx.help.v1 document instead of prose. `sshx text` keeps its
// dedicated Agent-facing document and its own sshx.text.help.v1 schema.
func PrintVerbUsage(config *sshclient.Config) error {
	verb := config.HelpVerb
	if verb == "text" {
		return HandleTextHelp(config)
	}
	sections := verbUsageSections(verb)
	if len(sections) == 0 {
		return fmt.Errorf("%w: unknown help verb %q (known verbs: %s)", execution.ErrConfig, verb, strings.Join(helpVerbs, ", "))
	}
	if config.JSONOutput {
		document := verbHelpDocument{
			SchemaVersion: helpSchemaVersion, Verb: verb,
			Summary: verbSummary(sections), Usage: helpDocumentSections(sections),
		}
		if err := encodeJSON(document); err != nil {
			return fmt.Errorf("%w: deliver help: %w", execution.ErrLocalIO, err)
		}
		return nil
	}
	fmt.Print(renderVerbUsage(verb, sections))
	return nil
}

// verbHelpDocument is the machine-readable form of a per-verb help surface.
type verbHelpDocument struct {
	SchemaVersion string            `json:"schema_version"`
	Verb          string            `json:"verb"`
	Summary       string            `json:"summary"`
	Usage         []verbHelpSection `json:"usage"`
}

type verbHelpSection struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

// verbUsageSections returns the blocks printed by `sshx <verb> --help`: the
// verb's own blocks first, then the shared option blocks. An unknown verb
// returns nil so the caller can report it.
func verbUsageSections(verb string) []usageSection {
	if !containsString(helpVerbs, verb) {
		return nil
	}
	var sections []usageSection
	for _, section := range usageSections() {
		if section.verb == verb {
			sections = append(sections, section)
		}
	}
	for _, section := range usageSections() {
		if section.verb == "" && containsString(verbSharedSections, section.title) {
			sections = append(sections, section)
		}
	}
	return sections
}

func verbSummary(sections []usageSection) string {
	for _, section := range sections {
		if section.summary != "" {
			return section.summary
		}
	}
	return ""
}

func helpDocumentSections(sections []usageSection) []verbHelpSection {
	document := make([]verbHelpSection, 0, len(sections))
	for _, section := range sections {
		document = append(document, verbHelpSection{Title: section.title, Text: strings.TrimRight(section.text, "\n")})
	}
	return document
}

func renderVerbUsage(verb string, sections []usageSection) string {
	var out strings.Builder
	fmt.Fprintf(&out, "sshx %s — %s\n\n", verb, verbSummary(sections))
	for _, section := range sections {
		if section.verb == verb {
			out.WriteString(section.text)
		}
	}
	out.WriteString("Shared options and semantics:\n")
	for _, section := range sections {
		if section.verb == "" {
			out.WriteString(section.text)
		}
	}
	fmt.Fprintf(&out, "See also:\n  %-28s full help surface\n  %-28s this document as %s\n",
		"sshx --help", "sshx "+verb+" --help --json", helpSchemaVersion)
	return out.String()
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// PrintTextUsage is the dedicated Agent-facing help for sshx text.
func PrintTextUsage() {
	fmt.Print(`sshx text — bounded remote text and log dissection

Use this instead of sshx run grep/journalctl pipelines. It streams a remote
file or a sshx-owned journalctl invocation, classifies exception blocks, and
returns bounded redacted hits.

Workflow:
  1. sshx text --help
     sshx text --help --json
  2. sshx text -h=<host> --path=/var/log/app.log --preset=exception --json
  3. sshx text -h=<host> --path=/var/log/app.log --around-line=<line> --context=5 --json
  4. sshx --download only when you need an incident archive

Sources (exactly one):
  --path=/abs/file       SFTP stream of a regular file (default --scan=end, last 8MiB)
  --journal=UNIT         sshx-owned journalctl --unit=UNIT --no-pager --output=short-iso

Filters:
  --preset=exception,error,panic,oom,http5xx
  --pattern=RE2          optional linear-time regexp (Go RE2, not PCRE)

Windows:
  --context=N            0..20 neighbor lines
  --around-line=L        slice around a previous hit
  --offset=L --limit=N   line window inside the scanned bytes
  --tail=N               last N scanned lines
  --scan=start|end       file origin (default end)
  --since= --until=      journal time bounds (no shell metacharacters)

Bounds and safety:
  --max-hits=N           default 20
  --max-bytes=N          default 64KiB of returned hit text
  --max-scan-bytes=N     default 8MiB
  --sudo                 sudo -S for unread files/journals
  --no-redact            keep password=/token=/JWT spans (redacted by default)
  --dry-run --json       local plan, zero connection

There is no --command. JSON schema is sshx.text.v1. Branch on success,
hits[].kind, stats.total_hits vs returned, truncated, truncated_reason,
and line_origin (file vs scanned_window).

Examples:
  sshx text -h=prod-web --path=/var/log/nginx/error.log --preset=exception --json
  sshx text -h=prod-web --journal=nginx.service --since=1h --preset=error --json
  sshx text -h=prod-web --path=/var/log/app.log --around-line=8821 --context=8 --json
`)
}
