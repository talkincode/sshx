package ros

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CommandsPayload mirrors roswire.commands.v1 schema.
type CommandsPayload struct {
	SchemaVersion string           `json:"schema_version"`
	Commands      []CommandSummary `json:"commands"`
}

type CommandSummary struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	Kind    string `json:"kind"`
}

// HelpIndexPayload mirrors roswire.help.index.v1 schema.
type HelpIndexPayload struct {
	SchemaVersion string           `json:"schema_version"`
	GlobalOptions []string         `json:"global_options"`
	Commands      []CommandSummary `json:"commands"`
}

// HelpCommandPayload mirrors roswire.help.command.v1 schema.
type HelpCommandPayload struct {
	SchemaVersion string         `json:"schema_version"`
	Command       CommandMapping `json:"command"`
}

// SchemaPayload mirrors roswire.schema.v1 schema.
type SchemaPayload struct {
	SchemaVersion string         `json:"schema_version"`
	Command       string         `json:"command"`
	Arguments     []ArgumentSpec `json:"arguments"`
}

// ExplainErrorPayload mirrors roswire.explain_error.v1 schema.
type ExplainErrorPayload struct {
	SchemaVersion      string   `json:"schema_version"`
	ErrorCode          string   `json:"error_code"`
	Summary            string   `json:"summary"`
	CommonCauses       []string `json:"common_causes"`
	SuggestedNextSteps []string `json:"suggested_next_steps"`
}

// DoctorPayload mirrors roswire.doctor.v1 schema.
type DoctorPayload struct {
	SchemaVersion    string        `json:"schema_version"`
	Local            LocalDoctor   `json:"local"`
	Remote           *RemoteDoctor `json:"remote,omitempty"`
	SelectedProtocol string        `json:"selected_protocol"`
	RouterOSVersion  string        `json:"routeros_version,omitempty"` //nolint:misspell // RouterOS domain field
	Warnings         []string      `json:"warnings"`
}

type LocalDoctor struct {
	HomeExists    bool              `json:"home_exists"`
	ConfigExists  bool              `json:"config_exists"`
	PermissionsOK bool              `json:"permissions_ok"`
	SSHKeysFound  []string          `json:"ssh_keys_found,omitempty"`
	Dependencies  map[string]string `json:"dependencies"`
	Warnings      []string          `json:"warnings"`
}

type RemoteDoctor struct {
	Status          string   `json:"status"`
	RouterOSVersion string   `json:"routeros_version,omitempty"` //nolint:misspell // RouterOS domain field
	Architecture    string   `json:"architecture,omitempty"`
	BoardName       string   `json:"board_name,omitempty"`
	Uptime          string   `json:"uptime,omitempty"`
	Warnings        []string `json:"warnings"`
}

// RenderCommandsJSON returns the JSON string for `commands`.
func RenderCommandsJSON() (string, error) {
	cmds := AllCommands()
	summaries := make([]CommandSummary, len(cmds))
	for i, c := range cmds {
		name := strings.Join(c.CLIPath, " ")
		if c.Action != "" && c.Action != "raw" {
			name += " " + c.Action
		}
		summaries[i] = CommandSummary{
			Name:    name,
			Summary: c.Summary,
			Kind:    string(c.ActionKind),
		}
	}
	payload := CommandsPayload{
		SchemaVersion: "roswire.commands.v1",
		Commands:      summaries,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	return string(b), err
}

// RenderHelpJSON returns the JSON string for `help` or `help <command>`.
func RenderHelpJSON(tokens []string) (string, error) {
	if len(tokens) == 0 {
		cmds := AllCommands()
		summaries := make([]CommandSummary, len(cmds))
		for i, c := range cmds {
			name := strings.Join(c.CLIPath, " ")
			if c.Action != "" && c.Action != "raw" {
				name += " " + c.Action
			}
			summaries[i] = CommandSummary{
				Name:    name,
				Summary: c.Summary,
				Kind:    string(c.ActionKind),
			}
		}
		payload := HelpIndexPayload{
			SchemaVersion: "roswire.help.index.v1",
			GlobalOptions: []string{
				"-h, --host",
				"-p, --port",
				"-u, --user",
				"-i, --key",
				"--ssh-password-key",
				"--json",
				"--dry-run",
				"--allow-write",
				"--force",
				"--timeout",
				"--raw",
			},
			Commands: summaries,
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		return string(b), err
	}

	// Lookup specific command
	path := tokens[:len(tokens)-1]
	action := tokens[len(tokens)-1]
	mapping, ok := LookupCommand(path, action)
	if !ok {
		// Try dynamic or entire tokens as path with "print"
		mapping, ok = LookupCommand(tokens, "print")
	}
	if !ok && len(tokens) == 1 {
		mapping, ok = LookupCommand(tokens, "")
	}
	if !ok {
		return "", NewUsageError(fmt.Sprintf("unknown command %q for help", strings.Join(tokens, " ")), "run `sshx ros commands` to list all available commands")
	}

	payload := HelpCommandPayload{
		SchemaVersion: "roswire.help.command.v1",
		Command:       *mapping,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	return string(b), err
}

// RenderSchemaJSON returns the JSON string for `schema <command>`.
func RenderSchemaJSON(tokens []string) (string, error) {
	if len(tokens) == 0 {
		return "", NewUsageError("schema requires a command", "example: `sshx ros schema ip address add`")
	}

	path := tokens[:len(tokens)-1]
	action := tokens[len(tokens)-1]
	mapping, ok := LookupCommand(path, action)
	if !ok {
		mapping, ok = LookupCommand(tokens, "print")
	}
	if !ok && len(tokens) == 1 {
		mapping, ok = LookupCommand(tokens, "")
	}
	if !ok {
		return "", NewUsageError(fmt.Sprintf("unknown command %q for schema", strings.Join(tokens, " ")), "run `sshx ros commands` to list all available commands")
	}

	cmdName := strings.Join(mapping.CLIPath, " ")
	if mapping.Action != "" && mapping.Action != "raw" {
		cmdName += " " + mapping.Action
	}

	payload := SchemaPayload{
		SchemaVersion: "roswire.schema.v1",
		Command:       cmdName,
		Arguments:     mapping.Arguments,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	return string(b), err
}

var errorExplanations = map[string]ExplainErrorPayload{
	ErrCodeUsageError: {
		SchemaVersion: "roswire.explain_error.v1",
		ErrorCode:     ErrCodeUsageError,
		Summary:       "Command usage or argument specification error",
		CommonCauses: []string{
			"Missing required arguments (e.g. address=... interface=...)",
			"Invalid subcommand or action syntax",
			"Raw mutating command executed without --allow-write",
		},
		SuggestedNextSteps: []string{
			"Run `sshx ros help <command>` to check the argument syntax",
			"Add --allow-write if you intend to perform raw state-modifying operations",
		},
	},
	ErrCodeDangerousCommandBlocked: {
		SchemaVersion: "roswire.explain_error.v1",
		ErrorCode:     ErrCodeDangerousCommandBlocked,
		Summary:       "Potentially destructive router operation was blocked by safety guardrail",
		CommonCauses: []string{
			"Command matches destructive patterns like reset-configuration, reboot, or shutdown",
		},
		SuggestedNextSteps: []string{
			"If this action was intentional, pass --force to bypass safety guardrail",
		},
	},
	ErrCodeAuthFailed: {
		SchemaVersion: "roswire.explain_error.v1",
		ErrorCode:     ErrCodeAuthFailed,
		Summary:       "SSH authentication to RouterOS failed",
		CommonCauses: []string{
			"Invalid username or password",
			"Public key not installed or configured on RouterOS (/user ssh-keys)",
			"Incorrect password keyring key name",
		},
		SuggestedNextSteps: []string{
			"Check your username (-u) and SSH key (-i) or password key (--ssh-password-key)",
			"Verify login credentials via direct `ssh user@host`",
		},
	},
	ErrCodeNetworkError: {
		SchemaVersion: "roswire.explain_error.v1",
		ErrorCode:     ErrCodeNetworkError,
		Summary:       "Unable to establish SSH TCP connection to RouterOS",
		CommonCauses: []string{
			"RouterOS host IP unreachable or firewall blocking port 22",
			"RouterOS SSH service (/ip service ssh) is disabled or listening on a custom port",
		},
		SuggestedNextSteps: []string{
			"Verify network route and ping to the router",
			"Specify custom port with -p=<port> if SSH is running on a non-standard port",
		},
	},
	ErrCodeFileTransferFailed: {
		SchemaVersion: "roswire.explain_error.v1",
		ErrorCode:     ErrCodeFileTransferFailed,
		Summary:       "SFTP file transfer failed between local host and RouterOS",
		CommonCauses: []string{
			"Remote path invalid or permission denied on RouterOS disk/flash",
			"Disk full on target RouterBOARD storage",
		},
		SuggestedNextSteps: []string{
			"Check storage capacity with `sshx ros -h=router system resource print`",
			"Verify target directory name (e.g. flash/ on NAND devices)",
		},
	},
}

// RenderExplainErrorJSON returns the JSON explanation for an error code.
func RenderExplainErrorJSON(code string) (string, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if exp, ok := errorExplanations[code]; ok {
		b, err := json.MarshalIndent(exp, "", "  ")
		return string(b), err
	}
	// Default fallback
	exp := ExplainErrorPayload{
		SchemaVersion: "roswire.explain_error.v1",
		ErrorCode:     code,
		Summary:       "RouterOS operational error: " + code,
		CommonCauses: []string{
			"Check execution context and error message for details",
		},
		SuggestedNextSteps: []string{
			"Run `sshx ros doctor` to inspect environment health",
		},
	}
	b, err := json.MarshalIndent(exp, "", "  ")
	return string(b), err
}
