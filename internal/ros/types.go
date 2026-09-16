package ros

import (
	"encoding/json"
	"fmt"
)

// ActionKind represents the semantic kind of a RouterOS action.
type ActionKind string

const (
	ActionPrint  ActionKind = "print"
	ActionAdd    ActionKind = "add"
	ActionSet    ActionKind = "set"
	ActionRemove ActionKind = "remove"
	ActionRaw    ActionKind = "raw-routeros-command" //nolint:misspell // RouterOS domain constant
)

// Standard Error Codes matching roswire contract.
const (
	ErrCodeUsageError              = "USAGE_ERROR"
	ErrCodeConfigError             = "CONFIG_ERROR"
	ErrCodeAuthFailed              = "AUTH_FAILED"
	ErrCodeNetworkError            = "NETWORK_ERROR"
	ErrCodeRosExecError            = "ROS_EXEC_ERROR"
	ErrCodeDangerousCommandBlocked = "DANGEROUS_COMMAND_BLOCKED"
	ErrCodeUnsupportedAction       = "UNSUPPORTED_ACTION"
	ErrCodeFileTooLarge            = "FILE_TOO_LARGE"
	ErrCodeFileTransferFailed      = "FILE_TRANSFER_FAILED"
	ErrCodeSchemaUnavailable       = "SCHEMA_UNAVAILABLE"
	ErrCodeInternalError           = "INTERNAL_ERROR"
)

// ArgumentSpec defines one argument accepted by a RouterOS command.
type ArgumentSpec struct {
	Name        string `json:"name"`
	Style       string `json:"style"` // "key-value", "flag", "positional"
	Required    bool   `json:"required"`
	Type        string `json:"type"` // "string", "ip", "cidr", "int", "bool", etc.
	Description string `json:"description"`
	Example     string `json:"example,omitempty"`
}

// CommandMapping specifies the canonical definition of a statically supported RouterOS command.
type CommandMapping struct {
	CLIPath      []string       `json:"cli_path"`
	Action       string         `json:"action"`
	ActionKind   ActionKind     `json:"action_kind"`
	RouterOSPath string         `json:"routeros_path"` //nolint:misspell // RouterOS domain field
	SideEffects  []string       `json:"side_effects"`
	Idempotency  string         `json:"idempotency"` // "read-only", "idempotent", "not-idempotent"
	Summary      string         `json:"summary"`
	Arguments    []ArgumentSpec `json:"arguments,omitempty"`
	Examples     []string       `json:"examples,omitempty"`
}

func (m *CommandMapping) IsRaw() bool {
	return len(m.CLIPath) == 1 && m.CLIPath[0] == "raw"
}

// ROSRequest contains the parsed RouterOS command invocation.
type ROSRequest struct {
	Path         []string          `json:"path"`
	Action       string            `json:"action"`
	Args         map[string]string `json:"args"`
	Flags        []string          `json:"flags"`
	RawCommand   string            `json:"raw_command,omitempty"`
	Mapping      *CommandMapping   `json:"mapping,omitempty"`
	WorkflowName string            `json:"workflow_name,omitempty"`
}

// ROSPlan is the execution plan emitted for dry-run preview.
type ROSPlan struct {
	SchemaVersion      string            `json:"schema_version"`
	DryRun             bool              `json:"dry_run"`
	Command            string            `json:"command"`
	RouterOSPath       string            `json:"routeros_path"` //nolint:misspell // RouterOS domain field
	Action             string            `json:"action"`
	ResolvedArgs       map[string]string `json:"resolved_args"`
	Flags              []string          `json:"flags"`
	SideEffects        []string          `json:"side_effects"`
	Idempotency        string            `json:"idempotency"`
	WillConnect        bool              `json:"will_connect"`
	WillModifyRouterOS bool              `json:"will_modify_routeros"` //nolint:misspell // RouterOS domain field
}

// ROSContext captures the contextual parameters for structured error reporting.
type ROSContext struct {
	Command      string            `json:"command"`
	Path         []string          `json:"path,omitempty"`
	Action       string            `json:"action,omitempty"`
	Host         string            `json:"host,omitempty"`
	ResolvedArgs map[string]string `json:"resolved_args,omitempty"`
}

// ROSErr represents a structured RouterOS error adhering to the roswire JSON contract.
type ROSErr struct {
	ErrorCode string     `json:"error_code"`
	Message   string     `json:"message"`
	Hint      string     `json:"hint,omitempty"`
	Context   ROSContext `json:"context"`
	ExitCode  int        `json:"-"`
}

func (e *ROSErr) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("[%s] %s (hint: %s)", e.ErrorCode, e.Message, e.Hint)
	}
	return fmt.Sprintf("[%s] %s", e.ErrorCode, e.Message)
}

// NewUsageError creates a usage-level error.
func NewUsageError(msg string, hint string) *ROSErr {
	return &ROSErr{
		ErrorCode: ErrCodeUsageError,
		Message:   msg,
		Hint:      hint,
		ExitCode:  2,
	}
}

// NewConfigError creates a configuration error.
func NewConfigError(msg string, hint string) *ROSErr {
	return &ROSErr{
		ErrorCode: ErrCodeConfigError,
		Message:   msg,
		Hint:      hint,
		ExitCode:  2,
	}
}

// NewDangerousCommandError creates a safety guardrail error.
func NewDangerousCommandError(command, reason, hint string) *ROSErr {
	return &ROSErr{
		ErrorCode: ErrCodeDangerousCommandBlocked,
		Message:   fmt.Sprintf("dangerous RouterOS command blocked (%s): %s", command, reason),
		Hint:      hint,
		ExitCode:  255,
	}
}

// ToJSON returns the formatted JSON string for the error.
func (e *ROSErr) ToJSON() string {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error_code":"%s","message":%q}`, e.ErrorCode, e.Message)
	}
	return string(data)
}
