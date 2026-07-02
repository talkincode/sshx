package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/talkincode/sshx/internal/sshclient"
)

type dryRunStatus struct {
	Status    string `json:"status"`
	ErrorKind string `json:"error_kind,omitempty"`
	Message   string `json:"message,omitempty"`
}

type dryRunPlan struct {
	DryRun bool `json:"dry_run"`
	Valid  bool `json:"valid"`

	Mode   string `json:"mode"`
	Action string `json:"action,omitempty"`

	HostInput      string       `json:"host_input,omitempty"`
	HostResolved   string       `json:"host_resolved,omitempty"`
	HostResolution dryRunStatus `json:"host_resolution,omitempty"`
	Port           string       `json:"port,omitempty"`
	User           string       `json:"user,omitempty"`

	Command    string `json:"command,omitempty"`
	SftpAction string `json:"sftp_action,omitempty"`
	LocalPath  string `json:"local_path,omitempty"`
	RemotePath string `json:"remote_path,omitempty"`

	TransferSource string `json:"transfer_source,omitempty"`
	TransferDest   string `json:"transfer_destination,omitempty"`

	UseKeyAuth       bool   `json:"use_key_auth"`
	KeyPath          string `json:"key_path,omitempty"`
	PasswordProvided bool   `json:"password_provided"`
	UsesSudo         bool   `json:"uses_sudo"`
	SudoKey          string `json:"sudo_key,omitempty"`

	Timeout              string `json:"timeout,omitempty"`
	JSONOutput           bool   `json:"json_output"`
	UsePTY               bool   `json:"pty"`
	SafetyCheckEnabled   bool   `json:"safety_check_enabled"`
	Force                bool   `json:"force"`
	AcceptUnknownHost    bool   `json:"accept_unknown_host"`
	AllowInsecureHostKey bool   `json:"allow_insecure_host_key"`
	KnownHostsPath       string `json:"known_hosts_path,omitempty"`

	ConfigCheck dryRunStatus `json:"config_check"`
	SafetyCheck dryRunStatus `json:"safety_check"`

	WouldConnect          bool `json:"would_connect"`
	WouldExecute          bool `json:"would_execute"`
	WouldReadSecret       bool `json:"would_read_secret"`
	WouldWriteLocalState  bool `json:"would_write_local_state"`
	WouldMutateRemote     bool `json:"would_mutate_remote"`
	MayMutateKnownHosts   bool `json:"may_mutate_known_hosts"`
	WouldPromptForSecret  bool `json:"would_prompt_for_secret"`
	WouldLookupHostConfig bool `json:"would_lookup_host_config"`

	Notes []string `json:"notes,omitempty"`

	hostTestReadsSecret bool
}

func emitDryRunPlan(config *sshclient.Config) error {
	plan := buildDryRunPlan(config)
	if config.JSONOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(plan)
	}
	printDryRunPlan(plan)
	return nil
}

func buildDryRunPlan(config *sshclient.Config) dryRunPlan {
	plan := dryRunPlan{
		DryRun:               true,
		Valid:                true,
		Mode:                 config.Mode,
		UseKeyAuth:           config.UseKeyAuth,
		PasswordProvided:     config.Password != "",
		JSONOutput:           config.JSONOutput,
		UsePTY:               config.UsePTY,
		SafetyCheckEnabled:   config.SafetyCheck,
		Force:                config.Force,
		AcceptUnknownHost:    config.AcceptUnknownHost,
		AllowInsecureHostKey: config.AllowInsecureHostKey,
		KnownHostsPath:       config.KnownHostsPath,
		ConfigCheck:          dryRunStatus{Status: "passed"},
		SafetyCheck:          dryRunStatus{Status: "not_applicable"},
		Notes: []string{
			"dry-run does not connect, execute, read keyring secrets, mutate known_hosts, or write local/remote state",
		},
	}

	applyDryRunDefaults(config, &plan)
	fillDryRunAction(config, &plan)
	fillDryRunHost(config, &plan)
	fillDryRunKeyDefault(config, &plan)
	fillDryRunSudo(config, &plan)
	fillDryRunValidation(config, &plan)
	fillDryRunEffects(config, &plan)

	return plan
}

func applyDryRunDefaults(config *sshclient.Config, plan *dryRunPlan) {
	if config.Port == "" && modeUsesSSHConnection(config) {
		config.Port = sshclient.DefaultSSHPort
	}
	if config.User == "" && modeUsesSSHConnection(config) {
		config.User = sshclient.DefaultSSHUser
	}
	plan.Port = config.Port
	plan.User = config.User
	if config.Timeout > 0 {
		plan.Timeout = config.Timeout.String()
	}
}

func fillDryRunAction(config *sshclient.Config, plan *dryRunPlan) {
	switch config.Mode {
	case "ssh":
		plan.Action = "command"
		plan.Command = config.Command
	case "sftp":
		plan.Action = config.SftpAction
		plan.SftpAction = config.SftpAction
		plan.LocalPath = config.LocalPath
		plan.RemotePath = config.RemotePath
	case "password":
		plan.Action = config.PasswordAction
	case "host":
		plan.Action = config.HostAction
	case "transfer":
		plan.Action = "transfer"
		plan.TransferSource = formatTransferEndpoint(config.TransferSrcHost, config.TransferSrcPath)
		plan.TransferDest = formatTransferEndpoint(config.TransferDstHost, config.TransferDstPath)
	}
}

func fillDryRunHost(config *sshclient.Config, plan *dryRunPlan) {
	switch {
	case config.Mode == "host" && (config.HostAction == "test" || config.HostAction == "remove" || config.HostAction == "update"):
		plan.HostInput = config.HostName
	case config.Mode == "host":
		plan.HostInput = firstNonEmpty(config.HostName, config.Host)
	default:
		plan.HostInput = config.Host
	}

	if config.Mode == "ssh" || config.Mode == "sftp" {
		resolveDryRunSSHHost(config, plan)
		return
	}
	if config.Mode == "host" && config.HostAction == "test" && config.HostName != "" {
		resolveDryRunHostTest(config, plan)
		return
	}

	if plan.HostInput != "" {
		plan.HostResolved = config.Host
	}
}

func resolveDryRunSSHHost(config *sshclient.Config, plan *dryRunPlan) {
	if config.Host == "" {
		plan.HostResolution = dryRunStatus{Status: "missing", ErrorKind: "config", Message: "host is required"}
		plan.Valid = false
		return
	}
	if isIPAddress(config.Host) {
		plan.HostResolved = config.Host
		plan.HostResolution = dryRunStatus{Status: "direct"}
		return
	}

	plan.WouldLookupHostConfig = true
	settings, err := LoadSettings()
	if err != nil {
		plan.HostResolved = config.Host
		plan.HostResolution = dryRunStatus{Status: "error_used_direct", ErrorKind: "config", Message: err.Error()}
		return
	}
	hostConfig, err := GetHost(settings, config.Host)
	if err != nil {
		plan.HostResolved = config.Host
		plan.HostResolution = dryRunStatus{Status: "not_found_used_direct", Message: err.Error()}
		return
	}

	originalHost := config.Host
	config.Host = hostConfig.Host
	if config.Port == "" || config.Port == sshclient.DefaultSSHPort {
		if hostConfig.Port != "" {
			config.Port = hostConfig.Port
		}
	}
	if config.User == "" || config.User == sshclient.DefaultSSHUser {
		if hostConfig.User != "" {
			config.User = hostConfig.User
		}
	}
	if hostConfig.PasswordKey != "" && config.SudoKey == sshclient.DefaultSudoKey {
		config.SudoKey = hostConfig.PasswordKey
	}
	if config.UseKeyAuth && config.KeyPath == "" {
		switch {
		case hostConfig.Key != "":
			config.KeyPath = hostConfig.Key
		case settings.Key != "":
			config.KeyPath = settings.Key
		}
	}

	plan.HostInput = originalHost
	plan.HostResolved = config.Host
	plan.Port = config.Port
	plan.User = config.User
	plan.KeyPath = config.KeyPath
	plan.HostResolution = dryRunStatus{Status: "resolved", Message: fmt.Sprintf("matched host %q in settings", originalHost)}
}

func fillDryRunKeyDefault(config *sshclient.Config, plan *dryRunPlan) {
	if config.UseKeyAuth && config.KeyPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			config.KeyPath = filepath.Join(home, ".ssh", "id_rsa")
		}
	}
	plan.KeyPath = config.KeyPath
}

func resolveDryRunHostTest(config *sshclient.Config, plan *dryRunPlan) {
	plan.WouldLookupHostConfig = true
	settings, err := LoadSettings()
	if err != nil {
		plan.HostResolution = dryRunStatus{Status: "error", ErrorKind: "config", Message: err.Error()}
		plan.Valid = false
		return
	}
	hostConfig, err := GetHost(settings, config.HostName)
	if err != nil {
		plan.HostResolution = dryRunStatus{Status: "not_found", ErrorKind: "config", Message: err.Error()}
		plan.Valid = false
		return
	}
	config.Host = hostConfig.Host
	config.Port = firstNonEmpty(hostConfig.Port, sshclient.DefaultSSHPort)
	config.User = firstNonEmpty(hostConfig.User, sshclient.DefaultSSHUser)
	if config.UseKeyAuth && config.KeyPath == "" {
		config.KeyPath = firstNonEmpty(hostConfig.Key, settings.Key)
	}
	if hostConfig.PasswordKey != "" {
		config.SudoKey = hostConfig.PasswordKey
		plan.hostTestReadsSecret = true
	}

	plan.HostResolved = config.Host
	plan.Port = config.Port
	plan.User = config.User
	plan.KeyPath = config.KeyPath
	plan.SudoKey = config.SudoKey
	plan.HostResolution = dryRunStatus{Status: "resolved", Message: fmt.Sprintf("matched host %q in settings", config.HostName)}
}

func fillDryRunSudo(config *sshclient.Config, plan *dryRunPlan) {
	if config.Mode == "ssh" {
		plan.UsesSudo = sshclient.CommandUsesSudo(config.Command)
		plan.SudoKey = config.SudoKey
		return
	}
	if config.Mode == "host" && config.HostAction == "test" {
		return
	}
	plan.SudoKey = config.SudoKey
}

func fillDryRunValidation(config *sshclient.Config, plan *dryRunPlan) {
	if config.Mode == "transfer" {
		if config.TransferSrcHost == "" || config.TransferSrcPath == "" {
			plan.ConfigCheck = dryRunStatus{
				Status:    "error",
				ErrorKind: "config",
				Message:   "source must be specified as --transfer=<host>:<path>",
			}
			plan.Valid = false
			return
		}
		if config.TransferDstHost == "" || config.TransferDstPath == "" {
			plan.ConfigCheck = dryRunStatus{
				Status:    "error",
				ErrorKind: "config",
				Message:   "destination must be specified as --to=<host>:<path>",
			}
			plan.Valid = false
		}
		return
	}
	if config.Mode == "ssh" {
		if config.Timeout < 0 {
			plan.ConfigCheck = dryRunStatus{
				Status:    "error",
				ErrorKind: "config",
				Message:   "invalid --timeout value (use e.g. 30s, 2m, or 30)",
			}
			plan.Valid = false
		}

		if config.JSONOutput && config.UsePTY {
			plan.ConfigCheck = dryRunStatus{
				Status:    "error",
				ErrorKind: "config",
				Message:   "--pty cannot be combined with --json for real command execution",
			}
			plan.Valid = false
		}

		if config.SafetyCheck && !config.Force {
			if blockErr := sshclient.ValidateCommand(config.Command); blockErr != nil {
				plan.SafetyCheck = dryRunStatus{
					Status:    "blocked",
					ErrorKind: classifyError(blockErr),
					Message:   blockErr.Error(),
				}
				plan.Valid = false
				return
			}
			plan.SafetyCheck = dryRunStatus{Status: "passed"}
			return
		}
		if config.Force {
			plan.SafetyCheck = dryRunStatus{Status: "bypassed", Message: "force mode skips safety checks"}
			return
		}
		plan.SafetyCheck = dryRunStatus{Status: "disabled"}
	}
}

func fillDryRunEffects(config *sshclient.Config, plan *dryRunPlan) {
	canProceed := plan.Valid && plan.ConfigCheck.Status != "error" && plan.SafetyCheck.Status != "blocked"

	switch config.Mode {
	case "ssh":
		plan.WouldConnect = canProceed
		plan.WouldExecute = plan.WouldConnect
		plan.WouldReadSecret = canProceed && plan.UsesSudo && config.SudoKey != ""
		plan.WouldMutateRemote = plan.WouldExecute
	case "sftp":
		plan.WouldConnect = canProceed
		plan.WouldMutateRemote = plan.WouldConnect && (config.SftpAction == "upload" || config.SftpAction == "mkdir" || config.SftpAction == "remove")
	case "transfer":
		plan.WouldConnect = canProceed
		plan.WouldMutateRemote = canProceed
	case "password":
		plan.WouldReadSecret = canProceed && (config.PasswordAction == "get" || config.PasswordAction == "check" || config.PasswordAction == "delete" || config.PasswordAction == "list")
		plan.WouldWriteLocalState = canProceed && (config.PasswordAction == "set" || config.PasswordAction == "delete")
		plan.WouldPromptForSecret = canProceed && config.PasswordAction == "set" && config.PasswordValue == ""
	case "host":
		plan.WouldConnect = canProceed && (config.HostAction == "test" || config.HostAction == "test-all")
		plan.WouldWriteLocalState = canProceed && (config.HostAction == "add" || config.HostAction == "update" || config.HostAction == "remove")
		switch config.HostAction {
		case "test":
			plan.WouldReadSecret = canProceed && plan.hostTestReadsSecret
		case "test-all":
			plan.WouldReadSecret = canProceed
		}
	}
	plan.MayMutateKnownHosts = plan.WouldConnect && config.AcceptUnknownHost
}

func modeUsesSSHConnection(config *sshclient.Config) bool {
	if config.Mode == "ssh" || config.Mode == "sftp" || config.Mode == "transfer" {
		return true
	}
	return config.Mode == "host" && (config.HostAction == "test" || config.HostAction == "test-all")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func printDryRunPlan(plan dryRunPlan) {
	fmt.Println("Dry run: no connection, execution, secret lookup, or state mutation performed.")
	fmt.Printf("Mode: %s\n", plan.Mode)
	if plan.Action != "" {
		fmt.Printf("Action: %s\n", plan.Action)
	}
	if plan.HostInput != "" {
		fmt.Printf("Host: %s", plan.HostInput)
		if plan.HostResolved != "" && plan.HostResolved != plan.HostInput {
			fmt.Printf(" -> %s", plan.HostResolved)
		}
		fmt.Println()
	}
	if plan.Mode != "transfer" && (plan.User != "" || plan.Port != "") {
		fmt.Printf("Target: %s@%s:%s\n", firstNonEmpty(plan.User, "-"), firstNonEmpty(plan.HostResolved, "-"), firstNonEmpty(plan.Port, "-"))
	}
	if plan.Command != "" {
		fmt.Printf("Command: %s\n", plan.Command)
	}
	if plan.SftpAction != "" {
		fmt.Printf("SFTP: %s local=%q remote=%q\n", plan.SftpAction, plan.LocalPath, plan.RemotePath)
	}
	if plan.TransferSource != "" || plan.TransferDest != "" {
		fmt.Printf("Transfer: %s → %s\n", plan.TransferSource, plan.TransferDest)
	}
	fmt.Printf("Config check: %s\n", statusText(plan.ConfigCheck))
	fmt.Printf("Safety check: %s\n", statusText(plan.SafetyCheck))
	fmt.Printf("Uses sudo: %t", plan.UsesSudo)
	if plan.SudoKey != "" {
		fmt.Printf(" (key: %s)", plan.SudoKey)
	}
	fmt.Println()
	fmt.Printf("Would connect: %t\n", plan.WouldConnect)
	fmt.Printf("Would execute: %t\n", plan.WouldExecute)
	fmt.Printf("Would read secret: %t\n", plan.WouldReadSecret)
	fmt.Printf("Would write local state: %t\n", plan.WouldWriteLocalState)
	fmt.Printf("Would mutate remote: %t\n", plan.WouldMutateRemote)
}

func statusText(status dryRunStatus) string {
	if status.Message == "" {
		return status.Status
	}
	return fmt.Sprintf("%s (%s)", status.Status, status.Message)
}
