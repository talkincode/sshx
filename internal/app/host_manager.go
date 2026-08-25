package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/logger"
)

const hostTestDialTimeout = 10 * time.Second

// HandleHostManagement handles host management commands
func HandleHostManagement(config *sshclient.Config) error {
	switch config.HostAction {
	case "add":
		return handleHostAdd(config)
	case "import":
		return handleHostImport(config)
	case "update":
		return handleHostUpdate(config)
	case "list":
		return handleHostList(config)
	case "test":
		return handleHostTest(config)
	case "test-all":
		return handleHostTestAll(config)
	case "remove":
		return handleHostRemove(config)
	default:
		return fmt.Errorf("unknown host action: %s", config.HostAction)
	}
}

// handleHostAdd adds a new host to settings
func handleHostAdd(config *sshclient.Config) error {
	// Load settings
	settings, err := LoadSettings()
	if err != nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}

	var host HostConfig

	// If host configuration is provided via command line
	if config.HostName != "" {
		host = HostConfig{
			Name:            config.HostName,
			Description:     config.HostDescription,
			Host:            config.Host,
			Port:            config.Port,
			User:            config.User,
			Key:             config.KeyPath,
			SudoPasswordKey: config.SudoKey,
			SSHPasswordKey:  config.SSHPasswordKey,
			Groups:          append([]string(nil), config.RunGroups...),
			Tags:            cloneTags(config.RunTags),
			Type:            config.HostType,
			Bind:            config.Bind,
		}
	} else {
		// Interactive mode
		reader := bufio.NewReader(os.Stdin)

		fmt.Println("=== Add New Host ===")

		// Host name (required)
		fmt.Print("Host name (unique identifier): ")
		name, readErr := reader.ReadString('\n')
		if readErr != nil {
			return fmt.Errorf("failed to read host name: %w", readErr)
		}
		host.Name = strings.TrimSpace(name)

		// Host address (required)
		fmt.Print("Host address (IP or hostname): ")
		addr, readErr := reader.ReadString('\n')
		if readErr != nil {
			return fmt.Errorf("failed to read host address: %w", readErr)
		}
		host.Host = strings.TrimSpace(addr)

		// Description (optional)
		fmt.Print("Description (optional): ")
		if desc, err := reader.ReadString('\n'); err == nil {
			host.Description = strings.TrimSpace(desc)
		}

		// Port (optional, default: 22)
		fmt.Print("Port (default: 22): ")
		if port, err := reader.ReadString('\n'); err == nil {
			host.Port = strings.TrimSpace(port)
		}

		// User (optional, default: master)
		fmt.Print("User (default: master): ")
		if user, err := reader.ReadString('\n'); err == nil {
			host.User = strings.TrimSpace(user)
		}

		// SSH private key (optional, overrides global key)
		fmt.Print("SSH private key path (optional, overrides global key): ")
		if keyPath, err := reader.ReadString('\n'); err == nil {
			host.Key = strings.TrimSpace(keyPath)
		}

		// Sudo password key (optional)
		fmt.Print("Sudo password key (optional): ")
		if pwdKey, err := reader.ReadString('\n'); err == nil {
			host.SudoPasswordKey = strings.TrimSpace(pwdKey)
		}
		// SSH login password key (optional, distinct from sudo)
		fmt.Print("SSH password key (optional): ")
		if pwdKey, err := reader.ReadString('\n'); err == nil {
			host.SSHPasswordKey = strings.TrimSpace(pwdKey)
		}
		fmt.Print("Groups (comma-separated, optional): ")
		if groups, err := reader.ReadString('\n'); err == nil {
			for _, g := range strings.Split(groups, ",") {
				g = strings.TrimSpace(g)
				if g != "" {
					host.Groups = append(host.Groups, g)
				}
			}
		}

		fmt.Print("Source bind (IP or interface, optional): ")
		if bind, err := reader.ReadString('\n'); err == nil {
			host.Bind = strings.TrimSpace(bind)
		}

		// Type (optional, default: linux)
		fmt.Print("System type [linux/windows/macos] (default: linux): ")
		if sysType, err := reader.ReadString('\n'); err == nil {
			host.Type = strings.TrimSpace(sysType)
		}
		if host.Type == "" {
			host.Type = DefaultHostType
		}
	}

	// Add host to settings
	if err := AddHost(settings, host); err != nil {
		return fmt.Errorf("failed to add host: %w", err)
	}

	// Save settings
	if err := SaveSettings(settings); err != nil {
		return fmt.Errorf("failed to save settings: %w", err)
	}

	logger.GetLogger().Success("Host '%s' added successfully", host.Name)
	return nil
}

// handleHostImport selectively imports hosts from an OpenSSH client config
// file (default ~/.ssh/config). It never imports everything blindly: wildcard
// patterns, existing names, and duplicate addresses are skipped, and the user
// chooses entries interactively or via --host-import=<name1,name2>.
func handleHostImport(config *sshclient.Config) error {
	settings, err := LoadSettings()
	if err != nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}

	configPath := config.SSHConfigPath
	if configPath == "" {
		configPath, err = defaultSSHConfigPath()
		if err != nil {
			return err
		}
	}

	file, err := os.Open(configPath) // #nosec G304 -- Path is the user's own ssh config
	if err != nil {
		return fmt.Errorf("failed to open ssh config %s: %w", configPath, err)
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // read-only file

	entries, parseNotes, err := parseSSHConfig(file)
	if err != nil {
		return err
	}

	plan := buildImportPlan(entries, settings)
	plan.Notes = append(plan.Notes, parseNotes...)

	var selected []importCandidate
	if config.HostImportNames != "" {
		selected, err = selectCandidatesByName(plan, config.HostImportNames)
		if err != nil {
			return err
		}
	} else {
		selected, err = selectCandidatesInteractively(plan, configPath)
		if err != nil {
			return err
		}
		if len(selected) == 0 {
			fmt.Println("Nothing imported.")
			return nil
		}
	}

	for _, candidate := range selected {
		if addErr := AddHost(settings, candidate.Host); addErr != nil {
			return fmt.Errorf("failed to add host '%s': %w", candidate.Host.Name, addErr)
		}
	}
	if err := SaveSettings(settings); err != nil {
		return fmt.Errorf("failed to save settings: %w", err)
	}

	for _, candidate := range selected {
		logger.GetLogger().Success("Imported host '%s' (%s)", candidate.Host.Name, candidate.Host.Host)
	}
	fmt.Printf("\nImported %d host(s) from %s\n", len(selected), configPath)
	printImportNotes(plan.Notes)
	return nil
}

// selectCandidatesInteractively prints the import plan and asks the user to
// pick entries by number, name, or "all". An empty answer cancels.
func selectCandidatesInteractively(plan importPlan, configPath string) ([]importCandidate, error) {
	fmt.Printf("=== Import hosts from %s ===\n\n", configPath)

	if len(plan.Skipped) > 0 {
		fmt.Println("Skipped (not importable):")
		for _, s := range plan.Skipped {
			fmt.Printf("  - %-20s %s\n", s.Alias, s.Reason)
		}
		fmt.Println()
	}

	if len(plan.Candidates) == 0 {
		fmt.Println("No importable hosts found.")
		printImportNotes(plan.Notes)
		return nil, nil
	}

	fmt.Println("Importable hosts:")
	for i, c := range plan.Candidates {
		fmt.Printf("  [%d] %s\n", i+1, candidateSummary(c))
	}
	printImportNotes(plan.Notes)

	fmt.Print("\nSelect hosts to import (numbers or names, comma-separated; 'all'; empty to cancel): ")
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil && answer == "" {
		return nil, fmt.Errorf("failed to read selection: %w", err)
	}
	return resolveImportSelection(plan, answer)
}

// resolveImportSelection maps a user answer ("all", "1,3", "web1 db1", …) to
// candidates. Unknown tokens fail the whole selection so nothing half-applies.
func resolveImportSelection(plan importPlan, answer string) ([]importCandidate, error) {
	answer = strings.TrimSpace(answer)
	if answer == "" {
		return nil, nil
	}
	if strings.EqualFold(answer, "all") {
		return plan.Candidates, nil
	}

	byName := make(map[string]int, len(plan.Candidates))
	for i, c := range plan.Candidates {
		byName[c.Host.Name] = i
	}

	var selected []importCandidate
	seen := make(map[int]bool)
	for _, token := range strings.FieldsFunc(answer, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		var idx int
		if n, err := strconv.Atoi(token); err == nil {
			if n < 1 || n > len(plan.Candidates) {
				return nil, fmt.Errorf("selection %d is out of range (1-%d)", n, len(plan.Candidates))
			}
			idx = n - 1
		} else if i, ok := byName[token]; ok {
			idx = i
		} else {
			return nil, fmt.Errorf("unknown selection %q (use listed numbers or names)", token)
		}
		if !seen[idx] {
			seen[idx] = true
			selected = append(selected, plan.Candidates[idx])
		}
	}
	return selected, nil
}

func printImportNotes(notes []string) {
	for _, note := range notes {
		fmt.Printf("Note: %s\n", note)
	}
}

// handleHostUpdate updates an existing host in settings
func handleHostUpdate(config *sshclient.Config) error {
	// Load settings
	settings, err := LoadSettings()
	if err != nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}

	// Host name is required for update
	if config.HostName == "" {
		return fmt.Errorf("host name is required for update (use --host-name=<name>)")
	}

	// Check that the host exists and capture its current values
	existingHost, err := GetHost(settings, config.HostName)
	if err != nil {
		return fmt.Errorf("host '%s' not found, use --host-add to create it", config.HostName)
	}

	// Build updated host config, keeping existing values unless overridden
	host := HostConfig{
		Name: config.HostName,
	}

	if config.Host != "" {
		host.Host = config.Host
	} else {
		host.Host = existingHost.Host
	}

	if config.HostDescription != "" {
		host.Description = config.HostDescription
	} else {
		host.Description = existingHost.Description
	}

	if config.Port != "" && config.Port != sshclient.DefaultSSHPort {
		host.Port = config.Port
	} else if existingHost.Port != "" {
		host.Port = existingHost.Port
	} else {
		host.Port = sshclient.DefaultSSHPort
	}

	if config.User != "" && config.User != sshclient.DefaultSSHUser {
		host.User = config.User
	} else if existingHost.User != "" {
		host.User = existingHost.User
	} else {
		host.User = sshclient.DefaultSSHUser
	}

	if config.SudoKey != "" && config.SudoKey != sshclient.DefaultSudoKey {
		host.SudoPasswordKey = config.SudoKey
	} else if existingHost.EffectiveSudoPasswordKey() != "" {
		host.SudoPasswordKey = existingHost.EffectiveSudoPasswordKey()
	}
	if config.SSHPasswordKey != "" {
		host.SSHPasswordKey = config.SSHPasswordKey
	} else {
		host.SSHPasswordKey = existingHost.SSHPasswordKey
	}
	if len(config.RunGroups) > 0 {
		host.Groups = append([]string(nil), config.RunGroups...)
	} else {
		host.Groups = append([]string(nil), existingHost.Groups...)
	}
	if len(config.RunTags) > 0 {
		host.Tags = cloneTags(config.RunTags)
	} else {
		host.Tags = cloneTags(existingHost.Tags)
	}

	if config.KeyPath != "" {
		host.Key = config.KeyPath
	} else {
		host.Key = existingHost.Key
	}

	if config.HostType != "" {
		host.Type = config.HostType
	} else if existingHost.Type != "" {
		host.Type = existingHost.Type
	} else {
		host.Type = DefaultHostType
	}

	if config.BindSet {
		host.Bind = config.Bind
	} else {
		host.Bind = existingHost.Bind
	}

	// Update host
	if err := UpdateHost(settings, host); err != nil {
		return fmt.Errorf("failed to update host: %w", err)
	}

	// Save settings
	if err := SaveSettings(settings); err != nil {
		return fmt.Errorf("failed to save settings: %w", err)
	}

	logger.GetLogger().Success("Host '%s' updated successfully", host.Name)
	return nil
}

// handleHostList lists all configured hosts
func handleHostList(config *sshclient.Config) error {
	// Load settings
	settings, err := LoadSettings()
	if err != nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}

	hosts := ListHosts(settings)

	if config.JSONOutput {
		return printHostListJSON(hosts)
	}

	if len(hosts) == 0 {
		fmt.Println("No hosts configured.")
		fmt.Println("\nTo add hosts:")
		fmt.Println("  - Interactive: sshx --host-add")
		return nil
	}

	// Detailed mode
	fmt.Printf("\n=== Configured Hosts (%d) ===\n\n", len(hosts))

	for i, host := range hosts {
		fmt.Printf("[%d] %s\n", i+1, host.Name)
		fmt.Printf("    Host:        %s\n", host.Host)
		if host.Description != "" {
			fmt.Printf("    Description: %s\n", host.Description)
		}
		if host.Port != "" && host.Port != "22" {
			fmt.Printf("    Port:        %s\n", host.Port)
		}
		if host.User != "" {
			fmt.Printf("    User:        %s\n", host.User)
		}
		if host.Key != "" {
			fmt.Printf("    Key:         %s\n", host.Key)
		}
		if sudoKey := host.EffectiveSudoPasswordKey(); sudoKey != "" {
			fmt.Printf("    Sudo Password Key: %s\n", sudoKey)
		}
		if sshKey := host.EffectiveSSHPasswordKey(); sshKey != "" {
			fmt.Printf("    SSH Password Key: %s\n", sshKey)
		}
		if len(host.Groups) > 0 {
			fmt.Printf("    Groups:      %s\n", strings.Join(host.Groups, ", "))
		}
		if len(host.Tags) > 0 {
			fmt.Printf("    Tags:        %s\n", formatTags(host.Tags))
		}
		if host.Type != "" {
			fmt.Printf("    Type:        %s\n", host.Type)
		}
		if host.Bind != "" {
			fmt.Printf("    Bind:        %s\n", host.Bind)
		}
		fmt.Println()
	}

	fmt.Println("Usage:")
	fmt.Printf("  sshx -h=%s \"command\"\n", hosts[0].Name)
	fmt.Printf("  sshx --host-test %s\n", hosts[0].Name)

	return nil
}

// hostListJSONEntry is the machine-readable projection of one configured
// host. It references credential keys but never secret values.
type hostListJSONEntry struct {
	Name            string            `json:"name"`
	Host            string            `json:"host"`
	Port            string            `json:"port,omitempty"`
	User            string            `json:"user,omitempty"`
	Description     string            `json:"description,omitempty"`
	KeyPath         string            `json:"key_path,omitempty"`
	SSHPasswordKey  string            `json:"ssh_password_key,omitempty"`
	SudoPasswordKey string            `json:"sudo_password_key,omitempty"`
	Groups          []string          `json:"groups,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	Type            string            `json:"type,omitempty"`
	Bind            string            `json:"bind,omitempty"`
}

func printHostListJSON(hosts []HostConfig) error {
	entries := make([]hostListJSONEntry, 0, len(hosts))
	for _, host := range hosts {
		entries = append(entries, hostListJSONEntry{
			Name:            host.Name,
			Host:            host.Host,
			Port:            host.Port,
			User:            host.User,
			Description:     host.Description,
			KeyPath:         host.Key,
			SSHPasswordKey:  host.EffectiveSSHPasswordKey(),
			SudoPasswordKey: host.EffectiveSudoPasswordKey(),
			Groups:          host.Groups,
			Tags:            host.Tags,
			Type:            host.Type,
			Bind:            host.Bind,
		})
	}
	doc := struct {
		SchemaVersion string              `json:"schema_version"`
		Count         int                 `json:"count"`
		Hosts         []hostListJSONEntry `json:"hosts"`
	}{SchemaVersion: "sshx.hosts.v1", Count: len(entries), Hosts: entries}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode host list: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// handleHostTest tests host connection
func handleHostTest(config *sshclient.Config) error {
	// Load settings
	settings, err := LoadSettings()
	if err != nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}

	if config.HostName == "" {
		return fmt.Errorf("host name is required for test")
	}

	// Get host configuration
	hostConfig, err := GetHost(settings, config.HostName)
	if err != nil {
		return fmt.Errorf("host not found: %w", err)
	}

	logger.GetLogger().Info("Testing connection to '%s' (%s)...", hostConfig.Name, hostConfig.Host)

	result := runHostDiagnostics(hostConfig, settings, config)
	if !result.ConnectionSuccess {
		if result.ConnectionError != nil {
			logger.GetLogger().Error("Connection failed: %v", result.ConnectionError)
		}
		return fmt.Errorf("connection test failed")
	}

	logger.GetLogger().Success("Connection successful! (%s)", formatAuthDescription(result.AuthMethod))

	if !result.CommandSuccess {
		if result.CommandError != nil {
			logger.GetLogger().Error("Command execution failed: %v", result.CommandError)
		}
		return fmt.Errorf("command execution test failed")
	}

	logger.GetLogger().Success("Command execution successful!")
	fmt.Printf("\nTest output: %s\n", strings.TrimSpace(result.CommandOutput))

	return nil
}

// handleHostRemove removes a host from settings
func handleHostRemove(config *sshclient.Config) error {
	// Load settings
	settings, err := LoadSettings()
	if err != nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}

	if config.HostName == "" {
		return fmt.Errorf("host name is required for removal")
	}

	// Remove host
	if err := RemoveHost(settings, config.HostName); err != nil {
		return fmt.Errorf("failed to remove host: %w", err)
	}

	// Save settings
	if err := SaveSettings(settings); err != nil {
		return fmt.Errorf("failed to save settings: %w", err)
	}

	logger.GetLogger().Success("Host '%s' removed successfully", config.HostName)
	return nil
}

// handleHostTestAll tests all configured hosts and prints a summary report.
func handleHostTestAll(config *sshclient.Config) error {
	settings, err := LoadSettings()
	if err != nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}

	hosts := ListHosts(settings)
	if len(hosts) == 0 {
		fmt.Println("No hosts configured. Use sshx --host-add to add hosts before running --host-test-all.")
		return nil
	}

	logger.GetLogger().Info("Testing %d host(s)...", len(hosts))
	results := make([]hostTestResult, 0, len(hosts))
	for _, host := range hosts {
		hostCopy := host
		logger.GetLogger().Info("→ %s (%s)", hostCopy.Name, hostCopy.Host)
		result := runHostDiagnostics(&hostCopy, settings, config)
		results = append(results, result)
	}

	successCount := 0
	fmt.Printf("\n=== Host Test Report (%d hosts) ===\n\n", len(results))
	for i, result := range results {
		statusIcon := "❌"
		statusMessage := "Connection failed"
		switch {
		case result.ConnectionSuccess && result.CommandSuccess:
			statusIcon = "✅"
			statusMessage = "Connection & command succeeded"
		case result.ConnectionSuccess && !result.CommandSuccess:
			statusIcon = "⚠️"
			statusMessage = "Command execution failed"
		}

		if result.ConnectionSuccess && result.CommandSuccess {
			successCount++
		}

		fmt.Printf("[%d] %s (%s)\n", i+1, result.Host.Name, result.Host.Host)
		fmt.Printf("    Status: %s %s\n", statusIcon, statusMessage)
		fmt.Printf("    Auth: %s\n", formatAuthDescription(result.AuthMethod))
		if !result.ConnectionSuccess && result.ConnectionError != nil {
			fmt.Printf("    Error: %v\n", result.ConnectionError)
		} else if result.CommandSuccess {
			output := strings.TrimSpace(result.CommandOutput)
			if output != "" {
				fmt.Printf("    Output: %s\n", output)
			}
		} else if result.CommandError != nil {
			fmt.Printf("    Command Error: %v\n", result.CommandError)
		}
		fmt.Println()
	}

	fmt.Printf("Summary: %d/%d hosts succeeded\n", successCount, len(results))
	if successCount != len(results) {
		return fmt.Errorf("host test failed for %d host(s)", len(results)-successCount)
	}

	return nil
}

func runHostDiagnostics(hostConfig *HostConfig, settings *Settings, baseConfig *sshclient.Config) hostTestResult {
	result := hostTestResult{
		Host:       *hostConfig,
		AuthMethod: sshclient.AuthMethodUnknown,
	}

	sshConfig := buildHostTestConfig(hostConfig, settings, baseConfig)
	client, err := sshclient.NewSSHClient(sshConfig)
	if err != nil {
		result.ConnectionError = err
		return result
	}
	defer func() {
		if closeErr := client.ForceClose(); closeErr != nil {
			logger.GetLogger().Debug("failed to close SSH client for host %s: %v", hostConfig.Name, closeErr)
		}
	}()

	if err := client.ConnectDirect(); err != nil {
		result.ConnectionError = err
		return result
	}

	result.ConnectionSuccess = true
	result.AuthMethod = client.AuthMethodUsed()

	sshConfig.Command = "echo 'Connection test successful'"
	output, execErr := client.ExecuteCommandWithOutput()
	if execErr != nil {
		result.CommandError = execErr
		return result
	}

	result.CommandSuccess = true
	result.CommandOutput = output
	return result
}

func buildHostTestConfig(hostConfig *HostConfig, settings *Settings, baseConfig *sshclient.Config) *sshclient.Config {
	testConfig := &sshclient.Config{
		Host:        hostConfig.Host,
		Port:        hostConfig.Port,
		User:        hostConfig.User,
		UseKeyAuth:  true,
		DialTimeout: hostTestDialTimeout,
	}

	if baseConfig != nil {
		testConfig.UseKeyAuth = baseConfig.UseKeyAuth
		testConfig.KeyPath = baseConfig.KeyPath
		testConfig.Password = baseConfig.Password
		if baseConfig.DialTimeout > 0 {
			testConfig.DialTimeout = baseConfig.DialTimeout
		}
	}
	if baseConfig != nil && baseConfig.BindSet {
		testConfig.Bind = baseConfig.Bind
	} else {
		testConfig.Bind = hostConfig.Bind
	}

	if testConfig.Port == "" {
		testConfig.Port = sshclient.DefaultSSHPort
	}
	if testConfig.User == "" {
		testConfig.User = sshclient.DefaultSSHUser
	}

	if !testConfig.UseKeyAuth {
		testConfig.KeyPath = ""
	} else if testConfig.KeyPath == "" {
		switch {
		case hostConfig.Key != "":
			testConfig.KeyPath = hostConfig.Key
		case settings != nil && settings.Key != "":
			testConfig.KeyPath = settings.Key
		}
	}

	// Only the typed SSH login password key may authorize password auth.
	// Legacy password_key / sudo_password_key are sudo-only and must not be used here.
	if sshKey := hostConfig.EffectiveSSHPasswordKey(); sshKey != "" {
		if password, err := sshclient.GetSudoPassword(sshKey); err == nil {
			testConfig.Password = password
		} else {
			logger.GetLogger().Warning("failed to get SSH password from keyring (%s): %v", sshKey, err)
		}
	}

	return testConfig
}

func formatAuthDescription(method sshclient.AuthMethod) string {
	switch method {
	case sshclient.AuthMethodKey:
		return "SSH key"
	case sshclient.AuthMethodPassword:
		return "Password"
	case sshclient.AuthMethodPasswordFallback:
		return "Password (fallback after key failure)"
	default:
		return "Unknown"
	}
}

type hostTestResult struct {
	Host              HostConfig
	AuthMethod        sshclient.AuthMethod
	ConnectionSuccess bool
	CommandSuccess    bool
	ConnectionError   error
	CommandError      error
	CommandOutput     string
}

func (r hostTestResult) Success() bool {
	return r.ConnectionSuccess && r.CommandSuccess
}

func formatTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	// stable display order
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+tags[k])
	}
	return strings.Join(parts, ", ")
}
