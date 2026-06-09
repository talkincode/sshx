package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/talkincode/sshx/internal/sshclient"
)

const (
	// SettingsDir is the directory where settings are stored
	SettingsDir = ".sshx"
	// SettingsFile is the name of the settings file
	SettingsFile = "settings.json"
	// DefaultHostType is the default system type assigned to a host
	DefaultHostType = "linux"
)

// HostConfig represents a configured host
type HostConfig struct {
	Name        string `json:"name"`                   // Host name (unique identifier)
	Description string `json:"description,omitempty"`  // Description
	Host        string `json:"host"`                   // IP or hostname
	Port        string `json:"port,omitempty"`         // Port (default: 22)
	User        string `json:"user,omitempty"`         // Username (default: master)
	Key         string `json:"key,omitempty"`          // SSH private key path (optional, overrides global key)
	PasswordKey string `json:"password_key,omitempty"` // Password key name (optional)
	Type        string `json:"type,omitempty"`         // System type (linux/windows/macos)
}

// Settings represents the user-level configuration
type Settings struct {
	Key   string       `json:"key,omitempty"` // Default SSH key path (e.g., ~/.ssh/id_rsa)
	Hosts []HostConfig `json:"hosts"`         // List of configured hosts
}

// GetSettingsPath returns the path to the settings file
func GetSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	return filepath.Join(home, SettingsDir, SettingsFile), nil
}

// GetSettingsDir returns the path to the settings directory
func GetSettingsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	return filepath.Join(home, SettingsDir), nil
}

// LoadSettings loads settings from the settings file
func LoadSettings() (*Settings, error) {
	settingsPath, err := GetSettingsPath()
	if err != nil {
		return nil, err
	}

	// If settings file doesn't exist, return default settings
	if _, statErr := os.Stat(settingsPath); os.IsNotExist(statErr) {
		return &Settings{
			Hosts: make([]HostConfig, 0),
		}, nil
	}

	data, err := os.ReadFile(settingsPath) // #nosec G304 -- Settings path is from user's home directory
	if err != nil {
		return nil, fmt.Errorf("failed to read settings file: %w", err)
	}

	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("failed to parse settings file: %w", err)
	}

	// Initialize Hosts slice if nil
	if settings.Hosts == nil {
		settings.Hosts = make([]HostConfig, 0)
	}

	return &settings, nil
}

// SaveSettings saves settings to the settings file
func SaveSettings(settings *Settings) error {
	settingsDir, err := GetSettingsDir()
	if err != nil {
		return err
	}

	// Create settings directory if it doesn't exist
	if mkdirErr := os.MkdirAll(settingsDir, 0700); mkdirErr != nil {
		return fmt.Errorf("failed to create settings directory: %w", mkdirErr)
	}

	settingsPath, err := GetSettingsPath()
	if err != nil {
		return err
	}

	// Marshal settings to JSON with indentation
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Write atomically: write to a temp file in the same directory, then
	// rename over the destination so a crash mid-write cannot corrupt or
	// truncate the existing settings file.
	tmpFile, err := os.CreateTemp(settingsDir, "settings-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp settings file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }() //nolint:errcheck // best-effort cleanup

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close() //nolint:errcheck
		return fmt.Errorf("failed to set settings file permissions: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close() //nolint:errcheck
		return fmt.Errorf("failed to write settings file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to flush settings file: %w", err)
	}
	if err := os.Rename(tmpPath, settingsPath); err != nil {
		return fmt.Errorf("failed to replace settings file: %w", err)
	}

	return nil
}

// ValidateHostConfig validates a host configuration
func ValidateHostConfig(host *HostConfig) error {
	if host.Name == "" {
		return fmt.Errorf("host name is required")
	}
	if host.Host == "" {
		return fmt.Errorf("host address is required")
	}
	return nil
}

// AddHost adds a new host to settings
func AddHost(settings *Settings, host HostConfig) error {
	// Validate host configuration
	if err := ValidateHostConfig(&host); err != nil {
		return err
	}

	// Set default values before checking duplicates
	if host.Port == "" {
		host.Port = sshclient.DefaultSSHPort
	}
	if host.User == "" {
		host.User = sshclient.DefaultSSHUser
	}

	// Check for duplicate host names and host+port combinations
	for _, h := range settings.Hosts {
		if h.Name == host.Name {
			return fmt.Errorf("host with name '%s' already exists", host.Name)
		}

		// Check for duplicate host+port combination
		existingPort := h.Port
		if existingPort == "" {
			existingPort = sshclient.DefaultSSHPort
		}
		if h.Host == host.Host && existingPort == host.Port {
			return fmt.Errorf("host with address '%s:%s' already exists (name: '%s')", host.Host, host.Port, h.Name)
		}
	}

	// Add host to settings
	settings.Hosts = append(settings.Hosts, host)

	return nil
}

// RemoveHost removes a host from settings by name
func RemoveHost(settings *Settings, name string) error {
	for i, h := range settings.Hosts {
		if h.Name == name {
			settings.Hosts = append(settings.Hosts[:i], settings.Hosts[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("host '%s' not found", name)
}

// GetHost retrieves a host configuration by name
func GetHost(settings *Settings, name string) (*HostConfig, error) {
	for i := range settings.Hosts {
		if settings.Hosts[i].Name == name {
			host := settings.Hosts[i]
			return &host, nil
		}
	}
	return nil, fmt.Errorf("host '%s' not found", name)
}

// UpdateHost updates an existing host configuration
func UpdateHost(settings *Settings, host HostConfig) error {
	// Validate host configuration
	if err := ValidateHostConfig(&host); err != nil {
		return err
	}

	// Set default values before checking duplicates
	if host.Port == "" {
		host.Port = sshclient.DefaultSSHPort
	}
	if host.User == "" {
		host.User = sshclient.DefaultSSHUser
	}

	// Check for duplicate host+port combination (excluding the host being updated)
	for _, h := range settings.Hosts {
		// Skip the host being updated
		if h.Name == host.Name {
			continue
		}

		// Check for duplicate host+port combination
		existingPort := h.Port
		if existingPort == "" {
			existingPort = sshclient.DefaultSSHPort
		}
		if h.Host == host.Host && existingPort == host.Port {
			return fmt.Errorf("host with address '%s:%s' already exists (name: '%s')", host.Host, host.Port, h.Name)
		}
	}

	// Find and update host
	for i, h := range settings.Hosts {
		if h.Name == host.Name {
			settings.Hosts[i] = host
			return nil
		}
	}

	return fmt.Errorf("host '%s' not found", host.Name)
}

// ListHosts returns all configured hosts
func ListHosts(settings *Settings) []HostConfig {
	return settings.Hosts
}
