package app

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/joho/godotenv"

	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
)

// ErrUsage is returned when only the usage information was printed.
var ErrUsage = errors.New("usage displayed")

// Run executes the CLI using the provided arguments (typically os.Args).
func Run(args []string) (err error) {
	// Handle usage
	if len(args) < 2 {
		PrintUsage()
		return ErrUsage
	}

	// Load environment variables
	//nolint:errcheck // Loading .env is optional
	_ = godotenv.Load()

	// Set log level from environment variable
	if logLevelStr := os.Getenv("SSHX_LOG_LEVEL"); logLevelStr != "" {
		logLevel := logger.LogLevelFromString(logLevelStr)
		logger.GetLogger().SetLevel(logLevel)
	}

	// Parse command-line arguments
	config := ParseArgs(args)

	// Handle password management mode
	if config.Mode == "password" {
		if pwdErr := HandlePasswordManagement(config); pwdErr != nil {
			return fmt.Errorf("password management failed: %w", pwdErr)
		}
		return nil
	}

	// Handle host management mode
	if config.Mode == "host" {
		if hostErr := HandleHostManagement(config); hostErr != nil {
			return fmt.Errorf("host management failed: %w", hostErr)
		}
		return nil
	}

	// Try to resolve host from settings if not an IP address
	if config.Host != "" && !isIPAddress(config.Host) {
		if resolveErr := resolveHostFromSettings(config); resolveErr != nil {
			logger.GetLogger().Info("Note: Could not find host '%s' in settings, using as hostname directly", config.Host)
		}
	}

	// Auto-fill sudo password if needed
	if strings.Contains(config.Command, "sudo") && config.SudoKey != "" {
		password, pwdErr := sshclient.GetSudoPassword(config.SudoKey)
		if pwdErr != nil {
			logger.GetLogger().Warning("failed to get sudo password from keyring: %v", pwdErr)
			logger.GetLogger().Info("Continuing without sudo password auto-fill...")
		} else {
			config.Password = password
			logger.GetLogger().Success("Sudo password will be auto-filled when prompted")
		}
	}

	// Create SSH client
	client, err := sshclient.NewSSHClient(config)
	if err != nil {
		return fmt.Errorf("failed to create SSH client: %w", err)
	}
	defer errutil.HandleCloseError(&err, client)

	// Connect to remote host (use direct connection for CLI mode, no need for pooling)
	if err = client.ConnectDirect(); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Handle SFTP mode
	if config.Mode == "sftp" {
		if err = client.ExecuteSftp(); err != nil {
			return fmt.Errorf("SFTP operation failed: %w", err)
		}
		return nil
	}

	// Handle SSH command execution
	if err = client.ExecuteCommand(); err != nil {
		// EOF is a normal session close signal, not an error
		if !errutil.IsEOFError(err) {
			return fmt.Errorf("failed to execute command: %w", err)
		}
	}

	return nil
}

// isIPAddress checks if a string is a valid IP address
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// resolveHostFromSettings tries to resolve host configuration from settings
func resolveHostFromSettings(config *sshclient.Config) error {
	// Load settings
	settings, err := LoadSettings()
	if err != nil {
		return err
	}

	// Try to find host by name
	hostConfig, err := GetHost(settings, config.Host)
	if err != nil {
		return err
	}

	logger.GetLogger().Success("Found host '%s' in settings", config.Host)

	// Update config with host settings
	config.Host = hostConfig.Host
	if config.Port == "" || config.Port == "22" {
		if hostConfig.Port != "" {
			config.Port = hostConfig.Port
		}
	}
	if config.User == "" || config.User == "master" {
		if hostConfig.User != "" {
			config.User = hostConfig.User
		}
	}

	// Use configured password key if available
	if hostConfig.PasswordKey != "" && config.SudoKey == sshclient.DefaultSudoKey {
		config.SudoKey = hostConfig.PasswordKey
		logger.GetLogger().Success("Using password key: %s", hostConfig.PasswordKey)
	}

	// Use per-host SSH key if available, otherwise fall back to the default key
	if config.UseKeyAuth && config.KeyPath == "" {
		switch {
		case hostConfig.Key != "":
			config.KeyPath = hostConfig.Key
			logger.GetLogger().Success("Using host SSH key: %s", hostConfig.Key)
		case settings.Key != "":
			config.KeyPath = settings.Key
			logger.GetLogger().Success("Using SSH key: %s", settings.Key)
		}
	}

	return nil
}
