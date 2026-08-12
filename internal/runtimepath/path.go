package runtimepath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// EnvHome overrides the local sshx runtime directory. It is primarily useful
	// for isolated agent and CI runs that must not touch a user's real config.
	EnvHome = "SSHX_HOME"
	// DefaultDir is the directory used below the current user's home directory.
	DefaultDir = ".sshx"
)

// Root returns the absolute local sshx runtime directory.
func Root() (string, error) {
	if configured := strings.TrimSpace(os.Getenv(EnvHome)); configured != "" {
		if strings.HasPrefix(configured, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("resolve %s: %w", EnvHome, err)
			}
			configured = filepath.Join(home, configured[2:])
		}
		absolute, err := filepath.Abs(configured)
		if err != nil {
			return "", fmt.Errorf("resolve %s path: %w", EnvHome, err)
		}
		absolute = filepath.Clean(absolute)
		if filepath.Dir(absolute) == absolute {
			return "", fmt.Errorf("%s may not be a filesystem root", EnvHome)
		}
		return absolute, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	return filepath.Join(home, DefaultDir), nil
}

// Plugins returns the directory that owns locally installed and editable
// inspection plugins.
func Plugins() (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "plugins"), nil
}

// Observations returns the optional local observation mirror directory.
func Observations() (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "observations"), nil
}
