package app

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"

	"github.com/zalando/go-keyring"

	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/logger"
)

// HandlePasswordManagement handles all password management operations.
func HandlePasswordManagement(config *sshclient.Config) error {
	switch config.PasswordAction {
	case "set":
		return setPassword(sshclient.KeyringServiceName, config.PasswordKey, config.PasswordValue)
	case "get":
		return getPassword(sshclient.KeyringServiceName, config.PasswordKey)
	case "delete", "del", "rm":
		return deletePassword(sshclient.KeyringServiceName, config.PasswordKey)
	case "list", "ls":
		return listPasswords()
	case "check", "exists":
		return checkPassword(sshclient.KeyringServiceName, config.PasswordKey)
	default:
		return fmt.Errorf("unknown password action: %s (use: set, get, delete, list, check)", config.PasswordAction)
	}
}

func setPassword(serviceName, key, value string) error {
	if key == "" {
		return fmt.Errorf("password key is required")
	}
	if value == "" {
		fmt.Printf("Enter password for key '%s': ", key)
		password, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		value = password
	}

	if err := keyring.Set(serviceName, key, value); err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}

	logger.GetLogger().Success("Password saved to system keyring")
	logger.GetLogger().Info("  Service: %s", serviceName)
	logger.GetLogger().Info("  Key: %s", key)

	fmt.Println("\nVerify with:")
	if isWindows() {
		fmt.Println("  Windows: Check Credential Manager -> Generic Credentials")
	} else if isMacOS() {
		fmt.Printf("  macOS: security find-generic-password -s %s -a %s -w\n", serviceName, key)
	} else {
		fmt.Printf("  Linux: secret-tool lookup service %s username %s\n", serviceName, key)
	}

	return nil
}

func getPassword(serviceName, key string) error {
	if key == "" {
		return fmt.Errorf("password key is required")
	}

	password, err := keyring.Get(serviceName, key)
	if err != nil {
		if err == keyring.ErrNotFound {
			return fmt.Errorf("password not found for key: %s", key)
		}
		return fmt.Errorf("failed to get password: %w", err)
	}

	// Never dump a secret onto an interactive terminal, where it would linger in
	// scrollback and shoulder-surfing range. sshx already uses the keyring
	// internally (it auto-fills sudo over stdin), so the plaintext value is only
	// needed when handing it to another program. When stdout is a pipe or file we
	// emit just the raw value (no decoration, no trailing newline) so it can be
	// captured cleanly, e.g. PW=$(sshx --password-get=key) or `... | pbcopy`.
	if term.IsTerminal(int(os.Stdout.Fd())) {
		logger.GetLogger().Success("Password exists for key '%s' (service: %s)", key, serviceName)
		logger.GetLogger().Info("Not printing the secret to a terminal. To use it, pipe stdout:")
		logger.GetLogger().Info("  sshx --password-get=%s | pbcopy   # copy to clipboard (macOS)", key)
		logger.GetLogger().Info("  sshx --password-get=%s | cat      # show on screen if you must", key)
		return nil
	}

	logger.GetLogger().Warning("Emitting the plaintext password for key '%s' on stdout.", key)
	fmt.Print(password)
	return nil
}

func deletePassword(serviceName, key string) error {
	if key == "" {
		return fmt.Errorf("password key is required")
	}

	_, err := keyring.Get(serviceName, key)
	if err != nil {
		if err == keyring.ErrNotFound {
			logger.GetLogger().Warning("Password not found for key: %s (already deleted or never existed)", key)
			return nil
		}
		return fmt.Errorf("failed to check password: %w", err)
	}

	if err := keyring.Delete(serviceName, key); err != nil {
		return fmt.Errorf("failed to delete password: %w", err)
	}

	logger.GetLogger().Success("Password deleted from system keyring")
	logger.GetLogger().Info("  Service: %s", serviceName)
	logger.GetLogger().Info("  Key: %s", key)

	return nil
}

func checkPassword(serviceName, key string) error {
	if key == "" {
		return fmt.Errorf("password key is required")
	}

	_, err := keyring.Get(serviceName, key)
	if err == nil {
		logger.GetLogger().Success("Password exists for key: %s", key)
		fmt.Printf("\nKey '%s' is stored in system keyring\n", key)
		fmt.Printf("Service: %s\n", serviceName)
		return nil
	}

	if err == keyring.ErrNotFound {
		logger.GetLogger().Warning("Password not found for key: %s", key)
		fmt.Printf("\nKey '%s' is NOT stored in system keyring\n", key)
		fmt.Printf("Use 'sshx --password-set=%s' to add it\n", key)
		return nil
	}

	return fmt.Errorf("failed to check password: %w", err)
}

func listPasswords() error {
	fmt.Println("Checking password keys in system keyring...")
	fmt.Println("Service:", sshclient.KeyringServiceName)
	fmt.Println()

	commonKeys := []string{
		"master",
		"sudo",
		"root",
		"admin",
		"password",
	}

	fmt.Println("Common keys:")
	found := false
	for _, key := range commonKeys {
		_, err := keyring.Get(sshclient.KeyringServiceName, key)
		switch err {
		case nil:
			fmt.Printf("  ✓ %s (exists)\n", key)
			found = true
		case keyring.ErrNotFound:
			fmt.Printf("    %s (not set)\n", key)
		default:
			fmt.Printf("  ? %s (error: %v)\n", key, err)
		}
	}

	if !found {
		fmt.Println("  (no common keys found)")
	}

	fmt.Println("\nNote: This list only shows predefined common keys.")
	fmt.Println("Custom password keys you've set (like 'test-password') are stored")
	fmt.Println("but not listed here due to keyring API limitations.")
	fmt.Println("\nTo check a custom key:")
	fmt.Println("  sshx --password-check=<your-key-name>")
	fmt.Println("\nPlatform-specific commands to list all:")
	if isMacOS() {
		fmt.Println("  macOS: security find-generic-password -s sshx")
	} else if isWindows() {
		fmt.Println("  Windows: Control Panel -> Credential Manager -> Generic Credentials")
	} else {
		fmt.Println("  Linux: Use your desktop's keyring manager (Seahorse, KWalletManager, etc.)")
	}

	return nil
}

func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(pw), nil
	}

	// Non-interactive input (e.g. piped): read a full line so passwords that
	// contain spaces are preserved.
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func isMacOS() bool {
	return runtime.GOOS == "darwin"
}
