package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"

	"github.com/talkincode/sshx/internal/keyringstore"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/logger"
)

const secretsSchemaVersion = "sshx.secrets.v1" //nolint:gosec // schema id, not a credential

// errPasswordNotFound is returned by --password-check when the named key is
// absent. Callers that branch on exit code must treat this as failure.
var errPasswordNotFound = errors.New("password not found")

type secretsJSONResult struct {
	SchemaVersion string   `json:"schema_version"`
	Success       bool     `json:"success"`
	Action        string   `json:"action"`
	Key           string   `json:"key,omitempty"`
	Exists        *bool    `json:"exists,omitempty"`
	Keys          []string `json:"keys,omitempty"`
	ListComplete  *bool    `json:"list_complete,omitempty"`
	Backend       string   `json:"backend,omitempty"`
	ErrorKind     string   `json:"error_kind,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// HandlePasswordManagement handles all password management operations.
func HandlePasswordManagement(config *sshclient.Config) error {
	switch config.PasswordAction {
	case "set":
		return setPassword(config, sshclient.KeyringServiceName, config.PasswordKey, config.PasswordValue)
	case "get":
		return getPassword(sshclient.KeyringServiceName, config.PasswordKey)
	case "delete", "del", "rm":
		return deletePassword(config, sshclient.KeyringServiceName, config.PasswordKey)
	case "list", "ls":
		return listPasswords(config)
	case "check", "exists":
		return checkPassword(config, sshclient.KeyringServiceName, config.PasswordKey)
	default:
		return fmt.Errorf("unknown password action: %s (use: set, get, delete, list, check)", config.PasswordAction)
	}
}

func emitSecretsJSON(result secretsJSONResult) error {
	result.SchemaVersion = secretsSchemaVersion
	if result.Backend == "" {
		result.Backend = secretBackendName()
	}
	if err := encodeJSON(result); err != nil {
		return fmt.Errorf("encode secrets result: %w", err)
	}
	return nil
}

func boolPtr(v bool) *bool { return &v }

func setPassword(config *sshclient.Config, serviceName, key, value string) error {
	if key == "" {
		return fmt.Errorf("password key is required")
	}
	if value == "" {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintf(os.Stderr, "Enter password for key '%s': ", key)
		}
		password, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		value = password
	}

	if err := keyringstore.Set(serviceName, key, value); err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}

	backend := secretBackendLabel()
	if config != nil && config.JSONOutput {
		return emitSecretsJSON(secretsJSONResult{
			Success: true,
			Action:  "set",
			Key:     key,
			Exists:  boolPtr(true),
			Backend: secretBackendName(),
		})
	}

	logger.GetLogger().Success("Password saved to %s", backend)
	logger.GetLogger().Info("  Service: %s", serviceName)
	logger.GetLogger().Info("  Key: %s", key)

	fmt.Fprintln(os.Stderr, "\nVerify with:")
	fmt.Fprintf(os.Stderr, "  sshx --password-check=%s\n", key)
	if keyringstore.CanReveal() {
		if isWindows() {
			fmt.Fprintln(os.Stderr, "  Windows: Check Credential Manager -> Generic Credentials")
		} else if isMacOS() {
			fmt.Fprintf(os.Stderr, "  macOS: security find-generic-password -s %s -a %s -w\n", serviceName, key)
		} else {
			fmt.Fprintf(os.Stderr, "  Linux: secret-tool lookup service %s username %s\n", serviceName, key)
		}
	} else {
		fmt.Fprintln(os.Stderr, "  Local vault is write-only; sshx injects the secret over stdin during execution.")
	}

	return nil
}

func getPassword(serviceName, key string) error {
	if key == "" {
		return fmt.Errorf("password key is required")
	}
	if !keyringstore.CanReveal() {
		return fmt.Errorf("%w: use --password-check to confirm %q exists; sshx injects the secret over stdin during execution", keyringstore.ErrRevealDenied, key)
	}

	password, err := keyringstore.Get(serviceName, key)
	if err != nil {
		if errors.Is(err, keyringstore.ErrNotFound) {
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

func deletePassword(config *sshclient.Config, serviceName, key string) error {
	if key == "" {
		return fmt.Errorf("password key is required")
	}

	_, err := keyringstore.Get(serviceName, key)
	if err != nil {
		if errors.Is(err, keyringstore.ErrNotFound) {
			if config != nil && config.JSONOutput {
				if emitErr := emitSecretsJSON(secretsJSONResult{
					Success:   true,
					Action:    "delete",
					Key:       key,
					Exists:    boolPtr(false),
					ErrorKind: "not_found",
					Error:     fmt.Sprintf("password not found for key: %s (already deleted or never existed)", key),
				}); emitErr != nil {
					return emitErr
				}
				return nil
			}
			logger.GetLogger().Warning("Password not found for key: %s (already deleted or never existed)", key)
			return nil
		}
		return fmt.Errorf("failed to check password: %w", err)
	}

	if err := keyringstore.Delete(serviceName, key); err != nil {
		return fmt.Errorf("failed to delete password: %w", err)
	}

	if config != nil && config.JSONOutput {
		return emitSecretsJSON(secretsJSONResult{
			Success: true,
			Action:  "delete",
			Key:     key,
			Exists:  boolPtr(false),
		})
	}

	logger.GetLogger().Success("Password deleted from %s", secretBackendLabel())
	logger.GetLogger().Info("  Service: %s", serviceName)
	logger.GetLogger().Info("  Key: %s", key)

	return nil
}

func checkPassword(config *sshclient.Config, serviceName, key string) error {
	if key == "" {
		return fmt.Errorf("password key is required")
	}

	_, err := keyringstore.Get(serviceName, key)
	if err == nil {
		if config != nil && config.JSONOutput {
			return emitSecretsJSON(secretsJSONResult{
				Success: true,
				Action:  "check",
				Key:     key,
				Exists:  boolPtr(true),
			})
		}
		logger.GetLogger().Success("Password exists for key: %s", key)
		fmt.Fprintf(os.Stderr, "\nKey '%s' is stored in %s\n", key, secretBackendLabel())
		fmt.Fprintf(os.Stderr, "Service: %s\n", serviceName)
		return nil
	}

	if errors.Is(err, keyringstore.ErrNotFound) {
		missing := fmt.Errorf("%w: key %q is not stored", errPasswordNotFound, key)
		if config != nil && config.JSONOutput {
			if emitErr := emitSecretsJSON(secretsJSONResult{
				Success:   false,
				Action:    "check",
				Key:       key,
				Exists:    boolPtr(false),
				ErrorKind: "not_found",
				Error:     missing.Error(),
			}); emitErr != nil {
				return emitErr
			}
			return ErrReported
		}
		logger.GetLogger().Warning("Password not found for key: %s", key)
		fmt.Fprintf(os.Stderr, "\nKey '%s' is NOT stored in %s\n", key, secretBackendLabel())
		fmt.Fprintf(os.Stderr, "Use 'sshx --password-set=%s' to add it\n", key)
		return missing
	}

	return fmt.Errorf("failed to check password: %w", err)
}

func listPasswords(config *sshclient.Config) error {
	jsonMode := config != nil && config.JSONOutput
	if !jsonMode {
		fmt.Println("Checking password keys in", secretBackendLabel()+"...")
		fmt.Println("Service:", sshclient.KeyringServiceName)
		fmt.Println()
	}

	names, err := keyringstore.Accounts(sshclient.KeyringServiceName)
	if err == nil {
		if jsonMode {
			if names == nil {
				names = []string{}
			}
			return emitSecretsJSON(secretsJSONResult{
				Success:      true,
				Action:       "list",
				Keys:         names,
				ListComplete: boolPtr(true),
			})
		}
		if len(names) == 0 {
			fmt.Println("  (no keys stored)")
			return nil
		}
		fmt.Println("Stored keys:")
		for _, name := range names {
			fmt.Printf("  ✓ %s\n", name)
		}
		return nil
	}
	if !errors.Is(err, keyringstore.ErrListUnsupported) {
		return fmt.Errorf("failed to list passwords: %w", err)
	}

	commonKeys := []string{
		"master",
		"sudo",
		"root",
		"admin",
		"password",
	}

	var present []string
	for _, key := range commonKeys {
		_, getErr := keyringstore.Get(sshclient.KeyringServiceName, key)
		if getErr == nil {
			present = append(present, key)
		} else if !errors.Is(getErr, keyringstore.ErrNotFound) && jsonMode {
			return fmt.Errorf("failed to list passwords: %w", getErr)
		}
	}
	if jsonMode {
		if present == nil {
			present = []string{}
		}
		return emitSecretsJSON(secretsJSONResult{
			Success:      true,
			Action:       "list",
			Keys:         present,
			ListComplete: boolPtr(false),
		})
	}

	fmt.Println("Common keys:")
	found := false
	for _, key := range commonKeys {
		_, getErr := keyringstore.Get(sshclient.KeyringServiceName, key)
		switch {
		case getErr == nil:
			fmt.Printf("  ✓ %s (exists)\n", key)
			found = true
		case errors.Is(getErr, keyringstore.ErrNotFound):
			fmt.Printf("    %s (not set)\n", key)
		default:
			fmt.Printf("  ? %s (error: %v)\n", key, getErr)
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

func secretBackendName() string {
	backend := keyringstore.Inspect().Backend
	if backend == "" {
		return keyringstore.BackendKeyring
	}
	return backend
}

func secretBackendLabel() string {
	switch keyringstore.Inspect().Backend {
	case keyringstore.BackendVault:
		return "local vault"
	case "invalid":
		return "invalid secret backend"
	default:
		return "system keyring"
	}
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
