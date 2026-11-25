//go:build darwin && !sshx_e2e

package keyringstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func systemKeyringGet(service, account string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// Read the diagnostics separately. The common backend collapses the
	// command's errors to an exit code on macOS.
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", service, "-wa", account) // #nosec G204 -- fixed command and option value slots, without a shell.
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%w: macOS security did not respond", ErrInteractionRequired)
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", classifyKeychainFailure(string(exit.Stderr), err)
		}
		return "", fmt.Errorf("read macOS keychain: %w", err)
	}
	value := strings.TrimSpace(string(out))
	// Interoperate with both encodings used by go-keyring and entries added
	// directly through Keychain Access or security.
	if encoded, ok := strings.CutPrefix(value, "go-keyring-base64:"); ok {
		secret, err := base64.StdEncoding.DecodeString(encoded)
		return string(secret), err
	}
	if encoded, ok := strings.CutPrefix(value, "go-keyring-encoded:"); ok {
		secret, err := hex.DecodeString(encoded)
		return string(secret), err
	}
	return value, nil
}

func classifyKeychainFailure(diagnostic string, cause error) error {
	diagnostic = strings.ToLower(diagnostic)
	switch {
	case strings.Contains(diagnostic, "user interaction is not allowed"),
		strings.Contains(diagnostic, "interaction required"),
		strings.Contains(diagnostic, "keychain is locked"):
		return ErrInteractionRequired
	case strings.Contains(diagnostic, "authorization denied"),
		strings.Contains(diagnostic, "user canceled"),
		strings.Contains(diagnostic, "access denied"),
		strings.Contains(diagnostic, "auth failed"):
		return ErrAccessDenied
	case strings.Contains(diagnostic, "specified item could not be found"):
		return ErrNotFound
	default:
		return fmt.Errorf("read macOS keychain: %w", cause)
	}
}
