//go:build sshx_e2e

package keyringstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotFound mirrors the public behavior of the OS keyring provider.
var ErrNotFound = errors.New("secret not found in isolated E2E keyring")

type fileState map[string]map[string]string

func Set(service, account, password string) error {
	state, path, err := load()
	if err != nil {
		return err
	}
	if state[service] == nil {
		state[service] = make(map[string]string)
	}
	state[service][account] = password
	return save(path, state)
}

func Get(service, account string) (string, error) {
	state, _, err := load()
	if err != nil {
		return "", err
	}
	value, ok := state[service][account]
	if !ok {
		return "", ErrNotFound
	}
	return value, nil
}

func Delete(service, account string) error {
	state, path, err := load()
	if err != nil {
		return err
	}
	if _, ok := state[service][account]; !ok {
		return ErrNotFound
	}
	delete(state[service], account)
	return save(path, state)
}

func load() (fileState, string, error) {
	path := os.Getenv("SSHX_E2E_KEYRING_FILE")
	if path == "" {
		return nil, "", fmt.Errorf("SSHX_E2E_KEYRING_FILE is required by the sshx_e2e build")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is an explicit E2E-only fixture location.
	if os.IsNotExist(err) {
		return make(fileState), path, nil
	}
	if err != nil {
		return nil, "", err
	}
	state := make(fileState)
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, "", fmt.Errorf("decode isolated E2E keyring: %w", err)
	}
	return state, path, nil
}

func save(path string, state fileState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create isolated E2E keyring directory: %w", err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode isolated E2E keyring: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G306 -- E2E credential fixture must be owner-only.
		return fmt.Errorf("write isolated E2E keyring: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure isolated E2E keyring: %w", err)
	}
	return nil
}
