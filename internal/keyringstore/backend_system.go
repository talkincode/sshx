//go:build !sshx_e2e

package keyringstore

import (
	"errors"

	"github.com/zalando/go-keyring"
)

func keyringSet(service, account, password string) error {
	return keyring.Set(service, account, password)
}

func keyringGet(service, account string) (string, error) {
	password, err := keyring.Get(service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", err
	}
	return password, nil
}

func keyringDelete(service, account string) error {
	err := keyring.Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func keyringAccounts(string) ([]string, error) {
	return nil, ErrListUnsupported
}
