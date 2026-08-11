//go:build !sshx_e2e

package keyringstore

import "github.com/zalando/go-keyring"

// ErrNotFound reports that a key has no value in the operating-system keyring.
var ErrNotFound = keyring.ErrNotFound

func Set(service, account, password string) error {
	return keyring.Set(service, account, password)
}

func Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func Delete(service, account string) error {
	return keyring.Delete(service, account)
}
