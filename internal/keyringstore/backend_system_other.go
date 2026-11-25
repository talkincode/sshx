//go:build !darwin && !sshx_e2e

package keyringstore

func systemKeyringGet(service, account string) (string, error) {
	return providerGet(service, account)
}
