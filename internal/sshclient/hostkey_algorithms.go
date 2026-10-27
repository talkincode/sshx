package sshclient

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// This is preference, not authorization: the normal callback still verifies
// the chosen key/certificate/revocation against the admitted trust material.
func preferredHostKeyAlgorithms(config *Config, address string) []string {
	data := config.KnownHostsData
	if data == nil {
		filename := config.KnownHostsPath
		if filename == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil
			}
			filename = filepath.Join(home, ".ssh", "known_hosts")
		}
		var err error
		data, err = os.ReadFile(filename) // #nosec G304 -- operator-selected public trust store
		if err != nil {
			return nil
		} // #nosec G304 -- configured public trust store
	}
	callback, err := snapshotHostKeyCallback(data)
	if err != nil {
		return nil
	}
	err = callback(address, &net.TCPAddr{}, unmatchedHostKey{})
	var mismatch *knownhosts.KeyError
	if !errors.As(err, &mismatch) || len(mismatch.Want) == 0 {
		return nil
	}
	var algorithms []string
	add := func(name string) {
		for _, old := range algorithms {
			if old == name {
				return
			}
		}
		algorithms = append(algorithms, name)
	}
	for _, key := range mismatch.Want {
		switch key.Key.Type() {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA256)
			add(ssh.KeyAlgoRSASHA512)
			add(ssh.KeyAlgoRSA)
		default:
			add(key.Key.Type())
		}
	}
	// Preserve the dependency's existing supported set (including legacy keys
	// already offered by its defaults). No algorithm bypasses host verification.
	for _, name := range append(ssh.SupportedAlgorithms().HostKeys, ssh.InsecureAlgorithms().HostKeys...) {
		add(name)
	}
	return algorithms
}

type unmatchedHostKey struct{}

func (unmatchedHostKey) Type() string                        { return "sshx-query-known-algorithms" }
func (unmatchedHostKey) Marshal() []byte                     { return []byte("sshx-query-known-algorithms") }
func (unmatchedHostKey) Verify([]byte, *ssh.Signature) error { return fmt.Errorf("not a signing key") }
