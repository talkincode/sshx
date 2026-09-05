package keyringstore

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestVaultMalformedEnvelopePreservesBytesAndRecovers(t *testing.T) {
	const phrase = "isolated-corruption-matrix"
	root := withVaultEnv(t, phrase)
	if err := Set("sshx", "keep", "original"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "vault")
	good, err := os.ReadFile(path) // #nosec G304 -- isolated test vault.
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func([]byte) []byte
	}{
		{"empty", func(data []byte) []byte { return data[:0] }},
		{"truncated magic", func(data []byte) []byte { return data[:7] }},
		{"truncated header", func(data []byte) []byte { return data[:vaultHeaderSize-1] }},
		{"truncated nonce", func(data []byte) []byte { return data[:vaultHeaderSize+vaultNonceSize-1] }},
		{"truncated ciphertext", func(data []byte) []byte { return data[:len(data)-1] }},
		{"unknown magic", func(data []byte) []byte { data[0] ^= 0xff; return data }},
		{"unknown kdf", func(data []byte) []byte { data[8] = 255; return data }},
		{"invalid kdf costs", func(data []byte) []byte {
			binary.BigEndian.PutUint32(data[9:13], 0xffffffff)
			return data
		}},
		{"authentication failure", func(data []byte) []byte { data[len(data)-1] ^= 0xff; return data }},
		{"oversize", func(data []byte) []byte { return append(data, make([]byte, vaultMaxBytes)...) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			corrupt := test.edit(bytes.Clone(good))
			if err := os.WriteFile(path, corrupt, 0o600); err != nil {
				t.Fatal(err)
			}
			if value, err := Get("sshx", "keep"); err == nil || value != "" {
				t.Fatalf("Get returned data from corrupt vault: %q, %v", value, err)
			}
			if _, err := Accounts("sshx"); err == nil {
				t.Fatal("Accounts accepted corrupt vault")
			}
			if err := Set("sshx", "keep", "replacement"); err == nil {
				t.Fatal("Set overwrote corrupt vault")
			}
			if err := Delete("sshx", "keep"); err == nil {
				t.Fatal("Delete overwrote corrupt vault")
			}
			after, err := os.ReadFile(path) // #nosec G304 -- isolated test vault.
			if err != nil || !bytes.Equal(after, corrupt) {
				t.Fatalf("rejected operations modified original bytes: %v", err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 || entries[0].Name() != "vault" {
				t.Fatalf("unexpected files after rejected writes: %v, %v", entries, err)
			}
			if writeErr := os.WriteFile(path, good, 0o600); writeErr != nil { // #nosec G703 -- restoring the original isolated test vault.
				t.Fatal(writeErr)
			}
			value, err := Get("sshx", "keep")
			if err != nil || value != "original" {
				t.Fatalf("restored original vault is unreadable: %q, %v", value, err)
			}
		})
	}
}

func TestVaultAuthenticatedInvalidPayloadFailsClosed(t *testing.T) {
	const phrase = "isolated-payload-matrix"
	root := withVaultEnv(t, phrase)
	header := vaultHeader{salt: bytes.Repeat([]byte{42}, vaultSaltSize), n: vaultScryptN, r: vaultScryptR, p: vaultScryptP}
	for _, plaintext := range []string{`{`, `{"v":2,"secrets":{}}`, `{"v":1,"secrets":[]}`, `{"v":1}{"v":1}`} {
		t.Run(plaintext, func(t *testing.T) {
			data, err := encryptVault([]byte(plaintext), phrase, header)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "vault")
			if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			if setErr := Set("sshx", "keep", "secret"); setErr == nil {
				t.Fatal("accepted authenticated but invalid vault payload")
			}
			after, err := os.ReadFile(path) // #nosec G304 -- isolated test vault.
			if err != nil || !bytes.Equal(data, after) {
				t.Fatalf("invalid payload was rewritten: %v", err)
			}
		})
	}
}
