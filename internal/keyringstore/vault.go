package keyringstore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/talkincode/sshx/internal/runtimepath"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	vaultFileName   = "vault"
	vaultMagic      = "SSHXVL01"
	vaultKDFScrypt  = 1
	vaultScryptN    = 1 << 15
	vaultScryptR    = 8
	vaultScryptP    = 1
	vaultSaltSize   = 16
	vaultNonceSize  = 24
	vaultKeySize    = 32
	vaultMaxBytes   = 1 << 20
	vaultHeaderSize = 8 + 1 + 4 + 4 + 4 + vaultSaltSize // magic + kdf + N + r + p + salt
)

var (
	vaultMu    sync.Mutex
	derivedMu  sync.Mutex
	derivedHit struct {
		set      bool
		n, r, p  uint32
		salt     []byte
		passHash [32]byte
		key      [vaultKeySize]byte
	}
)

type vaultPayload struct {
	Version int                          `json:"v"`
	Secrets map[string]map[string]string `json:"secrets"`
}

func vaultUnlockKind() string {
	if strings.TrimSpace(os.Getenv(EnvVaultKeyFile)) != "" {
		return UnlockKeyFile
	}
	if _, ok := os.LookupEnv(EnvVaultPassphrase); ok {
		return UnlockEnv
	}
	return UnlockMissing
}

func vaultPassphrase() (string, error) {
	if path := strings.TrimSpace(os.Getenv(EnvVaultKeyFile)); path != "" {
		return readVaultKeyFile(path)
	}
	value, ok := os.LookupEnv(EnvVaultPassphrase)
	if !ok {
		return "", fmt.Errorf("local vault requires %s or %s", EnvVaultPassphrase, EnvVaultKeyFile)
	}
	if value == "" {
		return "", fmt.Errorf("%s is empty", EnvVaultPassphrase)
	}
	return value, nil
}

func readVaultKeyFile(path string) (string, error) {
	if err := rejectSymlink(path); err != nil {
		return "", err
	}
	if err := requireOwnerOnlyFile(path); err != nil {
		return "", fmt.Errorf("vault key file: %w", err)
	}
	data, err := os.ReadFile(path) // #nosec G304,G703 -- path is the operator-set SSHX_VAULT_KEY_FILE
	if err != nil {
		return "", fmt.Errorf("read vault key file: %w", err)
	}
	secret := strings.TrimRight(string(data), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("vault key file %s is empty", path)
	}
	return secret, nil
}

func vaultPath() (string, error) {
	root, err := runtimepath.Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, vaultFileName), nil
}

func vaultSet(service, account, password string) error {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	state, path, header, err := loadVault()
	if err != nil {
		return err
	}
	if state.Secrets[service] == nil {
		state.Secrets[service] = make(map[string]string)
	}
	state.Secrets[service][account] = password
	return saveVault(path, state, header)
}

func vaultGet(service, account string) (string, error) {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	state, _, _, err := loadVault()
	if err != nil {
		return "", err
	}
	value, ok := state.Secrets[service][account]
	if !ok {
		return "", ErrNotFound
	}
	return value, nil
}

func vaultDelete(service, account string) error {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	state, path, header, err := loadVault()
	if err != nil {
		return err
	}
	if _, ok := state.Secrets[service][account]; !ok {
		return ErrNotFound
	}
	delete(state.Secrets[service], account)
	if len(state.Secrets[service]) == 0 {
		delete(state.Secrets, service)
	}
	return saveVault(path, state, header)
}

func vaultAccounts(service string) ([]string, error) {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	state, _, _, err := loadVault()
	if err != nil {
		return nil, err
	}
	accounts := make([]string, 0, len(state.Secrets[service]))
	for name := range state.Secrets[service] {
		accounts = append(accounts, name)
	}
	sort.Strings(accounts)
	return accounts, nil
}

type vaultHeader struct {
	salt []byte
	n    uint32
	r    uint32
	p    uint32
}

func loadVault() (vaultPayload, string, vaultHeader, error) {
	path, err := vaultPath()
	if err != nil {
		return vaultPayload{}, "", vaultHeader{}, err
	}
	info, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		if _, passErr := vaultPassphrase(); passErr != nil {
			return vaultPayload{}, "", vaultHeader{}, passErr
		}
		return emptyVault(), path, vaultHeader{}, nil
	}
	if statErr != nil {
		return vaultPayload{}, "", vaultHeader{}, statErr
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return vaultPayload{}, "", vaultHeader{}, fmt.Errorf("local vault must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return vaultPayload{}, "", vaultHeader{}, fmt.Errorf("local vault %s is not a regular file", path)
	}
	if permErr := requireOwnerOnlyFile(path); permErr != nil {
		return vaultPayload{}, "", vaultHeader{}, permErr
	}
	data, err := os.ReadFile(path) // #nosec G304,G703 -- path is derived from the sshx runtime root
	if err != nil {
		return vaultPayload{}, "", vaultHeader{}, err
	}
	if len(data) > vaultMaxBytes {
		return vaultPayload{}, "", vaultHeader{}, fmt.Errorf("local vault exceeds %d-byte limit", vaultMaxBytes)
	}
	payload, header, err := decryptVault(data)
	if err != nil {
		return vaultPayload{}, "", vaultHeader{}, err
	}
	return payload, path, header, nil
}

func emptyVault() vaultPayload {
	return vaultPayload{Version: 1, Secrets: map[string]map[string]string{}}
}

func saveVault(path string, state vaultPayload, header vaultHeader) error {
	if state.Version == 0 {
		state.Version = 1
	}
	if state.Secrets == nil {
		state.Secrets = map[string]map[string]string{}
	}
	plaintext, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode local vault: %w", err)
	}
	passphrase, err := vaultPassphrase()
	if err != nil {
		return err
	}
	if len(header.salt) != vaultSaltSize {
		header.salt = make([]byte, vaultSaltSize)
		if _, saltErr := rand.Read(header.salt); saltErr != nil {
			return fmt.Errorf("generate vault salt: %w", saltErr)
		}
		header.n = vaultScryptN
		header.r = vaultScryptR
		header.p = vaultScryptP
	}
	blob, err := encryptVault(plaintext, passphrase, header)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if mkdirErr := os.MkdirAll(dir, 0o700); mkdirErr != nil {
		return fmt.Errorf("create vault directory: %w", mkdirErr)
	}
	temporary, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("create vault temp file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath) //nolint:errcheck // best-effort temp cleanup
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close() //nolint:errcheck // cleanup after chmod failure
		return fmt.Errorf("set vault file permissions: %w", err)
	}
	if _, err := temporary.Write(blob); err != nil {
		_ = temporary.Close() //nolint:errcheck // cleanup after write failure
		return fmt.Errorf("write vault file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close() //nolint:errcheck // cleanup after sync failure
		return fmt.Errorf("sync vault file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close vault temp file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace vault file: %w", err)
	}
	removeTemporary = false
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure vault file: %w", err)
	}
	return nil
}

func encryptVault(plaintext []byte, passphrase string, header vaultHeader) ([]byte, error) {
	key, err := deriveVaultKey(passphrase, header)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key[:])

	var nonce [vaultNonceSize]byte
	if _, nonceErr := rand.Read(nonce[:]); nonceErr != nil {
		return nil, fmt.Errorf("generate vault nonce: %w", nonceErr)
	}
	box := secretbox.Seal(nil, plaintext, &nonce, &key)

	out := make([]byte, 0, vaultHeaderSize+vaultNonceSize+len(box))
	out = append(out, vaultMagic...)
	out = append(out, vaultKDFScrypt)
	out = binary.BigEndian.AppendUint32(out, header.n)
	out = binary.BigEndian.AppendUint32(out, header.r)
	out = binary.BigEndian.AppendUint32(out, header.p)
	out = append(out, header.salt...)
	out = append(out, nonce[:]...)
	out = append(out, box...)
	return out, nil
}

func decryptVault(data []byte) (vaultPayload, vaultHeader, error) {
	if len(data) < vaultHeaderSize+vaultNonceSize+secretbox.Overhead {
		return vaultPayload{}, vaultHeader{}, fmt.Errorf("local vault file is truncated")
	}
	if string(data[:8]) != vaultMagic {
		return vaultPayload{}, vaultHeader{}, fmt.Errorf("local vault file has unknown magic")
	}
	if data[8] != vaultKDFScrypt {
		return vaultPayload{}, vaultHeader{}, fmt.Errorf("local vault file has unknown kdf")
	}
	header := vaultHeader{
		n:    binary.BigEndian.Uint32(data[9:13]),
		r:    binary.BigEndian.Uint32(data[13:17]),
		p:    binary.BigEndian.Uint32(data[17:21]),
		salt: append([]byte(nil), data[21:21+vaultSaltSize]...),
	}
	if header.n < 1<<14 || header.n > 1<<20 || header.n&(header.n-1) != 0 || header.r < 1 || header.r > 32 || header.p < 1 || header.p > 16 {
		return vaultPayload{}, vaultHeader{}, fmt.Errorf("local vault file has invalid kdf parameters")
	}
	passphrase, err := vaultPassphrase()
	if err != nil {
		return vaultPayload{}, vaultHeader{}, err
	}
	key, err := deriveVaultKey(passphrase, header)
	if err != nil {
		return vaultPayload{}, vaultHeader{}, err
	}
	defer zeroBytes(key[:])

	var nonce [vaultNonceSize]byte
	copy(nonce[:], data[vaultHeaderSize:vaultHeaderSize+vaultNonceSize])
	box := data[vaultHeaderSize+vaultNonceSize:]
	plaintext, ok := secretbox.Open(nil, box, &nonce, &key)
	if !ok {
		return vaultPayload{}, vaultHeader{}, fmt.Errorf("failed to unlock local vault (wrong passphrase or corrupt file)")
	}
	var payload vaultPayload
	if jsonErr := json.Unmarshal(plaintext, &payload); jsonErr != nil {
		return vaultPayload{}, vaultHeader{}, fmt.Errorf("decode local vault: %w", jsonErr)
	}
	if payload.Version != 1 {
		return vaultPayload{}, vaultHeader{}, fmt.Errorf("unsupported local vault version %d", payload.Version)
	}
	if payload.Secrets == nil {
		payload.Secrets = map[string]map[string]string{}
	}
	return payload, header, nil
}

func deriveVaultKey(passphrase string, header vaultHeader) ([vaultKeySize]byte, error) {
	var key [vaultKeySize]byte
	passHash := sha256.Sum256([]byte(passphrase))
	derivedMu.Lock()
	defer derivedMu.Unlock()
	if derivedHit.set && derivedHit.n == header.n && derivedHit.r == header.r && derivedHit.p == header.p &&
		bytes.Equal(derivedHit.salt, header.salt) && derivedHit.passHash == passHash {
		return derivedHit.key, nil
	}
	derived, err := scrypt.Key([]byte(passphrase), header.salt, int(header.n), int(header.r), int(header.p), vaultKeySize)
	if err != nil {
		return key, fmt.Errorf("derive vault key: %w", err)
	}
	copy(key[:], derived)
	zeroBytes(derived)
	derivedHit.set = true
	derivedHit.n, derivedHit.r, derivedHit.p = header.n, header.r, header.p
	derivedHit.salt = append(derivedHit.salt[:0], header.salt...)
	derivedHit.passHash = passHash
	derivedHit.key = key
	return key, nil
}

func requireOwnerOnlyFile(path string) error {
	info, err := os.Stat(path) // #nosec G703 -- path is the vault or operator key file
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s must be owner-only (0600), got %o", path, perm)
	}
	return nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path) // #nosec G703 -- path is the operator-set SSHX_VAULT_KEY_FILE
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must not be a symlink", path)
	}
	return nil
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
