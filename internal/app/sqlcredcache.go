package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/talkincode/sshx/internal/keyringstore"
	"github.com/talkincode/sshx/internal/runtimepath"
	"github.com/talkincode/sshx/internal/sqlsafe"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/logger"
)

// DefaultCredCacheTTL bounds how long remotely resolved database credentials
// stay reusable. Short by design: the cache exists to avoid re-reading the
// production environment on every statement, not to become a credential store.
const DefaultCredCacheTTL = 15 * time.Minute

// #nosec G101 -- file name of the non-secret metadata index, not a credential.
const credCacheFileName = "sql-cred-cache.json" //nolint:gosec

// Keyring operations are indirected so tests never touch the OS keychain.
var (
	credKeyringSet    = keyringstore.Set
	credKeyringGet    = keyringstore.Get
	credKeyringDelete = keyringstore.Delete
	credCacheSave     = saveCredCache
)

// credCacheEntry is the non-secret metadata for one cached credential. The
// secret itself lives only in the secret backend under Key; this file records
// identity and expiry so stale keyring entries are actively deleted.
type credCacheEntry struct {
	Key       string    `json:"key"`
	Host      string    `json:"host"`
	Source    string    `json:"source"`
	ExpiresAt time.Time `json:"expires_at"`
}

type credCacheFile struct {
	Entries []credCacheEntry `json:"entries"`
}

func credCachePath() (string, error) {
	root, err := runtimepath.Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, credCacheFileName), nil
}

// credCacheKey derives a deterministic keyring account name for one
// host + credential-source pair.
func credCacheKey(host, source string) string {
	sum := sha256.Sum256([]byte(host + "\x00" + source))
	return "sqlcred-" + hex.EncodeToString(sum[:8])
}

func loadCredCache() (credCacheFile, string, error) {
	var state credCacheFile
	path, err := credCachePath()
	if err != nil {
		return state, "", err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path derived from the sshx runtime root
	if err != nil {
		if os.IsNotExist(err) {
			return state, path, nil
		}
		return state, path, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		// A corrupt cache file is discarded rather than trusted.
		return credCacheFile{}, path, nil
	}
	return state, path, nil
}

func saveCredCache(path string, state credCacheFile) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o700); mkdirErr != nil {
		return mkdirErr
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".sql-cred-cache-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			credCacheCleanup(os.Remove(temporaryPath))
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		credCacheCleanup(temporary.Close())
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		credCacheCleanup(temporary.Close())
		return err
	}
	if err := temporary.Sync(); err != nil {
		credCacheCleanup(temporary.Close())
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

// credCacheCleanup logs best-effort cache maintenance failures at debug
// level; they never block the pipeline.
func credCacheCleanup(err error) {
	if err != nil {
		logger.GetLogger().Debug("credential cache cleanup: %v", err)
	}
}

const (
	credCacheLockWait  = 2 * time.Second
	credCacheLockStale = 30 * time.Second
)

// withCredCacheLock serializes metadata/keyring updates across sshx processes.
// The lock is bounded and stale locks left by crashed processes are reclaimed.
func withCredCacheLock(fn func() error) error {
	path, err := credCachePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lockPath := path + ".lock"
	deadline := time.Now().Add(credCacheLockWait)
	for {
		lock, openErr := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- lock path is under the sshx runtime root
		if openErr == nil {
			if _, writeErr := fmt.Fprintf(lock, "%d\n", os.Getpid()); writeErr != nil {
				credCacheCleanup(lock.Close())
				credCacheCleanup(os.Remove(lockPath))
				return writeErr
			}
			if closeErr := lock.Close(); closeErr != nil {
				credCacheCleanup(os.Remove(lockPath))
				return closeErr
			}
			defer func() {
				credCacheCleanup(os.Remove(lockPath))
			}()
			return fn()
		}
		if !os.IsExist(openErr) {
			return openErr
		}
		if info, statErr := os.Stat(lockPath); statErr == nil &&
			time.Since(info.ModTime()) > credCacheLockStale {
			if removeErr := os.Remove(lockPath); removeErr == nil || os.IsNotExist(removeErr) {
				continue
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for credential cache lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// lookupCredCache returns unexpired cached credentials for host+source.
// Expired entries are removed from both the keyring and the metadata file.
func lookupCredCache(host, source string) (*sqlsafe.Credentials, bool) {
	var creds *sqlsafe.Credentials
	var found bool
	if err := withCredCacheLock(func() error {
		creds, found = lookupCredCacheUnlocked(host, source)
		return nil
	}); err != nil {
		return nil, false
	}
	return creds, found
}

func lookupCredCacheUnlocked(host, source string) (*sqlsafe.Credentials, bool) {
	state, path, err := loadCredCache()
	if err != nil || path == "" {
		return nil, false
	}
	now := time.Now()
	var hit *credCacheEntry
	kept := state.Entries[:0]
	dirty := false
	for i := range state.Entries {
		e := state.Entries[i]
		if now.After(e.ExpiresAt) {
			credCacheCleanup(credKeyringDelete(sshclient.KeyringServiceName, e.Key))
			dirty = true
			continue
		}
		if e.Host == host && e.Source == source {
			hit = &e
		}
		kept = append(kept, e)
	}
	if dirty {
		state.Entries = kept
		credCacheCleanup(credCacheSave(path, state))
	}
	if hit == nil {
		return nil, false
	}
	secret, err := credKeyringGet(sshclient.KeyringServiceName, hit.Key)
	if err != nil {
		return nil, false
	}
	var creds sqlsafe.Credentials
	if err := json.Unmarshal([]byte(secret), &creds); err != nil || creds.Password == "" {
		return nil, false
	}
	return &creds, true
}

// storeCredCache saves resolved credentials in the OS keyring and records
// only non-secret metadata (key id, identity, expiry) on disk.
func storeCredCache(host, source string, creds sqlsafe.Credentials, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	return withCredCacheLock(func() error {
		return storeCredCacheUnlocked(host, source, creds, ttl)
	})
}

func storeCredCacheUnlocked(host, source string, creds sqlsafe.Credentials, ttl time.Duration) error {
	state, path, err := loadCredCache()
	if err != nil {
		return err
	}
	// #nosec G117 -- serialized bytes are written only to the OS keyring.
	secret, err := json.Marshal(creds) //nolint:gosec
	if err != nil {
		return err
	}
	key := credCacheKey(host, source)
	previous, previousErr := credKeyringGet(sshclient.KeyringServiceName, key)
	if setErr := credKeyringSet(sshclient.KeyringServiceName, key, string(secret)); setErr != nil {
		return fmt.Errorf("failed to store credentials in system keyring: %w", setErr)
	}
	entry := credCacheEntry{Key: key, Host: host, Source: source, ExpiresAt: time.Now().Add(ttl)}
	replaced := false
	for i := range state.Entries {
		if state.Entries[i].Key == key {
			state.Entries[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		state.Entries = append(state.Entries, entry)
	}
	if saveErr := credCacheSave(path, state); saveErr != nil {
		var rollbackErr error
		if previousErr == nil {
			rollbackErr = credKeyringSet(sshclient.KeyringServiceName, key, previous)
		} else {
			rollbackErr = credKeyringDelete(sshclient.KeyringServiceName, key)
		}
		if rollbackErr != nil {
			return fmt.Errorf("failed to save credential cache metadata: %w (keyring rollback also failed: %v)", saveErr, rollbackErr)
		}
		return fmt.Errorf("failed to save credential cache metadata: %w", saveErr)
	}
	return nil
}

// dropCredCache removes one cached credential (used by --cred-refresh so a
// failed refresh never leaves a stale secret behind).
func dropCredCache(host, source string) {
	credCacheCleanup(withCredCacheLock(func() error {
		dropCredCacheUnlocked(host, source)
		return nil
	}))
}

func dropCredCacheUnlocked(host, source string) {
	state, path, err := loadCredCache()
	if err != nil || path == "" {
		return
	}
	key := credCacheKey(host, source)
	kept := state.Entries[:0]
	removed := false
	for _, e := range state.Entries {
		if e.Key == key {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	if !removed {
		return
	}
	credCacheCleanup(credKeyringDelete(sshclient.KeyringServiceName, key))
	state.Entries = kept
	credCacheCleanup(credCacheSave(path, state))
}
