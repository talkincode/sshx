package app

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/talkincode/sshx/internal/runtimepath"
	"github.com/talkincode/sshx/internal/sqlsafe"
)

// fakeKeyring redirects the cred-cache keyring indirection to memory so tests
// never touch the OS keychain.
type fakeKeyring struct {
	store map[string]string
}

func installFakeKeyring(t *testing.T) *fakeKeyring {
	t.Helper()
	fk := &fakeKeyring{store: map[string]string{}}
	origSet, origGet, origDelete := credKeyringSet, credKeyringGet, credKeyringDelete
	credKeyringSet = func(service, account, password string) error {
		fk.store[service+"/"+account] = password
		return nil
	}
	credKeyringGet = func(service, account string) (string, error) {
		v, ok := fk.store[service+"/"+account]
		if !ok {
			return "", errors.New("not found")
		}
		return v, nil
	}
	credKeyringDelete = func(service, account string) error {
		delete(fk.store, service+"/"+account)
		return nil
	}
	t.Cleanup(func() {
		credKeyringSet, credKeyringGet, credKeyringDelete = origSet, origGet, origDelete
	})
	return fk
}

func TestCredCacheRoundTrip(t *testing.T) {
	t.Setenv(runtimepath.EnvHome, t.TempDir())
	fk := installFakeKeyring(t)

	creds := sqlsafe.Credentials{User: "app", Password: "s3cr3t", Database: "appdb"}
	if err := storeCredCache("db1", "docker:pg-prod", creds, time.Minute); err != nil {
		t.Fatalf("store failed: %v", err)
	}
	if len(fk.store) != 1 {
		t.Fatalf("expected one keyring entry, got %d", len(fk.store))
	}

	got, ok := lookupCredCache("db1", "docker:pg-prod")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if *got != creds {
		t.Fatalf("cache returned %#v", got)
	}

	if _, ok := lookupCredCache("db2", "docker:pg-prod"); ok {
		t.Fatal("different host must miss")
	}
	if _, ok := lookupCredCache("db1", "docker:other"); ok {
		t.Fatal("different source must miss")
	}
}

func TestCredCacheExpiryDeletesSecret(t *testing.T) {
	t.Setenv(runtimepath.EnvHome, t.TempDir())
	fk := installFakeKeyring(t)

	creds := sqlsafe.Credentials{Password: "s3cr3t"}
	if err := storeCredCache("db1", "env-file:/opt/.env", creds, -time.Second); err != nil {
		t.Fatalf("store failed: %v", err)
	}
	// TTL <= 0 must be a no-op (caching disabled).
	if len(fk.store) != 0 {
		t.Fatal("ttl<=0 must not store anything")
	}

	if err := storeCredCache("db1", "env-file:/opt/.env", creds, time.Millisecond); err != nil {
		t.Fatalf("store failed: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, ok := lookupCredCache("db1", "env-file:/opt/.env"); ok {
		t.Fatal("expired entry must miss")
	}
	if len(fk.store) != 0 {
		t.Fatal("expired secret must be deleted from the keyring")
	}
}

func TestDropCredCache(t *testing.T) {
	t.Setenv(runtimepath.EnvHome, t.TempDir())
	fk := installFakeKeyring(t)

	creds := sqlsafe.Credentials{Password: "s3cr3t"}
	if err := storeCredCache("db1", "docker:pg", creds, time.Hour); err != nil {
		t.Fatalf("store failed: %v", err)
	}

	dropCredCache("db1", "docker:pg")
	if len(fk.store) != 0 {
		t.Fatal("drop must remove the keyring secret")
	}
	if _, ok := lookupCredCache("db1", "docker:pg"); ok {
		t.Fatal("dropped entry must miss")
	}
}

func TestCredCacheMetadataFailureRollsBackSecret(t *testing.T) {
	t.Setenv(runtimepath.EnvHome, t.TempDir())
	fk := installFakeKeyring(t)
	originalSave := credCacheSave
	credCacheSave = func(string, credCacheFile) error {
		return errors.New("metadata unavailable")
	}

	t.Cleanup(func() { credCacheSave = originalSave })
	err := storeCredCache("db1", "docker:pg", sqlsafe.Credentials{Password: "s3cr3t"}, time.Hour)
	if err == nil {
		t.Fatal("expected metadata save failure")
	}
	if len(fk.store) != 0 {
		t.Fatal("metadata failure must roll back the keyring secret")
	}
}

func TestConcurrentCredCacheStoresPreserveEntries(t *testing.T) {
	t.Setenv(runtimepath.EnvHome, t.TempDir())
	fk := installFakeKeyring(t)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, target := range []struct {
		host   string
		source string
	}{
		{host: "db1", source: "docker:pg1"},
		{host: "db2", source: "docker:pg2"},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- storeCredCache(target.host, target.source, sqlsafe.Credentials{Password: "secret"}, time.Hour)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent store failed: %v", err)
		}
	}
	if len(fk.store) != 2 {
		t.Fatalf("expected two keyring entries, got %d", len(fk.store))
	}
	state, _, err := loadCredCache()
	if err != nil {
		t.Fatalf("load metadata: %v", err)
	}
	if len(state.Entries) != 2 {
		t.Fatalf("expected two metadata entries, got %d", len(state.Entries))
	}
}
