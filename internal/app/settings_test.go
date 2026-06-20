package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSettings_NotExist(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() {
		if err := os.Setenv("HOME", oldHome); err != nil {
			t.Logf("Warning: failed to restore HOME: %v", err)
		}
	})
	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}

	settings, err := LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings() error = %v", err)
	}

	if settings == nil {
		t.Fatal("LoadSettings() returned nil settings")
	}

	if settings.Hosts == nil {
		t.Error("LoadSettings() Hosts should be initialized")
	}

	if len(settings.Hosts) != 0 {
		t.Errorf("LoadSettings() expected 0 hosts, got %d", len(settings.Hosts))
	}
}

func TestSaveAndLoadSettings(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() {
		if err := os.Setenv("HOME", oldHome); err != nil {
			t.Logf("Warning: failed to restore HOME: %v", err)
		}
	})
	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}

	// Create settings
	settings := &Settings{
		Key: "/home/user/.ssh/id_rsa",
		Hosts: []HostConfig{
			{
				Name:        "test-host",
				Description: "Test Host",
				Host:        "192.168.1.100",
				Port:        "22",
				User:        "root",
				PasswordKey: "test-password",
				Type:        "linux",
			},
		},
	}

	// Save settings
	if err := SaveSettings(settings); err != nil {
		t.Fatalf("SaveSettings() error = %v", err)
	}

	// Verify settings directory was created
	settingsDir, err := GetSettingsDir()
	if err != nil {
		t.Fatalf("GetSettingsDir() error = %v", err)
	}

	if _, statErr := os.Stat(settingsDir); os.IsNotExist(statErr) {
		t.Error("Settings directory was not created")
	}
	if info, statErr := os.Stat(settingsDir); statErr != nil {
		t.Fatalf("Stat settings dir error = %v", statErr)
	} else if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("settings dir perm = %o, want 700", perm)
	}

	// Load settings
	loadedSettings, err := LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings() error = %v", err)
	}

	// Compare
	if loadedSettings.Key != settings.Key {
		t.Errorf("Key mismatch: got %s, want %s", loadedSettings.Key, settings.Key)
	}

	if len(loadedSettings.Hosts) != len(settings.Hosts) {
		t.Fatalf("Hosts count mismatch: got %d, want %d", len(loadedSettings.Hosts), len(settings.Hosts))
	}

	host := loadedSettings.Hosts[0]
	expectedHost := settings.Hosts[0]

	if host.Name != expectedHost.Name {
		t.Errorf("Host name mismatch: got %s, want %s", host.Name, expectedHost.Name)
	}
	if host.Host != expectedHost.Host {
		t.Errorf("Host address mismatch: got %s, want %s", host.Host, expectedHost.Host)
	}
}

func TestValidateHostConfig(t *testing.T) {
	tests := []struct {
		name    string
		host    HostConfig
		wantErr bool
	}{
		{
			name: "valid host",
			host: HostConfig{
				Name: "test",
				Host: "192.168.1.100",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			host: HostConfig{
				Host: "192.168.1.100",
			},
			wantErr: true,
		},
		{
			name: "missing host",
			host: HostConfig{
				Name: "test",
			},
			wantErr: true,
		},
		{
			name:    "empty host",
			host:    HostConfig{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostConfig(&tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAddHost(t *testing.T) {
	settings := &Settings{
		Hosts: make([]HostConfig, 0),
	}

	// Test adding valid host
	host1 := HostConfig{
		Name: "host1",
		Host: "192.168.1.100",
	}

	if err := AddHost(settings, host1); err != nil {
		t.Fatalf("AddHost() error = %v", err)
	}

	if len(settings.Hosts) != 1 {
		t.Errorf("Expected 1 host, got %d", len(settings.Hosts))
	}

	// Verify default values
	if settings.Hosts[0].Port != "22" {
		t.Errorf("Expected default port 22, got %s", settings.Hosts[0].Port)
	}
	if settings.Hosts[0].User != "master" {
		t.Errorf("Expected default user master, got %s", settings.Hosts[0].User)
	}

	// Test adding duplicate host
	if err := AddHost(settings, host1); err == nil {
		t.Error("AddHost() should return error for duplicate host name")
	}

	// Test adding duplicate host+port combination with different name
	host2 := HostConfig{
		Name: "host2",
		Host: "192.168.1.100", // Same IP
		Port: "22",            // Same port (or default)
	}
	if err := AddHost(settings, host2); err == nil {
		t.Error("AddHost() should return error for duplicate host+port combination")
	}

	// Test adding same host but different port (should succeed)
	host3 := HostConfig{
		Name: "host3",
		Host: "192.168.1.100", // Same IP
		Port: "2222",          // Different port
	}
	if err := AddHost(settings, host3); err != nil {
		t.Errorf("AddHost() should allow same host with different port, got error: %v", err)
	}

	if len(settings.Hosts) != 2 {
		t.Errorf("Expected 2 hosts (host1 and host3), got %d", len(settings.Hosts))
	}

	// Test adding invalid host
	invalidHost := HostConfig{
		Name: "invalid",
	}
	if err := AddHost(settings, invalidHost); err == nil {
		t.Error("AddHost() should return error for invalid host")
	}
}

func TestRemoveHost(t *testing.T) {
	settings := &Settings{
		Hosts: []HostConfig{
			{Name: "host1", Host: "192.168.1.100"},
			{Name: "host2", Host: "192.168.1.101"},
		},
	}

	// Remove existing host
	if err := RemoveHost(settings, "host1"); err != nil {
		t.Fatalf("RemoveHost() error = %v", err)
	}

	if len(settings.Hosts) != 1 {
		t.Errorf("Expected 1 host after removal, got %d", len(settings.Hosts))
	}

	if settings.Hosts[0].Name != "host2" {
		t.Errorf("Wrong host removed, got %s", settings.Hosts[0].Name)
	}

	// Remove non-existent host
	if err := RemoveHost(settings, "host3"); err == nil {
		t.Error("RemoveHost() should return error for non-existent host")
	}
}

func TestGetHost(t *testing.T) {
	settings := &Settings{
		Hosts: []HostConfig{
			{Name: "host1", Host: "192.168.1.100"},
			{Name: "host2", Host: "192.168.1.101"},
		},
	}

	// Get existing host
	host, err := GetHost(settings, "host1")
	if err != nil {
		t.Fatalf("GetHost() error = %v", err)
	}

	if host.Name != "host1" {
		t.Errorf("Expected host1, got %s", host.Name)
	}

	// Get non-existent host
	_, err = GetHost(settings, "host3")
	if err == nil {
		t.Error("GetHost() should return error for non-existent host")
	}
}

func TestUpdateHost(t *testing.T) {
	settings := &Settings{
		Hosts: []HostConfig{
			{Name: "host1", Host: "192.168.1.100", Port: "22"},
			{Name: "host2", Host: "192.168.1.101", Port: "22"},
		},
	}

	// Update existing host
	updatedHost := HostConfig{
		Name:        "host1",
		Host:        "192.168.1.200",
		Port:        "2222",
		Description: "Updated host",
	}

	if err := UpdateHost(settings, updatedHost); err != nil {
		t.Fatalf("UpdateHost() error = %v", err)
	}

	host := settings.Hosts[0]
	if host.Host != "192.168.1.200" {
		t.Errorf("Host not updated, got %s", host.Host)
	}
	if host.Port != "2222" {
		t.Errorf("Port not updated, got %s", host.Port)
	}

	// Test updating to duplicate host+port combination
	duplicateUpdate := HostConfig{
		Name: "host1",
		Host: "192.168.1.101", // Same as host2
		Port: "22",            // Same as host2
	}
	if err := UpdateHost(settings, duplicateUpdate); err == nil {
		t.Error("UpdateHost() should return error when updating to duplicate host+port combination")
	}

	// Test updating to same host with different port (should succeed)
	validUpdate := HostConfig{
		Name: "host1",
		Host: "192.168.1.101", // Same as host2
		Port: "2222",          // Different port
	}
	if err := UpdateHost(settings, validUpdate); err != nil {
		t.Errorf("UpdateHost() should allow same host with different port, got error: %v", err)
	}

	// Update non-existent host
	nonExistentHost := HostConfig{
		Name: "host3",
		Host: "192.168.1.201",
	}
	if err := UpdateHost(settings, nonExistentHost); err == nil {
		t.Error("UpdateHost() should return error for non-existent host")
	}
}

func TestListHosts(t *testing.T) {
	settings := &Settings{
		Hosts: []HostConfig{
			{Name: "host1", Host: "192.168.1.100"},
			{Name: "host2", Host: "192.168.1.101"},
		},
	}

	hosts := ListHosts(settings)
	if len(hosts) != 2 {
		t.Errorf("Expected 2 hosts, got %d", len(hosts))
	}
}

func TestJSONMarshaling(t *testing.T) {
	host := HostConfig{
		Name:        "test",
		Description: "Test Host",
		Host:        "192.168.1.100",
		Port:        "22",
		User:        "root",
		PasswordKey: "",
		Type:        "linux",
	}

	data, err := json.Marshal(host)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var unmarshaled HostConfig
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if unmarshaled.Name != host.Name {
		t.Errorf("Name mismatch after unmarshal: got %s, want %s", unmarshaled.Name, host.Name)
	}
}

func TestSettingsPath(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() {
		if err := os.Setenv("HOME", oldHome); err != nil {
			t.Logf("Warning: failed to restore HOME: %v", err)
		}
	})
	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}

	settingsPath, err := GetSettingsPath()
	if err != nil {
		t.Fatalf("GetSettingsPath() error = %v", err)
	}

	expectedPath := filepath.Join(tmpDir, SettingsDir, SettingsFile)
	if settingsPath != expectedPath {
		t.Errorf("GetSettingsPath() = %s, want %s", settingsPath, expectedPath)
	}

	settingsDir, err := GetSettingsDir()
	if err != nil {
		t.Fatalf("GetSettingsDir() error = %v", err)
	}

	expectedDir := filepath.Join(tmpDir, SettingsDir)
	if settingsDir != expectedDir {
		t.Errorf("GetSettingsDir() = %s, want %s", settingsDir, expectedDir)
	}
}

func TestSaveSettings_AtomicOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() {
		if err := os.Setenv("HOME", oldHome); err != nil {
			t.Logf("Warning: failed to restore HOME: %v", err)
		}
	})
	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}

	first := &Settings{Hosts: []HostConfig{{Name: "a", Host: "10.0.0.1"}}}
	if err := SaveSettings(first); err != nil {
		t.Fatalf("first SaveSettings() error = %v", err)
	}

	second := &Settings{Hosts: []HostConfig{{Name: "b", Host: "10.0.0.2"}}}
	if err := SaveSettings(second); err != nil {
		t.Fatalf("second SaveSettings() error = %v", err)
	}

	loaded, err := LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings() error = %v", err)
	}
	if len(loaded.Hosts) != 1 || loaded.Hosts[0].Name != "b" {
		t.Fatalf("overwrite failed, got %+v", loaded.Hosts)
	}

	settingsDir, err := GetSettingsDir()
	if err != nil {
		t.Fatalf("GetSettingsDir() error = %v", err)
	}

	// No leftover temp files from the atomic write.
	leftovers, err := filepath.Glob(filepath.Join(settingsDir, "settings-*.tmp"))
	if err != nil {
		t.Fatalf("Glob error = %v", err)
	}
	if len(leftovers) != 0 {
		t.Errorf("found leftover temp files: %v", leftovers)
	}

	// Settings file must be created with 0600 permissions.
	info, err := os.Stat(filepath.Join(settingsDir, SettingsFile))
	if err != nil {
		t.Fatalf("Stat settings file error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("settings file perm = %o, want 600", perm)
	}
}

func TestSaveSettings_RenameFailureCleansTempFile(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() {
		if err := os.Setenv("HOME", oldHome); err != nil {
			t.Logf("Warning: failed to restore HOME: %v", err)
		}
	})
	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}

	settingsDir, err := GetSettingsDir()
	if err != nil {
		t.Fatalf("GetSettingsDir() error = %v", err)
	}
	if mkdirErr := os.MkdirAll(filepath.Join(settingsDir, SettingsFile), 0700); mkdirErr != nil {
		t.Fatalf("failed to create blocking settings directory: %v", mkdirErr)
	}

	err = SaveSettings(&Settings{Hosts: []HostConfig{{Name: "blocked", Host: "10.0.0.9"}}})
	if err == nil {
		t.Fatal("expected SaveSettings() to fail when settings path is a directory")
	}

	leftovers, err := filepath.Glob(filepath.Join(settingsDir, "settings-*.tmp"))
	if err != nil {
		t.Fatalf("Glob error = %v", err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("expected temp settings file cleanup after failure, got %v", leftovers)
	}

	info, err := os.Stat(filepath.Join(settingsDir, SettingsFile))
	if err != nil {
		t.Fatalf("expected blocking settings directory to remain: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected settings path to remain a directory after failed rename")
	}
}
