package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/talkincode/sshx/internal/sshclient"
)

func TestHostAddOmitsDefaultSudoKey(t *testing.T) {
	setTestHome(t, t.TempDir())
	cfg := ParseArgs([]string{"sshx", "--host-add", "--host-name=lab", "--host=127.0.0.1", "-u=probe", "--json"})
	if cfg.SudoKeySet {
		t.Fatal("omitted -pk must not set SudoKeySet")
	}
	var addErr error
	out := string(captureStdout(t, func() { addErr = HandleHostManagement(cfg) }))
	if addErr != nil {
		t.Fatalf("host-add: %v", addErr)
	}
	if strings.Contains(out, "added successfully") {
		t.Fatalf("json stdout leaked human text: %s", out)
	}
	var addDoc hostActionJSON
	if unmarshalErr := json.Unmarshal([]byte(out), &addDoc); unmarshalErr != nil {
		t.Fatalf("add json: %v (%s)", unmarshalErr, out)
	}
	if !addDoc.Success || addDoc.Action != "add" || addDoc.SchemaVersion != "sshx.hosts.v1" {
		t.Fatalf("add doc = %+v", addDoc)
	}
	if addDoc.Host == nil || addDoc.Host.SudoPasswordKey != "" {
		t.Fatalf("sudo_password_key should be omitted, got %+v", addDoc.Host)
	}

	listCfg := ParseArgs([]string{"sshx", "--host-list", "--json"})
	var listErr error
	listOut := string(captureStdout(t, func() { listErr = HandleHostManagement(listCfg) }))
	if listErr != nil {
		t.Fatalf("host-list: %v", listErr)
	}
	if strings.Contains(listOut, `"sudo_password_key": "master"`) {
		t.Fatalf("inventory persisted default master key: %s", listOut)
	}

	explicit := ParseArgs([]string{"sshx", "--host-add", "--host-name=web", "--host=10.0.0.1", "-pk=web-sudo", "--json"})
	if !explicit.SudoKeySet || explicit.SudoKey != "web-sudo" {
		t.Fatalf("explicit -pk not recorded: set=%t key=%q", explicit.SudoKeySet, explicit.SudoKey)
	}
	var explicitErr error
	_ = captureStdout(t, func() { explicitErr = HandleHostManagement(explicit) })
	if explicitErr != nil {
		t.Fatalf("explicit host-add: %v", explicitErr)
	}
	listOut = string(captureStdout(t, func() {
		listErr = HandleHostManagement(ParseArgs([]string{"sshx", "--host-list", "--json"}))
	}))
	if listErr != nil {
		t.Fatalf("host-list after explicit: %v", listErr)
	}
	if !strings.Contains(listOut, `"sudo_password_key": "web-sudo"`) {
		t.Fatalf("explicit sudo key missing: %s", listOut)
	}
}

func TestHostUpdateRemoveJSON(t *testing.T) {
	setTestHome(t, t.TempDir())
	var err error
	_ = captureStdout(t, func() {
		err = HandleHostManagement(ParseArgs([]string{"sshx", "--host-add", "--host-name=lab", "--host=127.0.0.1", "--json"}))
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	out := string(captureStdout(t, func() {
		err = HandleHostManagement(ParseArgs([]string{"sshx", "--host-update", "--host-name=lab", "--host-desc=updated", "--json"}))
	}))
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	var updateDoc hostActionJSON
	if unmarshalErr := json.Unmarshal([]byte(out), &updateDoc); unmarshalErr != nil {
		t.Fatalf("update json: %v (%s)", unmarshalErr, out)
	}
	if !updateDoc.Success || updateDoc.Host == nil || updateDoc.Host.Description != "updated" {
		t.Fatalf("update doc = %+v", updateDoc)
	}

	out = string(captureStdout(t, func() {
		err = HandleHostManagement(ParseArgs([]string{"sshx", "--host-remove=lab", "--json"}))
	}))
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	var removeDoc hostActionJSON
	if unmarshalErr := json.Unmarshal([]byte(out), &removeDoc); unmarshalErr != nil {
		t.Fatalf("remove json: %v (%s)", unmarshalErr, out)
	}
	if !removeDoc.Success || removeDoc.Action != "remove" {
		t.Fatalf("remove doc = %+v", removeDoc)
	}
}

func TestHostImportJSON(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	sshConfig := filepath.Join(home, "ssh_config")
	if err := os.WriteFile(sshConfig, []byte("Host imported\n  HostName 127.0.0.1\n  User probe\n"), 0o600); err != nil {
		t.Fatalf("write ssh config: %v", err)
	}
	var importErr error
	out := string(captureStdout(t, func() {
		importErr = HandleHostManagement(ParseArgs([]string{
			"sshx", "--host-import=imported", "--ssh-config=" + sshConfig, "--json",
		}))
	}))
	if importErr != nil {
		t.Fatalf("import: %v stdout=%s", importErr, out)
	}
	if strings.Contains(out, "Imported host") || strings.Contains(out, "Imported 1") {
		t.Fatalf("json stdout leaked human text: %s", out)
	}
	var doc hostActionJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("import json: %v (%s)", err, out)
	}
	if !doc.Success || doc.Action != "import" || doc.Count != 1 || len(doc.Hosts) != 1 {
		t.Fatalf("import doc = %+v", doc)
	}
	if doc.Hosts[0].Name != "imported" || doc.Hosts[0].Host != "127.0.0.1" {
		t.Fatalf("imported host = %+v", doc.Hosts[0])
	}
}

func TestHostTestJSONFailedConnect(t *testing.T) {
	setTestHome(t, t.TempDir())
	var err error
	_ = captureStdout(t, func() {
		err = HandleHostManagement(ParseArgs([]string{"sshx", "--host-add", "--host-name=lab", "--host=127.0.0.1", "-u=probe", "--json"}))
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	out := string(captureStdout(t, func() {
		err = HandleHostManagement(ParseArgs([]string{"sshx", "--host-test=lab", "--json", "--no-key"}))
	}))
	if !errors.Is(err, ErrReported) {
		t.Fatalf("test error = %v, want ErrReported; stdout=%s", err, out)
	}
	if strings.Contains(out, "Testing connection") || strings.Contains(out, "Connection failed") {
		t.Fatalf("json stdout leaked human text: %s", out)
	}
	var doc hostActionJSON
	if unmarshalErr := json.Unmarshal([]byte(out), &doc); unmarshalErr != nil {
		t.Fatalf("test json: %v (%s)", unmarshalErr, out)
	}
	if doc.Success || doc.Action != "test" || doc.ErrorKind == "" {
		t.Fatalf("test doc = %+v", doc)
	}
}

func TestFormatAuthDescription(t *testing.T) {
	tests := []struct {
		method   sshclient.AuthMethod
		expected string
	}{
		{sshclient.AuthMethodKey, "SSH key"},
		{sshclient.AuthMethodPassword, "Password"},
		{sshclient.AuthMethodPasswordFallback, "Password (fallback after key failure)"},
		{sshclient.AuthMethodUnknown, "Unknown"},
	}

	for _, tt := range tests {
		if got := formatAuthDescription(tt.method); got != tt.expected {
			t.Errorf("formatAuthDescription(%s) = %q, expected %q", tt.method, got, tt.expected)
		}
	}
}

func TestBuildHostTestConfigDefaults(t *testing.T) {
	settings := &Settings{Key: "/custom/key"}
	host := &HostConfig{
		Name: "demo",
		Host: "demo.example.com",
	}
	base := &sshclient.Config{UseKeyAuth: true}

	cfg := buildHostTestConfig(host, settings, base)

	if cfg.Port != sshclient.DefaultSSHPort {
		t.Fatalf("expected default port %s, got %s", sshclient.DefaultSSHPort, cfg.Port)
	}
	if cfg.User != sshclient.DefaultSSHUser {
		t.Fatalf("expected default user %s, got %s", sshclient.DefaultSSHUser, cfg.User)
	}
	if cfg.KeyPath != settings.Key {
		t.Fatalf("expected key path %s, got %s", settings.Key, cfg.KeyPath)
	}
	if !cfg.UseKeyAuth {
		t.Fatalf("expected key auth to remain enabled")
	}
	if cfg.DialTimeout != hostTestDialTimeout {
		t.Fatalf("expected dial timeout %s, got %s", hostTestDialTimeout, cfg.DialTimeout)
	}
}

func TestBuildHostTestConfig_DisableKeyAuth(t *testing.T) {
	host := &HostConfig{Host: "demo"}
	base := &sshclient.Config{UseKeyAuth: false, KeyPath: "/tmp/key", Password: "secret", DialTimeout: 5 * time.Second}

	cfg := buildHostTestConfig(host, nil, base)

	if cfg.UseKeyAuth {
		t.Fatalf("expected key auth to be disabled")
	}
	if cfg.KeyPath != "" {
		t.Fatalf("expected key path to be cleared, got %s", cfg.KeyPath)
	}
	if cfg.Password != "secret" {
		t.Fatalf("expected password to propagate from base config")
	}
	if cfg.DialTimeout != base.DialTimeout {
		t.Fatalf("expected dial timeout override to persist (want %s, got %s)", base.DialTimeout, cfg.DialTimeout)
	}
}

func TestBuildHostTestConfig_BindInheritAndOverride(t *testing.T) {
	host := &HostConfig{Host: "demo", Bind: "en0"}

	cfg := buildHostTestConfig(host, nil, &sshclient.Config{UseKeyAuth: true})
	if cfg.Bind != "en0" {
		t.Fatalf("inherited bind = %q", cfg.Bind)
	}

	cfg = buildHostTestConfig(host, nil, &sshclient.Config{UseKeyAuth: true, Bind: "192.0.2.10", BindSet: true})
	if cfg.Bind != "192.0.2.10" {
		t.Fatalf("cli bind = %q", cfg.Bind)
	}

	cfg = buildHostTestConfig(host, nil, &sshclient.Config{UseKeyAuth: true, Bind: "", BindSet: true})
	if cfg.Bind != "" {
		t.Fatalf("empty --bind= must clear host bind, got %q", cfg.Bind)
	}
}
