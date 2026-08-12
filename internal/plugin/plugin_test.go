package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCreateProducesRestrictiveCompleteScaffold(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SSHX_HOME", root)

	created, err := Create(CreateOptions{ID: "demo.inspect", Template: "generic"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.Resolved.Trusted {
		t.Fatal("new local plugin must start untrusted")
	}
	wantFiles := []string{"README.md", "collectors/linux.sh", "fixtures/complete.json", "fixtures/partial.json", "manifest.json", "result.schema.json"}
	if strings.Join(created.Files, ",") != strings.Join(wantFiles, ",") {
		t.Fatalf("files = %v, want %v", created.Files, wantFiles)
	}
	for _, relative := range created.Files {
		info, statErr := os.Stat(filepath.Join(created.Resolved.Path, relative))
		if statErr != nil {
			t.Fatalf("stat %s: %v", relative, statErr)
		}
		wantMode := os.FileMode(0o600)
		if relative == "collectors/linux.sh" {
			wantMode = 0o700
		}
		if info.Mode().Perm() != wantMode {
			t.Fatalf("%s mode = %04o, want %04o", relative, info.Mode().Perm(), wantMode)
		}
	}
}

func TestCreateRejectsTraversalAndPreservesReplacement(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SSHX_HOME", root)
	for _, id := range []string{"../escape", "/absolute", "Upper", "a/b", "a\\b"} {
		if _, err := Create(CreateOptions{ID: id}); err == nil {
			t.Fatalf("Create(%q) succeeded, want rejection", id)
		}
	}
	first, err := Create(CreateOptions{ID: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(first.Resolved.Path, "marker")
	if writeErr := os.WriteFile(marker, []byte("preserve"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if _, duplicateErr := Create(CreateOptions{ID: "demo"}); duplicateErr == nil {
		t.Fatal("duplicate create succeeded without --replace")
	}
	replaced, err := Create(CreateOptions{ID: "demo", Replace: true})
	if err != nil {
		t.Fatal(err)
	}
	if replaced.BackupPath == "" {
		t.Fatal("replace did not report a backup")
	}
	data, err := os.ReadFile(filepath.Join(replaced.BackupPath, "marker"))
	if err != nil || string(data) != "preserve" {
		t.Fatalf("replacement backup missing marker: %q, %v", data, err)
	}
}

func TestTrustInvalidatesWhenCollectorChanges(t *testing.T) {
	t.Setenv("SSHX_HOME", t.TempDir())
	created, err := Create(CreateOptions{ID: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := Trust("demo")
	if err != nil {
		t.Fatal(err)
	}
	if !trusted.Trusted {
		t.Fatal("Trust() did not trust current digest")
	}
	entrypoint := filepath.Join(created.Resolved.Path, "collectors", "linux.sh")
	file, err := os.OpenFile(entrypoint, os.O_APPEND|os.O_WRONLY, 0o700) // #nosec G304,G302 -- isolated executable test plugin.
	if err != nil {
		t.Fatal(err)
	}
	if _, writeErr := file.WriteString("\n# changed\n"); writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	changed, err := Resolve("demo")
	if err != nil {
		t.Fatal(err)
	}
	if changed.Trusted || changed.Digest == trusted.Digest {
		t.Fatalf("digest drift was not detected: old=%s new=%s trusted=%t", trusted.Digest, changed.Digest, changed.Trusted)
	}
}

func TestValidateRejectsSymlinkEntrypointAndMultipleJSONDocuments(t *testing.T) {
	t.Setenv("SSHX_HOME", t.TempDir())
	created, err := Create(CreateOptions{ID: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	entrypoint := filepath.Join(created.Resolved.Path, "collectors", "linux.sh")
	if removeErr := os.Remove(entrypoint); removeErr != nil {
		t.Fatal(removeErr)
	}
	if symlinkErr := os.Symlink("/bin/sh", entrypoint); symlinkErr != nil {
		t.Fatal(symlinkErr)
	}
	if _, resolveErr := Resolve("demo"); resolveErr == nil || !strings.Contains(resolveErr.Error(), "symlink") {
		t.Fatalf("Resolve() error = %v, want symlink rejection", resolveErr)
	}

	resolved, _ := resolveBuiltin("system.identity")
	_, err = ValidateResult(resolved, []byte(completeFixture+completeFixture))
	if err == nil || !strings.Contains(err.Error(), "multiple JSON documents") {
		t.Fatalf("ValidateResult() error = %v", err)
	}
}

func TestResolveRejectsWritablePluginDirectoryAndUnsafeLock(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SSHX_HOME", root)
	created, err := Create(CreateOptions{ID: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if chmodErr := os.Chmod(created.Resolved.Path, 0o777); chmodErr != nil { // #nosec G302 -- deliberately creates an unsafe test fixture.
		t.Fatal(chmodErr)
	}
	if _, err := Resolve("demo"); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("Resolve() error = %v, want unsafe directory rejection", err)
	}
	if err := os.Chmod(created.Resolved.Path, 0o700); err != nil { // #nosec G302 -- owner-only directory requires traversal.
		t.Fatal(err)
	}
	if _, err := Trust("demo"); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, LockFile)
	if err := os.Chmod(lockPath, 0o644); err != nil { // #nosec G302 -- deliberately creates an unsafe test fixture.
		t.Fatal(err)
	}
	if _, err := Resolve("demo"); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("Resolve() error = %v, want unsafe lock rejection", err)
	}
}

func TestRedactionRemovesSensitiveFieldsAndInlineValues(t *testing.T) {
	result := Result{
		Status: "complete",
		Facts: map[string]any{
			"password": "plain",
			"nested": map[string]any{
				"api_token": "plain",
				"note":      "status token=plain",
				"safe":      "kept",
			},
		},
		Evidence: []Evidence{{Kind: "direct", Source: "api_key=plain"}},
		Errors:   []ResultError{{Kind: "test", Message: "password:plain"}},
	}
	clean, paths := RedactResult(result, RedactionPolicy{})
	encoded, err := json.Marshal(clean)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "plain") {
		t.Fatalf("redacted output leaked secret fixture: %s", text)
	}
	if !strings.Contains(text, "kept") || len(paths) != 5 {
		t.Fatalf("unexpected redaction result: %s paths=%v", text, paths)
	}
}

func TestCacheReusableRejectsIdentityDriftAndClassifiesStale(t *testing.T) {
	resolved, _ := resolveBuiltin("system.identity")
	now := time.Now().UTC()
	target := TargetRef{Host: "server-a", Port: "22", User: "deploy", UID: "1000", HostKeyFingerprint: "SHA256:key", Platform: "linux", BootID: "boot-a"}
	observation := Observation{
		Schema:      ObservationV1,
		Capability:  CapabilityRef{ID: resolved.Manifest.ID, Version: resolved.Manifest.Version, Digest: resolved.Digest, Builtin: true},
		Target:      target,
		CollectedAt: now.Add(-2 * time.Minute),
		ExpiresAt:   now.Add(-time.Minute),
		Status:      "complete",
		Privilege:   "user",
		Parameters:  "params",
		Facts:       map[string]any{},
		Evidence:    []Evidence{},
		Errors:      []ResultError{},
	}
	reusable, stale, reason := CacheReusable(observation, resolved, target, "user", "params", now, time.Hour)
	if !reusable || !stale || reason != "stale" {
		t.Fatalf("cache = reusable:%t stale:%t reason:%s", reusable, stale, reason)
	}
	target.BootID = "boot-b"
	reusable, _, reason = CacheReusable(observation, resolved, target, "user", "params", now, time.Hour)
	if reusable || reason != "boot_id_changed" {
		t.Fatalf("boot drift cache = reusable:%t reason:%s", reusable, reason)
	}

	tests := []struct {
		name       string
		mutate     func(*Observation, *Resolved, *TargetRef, *string, *string)
		wantReason string
	}{
		{"capability version", func(o *Observation, _ *Resolved, _ *TargetRef, _ *string, _ *string) { o.Capability.Version = "9.9.9" }, "capability_version_changed"},
		{"plugin digest", func(o *Observation, _ *Resolved, _ *TargetRef, _ *string, _ *string) {
			o.Capability.Digest = "sha256:changed"
		}, "capability_digest_changed"},
		{"host", func(_ *Observation, _ *Resolved, target *TargetRef, _ *string, _ *string) { target.Host = "server-b" }, "host_changed"},
		{"port", func(_ *Observation, _ *Resolved, target *TargetRef, _ *string, _ *string) { target.Port = "2222" }, "port_changed"},
		{"user", func(_ *Observation, _ *Resolved, target *TargetRef, _ *string, _ *string) { target.User = "root" }, "user_changed"},
		{"host key", func(_ *Observation, _ *Resolved, target *TargetRef, _ *string, _ *string) {
			target.HostKeyFingerprint = "SHA256:other"
		}, "host_key_changed"},
		{"platform", func(_ *Observation, _ *Resolved, target *TargetRef, _ *string, _ *string) { target.Platform = "darwin" }, "platform_changed"},
		{"uid", func(_ *Observation, _ *Resolved, target *TargetRef, _ *string, _ *string) { target.UID = "2000" }, "uid_changed"},
		{"privilege", func(_ *Observation, _ *Resolved, _ *TargetRef, privilege *string, _ *string) { *privilege = "sudo" }, "privilege_changed"},
		{"parameters", func(_ *Observation, _ *Resolved, _ *TargetRef, _ *string, parameters *string) { *parameters = "other" }, "parameters_changed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := observation
			candidate.Target.BootID = "boot-a"
			candidate.Target.UID = "1000"
			candidate.ExpiresAt = now.Add(time.Hour)
			candidate.CollectedAt = now
			resolvedCopy := *resolved
			targetCopy := candidate.Target
			privilege := "user"
			parameters := "params"
			test.mutate(&candidate, &resolvedCopy, &targetCopy, &privilege, &parameters)
			candidateReusable, _, candidateReason := CacheReusable(candidate, &resolvedCopy, targetCopy, privilege, parameters, now, time.Hour)
			if candidateReusable || candidateReason != test.wantReason {
				t.Fatalf("cache = reusable:%t reason:%s, want %s", candidateReusable, candidateReason, test.wantReason)
			}
		})
	}
	future := observation
	future.Target.BootID = "boot-a"
	future.CollectedAt = now.Add(time.Minute)
	future.ExpiresAt = now.Add(2 * time.Minute)
	reusable, _, reason = CacheReusable(future, resolved, future.Target, "user", "params", now, time.Hour)
	if reusable || reason != "collected_at_in_future" {
		t.Fatalf("future cache = reusable:%t reason:%s", reusable, reason)
	}
}

func TestDockerTemplateDiscoversComposeMetadataWithoutEnvironmentValues(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SSHX_HOME", root)
	secretFixture := "registry-secret-fixture" // #nosec G101 -- verifies that collectors do not expose secret-bearing inputs.
	t.Setenv("DOCKER_REGISTRY_AUTH", secretFixture)
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("TOKEN="+secretFixture+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeDocker := `#!/bin/sh
set -eu
case "$1" in
  info)
    if [ "$#" -eq 1 ]; then exit 0; fi
    printf '%s\n' '{"docker_root_dir":"/var/lib/docker","storage_driver":"overlay2","cgroup_driver":"systemd","server_version":"27.0","rootless":[]}'
    ;;
  version)
    printf '%s\n' '{"client":"27.0","server":"27.0"}'
    ;;
  ps)
    printf '%s\n' 'container-id'
    ;;
  inspect)
    printf '%s\n' '{"id":"container-id","name":"/web","image":"example/web:1","state":"running","restart_count":0,"ports":{},"networks":{},"mounts":[],"compose":{"project":"example","service":"web","working_dir":"/srv/example","config_files":"/srv/example/compose.yml"}}'
    ;;
  image)
    printf '%s\n' '{"id":"sha256:image","repository":"example/web","tag":"1","digest":"sha256:digest","size":"10MB"}'
    ;;
  network)
    printf '%s\n' '{"id":"network-id","name":"example_default","driver":"bridge","scope":"local"}'
    ;;
  volume)
    printf '%s\n' '{"name":"example_data","driver":"local","scope":"local"}'
    ;;
  *) exit 2 ;;
esac
`
	dockerPath := filepath.Join(binDir, "docker")
	if err := os.WriteFile(dockerPath, []byte(fakeDocker), 0o700); err != nil { // #nosec G306 -- executable test fixture.
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := Create(CreateOptions{ID: "docker.environment", Template: "docker", Privilege: "optional"}); err != nil {
		t.Fatal(err)
	}
	_, result, _, err := Test("docker.environment", "")
	if err != nil {
		t.Fatalf("Test() error = %v", err)
	}
	containers, ok := result.Facts["containers"].([]any)
	if !ok || len(containers) != 1 {
		t.Fatalf("containers = %#v", result.Facts["containers"])
	}
	for _, key := range []string{"images", "networks", "volumes"} {
		items, itemsOK := result.Facts[key].([]any)
		if !itemsOK || len(items) != 1 {
			t.Fatalf("%s = %#v", key, result.Facts[key])
		}
	}
	container, ok := containers[0].(map[string]any)
	if !ok {
		t.Fatalf("container = %#v", containers[0])
	}
	compose, ok := container["compose"].(map[string]any)
	if !ok {
		t.Fatalf("compose = %#v", container["compose"])
	}
	if compose["project"] != "example" || compose["working_dir"] != "/srv/example" || compose["config_files"] != "/srv/example/compose.yml" {
		t.Fatalf("compose metadata = %#v", compose)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "env") || strings.Contains(string(encoded), "registry-auth") || strings.Contains(string(encoded), secretFixture) {
		t.Fatalf("docker result collected forbidden secret surfaces: %s", encoded)
	}
}

func TestDockerTemplateDistinguishesAbsentFromPermissionLimited(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell plugin tests require a POSIX shell")
	}
	t.Run("absent", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("SSHX_HOME", root)
		emptyPath := filepath.Join(root, "empty-bin")
		if err := os.MkdirAll(emptyPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/bin/sh", filepath.Join(emptyPath, "sh")); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", emptyPath)
		if _, err := Create(CreateOptions{ID: "docker.absent", Template: "docker"}); err != nil {
			t.Fatal(err)
		}
		_, result, _, err := Test("docker.absent", "")
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "complete" || result.Facts["present"] != false {
			t.Fatalf("absent result = %#v", result)
		}
	})

	t.Run("permission limited", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("SSHX_HOME", root)
		binDir := filepath.Join(root, "bin")
		if err := os.MkdirAll(binDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil { // #nosec G306 -- executable test fixture.
			t.Fatal(err)
		}
		if err := os.Symlink("/bin/sh", filepath.Join(binDir, "sh")); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", binDir)
		if _, err := Create(CreateOptions{ID: "docker.denied", Template: "docker"}); err != nil {
			t.Fatal(err)
		}
		_, result, _, err := Test("docker.denied", "")
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "partial" || result.Facts["present"] != true || result.Facts["daemon_accessible"] != false {
			t.Fatalf("permission-limited result = %#v", result)
		}
	})
}
