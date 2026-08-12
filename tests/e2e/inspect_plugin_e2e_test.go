package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pluginpkg "github.com/talkincode/sshx/internal/plugin"
)

func TestCLIPluginLifecycleCreatesValidRecoverableRuntimeAssets(t *testing.T) {
	home := t.TempDir()
	runtimeRoot := filepath.Join(t.TempDir(), "agent-runtime")
	runtimeEnv := map[string]string{"SSHX_HOME": runtimeRoot}

	created := runSSHX(t, home, []string{"plugin", "create", "private.environment", "--template=docker", "--privilege=optional", "--json"}, runtimeEnv)
	require.Equal(t, 0, created.exitCode, created.stderr)
	var createResult pluginpkg.ActionResult
	require.NoError(t, json.Unmarshal([]byte(created.stdout), &createResult))
	assert.True(t, createResult.Success)
	assert.False(t, createResult.Trusted)
	assert.Len(t, createResult.Files, 6)
	assert.Equal(t, filepath.Join(runtimeRoot, "plugins", "private.environment"), createResult.Path)
	for _, directory := range []string{
		runtimeRoot,
		filepath.Join(runtimeRoot, "plugins"),
		createResult.Path,
		filepath.Join(createResult.Path, "collectors"),
		filepath.Join(createResult.Path, "fixtures"),
	} {
		info, err := os.Stat(directory)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), directory)
	}

	for _, relative := range createResult.Files {
		info, err := os.Stat(filepath.Join(createResult.Path, relative))
		require.NoError(t, err)
		if strings.HasPrefix(relative, "collectors/") {
			assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
		} else {
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		}
	}

	validated := runSSHX(t, home, []string{"plugin", "validate", "private.environment", "--json"}, runtimeEnv)
	require.Equal(t, 0, validated.exitCode, validated.stderr)
	tested := runSSHX(t, home, []string{"plugin", "test", "private.environment", "--fixture=complete", "--json"}, runtimeEnv)
	require.Equal(t, 0, tested.exitCode, tested.stderr)
	shown := runSSHX(t, home, []string{"plugin", "show", "private.environment", "--json"}, runtimeEnv)
	require.Equal(t, 0, shown.exitCode, shown.stderr)
	var shownResult pluginpkg.ActionResult
	require.NoError(t, json.Unmarshal([]byte(shown.stdout), &shownResult))
	require.NotNil(t, shownResult.Manifest)
	assert.Equal(t, "private.environment", shownResult.Manifest.ID)
	listed := runSSHX(t, home, []string{"plugin", "list", "--json"}, runtimeEnv)
	require.Equal(t, 0, listed.exitCode, listed.stderr)
	assert.Contains(t, listed.stdout, "private.environment")

	assertValidationFailure := func(result cliResult, wantKind string) {
		t.Helper()
		assert.Equal(t, 255, result.exitCode, result.stderr)
		var failure pluginpkg.ActionResult
		require.NoError(t, json.Unmarshal([]byte(result.stdout), &failure))
		assert.Equal(t, wantKind, failure.ErrorKind)
	}
	restore := func() {
		t.Helper()
		replaced := runSSHX(t, home, []string{"plugin", "create", "private.environment", "--template=docker", "--privilege=optional", "--replace", "--json"}, runtimeEnv)
		require.Equal(t, 0, replaced.exitCode, replaced.stderr)
	}
	require.NoError(t, os.WriteFile(filepath.Join(createResult.Path, pluginpkg.ManifestFile), []byte("{\n"), 0o600))
	assertValidationFailure(runSSHX(t, home, []string{"plugin", "validate", "private.environment", "--json"}, runtimeEnv), "invalid_manifest")
	restore()
	require.NoError(t, os.Remove(filepath.Join(createResult.Path, "collectors", "linux.sh")))
	assertValidationFailure(runSSHX(t, home, []string{"plugin", "validate", "private.environment", "--json"}, runtimeEnv), "invalid_entrypoint")
	restore()
	require.NoError(t, os.WriteFile(filepath.Join(createResult.Path, "result.schema.json"), []byte("{\n"), 0o600))
	assertValidationFailure(runSSHX(t, home, []string{"plugin", "validate", "private.environment", "--json"}, runtimeEnv), "invalid_schema")
	restore()
	require.NoError(t, os.WriteFile(filepath.Join(createResult.Path, "fixtures", "complete.json"), []byte("{}{}\n"), 0o600))
	assertValidationFailure(runSSHX(t, home, []string{"plugin", "test", "private.environment", "--fixture=complete", "--json"}, runtimeEnv), "invalid_fixture")
	restore()

	duplicate := runSSHX(t, home, []string{"plugin", "create", "private.environment", "--json"}, runtimeEnv)
	assert.Equal(t, 255, duplicate.exitCode)
	var duplicateResult pluginpkg.ActionResult
	require.NoError(t, json.Unmarshal([]byte(duplicate.stdout), &duplicateResult))
	assert.Equal(t, "already_exists", duplicateResult.ErrorKind)

	replaced := runSSHX(t, home, []string{"plugin", "create", "private.environment", "--replace", "--json"}, runtimeEnv)
	require.Equal(t, 0, replaced.exitCode, replaced.stderr)
	var replaceResult pluginpkg.ActionResult
	require.NoError(t, json.Unmarshal([]byte(replaced.stdout), &replaceResult))
	assert.NotEmpty(t, replaceResult.BackupPath)
	_, err := os.Stat(filepath.Join(replaceResult.BackupPath, pluginpkg.ManifestFile))
	require.NoError(t, err)

	invalid := runSSHX(t, home, []string{"plugin", "create", "../escape", "--json"}, runtimeEnv)
	assert.Equal(t, 255, invalid.exitCode)
	assert.NoDirExists(t, filepath.Join(runtimeRoot, "escape"))

	removed := runSSHX(t, home, []string{"plugin", "remove", "private.environment", "--json"}, runtimeEnv)
	require.Equal(t, 0, removed.exitCode, removed.stderr)
	var removeResult pluginpkg.ActionResult
	require.NoError(t, json.Unmarshal([]byte(removed.stdout), &removeResult))
	assert.NotEmpty(t, removeResult.BackupPath)
	assert.NoDirExists(t, createResult.Path)
}

func TestCLIInspectionTrustExecutionRedactionAndRemoteCache(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	create := runSSHX(t, home, []string{"plugin", "create", "fleet.environment", "--privilege=optional", "--json"}, nil)
	require.Equal(t, 0, create.exitCode, create.stderr)

	collectorPath := filepath.Join(home, ".sshx", "plugins", "fleet.environment", "collectors", "linux.sh")
	collector := "#!/bin/sh\n" +
		"set -eu\n" +
		"if [ \"$SSHX_E2E_ROLE\" = \"reader\" ]; then\n" +
		"  printf '%s\\n' '{\"status\":\"partial\",\"facts\":{\"present\":true},\"evidence\":[{\"kind\":\"direct\",\"source\":\"role fixture\"}],\"errors\":[{\"kind\":\"permission_denied\",\"section\":\"runtime\"}]}'\n" +
		"else\n" +
		"  printf '%s\\n' '{\"status\":\"complete\",\"facts\":{\"present\":true,\"password\":\"super-secret\",\"nested\":{\"api_token\":\"super-secret\",\"note\":\"token=super-secret\",\"safe\":\"kept\"}},\"evidence\":[{\"kind\":\"direct\",\"source\":\"collector fixture\"}],\"errors\":[]}'\n" +
		"fi\n"
	require.NoError(t, os.WriteFile(collectorPath, []byte(collector), 0o700)) // #nosec G306 -- executable E2E fixture.

	base := []string{
		"inspect",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
		"fleet.environment",
	}
	env := map[string]string{"SSH_PASSWORD": operatorPassword}
	connectionsBefore := server.connections.Load()
	untrusted := runSSHX(t, home, append(append([]string{}, base...), "--accept-unknown-host"), env)
	assert.Equal(t, 255, untrusted.exitCode)
	assert.Equal(t, connectionsBefore, server.connections.Load(), "untrusted plugin must fail before SSH")
	var untrustedResult map[string]any
	require.NoError(t, json.Unmarshal([]byte(untrusted.stdout), &untrustedResult))
	assert.Equal(t, "untrusted_plugin", untrustedResult["error_kind"])

	trusted := runSSHX(t, home, []string{"plugin", "trust", "fleet.environment", "--json"}, nil)
	require.Equal(t, 0, trusted.exitCode, trusted.stderr)

	dryRun := runSSHX(t, home, append(append([]string{}, base...), "--accept-unknown-host", "--cache=remote-prefer", "--dry-run"), nil)
	require.Equal(t, 0, dryRun.exitCode, dryRun.stderr)
	var plan struct {
		Valid                 bool
		PluginTrusted         bool     `json:"plugin_trusted"`
		PluginEffects         []string `json:"plugin_effects"`
		PluginPrivilege       string   `json:"plugin_privilege"`
		WouldConnect          bool     `json:"would_connect"`
		WouldExecute          bool     `json:"would_execute"`
		WouldWriteRemoteState bool     `json:"would_write_remote_state"`
	}
	require.NoError(t, json.Unmarshal([]byte(dryRun.stdout), &plan))
	assert.True(t, plan.Valid)
	assert.True(t, plan.PluginTrusted)
	assert.Equal(t, []string{"remote.read"}, plan.PluginEffects)
	assert.Equal(t, "optional", plan.PluginPrivilege)
	assert.True(t, plan.WouldConnect)
	assert.True(t, plan.WouldExecute)
	assert.True(t, plan.WouldWriteRemoteState)
	assert.Equal(t, connectionsBefore, server.connections.Load(), "dry-run must not connect")
	overHardMax := runSSHX(t, home, append(append([]string{}, base...), "--accept-unknown-host", "--max-age=2h", "--allow-stale"), env)
	assert.Equal(t, 255, overHardMax.exitCode)
	assert.Contains(t, overHardMax.stdout, `"error_kind":"config"`)
	assert.Equal(t, connectionsBefore, server.connections.Load(), "hard max age must fail before SSH")

	collectorRunsBefore := server.collectorRuns.Load()
	cold := runSSHX(t, home, append(append([]string{}, base...), "--accept-unknown-host", "--cache=remote-prefer"), map[string]string{
		"SSH_PASSWORD":  operatorPassword,
		"SSHX_NO_AUDIT": "false",
	})
	require.Equal(t, 0, cold.exitCode, "stderr=%s stdout=%s", cold.stderr, cold.stdout)
	var observation pluginpkg.Observation
	require.NoError(t, json.Unmarshal([]byte(cold.stdout), &observation))
	assert.Equal(t, "complete", observation.Status)
	assert.False(t, observation.Cache.Hit)
	assert.Equal(t, "linux", observation.Target.Platform)
	assert.Equal(t, "boot-e2e", observation.Target.BootID)
	assert.NotEmpty(t, observation.Target.HostKeyFingerprint)
	assert.Equal(t, collectorRunsBefore+1, server.collectorRuns.Load())
	assert.NotContains(t, cold.stdout, "super-secret")
	assert.Contains(t, cold.stdout, "<redacted>")
	nested, ok := observation.Facts["nested"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "kept", nested["safe"])

	snapshotPath := filepath.Join(server.root, ".sshx", "observations", "v1", "fleet.environment.json")
	snapshot, err := os.ReadFile(snapshotPath) // #nosec G304 -- isolated E2E server root.
	require.NoError(t, err)
	assert.NotContains(t, string(snapshot), "super-secret")
	info, err := os.Stat(snapshotPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.NoFileExists(t, filepath.Join(server.root, ".sshx", "plugins", "fleet.environment", "collectors", "linux.sh"))

	auditFiles, err := filepath.Glob(filepath.Join(home, ".sshx", "audit", "*.jsonl"))
	require.NoError(t, err)
	require.NotEmpty(t, auditFiles)
	audit, err := os.ReadFile(auditFiles[0])
	require.NoError(t, err)
	assert.NotContains(t, string(audit), "super-secret")
	assert.Contains(t, string(audit), "fleet.environment")
	assert.Contains(t, string(audit), `"observation_status":"complete"`)
	assert.Contains(t, string(audit), `"cache_mode":"remote-prefer"`)

	runsAfterCold := server.collectorRuns.Load()
	connectionsAfterCold := server.connections.Load()
	warm := runSSHX(t, home, append(append([]string{}, base...), "--cache=remote-prefer"), env)
	require.Equal(t, 0, warm.exitCode, warm.stderr)
	require.NoError(t, json.Unmarshal([]byte(warm.stdout), &observation))
	assert.True(t, observation.Cache.Hit)
	assert.False(t, observation.Cache.Stale)
	assert.Equal(t, runsAfterCold, server.collectorRuns.Load(), "fresh cache must skip collector")
	assert.Equal(t, connectionsAfterCold+1, server.connections.Load(), "warm read still uses exactly one SSH connection")

	stale := runSSHX(t, home, append(append([]string{}, base...), "--cache=remote-prefer", "--max-age=1ns"), env)
	require.Equal(t, 0, stale.exitCode, stale.stderr)
	require.NoError(t, json.Unmarshal([]byte(stale.stdout), &observation))
	assert.False(t, observation.Cache.Hit)
	assert.Equal(t, runsAfterCold+1, server.collectorRuns.Load(), "stale cache must refresh")

	partial := runSSHX(t, home, []string{
		"inspect", "-h=" + server.host, "-p=" + server.port, "-u=reader",
		"--no-key", "--json", "fleet.environment",
	}, map[string]string{"SSH_PASSWORD": readerPassword})
	require.Equal(t, 0, partial.exitCode, partial.stderr)
	require.NoError(t, json.Unmarshal([]byte(partial.stdout), &observation))
	assert.Equal(t, "partial", observation.Status)
	require.Len(t, observation.Errors, 1)
	assert.Equal(t, "permission_denied", observation.Errors[0].Kind)
}

func TestCLIBuiltInBaselineRunsInOneConnection(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	beforeConnections := server.connections.Load()
	beforeRuns := server.collectorRuns.Load()

	result := runSSHX(t, home, []string{
		"inspect",
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--json",
		"system.baseline",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, result.exitCode, "stderr=%s stdout=%s", result.stderr, result.stdout)
	var observation pluginpkg.Observation
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &observation))
	assert.Contains(t, []string{"complete", "partial"}, observation.Status)
	for _, section := range []string{"identity", "resources", "interfaces", "routes", "dns", "listeners", "firewall"} {
		assert.Contains(t, observation.Facts, section)
	}
	assert.Equal(t, beforeConnections+1, server.connections.Load())
	assert.Equal(t, beforeRuns+1, server.collectorRuns.Load())
}

func TestCLIInspectionClassifiesCollectorFailuresAndUnsupportedPlatforms(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	require.Equal(t, 0, runSSHX(t, home, []string{"plugin", "create", "failure.check", "--json"}, nil).exitCode)
	collectorPath := filepath.Join(home, ".sshx", "plugins", "failure.check", "collectors", "linux.sh")
	base := []string{
		"inspect", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key",
		"--accept-unknown-host", "--json", "failure.check",
	}
	env := map[string]string{"SSH_PASSWORD": operatorPassword}

	runCase := func(name, collector, timeout, wantKind string) {
		t.Helper()
		require.NoError(t, os.WriteFile(collectorPath, []byte(collector), 0o700), name) // #nosec G306 -- executable E2E fixture.
		trusted := runSSHX(t, home, []string{"plugin", "trust", "failure.check", "--json"}, nil)
		require.Equal(t, 0, trusted.exitCode, trusted.stderr)
		args := append([]string{}, base...)
		if timeout != "" {
			args = append(args, "--timeout="+timeout)
		}
		result := runSSHX(t, home, args, env)
		assert.Equal(t, 255, result.exitCode, "%s: stderr=%s stdout=%s", name, result.stderr, result.stdout)
		var failure map[string]any
		require.NoError(t, json.Unmarshal([]byte(result.stdout), &failure), name)
		assert.Equal(t, wantKind, failure["error_kind"], name)
	}

	runCase("stdout contamination", "#!/bin/sh\nprintf '%s\\n%s\\n' '{\"status\":\"complete\",\"facts\":{},\"evidence\":[],\"errors\":[]}' '{} '\n", "", "invalid_output")
	runCase("remote non-zero", "#!/bin/sh\nexit 23\n", "", "collector_exit")
	runCase("timeout", "#!/bin/sh\nsleep 1\nprintf '%s\\n' '{\"status\":\"complete\",\"facts\":{},\"evidence\":[],\"errors\":[]}'\n", "150ms", "timeout")
	runCase("oversized stdout", "#!/bin/sh\ndd if=/dev/zero bs=1048576 count=11 2>/dev/null | tr '\\000' x\n", "", "output_too_large")

	remotePlugin := filepath.Join(server.root, ".sshx", "plugins", "failure.check", "collectors", "linux.sh")
	assert.NoFileExists(t, remotePlugin, "collectors must never be installed on the target")

	require.Equal(t, 0, runSSHX(t, home, []string{"plugin", "create", "darwin.only", "--platform=darwin", "--json"}, nil).exitCode)
	require.Equal(t, 0, runSSHX(t, home, []string{"plugin", "trust", "darwin.only", "--json"}, nil).exitCode)
	unsupported := runSSHX(t, home, []string{
		"inspect", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key",
		"--json", "darwin.only",
	}, env)
	require.Equal(t, 0, unsupported.exitCode, unsupported.stderr)
	var observation pluginpkg.Observation
	require.NoError(t, json.Unmarshal([]byte(unsupported.stdout), &observation))
	assert.Equal(t, "unsupported", observation.Status)
	require.Len(t, observation.Errors, 1)
	assert.Equal(t, "unsupported_platform", observation.Errors[0].Kind)
}

func TestCLIObservationFreshnessIdentityAndUntrustedInputFailClosed(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	require.Equal(t, 0, runSSHX(t, home, []string{"plugin", "create", "cache.check", "--json"}, nil).exitCode)
	require.Equal(t, 0, runSSHX(t, home, []string{"plugin", "trust", "cache.check", "--json"}, nil).exitCode)
	args := []string{
		"inspect", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key",
		"--json", "--cache=remote-prefer", "cache.check",
	}
	env := map[string]string{"SSH_PASSWORD": operatorPassword}
	first := runSSHX(t, home, append(append([]string{}, args...), "--accept-unknown-host"), env)
	require.Equal(t, 0, first.exitCode, first.stderr)
	snapshotPath := filepath.Join(server.root, ".sshx", "observations", "v1", "cache.check.json")

	t.Run("boot id drift refreshes", func(t *testing.T) {
		data, err := os.ReadFile(snapshotPath) // #nosec G304 -- isolated E2E server root.
		require.NoError(t, err)
		var observation pluginpkg.Observation
		require.NoError(t, json.Unmarshal(data, &observation))
		observation.Target.BootID = "previous-boot"
		data, err = json.Marshal(observation)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(snapshotPath, data, 0o600)) // #nosec G703 -- isolated E2E server root.
		runs := server.collectorRuns.Load()
		refreshed := runSSHX(t, home, args, env)
		require.Equal(t, 0, refreshed.exitCode, refreshed.stderr)
		assert.Equal(t, runs+1, server.collectorRuns.Load())
		require.NoError(t, json.Unmarshal([]byte(refreshed.stdout), &observation))
		assert.False(t, observation.Cache.Hit)
		assert.Equal(t, "boot-e2e", observation.Target.BootID)
	})

	t.Run("explicit allow stale skips collector", func(t *testing.T) {
		time.Sleep(2 * time.Millisecond)
		runs := server.collectorRuns.Load()
		stale := runSSHX(t, home, append(append([]string{}, args...), "--max-age=1ns", "--allow-stale"), env)
		require.Equal(t, 0, stale.exitCode, stale.stderr)
		var observation pluginpkg.Observation
		require.NoError(t, json.Unmarshal([]byte(stale.stdout), &observation))
		assert.True(t, observation.Cache.Hit)
		assert.True(t, observation.Cache.Stale)
		assert.Equal(t, runs, server.collectorRuns.Load())
	})

	t.Run("unsafe cache permissions are rejected", func(t *testing.T) {
		data, err := os.ReadFile(snapshotPath) // #nosec G304 -- isolated E2E server root.
		require.NoError(t, err)
		require.NoError(t, os.Chmod(snapshotPath, 0o644)) // #nosec G302 -- deliberately creates an unsafe cache fixture.
		runs := server.collectorRuns.Load()
		unsafe := runSSHX(t, home, args, env)
		assert.Equal(t, 255, unsafe.exitCode)
		assert.Equal(t, runs, server.collectorRuns.Load())
		assert.Contains(t, unsafe.stdout, "cache_invalid")
		require.NoError(t, os.WriteFile(snapshotPath, data, 0o600)) // #nosec G703 -- isolated E2E server root.
	})

	t.Run("oversized cache is rejected", func(t *testing.T) {
		data, err := os.ReadFile(snapshotPath) // #nosec G304 -- isolated E2E server root.
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(snapshotPath, make([]byte, pluginpkg.MaxObservation+1), 0o600))
		runs := server.collectorRuns.Load()
		oversized := runSSHX(t, home, args, env)
		assert.Equal(t, 255, oversized.exitCode)
		assert.Equal(t, runs, server.collectorRuns.Load())
		assert.Contains(t, oversized.stdout, "cache_invalid")
		require.NoError(t, os.WriteFile(snapshotPath, data, 0o600)) // #nosec G703 -- isolated E2E server root.
	})

	t.Run("wrong cache ownership is rejected", func(t *testing.T) {
		wrongOwnerServer := startSSHServer(t, serverOptions{root: server.root, reportedUID: "4294967294"})
		wrongOwnerArgs := []string{
			"inspect", "-h=" + wrongOwnerServer.host, "-p=" + wrongOwnerServer.port, "-u=operator", "--no-key",
			"--accept-unknown-host", "--json", "--cache=remote-prefer", "cache.check",
		}
		wrongOwner := runSSHX(t, home, wrongOwnerArgs, env)
		assert.Equal(t, 255, wrongOwner.exitCode)
		assert.Contains(t, wrongOwner.stdout, "cache_invalid")
		assert.Zero(t, wrongOwnerServer.collectorRuns.Load())
	})

	t.Run("malformed cache is rejected without collector", func(t *testing.T) {
		require.NoError(t, os.WriteFile(snapshotPath, []byte("{}\n"), 0o600))
		runs := server.collectorRuns.Load()
		malformed := runSSHX(t, home, args, env)
		assert.Equal(t, 255, malformed.exitCode)
		assert.Equal(t, runs, server.collectorRuns.Load())
		var failure map[string]any
		require.NoError(t, json.Unmarshal([]byte(malformed.stdout), &failure))
		assert.Equal(t, "cache_invalid", failure["error_kind"])
	})

	t.Run("symlink cache is rejected", func(t *testing.T) {
		require.NoError(t, os.Remove(snapshotPath))
		outside := filepath.Join(server.root, "outside.json")
		require.NoError(t, os.WriteFile(outside, []byte("{}"), 0o600))
		require.NoError(t, os.Symlink(outside, snapshotPath))
		runs := server.collectorRuns.Load()
		symlinked := runSSHX(t, home, args, env)
		assert.Equal(t, 255, symlinked.exitCode)
		assert.Equal(t, runs, server.collectorRuns.Load())
		assert.Contains(t, symlinked.stdout, "cache_invalid")
	})
}

func TestCLIConcurrentAndFailedCacheWritesPreserveValidObservation(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	require.Equal(t, 0, runSSHX(t, home, []string{"plugin", "create", "atomic.check", "--json"}, nil).exitCode)
	require.Equal(t, 0, runSSHX(t, home, []string{"plugin", "trust", "atomic.check", "--json"}, nil).exitCode)
	base := []string{
		"inspect", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key",
		"--accept-unknown-host", "--json", "--cache=remote-prefer", "atomic.check",
	}
	env := map[string]string{"SSH_PASSWORD": operatorPassword}
	require.Equal(t, 0, runSSHX(t, home, base, env).exitCode)
	snapshotPath := filepath.Join(server.root, ".sshx", "observations", "v1", "atomic.check.json")

	results := make([]cliResult, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index] = runSSHX(t, home, append(append([]string{}, base...), "--refresh"), env)
		}(index)
	}
	wait.Wait()
	for _, result := range results {
		require.Equal(t, 0, result.exitCode, "stderr=%s stdout=%s", result.stderr, result.stdout)
	}
	beforeFailure, err := os.ReadFile(snapshotPath) // #nosec G304 -- isolated E2E server root.
	require.NoError(t, err)
	_, err = pluginpkg.DecodeObservation(beforeFailure)
	require.NoError(t, err)

	readOnly := startSSHServer(t, serverOptions{root: server.root, sftpReadOnly: true})
	failed := runSSHX(t, home, []string{
		"inspect", "-h=" + readOnly.host, "-p=" + readOnly.port, "-u=operator", "--no-key",
		"--accept-unknown-host", "--json", "--cache=remote-prefer", "--refresh", "atomic.check",
	}, env)
	assert.Equal(t, 255, failed.exitCode)
	assert.Contains(t, failed.stdout, `"error_kind":"cache"`)
	afterFailure, err := os.ReadFile(snapshotPath) // #nosec G304 -- isolated E2E server root.
	require.NoError(t, err)
	assert.Equal(t, beforeFailure, afterFailure, "failed cache replacement must preserve the previous snapshot")
	_, err = pluginpkg.DecodeObservation(afterFailure)
	require.NoError(t, err)
}

func TestCLICacheWriteRejectsSymlinkedManagedRootBeforeCreatingChildren(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	require.Equal(t, 0, runSSHX(t, home, []string{"plugin", "create", "symlink.write", "--json"}, nil).exitCode)
	require.Equal(t, 0, runSSHX(t, home, []string{"plugin", "trust", "symlink.write", "--json"}, nil).exitCode)

	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(server.root, ".sshx")))
	result := runSSHX(t, home, []string{
		"inspect", "-h=" + server.host, "-p=" + server.port, "-u=operator", "--no-key",
		"--accept-unknown-host", "--json", "--cache=remote-prefer", "symlink.write",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})

	assert.Equal(t, 255, result.exitCode)
	assert.Contains(t, result.stdout, `"error_kind":"cache"`)
	entries, err := os.ReadDir(outside)
	require.NoError(t, err)
	assert.Empty(t, entries, "a rejected managed-root symlink must not create directories outside the cache root")
}
