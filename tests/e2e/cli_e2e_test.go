package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestCLICommandReturnsStructuredResult(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()

	result := runSSHX(t, home, []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--json",
		"probe",
	}, map[string]string{"SSH_PASSWORD": operatorPassword})

	require.Equal(t, 0, result.exitCode, result.stderr)
	var payload commandResult
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload))
	assert.True(t, payload.Success)
	assert.Equal(t, 0, payload.ExitCode)
	assert.Equal(t, "probe-ok\n", payload.Stdout)
	assert.Empty(t, payload.Stderr)
	assert.Equal(t, "password", payload.AuthMethod)
}

func TestCLIKeyAuthenticationAndExplicitPasswordFallback(t *testing.T) {
	authorizedSigner, authorizedKeyPath := newClientKey(t)
	server := startSSHServer(t, serverOptions{authorizedKey: authorizedSigner.PublicKey()})
	home := t.TempDir()
	base := []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--json",
	}

	keyResult := runSSHX(t, home, append(append([]string{}, base...),
		"-i="+authorizedKeyPath,
		"--accept-unknown-host",
		"probe",
	), nil)
	require.Equal(t, 0, keyResult.exitCode, keyResult.stderr)
	var keyPayload commandResult
	require.NoError(t, json.Unmarshal([]byte(keyResult.stdout), &keyPayload))
	assert.Equal(t, "key", keyPayload.AuthMethod)

	_, rejectedKeyPath := newClientKey(t)
	fallbackResult := runSSHX(t, home, append(append([]string{}, base...),
		"-i="+rejectedKeyPath,
		"probe",
	), map[string]string{"SSH_PASSWORD": operatorPassword})
	require.Equal(t, 0, fallbackResult.exitCode, "stderr=%s stdout=%s", fallbackResult.stderr, fallbackResult.stdout)
	var fallbackPayload commandResult
	require.NoError(t, json.Unmarshal([]byte(fallbackResult.stdout), &fallbackPayload))
	assert.Equal(t, "password-fallback", fallbackPayload.AuthMethod)
	assert.Equal(t, "probe-ok\n", fallbackPayload.Stdout)
}

func TestCLIProcessDistinguishesRemoteExitAndStreams(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	base := []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--json",
	}

	streams := runSSHX(t, home, append(append([]string{}, base...), "bothstreams"), map[string]string{
		"SSH_PASSWORD": operatorPassword,
	})
	require.Equal(t, 0, streams.exitCode, streams.stderr)
	var streamsPayload commandResult
	require.NoError(t, json.Unmarshal([]byte(streams.stdout), &streamsPayload))
	assert.Equal(t, "to-out\n", streamsPayload.Stdout)
	assert.Equal(t, "to-err\n", streamsPayload.Stderr)

	remoteExit := runSSHX(t, home, append(append([]string{}, base...), "exit7"), map[string]string{
		"SSH_PASSWORD": operatorPassword,
	})
	require.Equal(t, 7, remoteExit.exitCode, remoteExit.stderr)
	var exitPayload commandResult
	require.NoError(t, json.Unmarshal([]byte(remoteExit.stdout), &exitPayload))
	assert.False(t, exitPayload.Success)
	assert.Equal(t, 7, exitPayload.ExitCode)
	assert.Equal(t, "partial\n", exitPayload.Stdout)
	assert.Empty(t, exitPayload.ErrorKind)
}

func TestCLIFailuresAreClassifiedAcrossTimeoutAuthAndHostTrust(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	base := []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
	}

	t.Run("unknown host is rejected until explicitly trusted", func(t *testing.T) {
		home := t.TempDir()
		unknown := runSSHX(t, home, append(append([]string{}, base...), "probe"), map[string]string{
			"SSH_PASSWORD": operatorPassword,
		})
		assertSSHXFailure(t, unknown, "host_key")

		trusted := runSSHX(t, home, append(append([]string{}, base...), "--accept-unknown-host", "probe"), map[string]string{
			"SSH_PASSWORD": operatorPassword,
		})
		require.Equal(t, 0, trusted.exitCode, trusted.stderr)

		strictAfterTrust := runSSHX(t, home, append(append([]string{}, base...), "probe"), map[string]string{
			"SSH_PASSWORD": operatorPassword,
		})
		require.Equal(t, 0, strictAfterTrust.exitCode, strictAfterTrust.stderr)
	})

	t.Run("changed host key is rejected", func(t *testing.T) {
		home := t.TempDir()
		wrongSigner := newHostSigner(t)
		knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")
		require.NoError(t, os.MkdirAll(filepath.Dir(knownHostsPath), 0o700))
		pattern := fmt.Sprintf("[%s]:%s", server.host, server.port)
		require.NoError(t, os.WriteFile(knownHostsPath, []byte(knownhosts.Line([]string{pattern}, wrongSigner.PublicKey())+"\n"), 0o600))

		changed := runSSHX(t, home, append(append([]string{}, base...), "probe"), map[string]string{
			"SSH_PASSWORD": operatorPassword,
		})
		assertSSHXFailure(t, changed, "host_key")
	})

	t.Run("authentication failure is distinct", func(t *testing.T) {
		home := t.TempDir()
		trust := runSSHX(t, home, append(append([]string{}, base...), "--accept-unknown-host", "probe"), map[string]string{
			"SSH_PASSWORD": operatorPassword,
		})
		require.Equal(t, 0, trust.exitCode, trust.stderr)

		denied := runSSHX(t, home, append(append([]string{}, base...), "probe"), map[string]string{
			"SSH_PASSWORD": "wrong-password",
		})
		assertSSHXFailure(t, denied, "auth")
	})

	t.Run("command timeout is distinct", func(t *testing.T) {
		home := t.TempDir()
		timedOut := runSSHX(t, home, append(append([]string{}, base...), "--accept-unknown-host", "--timeout=100ms", "sleep"), map[string]string{
			"SSH_PASSWORD": operatorPassword,
		})
		assertSSHXFailure(t, timedOut, "timeout")
	})
}

func TestCLIPermissionsAndPartialCompletionAreObservable(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	operatorHome := t.TempDir()
	operatorBase := []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
	}

	changed := runSSHX(t, operatorHome, append(append([]string{}, operatorBase...), "--accept-unknown-host", "set-state ready"), map[string]string{
		"SSH_PASSWORD": operatorPassword,
	})
	require.Equal(t, 0, changed.exitCode, changed.stderr)

	readerHome := t.TempDir()
	readerBase := []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=reader",
		"--no-key",
		"--json",
	}
	denied := runSSHX(t, readerHome, append(append([]string{}, readerBase...), "--accept-unknown-host", "set-state forbidden"), map[string]string{
		"SSH_PASSWORD": readerPassword,
	})
	require.Equal(t, 13, denied.exitCode, denied.stderr)
	var deniedPayload commandResult
	require.NoError(t, json.Unmarshal([]byte(denied.stdout), &deniedPayload))
	assert.False(t, deniedPayload.Success)
	assert.Equal(t, 13, deniedPayload.ExitCode)
	assert.Equal(t, "permission denied\n", deniedPayload.Stderr)

	uncertain := runSSHX(t, operatorHome, append(append([]string{}, operatorBase...), "set-state-and-drop uncertain"), map[string]string{
		"SSH_PASSWORD": operatorPassword,
	})
	assertSSHXFailure(t, uncertain, "exit_missing")

	observed := runSSHX(t, operatorHome, append(append([]string{}, operatorBase...), "read-state"), map[string]string{
		"SSH_PASSWORD": operatorPassword,
	})
	require.Equal(t, 0, observed.exitCode, observed.stderr)
	var observedPayload commandResult
	require.NoError(t, json.Unmarshal([]byte(observed.stdout), &observedPayload))
	assert.Equal(t, "uncertain\n", observedPayload.Stdout, "callers must be able to inspect state after an ambiguous teardown")
}

func TestCLISafetyBlockPreventsConnectionAndForceIsExplicit(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	base := []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--json",
	}

	connectionsBefore := server.connections.Load()
	blocked := runSSHX(t, home, append(append([]string{}, base...), "rm -rf /"), map[string]string{
		"SSH_PASSWORD": operatorPassword,
	})
	assertSSHXFailure(t, blocked, "blocked")
	assert.Equal(t, connectionsBefore, server.connections.Load(), "blocked commands must not touch the network")

	forced := runSSHX(t, home, append(append([]string{}, base...), "--force", "--bypass-reason=e2e destructive command", "--accept-unknown-host", "rm -rf /"), map[string]string{
		"SSH_PASSWORD": operatorPassword,
	})
	require.Equal(t, 0, forced.exitCode, forced.stderr)
	var forcedPayload commandResult
	require.NoError(t, json.Unmarshal([]byte(forced.stdout), &forcedPayload))
	assert.Equal(t, "forced-ok\n", forcedPayload.Stdout)
	assert.Greater(t, server.connections.Load(), connectionsBefore)
}

func TestCLIDryRunDescribesEffectsWithoutCrossingBoundaries(t *testing.T) {
	server := startSSHServer(t, serverOptions{})
	home := t.TempDir()
	connectionsBefore := server.connections.Load()

	result := runSSHX(t, home, []string{
		"-h=" + server.host,
		"-p=" + server.port,
		"-u=operator",
		"--no-key",
		"--accept-unknown-host",
		"--dry-run",
		"--json",
		"sudo whoami",
	}, nil)
	require.Equal(t, 0, result.exitCode, result.stderr)
	var plan struct {
		DryRun             bool   `json:"dry_run"`
		Valid              bool   `json:"valid"`
		Mode               string `json:"mode"`
		Action             string `json:"action"`
		UsesSudo           bool   `json:"uses_sudo"`
		WouldConnect       bool   `json:"would_connect"`
		WouldExecute       bool   `json:"would_execute"`
		WouldReadSecret    bool   `json:"would_read_secret"`
		WouldMutateRemote  bool   `json:"would_mutate_remote"`
		MayMutateKnownHost bool   `json:"may_mutate_known_hosts"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &plan))
	assert.True(t, plan.DryRun)
	assert.True(t, plan.Valid)
	assert.Equal(t, "ssh", plan.Mode)
	assert.Equal(t, "command", plan.Action)
	assert.True(t, plan.UsesSudo)
	assert.True(t, plan.WouldConnect)
	assert.True(t, plan.WouldExecute)
	assert.True(t, plan.WouldReadSecret)
	assert.True(t, plan.WouldMutateRemote)
	assert.True(t, plan.MayMutateKnownHost)
	assert.Equal(t, connectionsBefore, server.connections.Load())
	_, err := os.Stat(filepath.Join(home, ".ssh", "known_hosts"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(filepath.Join(home, ".sshx", "audit"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestCLILoginDryRunAndHumanGates(t *testing.T) {
	home := t.TempDir()

	planResult := runSSHX(t, home, []string{
		"login", "--address=10.9.8.7", "-u=operator", "--sudo", "--dry-run", "--json",
	}, nil)
	require.Equal(t, 0, planResult.exitCode, planResult.stderr)
	var plan struct {
		DryRun            bool   `json:"dry_run"`
		Valid             bool   `json:"valid"`
		Mode              string `json:"mode"`
		Action            string `json:"action"`
		HostResolved      string `json:"host_resolved"`
		UsesSudo          bool   `json:"uses_sudo"`
		WouldConnect      bool   `json:"would_connect"`
		WouldReadSecret   bool   `json:"would_read_secret"`
		WouldMutateRemote bool   `json:"would_mutate_remote"`
		Command           string `json:"command"`
	}
	require.NoError(t, json.Unmarshal([]byte(planResult.stdout), &plan))
	assert.True(t, plan.DryRun)
	assert.True(t, plan.Valid)
	assert.Equal(t, "login", plan.Mode)
	assert.Equal(t, "login-sudo", plan.Action)
	assert.Equal(t, "10.9.8.7", plan.HostResolved)
	assert.True(t, plan.UsesSudo)
	assert.True(t, plan.WouldConnect)
	assert.True(t, plan.WouldReadSecret)
	assert.True(t, plan.WouldMutateRemote)
	assert.Contains(t, plan.Command, "sudo -S")

	jsonOnly := runSSHX(t, home, []string{"login", "--target=prod-web", "--json"}, nil)
	require.Equal(t, 255, jsonOnly.exitCode, jsonOnly.stderr)
	assert.Contains(t, jsonOnly.stderr, "login --json requires --dry-run")

	live := runSSHX(t, home, []string{"login", "--address=127.0.0.1", "--no-key"}, nil)
	require.Equal(t, 255, live.exitCode, live.stderr)
	if runtime.GOOS == "windows" {
		assert.Contains(t, live.stderr, "not supported")
	} else {
		assert.Contains(t, live.stderr, "not a TTY")
	}
}

func assertSSHXFailure(t *testing.T, result cliResult, kind string) {
	t.Helper()
	require.Equal(t, 255, result.exitCode, result.stderr)
	var payload commandResult
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload))
	assert.False(t, payload.Success)
	assert.Equal(t, -1, payload.ExitCode)
	assert.Equal(t, kind, payload.ErrorKind)
}
