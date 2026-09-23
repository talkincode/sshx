package sshclient

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplySudoScriptEvidenceAndCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the privileged remote script requires a POSIX shell")
	}
	for _, test := range []string{"replace", "noop", "empty", "precondition", "force", "before", "after", "rename", "recheck"} {
		t.Run(test, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "app.conf")
			staging := filepath.Join(dir, "stage.new")
			backupDir := filepath.Join(dir, "backups")
			before, payload := []byte("before\n"), []byte("after\n")
			if test == "noop" {
				payload = before
			}
			if test == "empty" {
				payload = []byte{}
			}
			require.NoError(t, os.WriteFile(target, before, 0o640)) // #nosec G306 -- fixture verifies preservation of group-readable permissions.
			require.NoError(t, os.WriteFile(staging, payload, 0o600))
			req := ApplyRequest{RemotePath: target, Payload: payload, Backup: true, ExpectSHA256: SHA256Hex(before)}
			if test == "precondition" || test == "force" {
				req.ExpectSHA256 = SHA256Hex([]byte("wrong"))
				req.Force = test == "force"
			}
			script, err := buildApplySudoScript(req, staging, backupDir)
			require.NoError(t, err)
			env := os.Environ()
			if test == "before" || test == "after" || test == "rename" || test == "recheck" {
				bin := filepath.Join(dir, "bin")
				require.NoError(t, os.Mkdir(bin, 0o700))
				commandName := "mv"
				if test == "before" || test == "recheck" {
					commandName = "chmod"
				}
				commandPath, pathErr := exec.LookPath(commandName)
				require.NoError(t, pathErr)
				wrapper := "#!/bin/sh\n"
				switch test {
				case "before":
					wrapper += "case \"$2\" in *.sshx.*) exit 9;; esac\nexec '" + commandPath + "' \"$@\"\n"
				case "after":
					wrapper += "'" + commandPath + "' \"$@\" || exit\nprintf 'other writer\\n' > \"$3\"\n"
				case "rename":
					wrapper += "exit 9\n"
				case "recheck":
					wrapper += "'" + commandPath + "' \"$@\" || exit\ncase \"$2\" in *.sshx.*) printf 'other writer\\n' > '" + target + "';; esac\n"
				}
				require.NoError(t, os.WriteFile(filepath.Join(bin, commandName), []byte(wrapper), 0o700)) // #nosec G306 -- owned executable fault fixture.
				env = append(env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			}
			result := runApplyScriptFixture(t, script, env)
			outcome, applyErr := parseApplyScriptReport(result)
			requireApplyOutcome(t, test, result, outcome, applyErr)
			require.Equal(t, SHA256Hex(before), outcome.BeforeSHA256)
			require.Equal(t, SHA256Hex(payload), outcome.PayloadSHA256)
			require.NotNil(t, outcome.UID, "%s: uid evidence missing: %s", test, result.Stdout)
			require.NotNil(t, outcome.GID, "%s: gid evidence missing: %s", test, result.Stdout)
			require.Equal(t, "640", outcome.Mode)
			switch test {
			case "precondition":
				require.ErrorIs(t, applyErr, ErrPrecondition)
				require.False(t, requireApplyExecuted(t, test, result, outcome, applyErr))
				require.Empty(t, outcome.BackupPath)
			case "before":
				require.Error(t, applyErr)
				require.False(t, requireApplyExecuted(t, test, result, outcome, applyErr))
				require.Equal(t, "unchanged", outcome.ChangeState)
				require.True(t, outcome.BackupVerified)
			case "after":
				require.ErrorIs(t, applyErr, ErrApplyVerification)
				require.True(t, requireApplyExecuted(t, test, result, outcome, applyErr))
				require.Equal(t, "changed", outcome.ChangeState)
				require.Equal(t, SHA256Hex([]byte("other writer\n")), outcome.AfterSHA256)
				require.False(t, outcome.Verified)
			case "rename":
				require.ErrorIs(t, applyErr, ErrApplyVerification)
				// Publication was attempted without acknowledgement, so the report must
				// stay unknown rather than claim the target was never published.
				require.Nil(t, outcome.Executed, "%s: publication evidence must be unknown: %s", test, result.Stdout)
				require.Equal(t, "unknown", outcome.ChangeState)
			case "recheck":
				require.ErrorIs(t, applyErr, ErrPrecondition)
				require.Equal(t, "failed", outcome.PreconditionStatus)
				require.Equal(t, SHA256Hex([]byte("other writer\n")), outcome.PreconditionSHA256)
				require.False(t, requireApplyExecuted(t, test, result, outcome, applyErr))
				require.True(t, outcome.BackupVerified)
				require.Equal(t, "unchanged", outcome.ChangeState)
			default:
				require.NoError(t, applyErr, "%s", result.Stderr)
				require.True(t, outcome.Verified)
				require.Equal(t, SHA256Hex(payload), outcome.AfterSHA256)
				require.Equal(t, test != "noop", requireApplyExecuted(t, test, result, outcome, applyErr))
			}
			if test != "precondition" && test != "noop" {
				require.True(t, outcome.BackupVerified)
				data, readErr := os.ReadFile(outcome.BackupPath)
				require.NoError(t, readErr)
				require.Equal(t, before, data)
				info, statErr := os.Stat(outcome.BackupPath)
				require.NoError(t, statErr)
				require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
			}
			entries, listErr := os.ReadDir(dir)
			require.NoError(t, listErr)
			for _, entry := range entries {
				require.NotContains(t, entry.Name(), ".sshx.", "owned temp must be cleaned")
				require.NotEqual(t, "stage.new", entry.Name(), "staging must be cleaned by remote script")
			}
			info, statErr := os.Stat(target)
			require.NoError(t, statErr)
			require.Equal(t, os.FileMode(0o640), info.Mode().Perm())

			if test == "replace" {
				lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
				result.Stdout, result.ExitCode = strings.Join(lines[:len(lines)-1], "\n"), -1
				partial, lostErr := parseApplyScriptReport(result)
				require.ErrorIs(t, lostErr, ErrApplyVerification)
				require.True(t, requireApplyExecuted(t, "replace (truncated report)", result, partial, lostErr))
				require.Equal(t, "changed", partial.ChangeState)
				require.True(t, partial.BackupVerified)
				require.False(t, partial.Verified)
			}
		})
	}
}

// applyScriptEnv appends the POSIX sbin directories to every PATH entry. A
// minimal test runner can ship a PATH without them (macOS keeps chown in
// /usr/sbin) while the generated privileged script shells out to chown; without
// this the fixture fails for environmental reasons instead of the behavior
// under test. Appending keeps fault fixtures' stub tools ahead of the real ones.
func applyScriptEnv(env []string) []string {
	extra := ""
	for _, dir := range []string{"/usr/sbin", "/sbin"} {
		if info, statErr := os.Stat(filepath.Join(dir, "chown")); statErr != nil || info.IsDir() {
			continue
		}
		extra += string(os.PathListSeparator) + dir
	}
	if extra == "" {
		return env
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			out = append(out, kv+extra)
			continue
		}
		out = append(out, kv)
	}
	return out
}

// runApplyScriptFixture runs the generated privileged script the way the remote
// host does: as a script file, with the child's stdout and stderr going to real
// files. Piping the script through the child's stdin or capturing it into
// bytes.Buffer values makes os/exec add pipes and copier goroutines, and a child
// that finishes while a copier unwinds can then observe EPIPE/SIGPIPE and report
// a truncated privileged result instead of the behavior under test (issue #83).
func runApplyScriptFixture(t *testing.T, script []byte, env []string) ExecResult {
	t.Helper()
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "apply.sh")
	require.NoError(t, os.WriteFile(scriptPath, script, 0o700)) // #nosec G306 -- owned fixture script.
	stdoutPath, stderrPath := filepath.Join(dir, "stdout"), filepath.Join(dir, "stderr")
	stdout, createErr := os.Create(stdoutPath) // #nosec G304 -- path is confined to the owned fixture directory.
	require.NoError(t, createErr)
	stderr, createErr := os.Create(stderrPath) // #nosec G304 -- path is confined to the owned fixture directory.
	require.NoError(t, createErr)
	cmd := exec.Command("sh", scriptPath) // #nosec G204 -- executes only the generated apply script in the owned fixture directory.
	cmd.Stdout, cmd.Stderr, cmd.Env = stdout, stderr, applyScriptEnv(env)
	err := cmd.Run()
	require.NoError(t, stdout.Close())
	require.NoError(t, stderr.Close())
	code := 0
	if err != nil {
		var exit *exec.ExitError
		require.True(t, errors.As(err, &exit), "%v", err)
		code = exit.ExitCode()
	}
	out, readErr := os.ReadFile(stdoutPath) // #nosec G304 -- path is confined to the owned fixture directory.
	require.NoError(t, readErr)
	errOut, readErr := os.ReadFile(stderrPath) // #nosec G304 -- path is confined to the owned fixture directory.
	require.NoError(t, readErr)
	return ExecResult{ExitCode: code, Stdout: string(out), Stderr: string(errOut), Started: true, ExitObserved: true}
}

// requireApplyOutcome reports a missing privileged report with the fixture's
// captured evidence instead of panicking on a nil pointer: a truncated report
// must fail the subtest readably, not abort the package run (issue #83).
func requireApplyOutcome(t *testing.T, stage string, result ExecResult, outcome *ApplyOutcome, parseErr error) *ApplyOutcome {
	t.Helper()
	require.NotNil(t, outcome, "%s: no privileged report: exit %d; stdout %q; stderr %q; parse error %v", stage, result.ExitCode, result.Stdout, result.Stderr, parseErr)
	return outcome
}

// requireApplyExecuted returns the publication evidence without dereferencing a
// nil pointer: an absent or truncated report must fail the subtest readably.
func requireApplyExecuted(t *testing.T, stage string, result ExecResult, outcome *ApplyOutcome, parseErr error) bool {
	t.Helper()
	requireApplyOutcome(t, stage, result, outcome, parseErr)
	require.NotNil(t, outcome.Executed, "%s: publication evidence missing: exit %d; stdout %q; stderr %q; parse error %v", stage, result.ExitCode, result.Stdout, result.Stderr, parseErr)
	return *outcome.Executed
}

func TestApplySudoCreatesEmptyAndDoesNotRemoveUnownedTemp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the privileged remote script requires a POSIX shell")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "empty.conf")
	staging := filepath.Join(dir, "stage.new")
	req := ApplyRequest{RemotePath: target, Payload: []byte{}}
	require.NoError(t, os.WriteFile(staging, req.Payload, 0o600))
	script, err := buildApplySudoScript(req, staging, filepath.Join(dir, "backups"))
	require.NoError(t, err)
	result := runApplyScriptFixture(t, script, os.Environ())
	outcome, parseErr := parseApplyScriptReport(result)
	requireApplyOutcome(t, "empty", result, outcome, parseErr)
	require.NoError(t, parseErr, "%s", result.Stderr)
	require.True(t, outcome.Created)
	require.True(t, outcome.Verified)
	require.Equal(t, SHA256Hex(nil), outcome.AfterSHA256)
	info, statErr := os.Stat(target)
	require.NoError(t, statErr)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.Zero(t, info.Size())

	req.Payload = []byte("new")
	require.NoError(t, os.WriteFile(staging, req.Payload, 0o600))
	unowned := filepath.Join(dir, ".empty.conf.sshx.stage.new.tmp")
	require.NoError(t, os.WriteFile(unowned, []byte("do not remove"), 0o600))
	script, err = buildApplySudoScript(req, staging, filepath.Join(dir, "backups"))
	require.NoError(t, err)
	result = runApplyScriptFixture(t, script, os.Environ())
	outcome, parseErr = parseApplyScriptReport(result)
	requireApplyOutcome(t, "unowned temp", result, outcome, parseErr)
	require.Error(t, parseErr)
	require.False(t, requireApplyExecuted(t, "unowned temp", result, outcome, parseErr))
	retained, readErr := os.ReadFile(unowned) // #nosec G304 -- path is confined to the owned test fixture.
	require.NoError(t, readErr)
	require.Equal(t, "do not remove", string(retained))
	_, statErr = os.Stat(staging)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}
func TestApplySudoReportStrictValidation(t *testing.T) {
	report := applyScriptReport{
		Status: "ok", Before: SHA256Hex([]byte("before")), After: SHA256Hex([]byte("new")),
		Payload: SHA256Hex([]byte("new")), Mode: "0640",
		Changed: true, ChangeState: "changed", Executed: applyTestBool(true), Verified: true, Verification: "passed",
		ReplaceMethod:      "same_directory_mv",
		PreconditionStatus: "not_performed",
	}
	valid, err := json.Marshal(report)
	require.NoError(t, err)
	decoded, decodeErr := parseApplyScriptReport(ExecResult{ExitCode: 0, Stdout: string(valid)})
	require.NoError(t, decodeErr)
	require.True(t, decoded.Verified)
	for _, invalid := range []string{
		"{}", "null", "banner\n" + string(valid),
		string(valid) + " garbage",
		strings.Replace(string(valid), `"status":"ok"`, `"status":"invented"`, 1),
		strings.Replace(string(valid), `"status":"ok"`, `"status":"ok","status":"ok"`, 1),
		strings.Replace(string(valid), `"verified":true`, `"verified":false`, 1),
		strings.Replace(string(valid), `"executed":true`, `"executed":null`, 1),
		strings.Replace(string(valid), `"after":"`+report.After+`"`, `"after":"bad"`, 1),
		strings.Replace(string(valid), `"after":"`+report.After+`"`, `"after":"`+report.Before+`"`, 1),
		strings.Replace(string(valid), `"status":"ok"`, `"unknown":true,"status":"ok"`, 1),
	} {
		_, parseErr := parseApplyScriptReport(ExecResult{ExitCode: 0, Stdout: invalid})
		require.ErrorIs(t, parseErr, ErrApplyVerification, "%s", invalid)
	}
	partial, nonzeroErr := parseApplyScriptReport(ExecResult{ExitCode: 1, Stdout: string(valid)})
	require.ErrorIs(t, nonzeroErr, ErrApplyVerification)
	require.NotNil(t, partial, "%v", nonzeroErr)
	require.Equal(t, report.Before, partial.BeforeSHA256)
	require.Equal(t, report.After, partial.AfterSHA256)
	require.False(t, partial.Verified)
	report.Status, report.Verified, report.Verification = "progress", false, "unknown"
	progress, err := json.Marshal(report)
	require.NoError(t, err)
	partial, parseErr := parseApplyScriptReport(ExecResult{ExitCode: -1, Stdout: string(progress) + "\n{\"status\":"})
	require.ErrorIs(t, parseErr, ErrApplyVerification)
	require.NotNil(t, partial, "%v", parseErr)
	require.Equal(t, report.Before, partial.BeforeSHA256)
	require.Equal(t, report.After, partial.AfterSHA256)
	require.NotNil(t, partial.Executed, "%v", parseErr)
	require.True(t, *partial.Executed)
}

func TestApplySudoUnacknowledgedScriptStartIsUnknown(t *testing.T) {
	req := ApplyRequest{RemotePath: "/app.conf", Payload: []byte("new")}
	outcome, err := applySudoOutcome(req, ExecResult{ExitCode: -1, StartAttempted: true})
	require.ErrorIs(t, err, ErrApplyVerification)
	require.NotNil(t, outcome, "%v", err)
	require.Nil(t, outcome.Executed)
	require.Equal(t, "unknown", outcome.ChangeState)
	require.Equal(t, "unknown", outcome.Verification)
	require.Equal(t, SHA256Hex(req.Payload), outcome.PayloadSHA256)

	outcome, err = applySudoOutcome(req, ExecResult{ExitCode: -1})
	require.Error(t, err)
	require.NotNil(t, outcome, "%v", err)
	require.NotNil(t, outcome.Executed, "%v", err)
	require.False(t, *outcome.Executed)
	require.Equal(t, "unchanged", outcome.ChangeState)
}

func TestApplySudoEarlyCheckpointDoesNotProveNoPublication(t *testing.T) {
	req := ApplyRequest{RemotePath: "/app.conf", Payload: []byte("new"), Backup: true}
	report := applyScriptReport{
		Status: "progress", Before: SHA256Hex([]byte("before")), Payload: SHA256Hex(req.Payload),
		Mode: "0600", ChangeState: "unchanged", Executed: applyTestBool(false),
		Verification: "not_performed", PreconditionStatus: "not_performed",
		Backup: "/backups/app.conf", BackupVerified: true,
	}
	data, marshalErr := json.Marshal(report)
	require.NoError(t, marshalErr)
	for _, suffix := range []string{"", "\n{"} {
		outcome, err := applySudoOutcome(req, ExecResult{ExitCode: -1, Started: true, Stdout: string(data) + suffix})
		require.ErrorIs(t, err, ErrApplyVerification)
		require.Nil(t, outcome.Executed)
		require.Equal(t, "unknown", outcome.ChangeState)
		require.Equal(t, "unknown", outcome.Verification)
		require.Equal(t, report.Before, outcome.BeforeSHA256)
		require.Equal(t, report.Backup, outcome.BackupPath)
		require.True(t, outcome.BackupVerified)
	}
}
