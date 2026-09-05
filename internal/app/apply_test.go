package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestParseArgs_ApplyBasic(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "apply", "--target=prod", "--path=/etc/nginx/nginx.conf",
		"--from=./nginx.conf", "--expect-sha256=" + strings.Repeat("ab", 32),
		"--sudo", "--json",
	})
	if config.Mode != "apply" {
		t.Fatalf("expected mode apply, got %s", config.Mode)
	}
	if config.Host != "prod" || config.RemotePath != "/etc/nginx/nginx.conf" || config.LocalPath != "./nginx.conf" {
		t.Fatalf("unexpected apply routing: %#v", config)
	}
	if !config.ApplyUseSudo || !config.JSONOutput {
		t.Fatal("sudo/json flags were not parsed")
	}
	if config.ApplyExpectSHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("unexpected expect hash: %s", config.ApplyExpectSHA256)
	}
}

func TestHandleApplyConsumesPreparedPayload(t *testing.T) {
	for _, payload := range [][]byte{[]byte("captured bytes"), {}} {
		t.Run(string(payload), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			config := ParseArgs([]string{"sshx", "apply", "-h=127.0.0.1", "--path=/app.conf", "--from=missing-local-file", "--no-key", "--insecure-hostkey", "--json", "--no-audit"})
			config.Context, config.Password, config.PreparedPayload = ctx, "fixture", payload
			raw := captureStdout(t, func() {
				require.ErrorIs(t, HandleApply(config, nil), ErrReported)
			})
			var result applyJSONResult
			require.NoError(t, json.Unmarshal(raw, &result))
			require.NotEqual(t, "local_io", result.ErrorKind)
			require.Equal(t, sshclient.SHA256Hex(payload), result.PayloadSHA256)
			require.Equal(t, len(payload), result.PayloadBytes)
		})
	}
}

func TestApplyFailurePreservesExecutionAndBackupEvidence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		executed   *bool
		state      string
		completion string
	}{
		{"before", applyBool(false), "unchanged", "not_started"},
		{"after", applyBool(true), "changed", "completed"},
		{"ack-loss", nil, "unknown", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := applyRun{
				config: &sshclient.Config{JSONOutput: true, RemotePath: "/app.conf"},
				phase:  "apply", start: time.Now(), payload: []byte{},
				outcome: &sshclient.ApplyOutcome{
					BeforeSHA256: strings.Repeat("a", 64), AfterSHA256: strings.Repeat("b", 64),
					PayloadSHA256: sshclient.SHA256Hex(nil), BackupPath: "/backups/app.conf",
					BackupVerified: true, ChangeState: tc.state, Executed: tc.executed,
					Verification: "failed",
				},
			}
			raw := captureStdout(t, func() {
				require.ErrorIs(t, run.fail("verification_failed", sshclient.ErrApplyVerification), ErrReported)
			})
			var result applyJSONResult
			require.NoError(t, json.Unmarshal(raw, &result))
			require.Equal(t, tc.completion, result.Completion)
			require.Equal(t, tc.state, result.ChangeState)
			require.Equal(t, tc.executed, result.Executed)
			require.Equal(t, run.outcome.BeforeSHA256, result.BeforeSHA256)
			require.Equal(t, run.outcome.AfterSHA256, result.AfterSHA256)
			require.Equal(t, sshclient.SHA256Hex(nil), result.PayloadSHA256)
			require.True(t, result.RollbackAvail)
			require.Equal(t, "/backups/app.conf", result.Backup.Path)
			require.False(t, result.Verified)
			run.outcome.BackupVerified = false
			require.False(t, run.baseResult(false, -1, "remote_io", errors.New("backup failed")).RollbackAvail)
		})
	}
}

func TestClassifyApplyTypedVerificationError(t *testing.T) {
	require.Equal(t, "verification_failed", classifyApplyError(errors.Join(errors.New("transport interrupted"), sshclient.ErrApplyVerification)))
}

func applyBool(value bool) *bool { return &value }

func TestParseArgs_ApplyUnknownOption(t *testing.T) {
	config := ParseArgs([]string{"sshx", "apply", "-h=prod", "--path=/tmp/a", "--from=./a", "--bogus"})
	if config.ArgumentError == "" {
		t.Fatal("expected an argument error for unknown option")
	}
}

func TestValidateApplyConfig_NoBackupRequiresForce(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "apply", "-h=prod", "--path=/tmp/app.conf", "--from=./app.conf", "--no-backup",
	})
	if err := validateApplyConfig(config); err == nil {
		t.Fatal("expected --no-backup without --force to fail")
	}
	config.Force = true
	if err := validateApplyConfig(config); err != nil {
		t.Fatalf("force should allow --no-backup: %v", err)
	}
}

func TestApplyPolicyBlocksPasswdWithoutBypass(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "apply", "-h=prod", "--path=/etc/passwd", "--from=./passwd",
	})
	if err := applyPolicy(config); err == nil {
		t.Fatal("expected /etc/passwd apply to be blocked")
	}
	config.Force = true
	config.BypassReason = "incident-restore"
	if err := applyPolicy(config); err != nil {
		t.Fatalf("force+bypass should allow the critical path: %v", err)
	}
}

func TestApplyDryRunDoesNotNeedHostConnection(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(local, []byte("payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := ParseArgs([]string{
		"sshx", "apply", "-h=prod", "--path=/tmp/app.conf", "--from=" + local, "--dry-run", "--json",
	})
	plan := buildDryRunPlan(config)
	if !plan.Valid {
		t.Fatalf("expected valid dry-run plan: %+v", plan.ConfigCheck)
	}
	if !plan.WouldConnect || !plan.WouldMutateRemote {
		t.Fatalf("unexpected effects: connect=%v mutate=%v", plan.WouldConnect, plan.WouldMutateRemote)
	}
	if plan.Apply == nil || plan.Apply.PayloadBytes != len("payload\n") || plan.Apply.Backup != "file" {
		t.Fatalf("unexpected apply plan: %+v", plan.Apply)
	}
}
