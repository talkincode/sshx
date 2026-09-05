package app

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sqlsafe"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestSQLLifecycleDomainFacts(t *testing.T) {
	config := &sshclient.Config{Mode: "sql", SQLStatement: "UPDATE t SET x=1 WHERE id=1"}
	run := &sqlRun{config: config, start: time.Now(), phase: "policy"}
	before := run.baseResult()
	require.NotNil(t, before.Executed)
	assert.False(t, *before.Executed)
	assert.Equal(t, "unchanged", before.ChangeState)
	assert.Equal(t, "not_started", before.Completion)

	run.phase = "backup_execute"
	run.evidence = sqlsafe.Evidence{
		StateChange: "unknown", Commit: "unknown", Verification: "unknown",
		EffectVerification: "unsupported", BackupStatus: "ready", OutcomeUncertain: true,
	}
	unknown := run.baseResult()
	assert.Nil(t, unknown.Executed)
	assert.Equal(t, "unknown", unknown.Completion)
	assert.Equal(t, "unknown", unknown.ChangeState)
	assert.False(t, unknown.Verified)

	n := int64(0)
	run.affectedRows = &n
	uncommitted := run.baseResult()
	require.NotNil(t, uncommitted.Executed)
	assert.True(t, *uncommitted.Executed)
	assert.Equal(t, "unknown", uncommitted.Completion)
	assert.Equal(t, "unknown", uncommitted.ChangeState)

	run.evidence.Commit = "acknowledged"
	run.evidence.Verification = "protocol_verified"
	complete := run.baseResult()
	assert.Equal(t, "completed", complete.Completion)
	assert.Equal(t, "unsupported", complete.Verification)
	assert.False(t, complete.Verified)
	assert.Equal(t, "unknown", complete.ChangeState)
}

func TestSQLJSONUsesLifecycleProjectorWithoutInventingExecution(t *testing.T) {
	config := &sshclient.Config{
		Mode: "sql", ExecutionID: "sql-evidence-fixture",
		SQLStatement: "UPDATE t SET x=1 WHERE id=1", SQLEngine: "postgres",
	}
	run := &sqlRun{
		config: config, start: time.Now(), phase: "backup_execute",
		evidence: sqlsafe.Evidence{
			StateChange: "unknown", Commit: "unknown", Verification: "failed",
			EffectVerification: "unsupported", BackupStatus: "ready", OutcomeUncertain: true,
		},
	}
	result := run.baseResult()
	result.ExitCode = 0
	result.ErrorKind = "verification_failed"
	output := captureStdout(t, func() { require.NoError(t, emitSQLJSON(config, result)) })
	var document map[string]any
	require.NoError(t, json.Unmarshal(output, &document), string(output))
	assert.Equal(t, "sshx.result.v1", document["schema_version"])
	assert.Equal(t, config.ExecutionID, document["execution_id"])
	assert.NotEmpty(t, document["execution_fingerprint"])
	assert.Contains(t, document, "executed")
	assert.Nil(t, document["executed"], "a successful client exit cannot turn missing SQL evidence into executed=true")
	assert.Equal(t, "unknown", document["change_state"])
	assert.Equal(t, false, document["verified"])
	assert.Equal(t, "failed", document["verification"])
}

func sqlConditionFixture(t *testing.T) *sqlRun {
	t.Helper()
	config := &sshclient.Config{
		Mode: "sql", ExecutionID: "sql-condition-fixture", SQLEngine: sqlsafe.EnginePostgres, SQLDatabase: "app",
		SQLStatement: "UPDATE t SET secret='private-value' WHERE id=1",
	}
	cls, err := sqlsafe.Classify(config.SQLStatement)
	require.NoError(t, err)
	count := int64(1)
	return &sqlRun{
		config: config, cls: cls, start: time.Now(), phase: "complete", affectedRows: &count,
		backup: &sqlBackupJSON{Kind: "rows", Table: "t", Path: ".sshx/sql-backups/preimage.csv"},
		evidence: sqlsafe.Evidence{
			StateChange: "unknown", Commit: "acknowledged", Verification: "protocol_verified",
			EffectVerification: "unsupported", AffectedRowsSemantics: "postgres_command_tag",
			BackupStatus: "ready", BackupConsistency: "locked_preimage", BackupFormat: "csv",
		},
	}
}

func TestSQLConditionsBindOnlyStructuredEvidence(t *testing.T) {
	run := sqlConditionFixture(t)
	result := run.baseResult()
	assert.Contains(t, result.Preconditions, execution.Condition{
		Kind: "sql_backup", Subject: run.backup.Path, Expected: "ready", Observed: "ready", Status: "passed",
	})
	assert.Contains(t, result.Preconditions, execution.Condition{
		Kind: "sql_backup_consistency", Subject: run.backup.Path, Expected: "locked_preimage", Observed: "locked_preimage", Status: "passed",
	})
	assert.Contains(t, result.Postconditions, execution.Condition{
		Kind: "sql_commit", Subject: "postgres:app", Expected: "acknowledged", Observed: "acknowledged", Status: "passed",
	})
	assert.Contains(t, result.Postconditions, execution.Condition{
		Kind: "sql_affected_rows", Subject: "postgres:app:t", Observed: "1", Status: "passed",
	})
	assert.Contains(t, result.Postconditions, execution.Condition{
		Kind: "sql_affected_rows_semantics", Subject: "postgres:app:t", Expected: "postgres_command_tag", Observed: "postgres_command_tag", Status: "passed",
	})
	assert.False(t, result.Verified)
	assert.Equal(t, "unsupported", result.Verification)
	data, err := json.Marshal(append(result.Preconditions, result.Postconditions...))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "private-value")
	assert.NotContains(t, string(data), "UPDATE")
}

func TestSQLFingerprintBindsCommitBackupAndCountEvidence(t *testing.T) {
	fingerprint := func(run *sqlRun, stdout string) string {
		result := run.baseResult()
		result.Success = true
		result.Stdout, result.Stderr = stdout, stdout
		document, err := finalizeLifecycle(run.config, result)
		require.NoError(t, err)
		var value string
		require.NoError(t, json.Unmarshal(document["execution_fingerprint"], &value))
		return value
	}
	baseline := fingerprint(sqlConditionFixture(t), "")
	assert.Equal(t, baseline, fingerprint(sqlConditionFixture(t), "private row/error output"), "raw output is excluded from the fingerprint")
	for _, tc := range []struct {
		name   string
		change func(*sqlRun)
	}{
		{"backup path", func(run *sqlRun) { run.backup.Path += ".different" }},
		{"backup kind", func(run *sqlRun) { run.backup.Kind = "table" }},
		{"backup status", func(run *sqlRun) { run.evidence.BackupStatus = "planned" }},
		{"backup consistency", func(run *sqlRun) { run.evidence.BackupConsistency = "unknown" }},
		{"backup format", func(run *sqlRun) { run.evidence.BackupFormat = "mysql_hex_rows_v1" }},
		{"row count", func(run *sqlRun) { *run.affectedRows = 2 }},
		{"row semantics", func(run *sqlRun) { run.evidence.AffectedRowsSemantics = "sqlite_changes" }},
		{"commit acknowledgement", func(run *sqlRun) { run.evidence.Commit = "unknown" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := sqlConditionFixture(t)
			tc.change(run)
			assert.NotEqual(t, baseline, fingerprint(run, ""))
		})
	}
}

func TestSQLOutputDeliveryErrorsPropagate(t *testing.T) {
	for _, mode := range []string{"json explain", "json failure", "human explain"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			require.NoError(t, err)
			require.NoError(t, reader.Close())
			require.NoError(t, writer.Close())
			original := os.Stdout
			os.Stdout = writer
			t.Cleanup(func() { os.Stdout = original })
			run := sqlConditionFixture(t)
			run.config.JSONOutput = mode != "human explain"
			run.explainPlan = "fixture plan"
			var outputErr error
			if mode == "json failure" {
				outputErr = run.failWithExit("remote_exit", sshclient.ExecResult{ExitCode: 1}, nil)
			} else {
				outputErr = run.reportExplainOnly()
			}
			require.ErrorIs(t, outputErr, execution.ErrLocalIO)
			assert.Equal(t, "acknowledged", run.evidence.Commit, "delivery failure must not erase a known database acknowledgement")
		})
	}
}
