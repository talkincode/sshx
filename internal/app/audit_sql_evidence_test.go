package app

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/talkincode/sshx/internal/sqlsafe"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestAuditSQLPersistsUncertainEvidenceSnapshot(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := &sshclient.Config{
		AuditEnabled: true, AuditOutput: t.TempDir(), Mode: "sql",
		SQLEngine: "postgres", SQLStatement: "UPDATE users SET active = true",
	}
	recorder := newAuditRecorder(config)
	evidence := sqlsafe.Evidence{
		AffectedRowsSemantics: "matched", StateChange: "unknown", Commit: "unknown",
		Verification: "unknown", BackupStatus: "ready", BackupConsistency: "locked_preimage",
		OutcomeUncertain: true, EffectVerification: "unsupported",
	}
	want := evidence
	failure := errors.New("commit acknowledgement lost")
	recorder.recordSQLOutcome(config, sshclient.AuthMethodKey, sqlAuditMeta{
		Evidence: &evidence, Class: "dml", Phase: "execute", Mutates: true,
		BackupPath: "/backup/preimage",
	}, -1, "exit_missing", failure)
	evidence.Commit = "acknowledged"
	evidence.StateChange = "changed"
	recorder.refresh(config)
	if !reflect.DeepEqual(recorder.event.SQLEvidence, &want) {
		t.Fatalf("SQL evidence was not snapshotted: %+v", recorder.event.SQLEvidence)
	}
	if err := recorder.finish(config, failure); err != nil {
		t.Fatal(err)
	}
	event := readSingleAuditEvent(t, config.AuditOutput)
	raw, err := json.Marshal(event["sql_evidence"])
	if err != nil {
		t.Fatal(err)
	}
	var got sqlsafe.Evidence
	if decodeErr := json.Unmarshal(raw, &got); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if !reflect.DeepEqual(got, want) || event["sql_backup_path"] != "/backup/preimage" {
		t.Fatalf("persisted SQL evidence = %+v, want %+v", got, want)
	}
}
