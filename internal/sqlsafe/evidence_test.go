package sqlsafe

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLProtocolFramesAreNotResultRows(t *testing.T) {
	p := newProtocol(EnginePostgres, "UPDATE t SET x=1 WHERE id=1", true, true)
	data := "UPDATE 999\n12345\n__SSHX_SQL_V1_other__|affected|999\n"
	output := p.frame("start", "1") + "\n" + p.frame("backup", "ready") + "\n" +
		data + p.frame("affected", "1") + "\n" + p.frame("commit", "acknowledged") + "\n"
	o, err := p.Parse(output)
	require.NoError(t, err)
	assert.Equal(t, data, o.Stdout)
	require.NotNil(t, o.AffectedRows)
	assert.Equal(t, int64(1), *o.AffectedRows)
	e := p.Summarize(o, true)
	assert.Equal(t, "unknown", e.StateChange, "PostgreSQL UPDATE counts matched rows, including unchanged values")
	assert.Equal(t, "acknowledged", e.Commit)
	assert.Equal(t, "protocol_verified", e.Verification)
}

func TestSQLProtocolRejectsDamagedEvidence(t *testing.T) {
	p := newProtocol(EngineSQLite, "UPDATE t SET x=1", true, true)
	start := p.frame("start", "1") + "\n"
	backup := p.frame("backup", "ready") + "\n"
	affected := p.frame("affected", "1") + "\n"
	commit := p.frame("commit", "acknowledged") + "\n"
	cases := []struct {
		name, output string
		protocol     bool
		committed    bool
	}{
		{"empty", "", true, false},
		{"unframed", "UPDATE 1\n1\n", true, false},
		{"duplicate start", start + start, true, false},
		{"duplicate affected", start + backup + affected + affected + commit, true, false},
		{"duplicate commit", start + backup + affected + commit + commit, true, true},
		{"negative", start + backup + p.frame("affected", "-1") + "\n", true, false},
		{"overflow", start + backup + p.frame("affected", "9223372036854775808") + "\n", true, false},
		{"malformed", start + p.frame("affected", "1|extra") + "\n", true, false},
		{"missing backup", start + affected + commit, false, false},
		{"missing rows", start + backup + commit, false, true},
		{"lost commit", start + backup + affected, false, false},
		{"truncated commit", start + backup + affected + p.frame("commit", "ack"), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := p.Parse(tc.output)
			require.Error(t, err)
			var protocolErr *ProtocolError
			assert.Equal(t, tc.protocol, errors.As(err, &protocolErr))
			assert.Equal(t, tc.committed, o.Committed)
			assert.NotContains(t, err.Error(), p.Token)
			e := p.Summarize(o, false)
			assert.Equal(t, "unknown", e.StateChange)
			assert.Equal(t, !tc.committed, e.OutcomeUncertain)
		})
	}
}

func TestSQLEngineRowSemantics(t *testing.T) {
	for _, engine := range []string{EnginePostgres, EngineSQLite, EngineMySQL} {
		t.Run(engine, func(t *testing.T) {
			p := newProtocol(engine, "UPDATE t SET x=1 WHERE id=1", true, true)
			p.BackupForm = "csv"
			n := int64(1)
			o := Observation{Started: true, BackupReady: true, AffectedRows: &n, Committed: true}
			e := p.Summarize(o, true)
			assert.NotEmpty(t, e.AffectedRowsSemantics)
			assert.Equal(t, "unknown", e.StateChange)
			assert.Equal(t, "unsupported", e.EffectVerification)
			n = 0
			assert.Equal(t, "unknown", p.Summarize(o, true).StateChange)
			p.Backup = false
			assert.Equal(t, "unknown", p.Summarize(o, true).StateChange, "unguarded triggers can modify other rows")
			p.Backup = true
			p.BackupForm = "sqlite_database"
			assert.Equal(t, "unknown", p.Summarize(o, true).StateChange, "whole-file backups allow triggers")
			o.Committed = false
			assert.True(t, p.Summarize(o, false).OutcomeUncertain)
		})
	}
}

func TestSQLCommitFramesFollowCommit(t *testing.T) {
	for _, executor := range []SQLExecutor{
		Conn{Database: "app"},
		MySQLConn{Database: "app"},
		SQLiteConn{Path: "/srv/app.db"},
	} {
		rc, err := executor.ExecuteWithBackupCommand("UPDATE t SET x=1 WHERE id=1", "t", "id=1", ".sshx/backup.csv", func() BackupKind {
			if _, ok := executor.(SQLiteConn); ok {
				return BackupTable
			}

			return BackupRows
		}())
		require.NoError(t, err)
		require.NotNil(t, rc.Protocol)
		commitSQL := strings.LastIndex(rc.Command, "COMMIT;")
		ack := strings.LastIndex(rc.Command, rc.Protocol.frame("commit", "acknowledged"))
		assert.Greater(t, ack, commitSQL)
		assert.GreaterOrEqual(t, commitSQL, 0)
	}
}

func TestSQLTrailingCommentCannotPrecedeAcknowledgement(t *testing.T) {
	for _, executor := range []SQLExecutor{Conn{Database: "app"}, MySQLConn{Database: "app"}, SQLiteConn{Path: "/srv/app.db"}} {
		rc := executor.ExecuteCommand("UPDATE t SET x=1 WHERE id=1 -- trailing comment")
		assert.Contains(t, rc.Stdin, "-- trailing comment\n;\n")
	}
}

func TestSQLVolatilePredicateRequiresWholeTablePreimage(t *testing.T) {
	cls, err := Classify("UPDATE t SET x=1 WHERE random() > 0.5")
	require.NoError(t, err)
	plan, planErr := DecideBackup(cls, 1, Options{})
	require.NoError(t, planErr)
	assert.Equal(t, BackupTable, plan.Kind)
}

func TestSQLTableSnapshotSupportsMultilinePredicate(t *testing.T) {
	stmt := "UPDATE t SET x=1 WHERE id=1\n OR id=2"
	for _, executor := range []SQLExecutor{Conn{Database: "app"}, MySQLConn{Database: "app"}, SQLiteConn{Path: "/srv/app.db"}} {
		_, err := executor.ExecuteWithBackupCommand(stmt, "t", "id=1\n OR id=2", ".sshx/preimage", BackupTable)
		require.NoError(t, err)
	}
}
