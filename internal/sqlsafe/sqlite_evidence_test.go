package sqlsafe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sqliteFixture(t *testing.T) (SQLiteConn, string) {
	t.Helper()
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("requires the real sqlite3 client")
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	cmd := exec.Command("sqlite3", db, "CREATE TABLE t (id INTEGER PRIMARY KEY, x TEXT UNIQUE); INSERT INTO t VALUES (1, 'old'), (2, 'other');") // #nosec G204 -- isolated SQLite fixture
	require.NoError(t, cmd.Run())
	return SQLiteConn{Path: db}, dir
}

func runSQLFixture(t *testing.T, rc RemoteCommand) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", rc.Command) // #nosec G204 -- generated SQL command against isolated fixture
	cmd.Stdin = strings.NewReader(rc.Stdin)
	output, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "generated SQL command hung")
	return string(output), err
}

func sqliteValue(t *testing.T, db, query string) string {
	t.Helper()
	output, err := exec.Command("sqlite3", db, query).CombinedOutput() // #nosec G204 -- isolated SQLite fixture
	require.NoError(t, err, string(output))
	return string(output)
}

func TestSQLiteWholeFileBackupAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[fail], func(t *testing.T) {
			conn, dir := sqliteFixture(t)
			backup := filepath.Join(dir, "snapshot.db")
			stmt := "UPDATE t SET x='new' WHERE id=1"
			if fail {
				stmt = "UPDATE t SET x='other' WHERE id=1"
			}
			rc, err := conn.ExecuteWithBackupCommand(stmt, "t", "", backup, BackupFile)
			require.NoError(t, err)
			output, runErr := runSQLFixture(t, rc)
			o, evidenceErr := rc.Protocol.Parse(output)
			assert.True(t, o.BackupReady, output)
			assert.Equal(t, "old\n", sqliteValue(t, backup, "SELECT x FROM t WHERE id=1;"))
			if fail {
				require.Error(t, runErr, output)
				require.Error(t, evidenceErr)
				assert.False(t, o.Committed)
				assert.True(t, rc.Protocol.Summarize(o, false).OutcomeUncertain)
				assert.Equal(t, "old\n", sqliteValue(t, conn.Path, "SELECT x FROM t WHERE id=1;"))
			} else {
				require.NoError(t, runErr, output)
				require.NoError(t, evidenceErr)
				assert.True(t, o.Committed)
				assert.Equal(t, "new\n", sqliteValue(t, conn.Path, "SELECT x FROM t WHERE id=1;"))
			}
		})
	}
}

func TestSQLiteMatchedRowsDoNotProveChangedValues(t *testing.T) {
	conn, dir := sqliteFixture(t)
	backup := filepath.Join(dir, "preimage.csv")
	rc, err := conn.ExecuteWithBackupCommand("UPDATE t SET x='old' WHERE id=1", "t", "id=1", backup, BackupTable)
	require.NoError(t, err)
	output, runErr := runSQLFixture(t, rc)
	require.NoError(t, runErr, output)
	o, parseErr := rc.Protocol.Parse(output)
	require.NoError(t, parseErr)
	require.NotNil(t, o.AffectedRows)
	assert.Equal(t, int64(1), *o.AffectedRows)
	assert.Equal(t, "unknown", rc.Protocol.Summarize(o, true).StateChange)
	data, readErr := os.ReadFile(backup) // #nosec G304 -- isolated snapshot artifact
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "other", "table backup includes rows outside the predicate")
}

func TestSQLiteBackupFailureCannotMutate(t *testing.T) {
	conn, dir := sqliteFixture(t)
	backup := filepath.Join(dir, "existing.csv")
	require.NoError(t, os.WriteFile(backup, []byte("do-not-overwrite"), 0o600))
	rc, err := conn.ExecuteWithBackupCommand("UPDATE t SET x='new' WHERE id=1", "t", "id=1", backup, BackupTable)
	require.NoError(t, err)
	output, runErr := runSQLFixture(t, rc)
	require.Error(t, runErr, output)
	o, parseErr := rc.Protocol.Parse(output)
	require.Error(t, parseErr)
	assert.False(t, o.BackupReady)
	assert.False(t, o.Committed)
	assert.Equal(t, "old\n", sqliteValue(t, conn.Path, "SELECT x FROM t WHERE id=1;"))
}

func TestSQLiteRechecksRelatedEffectsUnderLock(t *testing.T) {
	conn, dir := sqliteFixture(t)
	sqliteValue(t, conn.Path, "CREATE TABLE side(x TEXT); CREATE TRIGGER effect AFTER UPDATE ON t BEGIN INSERT INTO side VALUES (new.x); END;")
	rc, err := conn.ExecuteWithBackupCommand("UPDATE t SET x='new' WHERE id=1", "t", "id=1", filepath.Join(dir, "preimage.csv"), BackupTable)
	require.NoError(t, err)
	output, runErr := runSQLFixture(t, rc)
	require.Error(t, runErr, output)
	o, parseErr := rc.Protocol.Parse(output)
	require.Error(t, parseErr)
	assert.False(t, o.BackupReady)
	assert.False(t, o.Committed)
	assert.Equal(t, "old\n", sqliteValue(t, conn.Path, "SELECT x FROM t WHERE id=1;"))
	assert.Equal(t, "0\n", sqliteValue(t, conn.Path, "SELECT count(*) FROM side;"))
}

func TestSQLiteCommitFailurePreservesPartialEvidence(t *testing.T) {
	conn, dir := sqliteFixture(t)
	sqliteValue(t, conn.Path, "CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED); INSERT INTO parent VALUES(1); INSERT INTO child VALUES(1);")
	rc, err := conn.ExecuteWithBackupCommand("UPDATE child SET id=2 WHERE id=1", "child", "", filepath.Join(dir, "preimage.db"), BackupFile)
	require.NoError(t, err)
	// This connection setting forces a deferred constraint failure at COMMIT,
	// after the affected-row frame has already been emitted.
	rc.Command = strings.Replace(rc.Command, "BEGIN IMMEDIATE;", "PRAGMA foreign_keys=ON;\nBEGIN IMMEDIATE;", 1)
	output, runErr := runSQLFixture(t, rc)
	require.Error(t, runErr, output)
	o, parseErr := rc.Protocol.Parse(output)
	require.Error(t, parseErr)
	assert.True(t, o.BackupReady)
	require.NotNil(t, o.AffectedRows)
	assert.Equal(t, int64(1), *o.AffectedRows)
	assert.False(t, o.Committed)
	assert.Equal(t, "1\n", sqliteValue(t, conn.Path, "SELECT id FROM child;"))
}

func TestSQLiteCaseInsensitiveGuardedTableResolution(t *testing.T) {
	for _, table := range []string{"T", `"T"`, "main.T"} {
		t.Run(table, func(t *testing.T) {
			conn, dir := sqliteFixture(t)
			backup := filepath.Join(dir, "preimage.csv")
			rc, err := conn.ExecuteWithBackupCommand("UPDATE "+table+" SET x='new' WHERE id=1", table, "id=1", backup, BackupTable)
			require.NoError(t, err)
			output, runErr := runSQLFixture(t, rc)
			require.NoError(t, runErr, output)
			o, parseErr := rc.Protocol.Parse(output)
			require.NoError(t, parseErr)
			assert.True(t, o.BackupReady)
			assert.True(t, o.Committed)
			assert.Equal(t, "new\n", sqliteValue(t, conn.Path, "SELECT x FROM t WHERE id=1;"))
			data, readErr := os.ReadFile(backup) // #nosec G304 -- isolated case-insensitive preimage fixture
			require.NoError(t, readErr)
			assert.Contains(t, string(data), "old")
		})
	}
}

func TestSQLiteCaseInsensitiveRelatedEffects(t *testing.T) {
	for _, relation := range []string{"trigger", "cascade"} {
		t.Run(relation, func(t *testing.T) {
			conn, dir := sqliteFixture(t)
			if relation == "trigger" {
				sqliteValue(t, conn.Path, "CREATE TABLE side(x TEXT); CREATE TRIGGER effect AFTER UPDATE ON t BEGIN INSERT INTO side VALUES(new.x); END;")
			} else {
				sqliteValue(t, conn.Path, "CREATE TABLE child(id INTEGER REFERENCES T(id) ON UPDATE CASCADE); INSERT INTO child VALUES(1);")
			}
			for _, table := range []string{"t", "T"} {
				check, buildErr := conn.RelatedEffectsCommand(table, "UPDATE")
				require.NoError(t, buildErr)
				output, runErr := runSQLFixture(t, check)
				require.NoError(t, runErr, output)
				related, parseErr := ParseBooleanOutput(output)
				require.NoError(t, parseErr)
				assert.True(t, related, "identifier spelling must not hide "+relation)
			}
			rc, err := conn.ExecuteWithBackupCommand("UPDATE T SET id=3 WHERE id=1", "T", "id=1", filepath.Join(dir, "preimage.csv"), BackupTable)
			require.NoError(t, err)
			output, runErr := runSQLFixture(t, rc)
			require.Error(t, runErr, output)
			assert.Equal(t, "1\n2\n", sqliteValue(t, conn.Path, "SELECT id FROM t ORDER BY id;"))
		})
	}
}
