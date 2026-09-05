package sqlsafe

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifySQLiteReads(t *testing.T) {
	cases := []struct {
		sql  string
		verb string
	}{
		{"SELECT * FROM users", "SELECT"},
		{"VALUES (1), (2)", "VALUES"},
		{"EXPLAIN SELECT * FROM t", "EXPLAIN"},
		{"EXPLAIN QUERY PLAN DELETE FROM t WHERE id=1", "EXPLAIN"},
		{"PRAGMA table_info(users)", "PRAGMA"},
		{"PRAGMA foreign_key_list('users')", "PRAGMA"},
		{"WITH x AS (SELECT 1) SELECT * FROM x", "SELECT"},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			cls, err := ClassifySQLite(tc.sql)
			require.NoError(t, err)
			assert.Equal(t, ClassRead, cls.Class)
			assert.Equal(t, tc.verb, cls.Verb)
		})
	}
}

func TestClassifySQLiteDML(t *testing.T) {
	t.Run("update where", func(t *testing.T) {
		cls, err := ClassifySQLite("UPDATE users SET active=0 WHERE id=42")
		require.NoError(t, err)
		assert.Equal(t, ClassDML, cls.Class)
		assert.Equal(t, "UPDATE", cls.Verb)
		assert.Equal(t, "users", cls.Table)
		assert.True(t, cls.HasWhere)
		assert.False(t, cls.ComplexSource)
	})
	t.Run("insert or replace is overwrite", func(t *testing.T) {
		cls, err := ClassifySQLite("INSERT OR REPLACE INTO users (id, name) VALUES (1, 'x')")
		require.NoError(t, err)
		assert.Equal(t, "INSERT", cls.Verb)
		assert.Equal(t, "users", cls.Table)
		assert.True(t, cls.ComplexSource)
	})
	t.Run("replace into is overwrite", func(t *testing.T) {
		cls, err := ClassifySQLite("REPLACE INTO users (id, name) VALUES (1, 'x')")
		require.NoError(t, err)
		assert.Equal(t, "REPLACE", cls.Verb)
		assert.Equal(t, "users", cls.Table)
		assert.True(t, cls.ComplexSource)
	})
	t.Run("update or ignore", func(t *testing.T) {
		cls, err := ClassifySQLite("UPDATE OR IGNORE users SET x=1 WHERE id=2")
		require.NoError(t, err)
		assert.Equal(t, "users", cls.Table)
		assert.True(t, cls.ComplexSource)
		assert.True(t, cls.HasWhere)
	})
	t.Run("upsert on conflict", func(t *testing.T) {
		cls, err := ClassifySQLite("INSERT INTO users (id) VALUES (1) ON CONFLICT(id) DO UPDATE SET name='x'")
		require.NoError(t, err)
		assert.True(t, cls.ComplexSource)
	})
}

func TestClassifySQLiteBlocked(t *testing.T) {
	cases := []string{
		"SELECT 1; DELETE FROM t",
		".shell rm -rf /",
		"SELECT 1\n.once /tmp/out.csv",
		"ATTACH DATABASE '/tmp/x.db' AS extra",
		"DETACH extra",
		"SELECT load_extension('evil')",
		"PRAGMA load_extension=1",
		"PRAGMA journal_mode=WAL",
		"PRAGMA key='secret'",
		"VACUUM INTO '/tmp/copy.db'",
		"BEGIN",
		"DROP DATABASE main",
		"SHOW TABLES",
		"MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET x=1",
		"EXPLAIN ANALYZE SELECT 1",
	}
	for _, sql := range cases {
		t.Run(sql, func(t *testing.T) {
			_, err := ClassifySQLite(sql)
			require.Error(t, err)
			var blocked *BlockedError
			assert.True(t, errors.As(err, &blocked), "got %v", err)
		})
	}
}

func TestClassifyForEngine(t *testing.T) {
	_, err := ClassifyFor("sqlite", "SHOW server_version")
	require.Error(t, err)
	cls, err := ClassifyFor("postgres", "SHOW server_version")
	require.NoError(t, err)
	assert.Equal(t, "SHOW", cls.Verb)
	cls, err = ClassifyFor("mysql", "SELECT 1")
	require.NoError(t, err)
	assert.Equal(t, ClassRead, cls.Class)
}

func TestValidateSQLitePath(t *testing.T) {
	require.NoError(t, ValidateSQLitePath("/var/lib/app/app.db"))
	require.NoError(t, ValidateSQLitePath(`C:\data\app.db`))
	assert.Error(t, ValidateSQLitePath("app.db"))
	assert.Error(t, ValidateSQLitePath("/var/lib/../etc/passwd"))
	assert.Error(t, ValidateSQLitePath(":memory:"))
	assert.Error(t, ValidateSQLitePath("file:/tmp/x.db"))
	assert.Error(t, ValidateSQLitePath("/tmp/x.db?mode=rw"))
}

func TestDecideSQLiteBackup(t *testing.T) {
	t.Run("bounded update uses table snapshot", func(t *testing.T) {
		cls, err := ClassifySQLite("UPDATE users SET x=1 WHERE id=1")
		require.NoError(t, err)
		plan, err := DecideSQLiteBackup(cls, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupTable, plan.Kind)
		assert.Equal(t, "users", plan.Table)
	})
	t.Run("replace uses file snapshot", func(t *testing.T) {
		cls, err := ClassifySQLite("REPLACE INTO users (id) VALUES (1)")
		require.NoError(t, err)
		plan, err := DecideSQLiteBackup(cls, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupFile, plan.Kind)
	})
	t.Run("insert needs no backup", func(t *testing.T) {
		cls, err := ClassifySQLite("INSERT INTO users (name) VALUES ('x')")
		require.NoError(t, err)
		plan, err := DecideSQLiteBackup(cls, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupNone, plan.Kind)
	})
}

func TestSQLiteCommands(t *testing.T) {
	conn := SQLiteConn{Path: "/var/lib/app/app.db"}

	t.Run("read only uri", func(t *testing.T) {
		rc := conn.ExecuteReadCommand("SELECT 1")
		assert.Contains(t, rc.Command, "sqlite3 -batch -bail")
		assert.Contains(t, rc.Command, "file:/var/lib/app/app.db?mode=ro")
		assert.NotContains(t, rc.Command, "-readonly")
		assert.NotContains(t, rc.Command, "-uri")
		assert.Contains(t, rc.Stdin, "SELECT 1;\n")
		require.NotNil(t, rc.Protocol)
		assert.NotContains(t, rc.Command, "PGPASSWORD")
	})
	t.Run("explain query plan", func(t *testing.T) {
		rc := conn.ExplainCommand("UPDATE t SET x=1 WHERE id=1")
		assert.Equal(t, "EXPLAIN QUERY PLAN UPDATE t SET x=1 WHERE id=1;\n", rc.Stdin)
	})
	t.Run("table backup under begin immediate", func(t *testing.T) {
		rc, err := conn.ExecuteWithBackupCommand(
			"UPDATE t SET x=1 WHERE id=1", "t", "id=1",
			".sshx/sql-backups/f.csv", BackupTable,
		)
		require.NoError(t, err)
		assert.Contains(t, rc.Command, "umask 077")
		assert.Contains(t, rc.Command, "sqlite3 -batch -bail /var/lib/app/app.db")
		assert.Contains(t, rc.Command, "BEGIN IMMEDIATE;")
		assert.Contains(t, rc.Command, "SELECT * FROM t;")
		assert.NotContains(t, rc.Command, "SELECT * FROM t WHERE")
		assert.Contains(t, rc.Command, "UPDATE t SET x=1 WHERE id=1;")
		assert.Contains(t, rc.Command, "changes();")
		assert.Contains(t, rc.Command, "COMMIT;")
	})
	t.Run("file backup uses .backup", func(t *testing.T) {
		rc, err := conn.ExecuteWithBackupCommand(
			"REPLACE INTO t (id) VALUES (1)", "t", "",
			".sshx/sql-backups/f.db", BackupFile,
		)
		require.NoError(t, err)
		assert.Contains(t, rc.Command, ".backup .sshx/sql-backups/f.db")
		assert.NotContains(t, rc.Command, "SELECT * FROM")
		assert.Equal(t, 2, strings.Count(rc.Command, "sqlite3 -batch -bail"))
	})
	t.Run("rejects unsafe backup path", func(t *testing.T) {
		_, err := conn.ExecuteWithBackupCommand("UPDATE t SET x=1", "t", "", "bad path.csv", BackupTable)
		assert.Error(t, err)
	})
	t.Run("related effects inspects triggers", func(t *testing.T) {
		rc, err := conn.RelatedEffectsCommand("users", "DELETE")
		require.NoError(t, err)
		assert.Contains(t, rc.Stdin, "sqlite_master")
		assert.Contains(t, rc.Stdin, "pragma_foreign_key_list")
		assert.Contains(t, rc.Stdin, "on_delete")
	})
}

func TestParseChangesOutput(t *testing.T) {
	n, ok := ParseChangesOutput("1\n")
	assert.True(t, ok)
	assert.Equal(t, int64(1), n)
	n, ok = ParseChangesOutput("ignored\n3")
	assert.True(t, ok)
	assert.Equal(t, int64(3), n)
	_, ok = ParseChangesOutput("not-a-number")
	assert.False(t, ok)
}

func TestWrapSudoStdin(t *testing.T) {
	wrapped := WrapSudoStdin("sqlite3 -batch -bail 'file:/var/lib/app.db?mode=ro'")
	assert.True(t, strings.HasPrefix(wrapped, "sudo -S -p '' sh -c "))
	assert.Contains(t, wrapped, "file:/var/lib/app.db?mode=ro")
	assert.NotContains(t, wrapped, "password")
	assert.Equal(t, "", WrapSudoStdin(""))
	assert.Equal(t, "   ", WrapSudoStdin("   "))
}

func TestNormalizeEngine(t *testing.T) {
	assert.Equal(t, EnginePostgres, NormalizeEngine(""))
	assert.Equal(t, EnginePostgres, NormalizeEngine("PostgreSQL"))
	assert.Equal(t, EngineSQLite, NormalizeEngine("SQLite3"))
	assert.Equal(t, EngineMySQL, NormalizeEngine("MariaDB"))
	assert.Equal(t, "mysql", NormalizeEngine("MySQL"))
}

func TestBackupPathFileKind(t *testing.T) {
	path := BackupPath(".sshx/sql-backups", "/var/lib/app.db", "users", BackupFile)
	assert.True(t, strings.HasSuffix(path, ".db"), path)
}

func TestSQLiteBackupRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 not installed")
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "app.db")
	setup := exec.Command("sqlite3", db, "CREATE TABLE t (id INTEGER PRIMARY KEY, x TEXT); INSERT INTO t VALUES (1, 'old');") // #nosec G204 -- fixed test fixture
	require.NoError(t, setup.Run())

	backup := filepath.Join(dir, "snap.csv")
	rc, err := SQLiteConn{Path: db}.ExecuteWithBackupCommand(
		"UPDATE t SET x='new' WHERE id=1", "t", "id=1", backup, BackupTable,
	)
	require.NoError(t, err)

	cmd := exec.Command("sh", "-c", rc.Command) // #nosec G204 -- command is generated from validated fixture paths
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(rc.Stdin)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	observed, parseErr := rc.Protocol.Parse(string(out))
	require.NoError(t, parseErr)
	require.NotNil(t, observed.AffectedRows)
	assert.Equal(t, int64(1), *observed.AffectedRows)
	assert.True(t, observed.Committed)
	assert.True(t, observed.BackupReady)

	got, err := exec.Command("sqlite3", db, "SELECT x FROM t WHERE id=1;").Output() // #nosec G204 -- fixed test fixture
	require.NoError(t, err)
	assert.Equal(t, "new\n", string(got))

	data, err := os.ReadFile(backup) // #nosec G304 -- isolated test backup path
	require.NoError(t, err)
	assert.Contains(t, string(data), "old")
}

func TestSQLiteReadCommandRunsWithoutReadonlyFlag(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 not installed")
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "app.db")
	setup := exec.Command("sqlite3", db, "CREATE TABLE t (id INTEGER PRIMARY KEY); INSERT INTO t VALUES (1);") // #nosec G204 -- fixed test fixture
	require.NoError(t, setup.Run())

	rc := SQLiteConn{Path: db}.ExecuteReadCommand("SELECT id FROM t")
	require.NotContains(t, rc.Command, "-readonly")

	cmd := exec.Command("sh", "-c", rc.Command) // #nosec G204 -- command is generated from validated fixture paths
	cmd.Stdin = strings.NewReader(rc.Stdin)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	observed, parseErr := rc.Protocol.Parse(string(out))
	require.NoError(t, parseErr)
	assert.Equal(t, "1\n", observed.Stdout)

	write := exec.Command("sh", "-c", rc.Command) // #nosec G204 -- same generated read-only command
	write.Stdin = strings.NewReader("INSERT INTO t VALUES (2);\n")
	writeOut, writeErr := write.CombinedOutput()
	require.Error(t, writeErr, string(writeOut))
	assert.Contains(t, strings.ToLower(string(writeOut)), "readonly")
}
