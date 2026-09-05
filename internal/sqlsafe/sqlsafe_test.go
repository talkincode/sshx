package sqlsafe

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyReads(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		verb string
	}{
		{"select", "SELECT * FROM users", "SELECT"},
		{"select lowercase", "select id from users where name = 'x'", "SELECT"},
		{"select trailing semicolon", "SELECT 1;", "SELECT"},
		{"select with comments", "-- count them\nSELECT count(*) FROM t /* inline */", "SELECT"},
		{"show", "SHOW server_version", "SHOW"},
		{"explain", "EXPLAIN SELECT * FROM users", "EXPLAIN"},
		{"values", "VALUES (1), (2)", "VALUES"},
		{"table", "TABLE users", "TABLE"},
		{"cte read", "WITH x AS (SELECT 1) SELECT * FROM x", "SELECT"},
		{"keyword inside string", "SELECT 'DROP DATABASE prod' FROM t", "SELECT"},
		{"keyword inside identifier", `SELECT "delete" FROM audit_log`, "SELECT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cls, err := Classify(tc.sql)
			require.NoError(t, err)
			assert.Equal(t, ClassRead, cls.Class)
			assert.Equal(t, tc.verb, cls.Verb)
		})
	}
}

func TestClassifyDML(t *testing.T) {
	t.Run("update simple", func(t *testing.T) {
		cls, err := Classify("UPDATE users SET active = false WHERE id = 42")
		require.NoError(t, err)
		assert.Equal(t, ClassDML, cls.Class)
		assert.Equal(t, "UPDATE", cls.Verb)
		assert.Equal(t, "users", cls.Table)
		assert.True(t, cls.HasWhere)
		assert.Equal(t, "id = 42", cls.WhereClause)
		assert.False(t, cls.ComplexSource)
	})
	t.Run("update schema qualified", func(t *testing.T) {
		cls, err := Classify(`UPDATE app.users SET x=1 WHERE y=2`)
		require.NoError(t, err)
		assert.Equal(t, "app.users", cls.Table)
	})
	t.Run("update quoted table", func(t *testing.T) {
		cls, err := Classify(`UPDATE "User Accounts" SET x=1 WHERE y=2`)
		require.NoError(t, err)
		assert.Equal(t, `"User Accounts"`, cls.Table)
	})
	t.Run("update only", func(t *testing.T) {
		cls, err := Classify("UPDATE ONLY users SET x=1 WHERE id=1")
		require.NoError(t, err)
		assert.Equal(t, "users", cls.Table)
	})
	t.Run("update without where", func(t *testing.T) {
		cls, err := Classify("UPDATE users SET active = false")
		require.NoError(t, err)
		assert.False(t, cls.HasWhere)
	})
	t.Run("update where in subquery only", func(t *testing.T) {
		cls, err := Classify("UPDATE users SET n = (SELECT count(*) FROM t WHERE t.u = users.id)")
		require.NoError(t, err)
		assert.False(t, cls.HasWhere, "WHERE inside a subquery must not count as a top-level WHERE")
	})
	t.Run("update from is complex", func(t *testing.T) {
		cls, err := Classify("UPDATE a SET x = b.x FROM b WHERE a.id = b.id")
		require.NoError(t, err)
		assert.True(t, cls.ComplexSource)
	})
	t.Run("update alias is complex", func(t *testing.T) {
		cls, err := Classify("UPDATE users AS u SET active=false WHERE u.id=42")
		require.NoError(t, err)
		assert.True(t, cls.ComplexSource)
	})
	t.Run("update where excludes returning", func(t *testing.T) {
		cls, err := Classify("UPDATE t SET x=1 WHERE id=5 RETURNING *")
		require.NoError(t, err)
		assert.Equal(t, "id=5", cls.WhereClause)
	})
	t.Run("delete simple", func(t *testing.T) {
		cls, err := Classify("DELETE FROM logs WHERE created_at < '2020-01-01'")
		require.NoError(t, err)
		assert.Equal(t, "DELETE", cls.Verb)
		assert.Equal(t, "logs", cls.Table)
		assert.True(t, cls.HasWhere)
		assert.Equal(t, "created_at < '2020-01-01'", cls.WhereClause)
	})
	t.Run("delete using is complex", func(t *testing.T) {
		cls, err := Classify("DELETE FROM a USING b WHERE a.id = b.id")
		require.NoError(t, err)
		assert.True(t, cls.ComplexSource)
	})
	t.Run("delete alias is complex", func(t *testing.T) {
		cls, err := Classify("DELETE FROM users u WHERE u.id=42")
		require.NoError(t, err)
		assert.True(t, cls.ComplexSource)
	})
	t.Run("insert", func(t *testing.T) {
		cls, err := Classify("INSERT INTO users (name) VALUES ('x')")
		require.NoError(t, err)
		assert.Equal(t, "INSERT", cls.Verb)
		assert.Equal(t, "users", cls.Table)
	})
	t.Run("upsert is complex", func(t *testing.T) {
		cls, err := Classify("INSERT INTO users (id, name) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET name=excluded.name")
		require.NoError(t, err)
		assert.True(t, cls.ComplexSource)
	})
	t.Run("merge is complex", func(t *testing.T) {
		cls, err := Classify("MERGE INTO tgt USING src ON tgt.id = src.id WHEN MATCHED THEN UPDATE SET x = src.x")
		require.NoError(t, err)
		assert.Equal(t, "MERGE", cls.Verb)
		assert.Equal(t, "tgt", cls.Table)
		assert.True(t, cls.ComplexSource)
	})
	t.Run("cte wrapped delete", func(t *testing.T) {
		cls, err := Classify("WITH old AS (SELECT id FROM t WHERE ts < now()) DELETE FROM t WHERE id IN (SELECT id FROM old)")
		require.NoError(t, err)
		assert.Equal(t, ClassDML, cls.Class)
		assert.Equal(t, "DELETE", cls.Verb)
		assert.Equal(t, "t", cls.Table)
		assert.True(t, cls.ComplexSource)
	})
}

func TestClassifyDDL(t *testing.T) {
	t.Run("truncate", func(t *testing.T) {
		cls, err := Classify("TRUNCATE TABLE audit_log")
		require.NoError(t, err)
		assert.Equal(t, ClassDDL, cls.Class)
		assert.True(t, cls.Destructive)
		assert.Equal(t, "audit_log", cls.Table)
	})
	t.Run("truncate multiple tables has no single backup target", func(t *testing.T) {
		cls, err := Classify("TRUNCATE a, b")
		require.NoError(t, err)
		assert.Empty(t, cls.Table)
	})
	t.Run("drop table", func(t *testing.T) {
		cls, err := Classify("DROP TABLE IF EXISTS tmp_import")
		require.NoError(t, err)
		assert.Equal(t, "DROP TABLE", cls.Verb)
		assert.True(t, cls.Destructive)
		assert.Equal(t, "tmp_import", cls.Table)
	})
	t.Run("create index", func(t *testing.T) {
		cls, err := Classify("CREATE INDEX idx ON t (x)")
		require.NoError(t, err)
		assert.Equal(t, ClassDDL, cls.Class)
		assert.False(t, cls.Destructive)
	})
	t.Run("alter table", func(t *testing.T) {
		cls, err := Classify("ALTER TABLE t ADD COLUMN x int")
		require.NoError(t, err)
		assert.Equal(t, ClassDDL, cls.Class)
		assert.True(t, cls.Destructive)
		assert.Equal(t, "t", cls.Table)
	})
	t.Run("vacuum", func(t *testing.T) {
		cls, err := Classify("VACUUM ANALYZE t")
		require.NoError(t, err)
		assert.Equal(t, ClassDDL, cls.Class)
	})
	t.Run("refresh materialized view is destructive", func(t *testing.T) {
		cls, err := Classify("REFRESH MATERIALIZED VIEW reporting.daily_totals")
		require.NoError(t, err)
		assert.True(t, cls.Destructive)
		assert.Equal(t, "reporting.daily_totals", cls.Table)
	})
	t.Run("drop materialized view is destructive", func(t *testing.T) {
		cls, err := Classify("DROP MATERIALIZED VIEW reporting.daily_totals")
		require.NoError(t, err)
		assert.True(t, cls.Destructive)
		assert.Equal(t, "reporting.daily_totals", cls.Table)
	})
	t.Run("drop cascade is destructive", func(t *testing.T) {
		cls, err := Classify("DROP TYPE app.status CASCADE")
		require.NoError(t, err)
		assert.True(t, cls.Destructive)
		assert.Error(t, CheckPolicy(cls, Options{Force: true}))
		assert.NoError(t, CheckPolicy(cls, Options{Force: true, NoBackup: true}))
	})
}

func TestClassifyBlocked(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"multi statement", "SELECT 1; DROP TABLE users"},
		{"multi statement dml", "UPDATE t SET x=1 WHERE id=1; UPDATE t SET x=2 WHERE id=2"},
		{"drop database", "DROP DATABASE prod"},
		{"drop schema", "DROP SCHEMA app CASCADE"},
		{"drop owned", "DROP OWNED BY someone"},
		{"drop tablespace", "DROP TABLESPACE ts"},
		{"alter system", "ALTER SYSTEM SET work_mem = '1GB'"},
		{"do block", "DO $$ BEGIN RAISE NOTICE 'hi'; END $$"},
		{"copy program", "COPY t FROM PROGRAM 'rm -rf /'"},
		{"begin", "BEGIN"},
		{"commit", "COMMIT"},
		{"set", "SET search_path TO public"},
		{"unterminated string", "SELECT 'oops"},
		{"unterminated comment", "SELECT 1 /* oops"},
		{"unterminated dollar quote", "SELECT $$oops"},
		{"empty", "   "},
		{"comment only", "-- nothing"},
		{"unknown head", "FROBNICATE the database"},
		{"psql gexec", "SELECT 'DROP TABLE users'\n\\gexec\n--"},
		{"psql include", "SELECT 1\n\\i /tmp/payload.sql"},
		{"explain analyze delete", "EXPLAIN ANALYZE DELETE FROM users"},
		{"explain analyze option", "EXPLAIN (ANALYZE true) UPDATE users SET x=1"},
		{"data modifying cte", "WITH gone AS (DELETE FROM users RETURNING *) SELECT 1"},
		{"call procedure", "CALL cleanup()"},
		{"select into", "SELECT * INTO shadow_users FROM users"},
		{"dblink exec", "SELECT dblink_exec('dbname=app', 'DELETE FROM users')"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Classify(tc.sql)
			require.Error(t, err)
			var blocked *BlockedError
			assert.True(t, errors.As(err, &blocked), "expected BlockedError, got %T: %v", err, err)
		})
	}
}

func TestClassifySemicolonHandling(t *testing.T) {
	t.Run("semicolon inside string is not a separator", func(t *testing.T) {
		cls, err := Classify("SELECT 'a;b' FROM t")
		require.NoError(t, err)
		assert.Equal(t, ClassRead, cls.Class)
	})
	t.Run("trailing semicolon and whitespace", func(t *testing.T) {
		cls, err := Classify("DELETE FROM t WHERE id=1;\n\n")
		require.NoError(t, err)
		assert.Equal(t, "DELETE", cls.Verb)
		assert.Equal(t, "DELETE FROM t WHERE id=1", cls.Statement)
	})
}

func TestCheckPolicy(t *testing.T) {
	classify := func(t *testing.T, sql string) *Classification {
		t.Helper()
		cls, err := Classify(sql)
		require.NoError(t, err)
		return cls
	}

	t.Run("read always allowed", func(t *testing.T) {
		assert.NoError(t, CheckPolicy(classify(t, "SELECT 1"), Options{}))
	})
	t.Run("update with where allowed", func(t *testing.T) {
		assert.NoError(t, CheckPolicy(classify(t, "UPDATE t SET x=1 WHERE id=1"), Options{}))
	})
	t.Run("update without where blocked", func(t *testing.T) {
		err := CheckPolicy(classify(t, "UPDATE t SET x=1"), Options{})
		var blocked *BlockedError
		require.True(t, errors.As(err, &blocked))
		assert.Contains(t, blocked.Reason, "--allow-full-table")
	})
	t.Run("update without where allowed with flag", func(t *testing.T) {
		assert.NoError(t, CheckPolicy(classify(t, "UPDATE t SET x=1"), Options{AllowFullTable: true}))
	})
	t.Run("delete without where blocked", func(t *testing.T) {
		assert.Error(t, CheckPolicy(classify(t, "DELETE FROM t"), Options{}))
	})
	t.Run("ddl requires force", func(t *testing.T) {
		assert.Error(t, CheckPolicy(classify(t, "ALTER TABLE t ADD c int"), Options{}))
		assert.Error(t, CheckPolicy(classify(t, "ALTER TABLE t ADD c int"), Options{Force: true}))
		assert.NoError(t, CheckPolicy(classify(t, "ALTER TABLE t ADD c int"), Options{Force: true, NoBackup: true}))
	})
	t.Run("no-backup dml requires force", func(t *testing.T) {
		cls := classify(t, "DELETE FROM t WHERE id=1")
		assert.Error(t, CheckPolicy(cls, Options{NoBackup: true}))
		assert.NoError(t, CheckPolicy(cls, Options{NoBackup: true, Force: true}))
	})
}

func TestDecideBackup(t *testing.T) {
	classify := func(t *testing.T, sql string) *Classification {
		t.Helper()
		cls, err := Classify(sql)
		require.NoError(t, err)
		return cls
	}

	t.Run("read no backup", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "SELECT 1"), -1, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupNone, plan.Kind)
	})
	t.Run("insert no backup", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "INSERT INTO t VALUES (1)"), -1, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupNone, plan.Kind)
	})
	t.Run("upsert table backup", func(t *testing.T) {
		plan, err := DecideBackup(classify(t,
			"INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id=excluded.id"), 1, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupTable, plan.Kind)
	})
	t.Run("small update rows backup", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "UPDATE t SET x=1 WHERE id=1"), 3, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupRows, plan.Kind)
		assert.Equal(t, "t", plan.Table)
	})
	t.Run("large update table backup", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "UPDATE t SET x=1 WHERE id > 0"), 50000, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupTable, plan.Kind)
	})
	t.Run("threshold boundary stays rows", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "UPDATE t SET x=1 WHERE id > 0"), DefaultRowThreshold, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupRows, plan.Kind)
	})
	t.Run("custom threshold", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "UPDATE t SET x=1 WHERE id > 0"), 20, Options{RowThreshold: 10})
		require.NoError(t, err)
		assert.Equal(t, BackupTable, plan.Kind)
	})
	t.Run("unknown estimate stays rows", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "DELETE FROM t WHERE id=9"), -1, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupRows, plan.Kind)
	})
	t.Run("complex source forces table backup", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "DELETE FROM a USING b WHERE a.id=b.id"), 2, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupTable, plan.Kind)
	})
	t.Run("full table delete forces table backup", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "DELETE FROM t"), 2, Options{AllowFullTable: true})
		require.NoError(t, err)
		assert.Equal(t, BackupTable, plan.Kind)
	})
	t.Run("multiline where forces table backup", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "DELETE FROM t WHERE id IN (1,\n2)"), 2, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupTable, plan.Kind)
	})
	t.Run("truncate table backup", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "TRUNCATE t"), -1, Options{})
		require.NoError(t, err)
		assert.Equal(t, BackupTable, plan.Kind)
	})
	t.Run("no table extractable fails closed", func(t *testing.T) {
		cls := classify(t, "TRUNCATE a, b")
		_, err := DecideBackup(cls, -1, Options{})
		var blocked *BlockedError
		require.True(t, errors.As(err, &blocked))
	})
	t.Run("no-backup opt out", func(t *testing.T) {
		plan, err := DecideBackup(classify(t, "DELETE FROM t WHERE id=1"), -1, Options{NoBackup: true})
		require.NoError(t, err)
		assert.Equal(t, BackupNone, plan.Kind)
	})
}

func TestPostgresCommands(t *testing.T) {
	conn := Conn{Database: "appdb", User: "svc", Host: "127.0.0.1", Port: "5432", PasswordStdin: true}

	t.Run("password never in argv", func(t *testing.T) {
		secret := "s3cret-password"
		for _, rc := range []RemoteCommand{
			conn.ExplainCommand("UPDATE t SET x=1 WHERE id=1"),
			conn.ExecuteCommand("UPDATE t SET x=1 WHERE id=1"),
		} {
			assert.NotContains(t, rc.Command, secret)
			assert.Contains(t, rc.Command, "IFS= read -r PGPASSWORD")
		}
	})
	t.Run("explain command", func(t *testing.T) {
		rc := conn.ExplainCommand("DELETE FROM t WHERE id=1")
		assert.Contains(t, rc.Command, "psql -X -w -v ON_ERROR_STOP=1 -q -A -t -d appdb -U svc -h 127.0.0.1 -p 5432")
		assert.Equal(t, "EXPLAIN (FORMAT JSON) DELETE FROM t WHERE id=1;\n", rc.Stdin)
	})
	t.Run("execute command", func(t *testing.T) {
		rc := conn.ExecuteCommand("SELECT 1")
		assert.Contains(t, rc.Stdin, "SELECT 1;\n")
		require.NotNil(t, rc.Protocol)
	})
	t.Run("read command uses read only transaction", func(t *testing.T) {
		rc := conn.ExecuteReadCommand("SELECT side_effecting_function()")
		assert.Contains(t, rc.Stdin, "BEGIN TRANSACTION READ ONLY;")
		assert.Contains(t, rc.Stdin, "SELECT side_effecting_function();")
		assert.Contains(t, rc.Stdin, "COMMIT;")
	})
	t.Run("no password wrapper without key", func(t *testing.T) {
		plain := Conn{Database: "appdb"}
		rc := plain.ExecuteCommand("SELECT 1")
		assert.NotContains(t, rc.Command, "PGPASSWORD")
	})
	t.Run("transactional row backup and update", func(t *testing.T) {
		rc, err := conn.ExecuteWithBackupCommand(
			"UPDATE t SET x=1 WHERE id=1", "t", "id=1",
			".sshx/sql-backups/f.csv", BackupRows,
		)
		require.NoError(t, err)
		assert.Contains(t, rc.Command, "umask 077; mkdir -p .sshx/sql-backups && chmod 700 .sshx/sql-backups && ")
		assert.Contains(t, rc.Command, "BEGIN;")
		assert.Contains(t, rc.Command, "LOCK TABLE t IN SHARE ROW EXCLUSIVE MODE;")
		assert.Contains(t, rc.Command, "pg_catalog.pg_class")
		assert.Contains(t, rc.Command, `COPY (SELECT * FROM t WHERE id=1)`)
		assert.Contains(t, rc.Command, "UPDATE t SET x=1 WHERE id=1;")
		assert.Contains(t, rc.Command, "COMMIT;")
		require.NotNil(t, rc.Protocol)
	})
	t.Run("transactional backup rejects unsafe input", func(t *testing.T) {
		_, err := conn.ExecuteWithBackupCommand("UPDATE t SET x=1", "t; DROP TABLE x", "", "f.csv", BackupTable)
		assert.Error(t, err)
		_, err = conn.ExecuteWithBackupCommand("UPDATE t SET x=1", "t", "id IN (1,\n2)", "f.csv", BackupRows)
		assert.Error(t, err)
	})
	t.Run("docker transactional backup streams to host", func(t *testing.T) {
		dockerConn := conn
		dockerConn.Docker = "pg-prod"
		rc, err := dockerConn.ExecuteWithBackupCommand(
			"UPDATE t SET x=1 WHERE id=1", "t", "id=1",
			".sshx/sql-backups/f.csv", BackupRows,
		)
		require.NoError(t, err)
		assert.Contains(t, rc.Command, "docker exec -i -e PGPASSWORD pg-prod")
		assert.Contains(t, rc.Command, "mkfifo")
		assert.Contains(t, rc.Command, ".sshx/sql-backups/f.csv.stream-")
		assert.Contains(t, rc.Command, "COPY (SELECT * FROM t WHERE id=1) TO STDOUT")
		assert.Empty(t, rc.Stdin)
		if runtime.GOOS != "windows" {
			require.NoError(t, exec.Command("sh", "-n", "-c", rc.Command).Run()) // #nosec G204 -- generated command is fixed test data and sh only parses it
		}
	})
	t.Run("related effects query", func(t *testing.T) {
		rc, err := conn.RelatedEffectsCommand("app.users", "DELETE")
		require.NoError(t, err)
		assert.Contains(t, rc.Stdin, "pg_catalog.pg_trigger")
		assert.Contains(t, rc.Stdin, "confdeltype IN ('c','n','d')")
		assert.Contains(t, rc.Stdin, "pg_catalog.pg_rewrite")
		assert.Contains(t, rc.Stdin, "pg_catalog.pg_inherits")
		assert.NotContains(t, rc.Command, "app.users")
	})
}

func TestRedactForAudit(t *testing.T) {
	got := RedactForAudit("UPDATE users SET password = 'secret', pin=1234 WHERE id=42 /* token */")
	assert.NotContains(t, got, "secret")
	assert.NotContains(t, got, "1234")
	assert.NotContains(t, got, "token")
	assert.Contains(t, got, "UPDATE users SET password")
	assert.Contains(t, got, "?")
}

func TestValidateTableIdent(t *testing.T) {
	valid := []string{"users", "app.users", `"User Accounts"`, `app."Users"`, "_tmp", "t$1"}
	for _, v := range valid {
		assert.NoError(t, ValidateTableIdent(v), v)
	}

	invalid := []string{"", "users; DROP", "a.b.c", "1abc", `"a'b"`, "users --", "a b"}
	for _, v := range invalid {
		assert.Error(t, ValidateTableIdent(v), v)
	}
}

func TestValidateBackupDir(t *testing.T) {
	assert.NoError(t, ValidateBackupDir(".sshx/sql-backups"))
	assert.NoError(t, ValidateBackupDir("/tmp/operator's backups"))
	assert.Error(t, ValidateBackupDir("safe\nDROP TABLE users"))
	assert.Error(t, ValidateBackupDir(strings.Repeat("x", 4097)))
}

func TestBackupPath(t *testing.T) {
	p := BackupPath("", "appdb", `"User Accounts"`, BackupRows)
	assert.True(t, strings.HasPrefix(p, DefaultBackupDir+"/appdb-_User_Accounts_-"), p)
	assert.True(t, strings.HasSuffix(p, ".csv"))
	p2 := BackupPath("/tmp/backups/", "appdb", "t", BackupTable)
	assert.True(t, strings.HasPrefix(p2, "/tmp/backups/appdb-t-"), p2)
	assert.True(t, strings.HasSuffix(p2, ".csv"))
}

func TestParseExplainRows(t *testing.T) {
	out := `[
  {
    "Plan": {
      "Node Type": "ModifyTable",
      "Plan Rows": 42
    }
  }
]`
	rows, err := ParseExplainRows(out)
	require.NoError(t, err)
	assert.Equal(t, int64(42), rows)

	_, err = ParseExplainRows("garbage")
	assert.Error(t, err)
}

func TestParseCommandTag(t *testing.T) {
	cases := []struct {
		out  string
		rows int64
		ok   bool
	}{
		{"UPDATE 5\n", 5, true},
		{"DELETE 0\n", 0, true},
		{"INSERT 0 3\n", 3, true},
		{"MERGE 7\n", 7, true},
		{"COPY 12\n", 12, true},
		{" id \n----\n(3 rows)\nSELECT 3\n", 3, true},
		{"TRUNCATE TABLE\n", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		rows, ok := ParseCommandTag(tc.out)
		assert.Equal(t, tc.ok, ok, tc.out)
		if ok {
			assert.Equal(t, tc.rows, rows, tc.out)
		}
	}
}
