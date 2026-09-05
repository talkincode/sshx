package sqlsafe

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyMySQL(t *testing.T) {
	cls, err := ClassifyMySQL("SELECT count(*) FROM users")
	require.NoError(t, err)
	assert.Equal(t, ClassRead, cls.Class)

	cls, err = ClassifyMySQL("UPDATE users SET active=0 WHERE id=1")
	require.NoError(t, err)
	assert.Equal(t, ClassDML, cls.Class)
	assert.True(t, cls.HasWhere)
	assert.Equal(t, "users", cls.Table)

	cls, err = ClassifyMySQL("INSERT INTO users (id) VALUES (1) ON DUPLICATE KEY UPDATE id=id")
	require.NoError(t, err)
	assert.True(t, cls.ComplexSource)

	blocked := []string{
		"SELECT * FROM users INTO OUTFILE '/tmp/x'",
		"LOAD DATA INFILE '/tmp/x' INTO TABLE users",
		"CALL do_thing()",
		"SET GLOBAL max_connections=10",
		"SET @@GLOBAL.sql_mode=''",
		"CREATE PROCEDURE p() BEGIN SELECT 1; END",
		"SELECT 1; SELECT 2",
		"SELECT 1 /*! INTO OUTFILE '/srv/exfiltrate' */",
		"UPDATE users SET active=0 WHERE id=1 /*M! ; COMMIT */",
	}
	for _, sql := range blocked {
		_, classifyErr := ClassifyMySQL(sql)
		require.Error(t, classifyErr, sql)
	}
	_, err = ClassifyMySQL("SELECT '/*! harmless literal */'")
	require.NoError(t, err)
}

func TestLookupDialectMySQL(t *testing.T) {
	d, err := LookupDialect("mariadb")
	require.NoError(t, err)
	assert.Equal(t, EngineMySQL, d.Name())
	cls, err := d.Classify("SHOW TABLES")
	require.NoError(t, err)
	assert.Equal(t, ClassRead, cls.Class)
	plan, err := d.DecideBackup(cls, -1, Options{})
	require.NoError(t, err)
	assert.Equal(t, BackupNone, plan.Kind)
}

func TestParseMySQLExplainRows(t *testing.T) {
	raw := `{"query_block":{"select_id":1,"cost_info":{"query_cost":"1.00"},"table":{"table_name":"users","rows":42}}}`
	rows, err := ParseMySQLExplainRows(raw)
	require.NoError(t, err)
	assert.Equal(t, int64(42), rows)
}

func TestMySQLExplainRequestsRawJSONOnlyForExplain(t *testing.T) {
	for _, docker := range []string{"", "mysql-fixture"} {
		t.Run("docker="+docker, func(t *testing.T) {
			conn := MySQLConn{Database: "app", Host: "127.0.0.1", PasswordStdin: true, Docker: docker}
			explain := conn.ExplainCommand("UPDATE users SET active=0 WHERE id=1")
			assert.Contains(t, explain.Command, "--raw", "batch mode otherwise escapes JSON formatting newlines as literal backslash-n")
			assert.Contains(t, explain.Command, "IFS= read -r MYSQL_PWD")
			assert.Contains(t, explain.Command, "--batch")
			assert.NotContains(t, conn.ExecuteReadCommand("SELECT name FROM users").Command, "--raw", "ordinary read display must not change")
			assert.NotContains(t, conn.ExecuteCommand("UPDATE users SET active=0 WHERE id=1").Command, "--raw")
			if docker != "" {
				assert.Contains(t, explain.Command, "docker exec -i -e MYSQL_PWD "+docker+" mysql")
			}
		})
	}
}

func TestParseMySQLPrettyExplainRows(t *testing.T) {
	raw := `{
  "query_block": {
    "table": {
      "rows_examined_per_scan": 7,
      "attached_condition": "users.name = 'a\\\\b'"
    }
  }
}`
	rows, err := ParseMySQLExplainRows(raw)
	require.NoError(t, err)
	assert.Equal(t, int64(7), rows)
	batchEscaped := strings.ReplaceAll(strings.ReplaceAll(raw, `\`, `\\`), "\n", `\n`)
	_, parseErr := ParseMySQLExplainRows(batchEscaped)
	require.Error(t, parseErr, "batch-escaped output is not JSON; request --raw rather than guessing how to unescape SQL data")
}

func TestMySQLBackupUsesOneLockedTransactionalClient(t *testing.T) {
	rc, err := (MySQLConn{Database: "app"}).ExecuteWithBackupCommand("UPDATE t SET x=1 WHERE id=1", "t", "id=1", ".sshx/backup.csv", BackupRows)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(rc.Command, "mysql --no-defaults"))
	assert.Contains(t, rc.Command, "SET autocommit=0;\nLOCK TABLES t WRITE;")
	assert.NotContains(t, rc.Command, "START TRANSACTION")
	assert.NotContains(t, rc.Command, "CREATE TABLE")
	assert.Contains(t, rc.Command, "ENGINE=")
	assert.Contains(t, rc.Command, "--skip-reconnect")
	assert.Contains(t, rc.Command, "SSHX_MYSQL_HEX_ROWS_V1")
	assert.Contains(t, rc.Command, "COMMIT;")
	require.NotNil(t, rc.Protocol)
	assert.Equal(t, "mysql_hex_rows_v1", rc.Protocol.BackupForm)
}

func TestMySQLGuardRejectsUnsupportedForms(t *testing.T) {
	for _, stmt := range []string{
		"TRUNCATE t",
		"UPDATE t JOIN s ON t.id=s.id SET t.x=1 WHERE t.id=1",
		"REPLACE INTO t (id) VALUES (1)",
	} {
		_, err := (MySQLConn{Database: "app"}).ExecuteWithBackupCommand(stmt, "t", "", ".sshx/backup.csv", BackupTable)
		require.Error(t, err, stmt)
	}
}

func TestMySQLExplainNeverUsesCostAsRows(t *testing.T) {
	rows, err := ParseMySQLExplainRows(`{"query_block":{"cost_info":{"query_cost":42}}}`)
	require.NoError(t, err)
	assert.Equal(t, int64(-1), rows, "cost is not a row estimate")
	rows, err = ParseMySQLExplainRows(`{"query_block":{"table":{"rows_examined_per_scan":17}}}`)
	require.NoError(t, err)
	assert.Equal(t, int64(17), rows)
}

func TestMySQLExplainUnavailableEstimateIsNotMalformed(t *testing.T) {
	for _, plan := range []string{
		`{"query_block":{"table":{"insert":true,"table_name":"t","access_type":"ALL"}}}`,
		`{"query_block":{"select_id":1,"message":"No tables used"}}`,
	} {
		rows, err := ParseMySQLExplainRows(plan)
		require.NoError(t, err)
		assert.Equal(t, int64(-1), rows)
	}
	for _, malformed := range []string{"", "not JSON", `{}`, `[]`, `{"query_block":[]}`, `{"query_block":{}}`, `{"query_block":{"table":{"rows":"invalid"}}}`, `{"query_block":{"table":{"rows":-2}}}`} {
		_, err := ParseMySQLExplainRows(malformed)
		require.Error(t, err, malformed)
	}
}

func TestMySQLUnavailableEstimateBackupPolicy(t *testing.T) {
	dialect, err := LookupDialect(EngineMySQL)
	require.NoError(t, err)
	for _, tc := range []struct {
		statement string
		options   Options
		kind      BackupKind
	}{
		{"INSERT INTO t (id) VALUES (1)", Options{}, BackupNone},
		{"INSERT INTO t (id) VALUES (1)", Options{Force: true, NoBackup: true}, BackupNone},
		{"UPDATE t SET x=1 WHERE id=1", Options{}, BackupTable},
	} {
		cls, classifyErr := dialect.Classify(tc.statement)
		require.NoError(t, classifyErr)
		plan, planErr := dialect.DecideBackup(cls, -1, tc.options)
		require.NoError(t, planErr)
		assert.Equal(t, tc.kind, plan.Kind, tc.statement)
	}
}
