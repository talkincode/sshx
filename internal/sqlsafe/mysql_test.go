package sqlsafe

import (
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
	}
	for _, sql := range blocked {
		_, err := ClassifyMySQL(sql)
		require.Error(t, err, sql)
	}
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

func TestMySQLBackupTableStable(t *testing.T) {
	a := mysqlBackupTable("/tmp/a.csv")
	b := mysqlBackupTable("/tmp/a.csv")
	assert.Equal(t, a, b)
	assert.True(t, len(a) > 8)
}
