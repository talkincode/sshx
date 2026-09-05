package sqlsafe

import (
	"fmt"
	"strings"
)

// Dialect captures engine-specific classification and backup policy.
// Remote client invocation stays on SQLExecutor (Conn / SQLiteConn / MySQLConn).
type Dialect interface {
	Name() string
	Classify(sql string) (*Classification, error)
	DecideBackup(cls *Classification, estimatedRows int64, opts Options) (BackupPlan, error)
}

type postgresDialect struct{}

func (postgresDialect) Name() string { return EnginePostgres }
func (postgresDialect) Classify(sql string) (*Classification, error) {
	return Classify(sql)
}
func (postgresDialect) DecideBackup(cls *Classification, estimatedRows int64, opts Options) (BackupPlan, error) {
	return DecideBackup(cls, estimatedRows, opts)
}

type sqliteDialect struct{}

func (sqliteDialect) Name() string { return EngineSQLite }
func (sqliteDialect) Classify(sql string) (*Classification, error) {
	return ClassifySQLite(sql)
}
func (sqliteDialect) DecideBackup(cls *Classification, _ int64, opts Options) (BackupPlan, error) {
	return DecideSQLiteBackup(cls, opts)
}

type mysqlDialect struct{}

func (mysqlDialect) Name() string { return EngineMySQL }
func (mysqlDialect) Classify(sql string) (*Classification, error) {
	return ClassifyMySQL(sql)
}
func (mysqlDialect) DecideBackup(cls *Classification, estimatedRows int64, opts Options) (BackupPlan, error) {
	plan, err := DecideBackup(cls, estimatedRows, opts)
	if err == nil && plan.Kind != BackupNone {
		plan.Reason = strings.ReplaceAll(plan.Reason, "CSV", "hex-row")
		if estimatedRows < 0 && plan.Kind == BackupRows {
			plan.Kind = BackupTable
			plan.Reason = "MySQL row estimate unavailable; taking a full-table hex-row snapshot"
		}
	}
	return plan, err
}

// LookupDialect returns the dialect for a user-supplied --engine value.
func LookupDialect(engine string) (Dialect, error) {
	switch NormalizeEngine(engine) {
	case EnginePostgres:
		return postgresDialect{}, nil
	case EngineSQLite:
		return sqliteDialect{}, nil
	case EngineMySQL:
		return mysqlDialect{}, nil
	default:
		return nil, &BlockedError{Reason: fmt.Sprintf("unsupported --engine %q (implemented: postgres, sqlite, mysql)", engine)}
	}
}
