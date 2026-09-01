package sqlsafe

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Engine names accepted by sshx sql.
const (
	EnginePostgres = "postgres"
	EngineSQLite   = "sqlite"
	EngineMySQL    = "mysql"
)

// NormalizeEngine maps a user-supplied --engine value to a canonical name.
// An empty value is postgres, matching the historical default.
func NormalizeEngine(engine string) string {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case "", EnginePostgres, "postgresql":
		return EnginePostgres
	case EngineSQLite, "sqlite3":
		return EngineSQLite
	case EngineMySQL, "mariadb":
		return EngineMySQL
	default:
		return strings.ToLower(strings.TrimSpace(engine))
	}
}

// ClassifyFor dispatches statement analysis to the engine-specific classifier.
func ClassifyFor(engine, sql string) (*Classification, error) {
	dialect, err := LookupDialect(engine)
	if err != nil {
		return nil, err
	}
	return dialect.Classify(sql)
}

// SQLExecutor assembles remote client commands for one engine. sshx embeds no
// database driver: every method returns a command for the SSH exec channel.
type SQLExecutor interface {
	NeedsPasswordLine() bool
	ExplainCommand(stmt string) RemoteCommand
	ExecuteCommand(stmt string) RemoteCommand
	ExecuteReadCommand(stmt string) RemoteCommand
	ExecuteWithBackupCommand(stmt, table, where, path string, kind BackupKind) (RemoteCommand, error)
	RelatedEffectsCommand(table, verb string) (RemoteCommand, error)
}

// SQLiteConn describes how the remote sqlite3 process opens one database file.
// There is no password, role, or network endpoint: identity is the file path.
type SQLiteConn struct {
	Path string
}

var (
	_ SQLExecutor = Conn{}
	_ SQLExecutor = SQLiteConn{}
	_ SQLExecutor = MySQLConn{}
)

// NeedsPasswordLine is always false: SQLite file access uses OS permissions.
func (c SQLiteConn) NeedsPasswordLine() bool { return false }

func (c SQLiteConn) sqliteCommand(readOnly bool) (string, error) {
	if err := ValidateSQLitePath(c.Path); err != nil {
		return "", err
	}
	argv := []string{"sqlite3", "-batch", "-bail"}
	if readOnly {
		// Do not pass -readonly: that CLI flag is missing on sqlite 3.22
		// (Ubuntu 18.04 / several still-deployed distro packages). The
		// file: URI mode=ro is honored by the sqlite3 shell without extra
		// flags and still rejects writes.
		argv = append(argv, "file:"+c.Path+"?mode=ro")
	} else {
		argv = append(argv, c.Path)
	}
	return shellJoin(argv), nil
}

// ExplainCommand runs EXPLAIN QUERY PLAN. SQLite has no JSON plan-row
// estimate; callers store the text and do not parse a row count.
func (c SQLiteConn) ExplainCommand(stmt string) RemoteCommand {
	cmd, err := c.sqliteCommand(true)
	if err != nil {
		return RemoteCommand{Command: "false", Stdin: ""}
	}
	return RemoteCommand{
		Command: cmd,
		Stdin:   "EXPLAIN QUERY PLAN " + stmt + ";\n",
	}
}

// ExecuteCommand runs the statement and prints sqlite3's changes() count
// so DML affected-row reporting stays machine-readable.
func (c SQLiteConn) ExecuteCommand(stmt string) RemoteCommand {
	cmd, err := c.sqliteCommand(false)
	if err != nil {
		return RemoteCommand{Command: "false", Stdin: ""}
	}
	return RemoteCommand{
		Command: cmd,
		Stdin:   stmt + ";\nSELECT changes();\n",
	}
}

// ExecuteReadCommand opens the file URI in read-only mode so writes fail.
func (c SQLiteConn) ExecuteReadCommand(stmt string) RemoteCommand {
	cmd, err := c.sqliteCommand(true)
	if err != nil {
		return RemoteCommand{Command: "false", Stdin: ""}
	}
	return RemoteCommand{
		Command: cmd,
		Stdin:   stmt + ";\n",
	}
}

// ExecuteWithBackupCommand locks the database with BEGIN IMMEDIATE, snapshots
// either the target table (CSV) or the whole file (.backup), then mutates.
func (c SQLiteConn) ExecuteWithBackupCommand(stmt, table, where, path string, kind BackupKind) (RemoteCommand, error) {
	if kind != BackupTable && kind != BackupFile {
		return RemoteCommand{}, fmt.Errorf("unsupported sqlite backup kind %q", kind)
	}
	if !safeArgRE.MatchString(path) {
		return RemoteCommand{}, &BlockedError{Reason: "backup path contains characters that cannot be embedded in a sqlite3 script"}
	}
	cmd, err := c.sqliteCommand(false)
	if err != nil {
		return RemoteCommand{}, err
	}

	lines := []string{"BEGIN IMMEDIATE;"}
	switch kind {
	case BackupTable:
		if err := ValidateTableIdent(table); err != nil {
			return RemoteCommand{}, err
		}
		if containsNewline(where) {
			return RemoteCommand{}, &BlockedError{Reason: "table backup WHERE clause must be single-line"}
		}
		filter := ""
		if strings.TrimSpace(where) != "" {
			filter = " WHERE " + strings.TrimSpace(where)
		}
		lines = append(lines,
			".headers on",
			".mode csv",
			".once "+path,
			"SELECT * FROM "+table+filter+";",
		)
	case BackupFile:
		lines = append(lines, ".backup "+path)
	}
	lines = append(lines, stmt+";", "SELECT changes();", "COMMIT;")
	return RemoteCommand{
		Command: mkdirPrefix(path) + cmd,
		Stdin:   strings.Join(lines, "\n") + "\n",
	}, nil
}

// RelatedEffectsCommand reports whether a mutation may fire triggers or
// cascading foreign keys outside the copied table CSV.
func (c SQLiteConn) RelatedEffectsCommand(table, verb string) (RemoteCommand, error) {
	if err := ValidateTableIdent(table); err != nil {
		return RemoteCommand{}, err
	}
	cmd, err := c.sqliteCommand(true)
	if err != nil {
		return RemoteCommand{}, err
	}
	return RemoteCommand{
		Command: cmd,
		Stdin:   sqliteRelatedEffectsSQL(table, verb) + "\n",
	}, nil
}

func sqliteRelatedEffectsSQL(table, verb string) string {
	literal := "'" + strings.ReplaceAll(tableIdentName(table), "'", "''") + "'"
	fkColumn := ""
	switch verb {
	case "UPDATE":
		fkColumn = "on_update"
	case "DELETE":
		fkColumn = "on_delete"
	}
	trigger := "EXISTS (SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name=" + literal + ")"
	if fkColumn == "" {
		return "SELECT CASE WHEN " + trigger + " THEN 1 ELSE 0 END;"
	}
	return "SELECT CASE WHEN " + trigger + " OR (" +
		"(SELECT foreign_keys FROM pragma_foreign_keys) = 1 AND EXISTS (" +
		"SELECT 1 FROM pragma_foreign_key_list(" + literal + ") " +
		`WHERE "` + fkColumn + `" IN ('CASCADE','SET NULL','SET DEFAULT')))` +
		" THEN 1 ELSE 0 END;"
}

func tableIdentName(table string) string {
	if i := strings.LastIndex(table, "."); i >= 0 {
		table = table[i+1:]
	}
	return strings.Trim(table, `"`)
}

// DecideSQLiteBackup chooses a SQLite backup. L1 never uses row-level CSV:
// bounded single-table DML snapshots the table; everything else that needs a
// backup snapshots the whole database file (always available).
func DecideSQLiteBackup(cls *Classification, opts Options) (BackupPlan, error) {
	if opts.NoBackup {
		return BackupPlan{Kind: BackupNone, Reason: "backups disabled by --no-backup"}, nil
	}
	switch {
	case cls.Class == ClassRead:
		return BackupPlan{Kind: BackupNone, Reason: "read-only statement"}, nil
	case cls.Verb == "INSERT" && !cls.ComplexSource:
		return BackupPlan{Kind: BackupNone, Reason: "INSERT is reversible by deleting the inserted rows"}, nil
	case cls.Class == ClassDDL && !cls.Destructive:
		return BackupPlan{Kind: BackupNone, Reason: "non-destructive DDL/maintenance statement"}, nil
	}
	if cls.Class == ClassDML && cls.HasWhere && !cls.ComplexSource && cls.Table != "" {
		return BackupPlan{Kind: BackupTable, Table: cls.Table,
			Reason: "SQLite snapshots the whole target table before mutation (no row-estimate gate)"}, nil
	}
	return BackupPlan{Kind: BackupFile, Table: cls.Table,
		Reason: "taking a consistent whole-file snapshot with sqlite3 .backup under BEGIN IMMEDIATE"}, nil
}

// RestoreHintFor is the engine-aware restore hint used in JSON results.
func RestoreHintFor(engine string, plan BackupPlan, path string) string {
	switch NormalizeEngine(engine) {
	case EngineSQLite:
		return sqliteRestoreHint(plan, path)
	case EngineMySQL:
		return mysqlRestoreHint(plan, path)
	default:
		return RestoreHint(plan, path)
	}
}

func sqliteRestoreHint(plan BackupPlan, path string) string {
	switch plan.Kind {
	case BackupTable:
		return fmt.Sprintf("restore table data with: sqlite3 <db> \".mode csv\" \".import %s %s\" (reconcile existing rows first)", path, plan.Table)
	case BackupFile:
		return fmt.Sprintf("restore the database file from %s (stop writers, replace the live file plus any leftover -wal/-shm, then reopen)", path)
	default:
		return ""
	}
}

// ParseChangesOutput reads the last integer line emitted by SELECT changes().
func ParseChangesOutput(output string) (int64, bool) {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// ValidateSQLitePath accepts an absolute filesystem path and rejects URI
// forms, relative paths, parent segments, and characters that would break the
// file: URI or the sqlite3 script we generate.
func ValidateSQLitePath(path string) error {
	if path == "" {
		return &BlockedError{Reason: "SQLite database path is required (use --db-file=<absolute-path>)"}
	}
	if len(path) > 4096 {
		return &BlockedError{Reason: "SQLite database path is too long"}
	}
	if strings.ContainsAny(path, "\x00\r\n?#&") {
		return &BlockedError{Reason: "SQLite database path contains unsupported characters"}
	}
	lower := strings.ToLower(path)
	if path == ":memory:" || strings.HasPrefix(lower, "file:") {
		return &BlockedError{Reason: "SQLite URI and in-memory databases are not allowed; pass an absolute file path"}
	}
	if !isAbsoluteSQLitePath(path) {
		return &BlockedError{Reason: "SQLite database path must be absolute"}
	}
	for _, seg := range splitPathSegments(path) {
		if seg == ".." {
			return &BlockedError{Reason: "SQLite database path must not contain .. segments"}
		}
	}
	return nil
}

func isAbsoluteSQLitePath(path string) bool {
	if strings.HasPrefix(path, "/") {
		return true
	}
	if len(path) >= 3 && unicode.IsLetter(rune(path[0])) && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		return true
	}
	return false
}

func splitPathSegments(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
}
