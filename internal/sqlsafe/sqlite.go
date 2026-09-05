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
	argv = append(argv, "-init", "/dev/null")
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
		return protocolFailureCommand()
	}
	p := newProtocol(EngineSQLite, stmt, true, false)
	lines := []string{p.sqlite("start", "1"), statementSQL(stmt)}
	if p.Affected {
		lines = append(lines, "SELECT '"+p.prefix()+"affected|' || changes();")
	}
	lines = append(lines, p.sqlite("commit", "acknowledged"))
	return RemoteCommand{
		Command:  cmd,
		Stdin:    strings.Join(lines, "\n") + "\n",
		Protocol: p,
	}
}

// ExecuteReadCommand opens the file URI in read-only mode so writes fail.
func (c SQLiteConn) ExecuteReadCommand(stmt string) RemoteCommand {
	cmd, err := c.sqliteCommand(true)
	if err != nil {
		return protocolFailureCommand()
	}
	p := newProtocol(EngineSQLite, stmt, false, false)
	return RemoteCommand{
		Command:  cmd,
		Stdin:    p.sqlite("start", "1") + "\n" + statementSQL(stmt) + "\n" + p.sqlite("commit", "acknowledged") + "\n",
		Protocol: p,
	}
}

// ExecuteWithBackupCommand locks the database with BEGIN IMMEDIATE, captures
// a preimage before sending the mutation, and acknowledges only after COMMIT.
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

	p := newProtocol(EngineSQLite, stmt, true, true)
	p.BackupForm = "csv"
	lines := []string{p.sqlite("start", "1"), "BEGIN IMMEDIATE;"}
	switch kind {
	case BackupTable:
		if err := ValidateTableIdent(table); err != nil {
			return RemoteCommand{}, err
		}
		// A table backup must contain the entire table, not merely the rows
		// selected by the mutation. Recheck impact after acquiring the lock.
		guard := "__sshx_guard_" + p.Token
		expression := sqliteRelatedEffectsExpression(table, mutationVerb(stmt))
		literal := "'" + strings.ReplaceAll(tableIdentName(table), "'", "''") + "'"
		lines = append(lines,
			"CREATE TEMP TABLE "+guard+" (unsafe INTEGER CHECK (unsafe=0));",
			"INSERT INTO "+guard+" SELECT CASE WHEN "+expression+
				" OR NOT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name COLLATE NOCASE="+literal+
				" AND upper(sql) NOT LIKE 'CREATE VIRTUAL%') THEN 1 ELSE 0 END;",
			"DROP TABLE "+guard+";",
			p.sqlite("copy", "begin"),
			".headers on",
			".mode csv",
			"SELECT * FROM "+table+";",
			p.sqlite("copy", "end"),
		)
	case BackupFile:
		p.BackupForm = "sqlite_database"
		lines = append(lines, p.sqlite("copy", "begin"), p.sqlite("copy", "end"))
	}
	mutation := ".headers off\n.mode list\n" + statementSQL(stmt) + "\n"
	if p.Affected {
		mutation += "SELECT '" + p.prefix() + "affected|' || changes();\n"
	}
	mutation += "COMMIT;\n" + p.sqlite("commit", "acknowledged") + "\n"
	prelude := strings.Join(lines, "\n") + "\n"
	command := streamLockedBackup(cmd, prelude, mutation, path, p)
	if kind == BackupFile {
		reader, readerErr := c.sqliteCommand(true)
		if readerErr != nil {
			return RemoteCommand{}, readerErr
		}
		command = lockedSQLiteFileBackup(cmd, reader, prelude, mutation, path, p)
	}
	return RemoteCommand{
		Command:  command,
		Protocol: p,
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
	return "SELECT CASE WHEN " + sqliteRelatedEffectsExpression(table, verb) + " THEN 1 ELSE 0 END;"
}

func sqliteRelatedEffectsExpression(table, verb string) string {
	literal := "'" + strings.ReplaceAll(tableIdentName(table), "'", "''") + "'"
	fkColumn := ""
	switch verb {
	case "UPDATE":
		fkColumn = "on_update"
	case "DELETE":
		fkColumn = "on_delete"
	}
	trigger := "EXISTS (SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name COLLATE NOCASE=" + literal + ")"
	if fkColumn == "" {
		return trigger
	}
	return trigger + " OR EXISTS (" +
		"SELECT 1 FROM sqlite_master AS child, pragma_foreign_key_list(child.name) AS fk " +
		`WHERE child.type='table' AND fk."table" COLLATE NOCASE=` + literal +
		` AND fk."` + fkColumn + `" IN ('CASCADE','SET NULL','SET DEFAULT'))`
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
