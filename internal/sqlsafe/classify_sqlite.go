package sqlsafe

import (
	"fmt"
	"strings"
)

// sqliteHardBlockReasons are statement heads that never execute through
// sshx sql --engine=sqlite. ATTACH/DETACH escape the target file; the rest
// match the one-shot / unanalyzable contract used by the PostgreSQL engine.
var sqliteHardBlockReasons = map[string]string{
	"ATTACH":    "ATTACH can open another database file outside the guarded target",
	"DETACH":    "DETACH changes the connection's database set and is never allowed",
	"BEGIN":     "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"START":     "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"COMMIT":    "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"ROLLBACK":  "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"END":       "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"SAVEPOINT": "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"RELEASE":   "transaction control is not supported: sshx sql executes exactly one atomic statement",
}

// sqliteReadPragmas are assignment-free PRAGMA names that only inspect state.
// Unknown names and any PRAGMA assignment are blocked fail-closed.
var sqliteReadPragmas = map[string]bool{
	"COMPILE_OPTIONS":   true,
	"DATABASE_LIST":     true,
	"FOREIGN_KEY_CHECK": true,
	"FOREIGN_KEY_LIST":  true,
	"FREELIST_COUNT":    true,
	"FUNCTION_LIST":     true,
	"INDEX_INFO":        true,
	"INDEX_LIST":        true,
	"INDEX_XINFO":       true,
	"INTEGRITY_CHECK":   true,
	"JOURNAL_MODE":      true,
	"MODULE_LIST":       true,
	"PAGE_COUNT":        true,
	"PAGE_SIZE":         true,
	"PRAGMA_LIST":       true,
	"QUICK_CHECK":       true,
	"SCHEMA_VERSION":    true,
	"TABLE_INFO":        true,
	"TABLE_LIST":        true,
	"TABLE_XINFO":       true,
	"USER_VERSION":      true,
}

var sqliteConflictActions = map[string]bool{
	"ABORT":    true,
	"FAIL":     true,
	"IGNORE":   true,
	"REPLACE":  true,
	"ROLLBACK": true,
}

// ClassifySQLite analyzes sql under the SQLite dialect. It shares the
// fail-closed lexer with Classify but uses a SQLite verb table and blocks
// sqlite3 dot-commands, ATTACH, load_extension, and writable PRAGMA forms.
func ClassifySQLite(sql string) (*Classification, error) {
	stmts, maskedStmts, err := splitStatements(sql)
	if err != nil {
		return nil, &BlockedError{Reason: err.Error()}
	}
	if len(stmts) > 1 {
		return nil, &BlockedError{Reason: fmt.Sprintf("multiple statements are not allowed (%d found); submit exactly one statement per invocation", len(stmts))}
	}

	stmt := stmts[0]
	masked := maskedStmts[0]
	if containsDotCommand(masked) {
		return nil, &BlockedError{Reason: "sqlite3 dot-commands are never allowed"}
	}
	if strings.Contains(string(masked), `\`) {
		return nil, &BlockedError{Reason: "backslash meta-commands are never allowed"}
	}
	if containsKeyword(masked, "LOAD_EXTENSION") {
		return nil, &BlockedError{Reason: "load_extension can execute native code and is never allowed"}
	}

	tokens := topLevelTokens(masked)
	if len(tokens) == 0 {
		return nil, &BlockedError{Reason: "statement contains no SQL tokens"}
	}

	cls := &Classification{Statement: stmt}
	head := tokens[0].upper

	switch head {
	case "SELECT":
		cls.Class = ClassRead
		cls.Verb = head
		return cls, nil
	case "VALUES":
		cls.Class = ClassRead
		cls.Verb = head
		return cls, nil
	case "EXPLAIN":
		if containsKeyword(masked, "ANALYZE", "ANALYSE") { //nolint:misspell // ANALYSE is rejected for parity
			return nil, &BlockedError{Reason: "EXPLAIN ANALYZE executes the statement and is never accepted as a read; use --explain instead"}
		}
		cls.Class = ClassRead
		cls.Verb = head
		return cls, nil
	case "PRAGMA":
		return classifySQLitePragma(cls, tokens)
	case "WITH":
		return classifySQLiteWith(cls, stmt, masked, tokens)
	case "INSERT":
		return classifySQLiteInsert(cls, stmt, tokens)
	case "REPLACE":
		cls.Class = ClassDML
		cls.Verb = "REPLACE"
		cls.ComplexSource = true
		cls.Table = tableAfter(stmt, tokens, 0, "INTO")
		return cls, nil
	case "UPDATE":
		return classifySQLiteUpdate(cls, stmt, tokens)
	case "DELETE":
		return classifyDelete(cls, stmt, tokens, 0)
	case "VACUUM":
		if findKeyword(tokens, 1, "INTO") >= 0 {
			return nil, &BlockedError{Reason: "VACUUM INTO writes another file and is never allowed; sshx takes its own backups"}
		}
		cls.Class = ClassDDL
		cls.Verb = head
		cls.Destructive = true
		return cls, nil
	case "DROP":
		return classifySQLiteDrop(cls, tokens)
	case "ALTER":
		cls.Class = ClassDDL
		cls.Verb = "ALTER"
		if len(tokens) > 1 && tokens[1].upper == "TABLE" {
			cls.Verb = "ALTER TABLE"
			cls.Table = firstTableToken(stmt, tokens, 2)
			cls.Destructive = true
		}
		return cls, nil
	case "CREATE", "REINDEX", "ANALYZE", "ANALYSE": //nolint:misspell // ANALYSE is accepted as an ANALYZE alias
		cls.Class = ClassDDL
		cls.Verb = head
		return cls, nil
	}

	if reason, ok := sqliteHardBlockReasons[head]; ok {
		return nil, &BlockedError{Reason: reason}
	}
	return nil, &BlockedError{Reason: fmt.Sprintf("unrecognized statement head %q (fail-closed)", head)}
}

func classifySQLitePragma(cls *Classification, tokens []token) (*Classification, error) {
	if len(tokens) < 2 {
		return nil, &BlockedError{Reason: "incomplete PRAGMA statement"}
	}
	name := tokens[1].upper
	if name == "LOAD_EXTENSION" {
		return nil, &BlockedError{Reason: "PRAGMA load_extension is never allowed"}
	}
	if findKeyword(tokens, 1, "KEY", "REKEY", "TEXTKEY") >= 0 {
		return nil, &BlockedError{Reason: "SQLCipher key pragmas are never allowed through sshx sql"}
	}
	if pragmaHasAssignment(cls.Statement, tokens) {
		return nil, &BlockedError{Reason: fmt.Sprintf("PRAGMA %s assignment can change database or connection state and is never allowed", name)}
	}
	if !sqliteReadPragmas[name] {
		return nil, &BlockedError{Reason: fmt.Sprintf("PRAGMA %s is not on the read-only allowlist (fail-closed)", name)}
	}
	cls.Class = ClassRead
	cls.Verb = "PRAGMA"
	return cls, nil
}

func pragmaHasAssignment(stmt string, tokens []token) bool {
	if len(tokens) < 2 {
		return false
	}
	start := tokens[1].end
	end := len(stmt)
	if len(tokens) > 2 {
		end = tokens[2].pos
	}
	return strings.Contains(stmt[start:end], "=")
}

func classifySQLiteWith(cls *Classification, stmt string, masked []byte, tokens []token) (*Classification, error) {
	if idx := findKeyword(tokens, 1, "INSERT", "UPDATE", "DELETE", "REPLACE"); idx >= 0 {
		if containsKeyword(masked[:tokens[idx].pos], "INSERT", "UPDATE", "DELETE", "REPLACE") {
			return nil, &BlockedError{Reason: "data-modifying CTE bodies are not supported because their effects cannot be safely backed up"}
		}
		verb := tokens[idx].upper
		switch verb {
		case "UPDATE":
			if _, err := classifySQLiteUpdateFrom(cls, stmt, tokens, idx); err != nil {
				return nil, err
			}
		case "DELETE":
			if _, err := classifyDelete(cls, stmt, tokens, idx); err != nil {
				return nil, err
			}
		case "INSERT":
			if _, err := classifySQLiteInsertFrom(cls, stmt, tokens, idx); err != nil {
				return nil, err
			}
		default:
			cls.Class = ClassDML
			cls.Verb = verb
			cls.Table = tableAfter(stmt, tokens, idx, "INTO")
		}
		cls.ComplexSource = true
		return cls, nil
	}
	if containsKeyword(masked, "INSERT", "UPDATE", "DELETE", "REPLACE") {
		return nil, &BlockedError{Reason: "data-modifying CTE bodies are not supported because their effects cannot be safely backed up"}
	}
	cls.Class = ClassRead
	cls.Verb = "SELECT"
	return cls, nil
}

func classifySQLiteInsert(cls *Classification, stmt string, tokens []token) (*Classification, error) {
	return classifySQLiteInsertFrom(cls, stmt, tokens, 0)
}

func classifySQLiteInsertFrom(cls *Classification, stmt string, tokens []token, at int) (*Classification, error) {
	cls.Class = ClassDML
	cls.Verb = "INSERT"
	body := skipSQLiteConflict(tokens, at)
	cls.Table = tableAfter(stmt, tokens, body-1, "INTO")
	if at+1 < body {
		cls.ComplexSource = true
	}
	if findKeyword(tokens, body, "CONFLICT") >= 0 && findKeyword(tokens, body, "UPDATE") >= 0 {
		cls.ComplexSource = true
	}
	return cls, nil
}

func classifySQLiteUpdate(cls *Classification, stmt string, tokens []token) (*Classification, error) {
	return classifySQLiteUpdateFrom(cls, stmt, tokens, 0)
}

func classifySQLiteUpdateFrom(cls *Classification, stmt string, tokens []token, at int) (*Classification, error) {
	cls.Class = ClassDML
	cls.Verb = "UPDATE"
	body := skipSQLiteConflict(tokens, at)
	cls.Table = firstTableToken(stmt, tokens, body)
	if at+1 < body {
		cls.ComplexSource = true
	}
	if tableIdx := tableTokenIndex(tokens, body); tableIdx >= 0 {
		setIdx := findKeyword(tokens, tableIdx+1, "SET")
		if setIdx > tableIdx+1 {
			cls.ComplexSource = true
		}
	}
	fillWhere(cls, stmt, tokens, at)
	if findKeyword(tokens, body, "FROM") >= 0 {
		cls.ComplexSource = true
	}
	return cls, nil
}

func classifySQLiteDrop(cls *Classification, tokens []token) (*Classification, error) {
	if len(tokens) < 2 {
		return nil, &BlockedError{Reason: "incomplete DROP statement"}
	}
	target := tokens[1].upper
	switch target {
	case "DATABASE", "SCHEMA":
		return nil, &BlockedError{Reason: fmt.Sprintf("DROP %s destroys data beyond a single table and is never allowed through sshx sql", target)}
	case "TABLE":
		cls.Class = ClassDDL
		cls.Verb = "DROP TABLE"
		cls.Destructive = true
		cls.Table = tableAfter(cls.Statement, tokens, 1, "TABLE")
		return cls, nil
	default:
		cls.Class = ClassDDL
		cls.Verb = "DROP " + target
		cls.Destructive = findKeyword(tokens, 2, "CASCADE") >= 0
		return cls, nil
	}
}

// skipSQLiteConflict returns the index after an optional OR <action> clause
// that follows INSERT or UPDATE (INSERT OR REPLACE / UPDATE OR IGNORE).
func skipSQLiteConflict(tokens []token, at int) int {
	i := at + 1
	if i+1 < len(tokens) && tokens[i].upper == "OR" && sqliteConflictActions[tokens[i+1].upper] {
		return i + 2
	}
	return i
}

func containsDotCommand(masked []byte) bool {
	atLineStart := true
	for i := 0; i < len(masked); i++ {
		c := masked[i]
		if c == '\n' || c == '\r' {
			atLineStart = true
			continue
		}
		if atLineStart && (c == ' ' || c == '\t') {
			continue
		}
		if atLineStart && c == '.' {
			return true
		}
		atLineStart = false
	}
	return false
}
