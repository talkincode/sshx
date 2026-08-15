package sqlsafe

import (
	"fmt"
	"strings"
)

// Class is the coarse risk class of one SQL statement.
type Class string

const (
	// ClassRead statements never mutate data (SELECT, SHOW, EXPLAIN, ...).
	ClassRead Class = "read"
	// ClassDML statements mutate rows (INSERT, UPDATE, DELETE, MERGE).
	ClassDML Class = "dml"
	// ClassDDL statements mutate schema or run privileged maintenance and
	// always require --force.
	ClassDDL Class = "ddl"
	// ClassBlocked statements are never executed by sshx sql.
	ClassBlocked Class = "blocked"
)

// BlockedError wraps every classification/policy rejection so callers can map
// it to the stable "blocked" error kind.
type BlockedError struct {
	Reason string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("SQL statement blocked: %s", e.Reason)
}

// Classification is the fail-closed analysis of exactly one SQL statement.
type Classification struct {
	// Statement is the single trimmed statement without a trailing semicolon.
	Statement string `json:"statement"`
	Class     Class  `json:"class"`
	Verb      string `json:"verb"`
	// Table is the primary target table (DML and destructive DDL). Empty when
	// not applicable or not extractable.
	Table string `json:"table,omitempty"`
	// HasWhere reports a top-level WHERE clause (UPDATE/DELETE).
	HasWhere bool `json:"has_where"`
	// WhereClause is the original text of the top-level WHERE condition
	// (excluding the WHERE keyword and any trailing RETURNING clause).
	WhereClause string `json:"-"`
	// ComplexSource marks UPDATE ... FROM, DELETE ... USING, MERGE, and
	// CTE-wrapped DML whose affected row set cannot be reproduced by a simple
	// SELECT; these always take a table-level backup.
	ComplexSource bool `json:"complex_source,omitempty"`
	// Destructive marks DDL that destroys data (DROP TABLE, TRUNCATE) and
	// therefore requires a table backup in addition to --force.
	Destructive bool `json:"destructive,omitempty"`
	// MayAffectRelated marks syntax such as TRUNCATE ... CASCADE whose effects
	// are known to extend beyond the primary target table.
	MayAffectRelated bool `json:"may_affect_related,omitempty"`
}

// hard blocks that no flag can override: statements that destroy whole
// databases, escape into arbitrary code, or bypass analysis entirely.
var hardBlockReasons = map[string]string{
	"DO":         "DO blocks execute arbitrary code that cannot be analyzed",
	"COPY":       "COPY can read/write server files or run programs; use \\copy workflows outside sshx sql",
	"BEGIN":      "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"START":      "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"COMMIT":     "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"ROLLBACK":   "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"END":        "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"SET":        "session settings do not persist across one-shot execution",
	"RESET":      "session settings do not persist across one-shot execution",
	"PREPARE":    "prepared statements do not persist across one-shot execution",
	"EXECUTE":    "prepared statements do not persist across one-shot execution",
	"DEALLOCATE": "prepared statements do not persist across one-shot execution",
	"LISTEN":     "asynchronous notification does not fit one-shot execution",
	"UNLISTEN":   "asynchronous notification does not fit one-shot execution",
	"NOTIFY":     "asynchronous notification does not fit one-shot execution",
	"LOCK":       "explicit locks do not persist across one-shot execution",
	"DECLARE":    "cursors do not persist across one-shot execution",
	"FETCH":      "cursors do not persist across one-shot execution",
	"MOVE":       "cursors do not persist across one-shot execution",
	"CLOSE":      "cursors do not persist across one-shot execution",
	"CHECKPOINT": "server administration statements are out of scope",
	"LOAD":       "server administration statements are out of scope",
	"SECURITY":   "security label management is out of scope",
	"IMPORT":     "foreign schema import is out of scope",
	"CALL":       "stored procedures can perform arbitrary writes that cannot be analyzed",
}

// Classify analyzes sql and returns the classification of the single
// statement it contains. It is fail-closed: multiple statements, lexing
// errors, and unrecognized statement heads are all rejected.
func Classify(sql string) (*Classification, error) {
	stmts, maskedStmts, err := splitStatements(sql)
	if err != nil {
		return nil, &BlockedError{Reason: err.Error()}
	}
	if len(stmts) > 1 {
		return nil, &BlockedError{Reason: fmt.Sprintf("multiple statements are not allowed (%d found); submit exactly one statement per invocation", len(stmts))}
	}

	stmt := stmts[0]
	masked := maskedStmts[0]
	if strings.Contains(string(masked), `\`) {
		return nil, &BlockedError{Reason: "psql backslash meta-commands are never allowed"}
	}
	if containsKeyword(masked, "DBLINK", "DBLINK_EXEC", "DBLINK_CONNECT", "DBLINK_SEND_QUERY") {
		return nil, &BlockedError{Reason: "dblink functions can mutate another database outside the guarded transaction"}
	}
	tokens := topLevelTokens(masked)
	if len(tokens) == 0 {
		return nil, &BlockedError{Reason: "statement contains no SQL tokens"}
	}

	cls := &Classification{Statement: stmt}
	head := tokens[0].upper

	switch head {
	case "SELECT":
		if findKeyword(tokens, 1, "INTO") >= 0 {
			return nil, &BlockedError{Reason: "SELECT INTO creates a table and is not a read-only query"}
		}
		cls.Class = ClassRead
		cls.Verb = head
		return cls, nil
	case "TABLE", "VALUES", "SHOW":
		cls.Class = ClassRead
		cls.Verb = head
		return cls, nil
	case "EXPLAIN":
		if containsKeyword(masked, "ANALYZE", "ANALYSE") { //nolint:misspell // ANALYSE is PostgreSQL's alias
			return nil, &BlockedError{Reason: "EXPLAIN ANALYZE executes the statement and is never accepted as a read; use --explain instead"}
		}
		cls.Class = ClassRead
		cls.Verb = head
		return cls, nil
	case "WITH":
		return classifyWith(cls, stmt, masked, tokens)
	case "INSERT":
		cls.Class = ClassDML
		cls.Verb = head
		cls.Table = tableAfter(stmt, tokens, 0, "INTO")
		if conflict := findKeyword(tokens, 1, "CONFLICT"); conflict >= 0 &&
			findKeyword(tokens, conflict+1, "UPDATE") >= 0 {
			cls.ComplexSource = true
		}
		return cls, nil
	case "UPDATE":
		return classifyUpdate(cls, stmt, tokens, 0)
	case "DELETE":
		return classifyDelete(cls, stmt, tokens, 0)
	case "MERGE":
		cls.Class = ClassDML
		cls.Verb = head
		cls.ComplexSource = true
		cls.Table = tableAfter(stmt, tokens, 0, "INTO")
		return cls, nil
	case "TRUNCATE":
		cls.Class = ClassDDL
		cls.Verb = head
		cls.Destructive = true
		cls.Table = truncateTable(stmt, tokens)
		cls.MayAffectRelated = findKeyword(tokens, 1, "CASCADE") >= 0
		return cls, nil
	case "DROP":
		return classifyDrop(cls, tokens)
	case "ALTER":
		if len(tokens) > 1 && tokens[1].upper == "SYSTEM" {
			return nil, &BlockedError{Reason: "ALTER SYSTEM rewrites server configuration and is never allowed"}
		}
		cls.Class = ClassDDL
		cls.Verb = "ALTER"
		if len(tokens) > 1 && tokens[1].upper == "TABLE" {
			cls.Verb = "ALTER TABLE"
			cls.Table = firstTableToken(stmt, tokens, 2)
			cls.Destructive = true
			cls.MayAffectRelated = findKeyword(tokens, 2, "CASCADE") >= 0
		}
		return cls, nil
	case "REFRESH":
		cls.Class = ClassDDL
		cls.Verb = head
		if findKeyword(tokens, 1, "MATERIALIZED") >= 0 && findKeyword(tokens, 1, "VIEW") >= 0 {
			cls.Verb = "REFRESH MATERIALIZED VIEW"
			cls.Destructive = true
			cls.Table = tableAfter(cls.Statement, tokens, 1, "VIEW")
		}
		return cls, nil
	case "CREATE", "COMMENT", "GRANT", "REVOKE", "REINDEX", "VACUUM",
		"ANALYZE", "ANALYSE", "CLUSTER", "REASSIGN": //nolint:misspell // ANALYSE is PostgreSQL's documented alias for ANALYZE
		cls.Class = ClassDDL
		cls.Verb = head
		return cls, nil
	}

	if reason, ok := hardBlockReasons[head]; ok {
		return nil, &BlockedError{Reason: reason}
	}
	return nil, &BlockedError{Reason: fmt.Sprintf("unrecognized statement head %q (fail-closed)", head)}
}

// classifyWith resolves CTE-wrapped statements. A WITH statement is a read
// unless a top-level data-modifying verb appears after the CTE list.
func classifyWith(cls *Classification, stmt string, masked []byte, tokens []token) (*Classification, error) {
	if idx := findKeyword(tokens, 1, "INSERT", "UPDATE", "DELETE", "MERGE"); idx >= 0 {
		if containsKeyword(masked[:tokens[idx].pos], "INSERT", "UPDATE", "DELETE", "MERGE") {
			return nil, &BlockedError{Reason: "data-modifying CTE bodies are not supported because their effects cannot be safely backed up"}
		}
		verb := tokens[idx].upper
		cls.ComplexSource = true
		switch verb {
		case "UPDATE":
			if _, err := classifyUpdate(cls, stmt, tokens, idx); err != nil {
				return nil, err
			}
		case "DELETE":
			if _, err := classifyDelete(cls, stmt, tokens, idx); err != nil {
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
	if containsKeyword(masked, "INSERT", "UPDATE", "DELETE", "MERGE") {
		return nil, &BlockedError{Reason: "data-modifying CTE bodies are not supported because their effects cannot be safely backed up"}
	}
	cls.Class = ClassRead
	cls.Verb = "SELECT"
	return cls, nil
}

func classifyUpdate(cls *Classification, stmt string, tokens []token, at int) (*Classification, error) {
	cls.Class = ClassDML
	cls.Verb = "UPDATE"
	cls.Table = firstTableToken(stmt, tokens, at+1)
	if tableIdx := tableTokenIndex(tokens, at+1); tableIdx >= 0 {
		setIdx := findKeyword(tokens, tableIdx+1, "SET")
		if setIdx > tableIdx+1 {
			cls.ComplexSource = true
		}
	}
	fillWhere(cls, stmt, tokens, at)
	if findKeyword(tokens, at+1, "FROM") >= 0 {
		cls.ComplexSource = true
	}
	return cls, nil
}

func classifyDelete(cls *Classification, stmt string, tokens []token, at int) (*Classification, error) {
	cls.Class = ClassDML
	cls.Verb = "DELETE"
	cls.Table = tableAfter(stmt, tokens, at, "FROM")
	if fromIdx := findKeyword(tokens, at, "FROM"); fromIdx >= 0 {
		if tableIdx := tableTokenIndex(tokens, fromIdx+1); tableIdx >= 0 {
			end := len(tokens)
			if clauseIdx := findKeyword(tokens, tableIdx+1, "WHERE", "USING", "RETURNING"); clauseIdx >= 0 {
				end = clauseIdx
			}
			if end > tableIdx+1 {
				cls.ComplexSource = true
			}
		}
	}
	fillWhere(cls, stmt, tokens, at)
	if findKeyword(tokens, at+1, "USING") >= 0 {
		cls.ComplexSource = true
	}
	return cls, nil
}

func classifyDrop(cls *Classification, tokens []token) (*Classification, error) {
	if len(tokens) < 2 {
		return nil, &BlockedError{Reason: "incomplete DROP statement"}
	}
	target := tokens[1].upper
	switch target {
	case "DATABASE", "TABLESPACE", "OWNED", "SCHEMA":
		return nil, &BlockedError{Reason: fmt.Sprintf("DROP %s destroys data beyond a single table and is never allowed through sshx sql", target)}
	case "TABLE":
		cls.Class = ClassDDL
		cls.Verb = "DROP TABLE"
		cls.Destructive = true
		cls.Table = tableAfter(cls.Statement, tokens, 1, "TABLE")
		cls.MayAffectRelated = findKeyword(tokens, 2, "CASCADE") >= 0
		return cls, nil
	case "MATERIALIZED":
		if len(tokens) < 3 || tokens[2].upper != "VIEW" {
			return nil, &BlockedError{Reason: "unsupported DROP MATERIALIZED form"}
		}
		cls.Class = ClassDDL
		cls.Verb = "DROP MATERIALIZED VIEW"
		cls.Destructive = true
		cls.Table = tableAfter(cls.Statement, tokens, 2, "VIEW")
		cls.MayAffectRelated = findKeyword(tokens, 3, "CASCADE") >= 0
		return cls, nil
	default:
		cls.Class = ClassDDL
		cls.Verb = "DROP " + target
		cls.Destructive = findKeyword(tokens, 2, "CASCADE") >= 0
		return cls, nil
	}
}

// fillWhere locates the top-level WHERE clause after tokens[at] and records
// both its presence and its original text (up to a top-level RETURNING).
func fillWhere(cls *Classification, stmt string, tokens []token, at int) {
	whereIdx := findKeyword(tokens, at+1, "WHERE")
	if whereIdx < 0 {
		return
	}
	cls.HasWhere = true
	start := tokens[whereIdx].end
	end := len(stmt)
	if retIdx := findKeyword(tokens, whereIdx+1, "RETURNING"); retIdx >= 0 {
		end = tokens[retIdx].pos
	}
	cls.WhereClause = strings.TrimSpace(stmt[start:end])
}

// tableAfter returns the original text of the table token that follows the
// given keyword (searched from index from), skipping ONLY / IF / EXISTS
// noise words. Empty when not found.
func tableAfter(stmt string, tokens []token, from int, keyword string) string {
	idx := findKeyword(tokens, from, keyword)
	if idx < 0 {
		return ""
	}
	return firstTableToken(stmt, tokens, idx+1)
}

func firstTableToken(stmt string, tokens []token, from int) string {
	idx := tableTokenIndex(tokens, from)
	if idx < 0 {
		return ""
	}
	return stmt[tokens[idx].pos:tokens[idx].end]
}

func tableTokenIndex(tokens []token, from int) int {
	for i := from; i < len(tokens); i++ {
		switch tokens[i].upper {
		case "ONLY", "IF", "EXISTS", "TABLE":
			continue
		}
		return i
	}
	return -1
}

// truncateTable extracts the single target of a TRUNCATE statement. Multiple
// tables yield an empty result (forcing the fail-closed backup path to error).
func truncateTable(stmt string, tokens []token) string {
	table := ""
	for i := 1; i < len(tokens); i++ {
		switch tokens[i].upper {
		case "TABLE", "ONLY":
			continue
		case "RESTART", "CONTINUE", "CASCADE", "RESTRICT", "IDENTITY":
			return table
		}
		if table != "" {
			return "" // multiple tables: not representable as one backup target
		}
		table = stmt[tokens[i].pos:tokens[i].end]
	}
	return table
}
