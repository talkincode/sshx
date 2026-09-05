package sqlsafe

import (
	"fmt"
	"strings"
)

var mysqlHardBlockReasons = map[string]string{
	"LOAD":       "LOAD DATA / LOAD XML can read server files and is never allowed",
	"CALL":       "stored procedures can perform arbitrary writes that cannot be analyzed",
	"DELIMITER":  "DELIMITER changes client statement boundaries and is never allowed",
	"DO":         "DO executes expressions that cannot be analyzed",
	"HANDLER":    "HANDLER cursors do not persist across one-shot execution",
	"BEGIN":      "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"START":      "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"COMMIT":     "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"ROLLBACK":   "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"SAVEPOINT":  "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"RELEASE":    "transaction control is not supported: sshx sql executes exactly one atomic statement",
	"XA":         "distributed transactions are out of scope",
	"LOCK":       "explicit locks do not persist across one-shot execution",
	"UNLOCK":     "explicit locks do not persist across one-shot execution",
	"PREPARE":    "prepared statements do not persist across one-shot execution",
	"EXECUTE":    "prepared statements do not persist across one-shot execution",
	"DEALLOCATE": "prepared statements do not persist across one-shot execution",
	"PURGE":      "binary-log administration is out of scope",
	"CHANGE":     "replication administration is out of scope",
	"STOP":       "replication/server administration is out of scope",
	"RESET":      "session or server reset is out of scope",
}

// ClassifyMySQL analyzes sql under the MySQL/MariaDB dialect.
func ClassifyMySQL(sql string) (*Classification, error) {
	if mysqlExecutableComment(sql) {
		return nil, &BlockedError{Reason: "MySQL executable/version comments can hide transaction control or additional writes and are not supported"}
	}
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
		return nil, &BlockedError{Reason: "client backslash meta-commands are never allowed"}
	}
	if containsKeyword(masked, "INTO") && (containsKeyword(masked, "OUTFILE") || containsKeyword(masked, "DUMPFILE")) {
		return nil, &BlockedError{Reason: "SELECT/INTO OUTFILE and DUMPFILE can write server files and are never allowed"}
	}
	if containsKeyword(masked, "LOAD_FILE") {
		return nil, &BlockedError{Reason: "LOAD_FILE can read server files and is never allowed"}
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
			return nil, &BlockedError{Reason: "SELECT INTO creates a table or writes a file and is not a read-only query"}
		}
		cls.Class = ClassRead
		cls.Verb = head
		return cls, nil
	case "TABLE", "VALUES", "SHOW", "DESCRIBE", "DESC", "EXPLAIN":
		if head == "EXPLAIN" && containsKeyword(masked, "ANALYZE") {
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
		if findKeyword(tokens, 1, "DUPLICATE") >= 0 && findKeyword(tokens, 1, "UPDATE") >= 0 {
			cls.ComplexSource = true
		}
		return cls, nil
	case "REPLACE":
		cls.Class = ClassDML
		cls.Verb = head
		cls.ComplexSource = true
		cls.Table = tableAfter(stmt, tokens, 0, "INTO")
		if cls.Table == "" {
			cls.Table = firstTableToken(stmt, tokens, 1)
		}
		return cls, nil
	case "UPDATE":
		return classifyUpdate(cls, stmt, tokens, 0)
	case "DELETE":
		return classifyDelete(cls, stmt, tokens, 0)
	case "TRUNCATE":
		cls.Class = ClassDDL
		cls.Verb = head
		cls.Destructive = true
		cls.Table = truncateTable(stmt, tokens)
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
		}
		return cls, nil
	case "SET":
		if mysqlWritableSet(tokens) {
			return nil, &BlockedError{Reason: "writable SET GLOBAL / SET @@global is never allowed"}
		}
		return nil, &BlockedError{Reason: "session settings do not persist across one-shot execution"}
	case "CREATE":
		if len(tokens) > 1 {
			switch tokens[1].upper {
			case "PROCEDURE", "FUNCTION", "TRIGGER", "EVENT":
				return nil, &BlockedError{Reason: "stored programs cannot be analyzed and are never allowed"}
			}
		}
		cls.Class = ClassDDL
		cls.Verb = head
		return cls, nil
	case "COMMENT", "GRANT", "REVOKE", "RENAME", "ANALYZE", "OPTIMIZE", "REPAIR", "CHECK":
		cls.Class = ClassDDL
		cls.Verb = head
		return cls, nil
	}
	if reason, ok := mysqlHardBlockReasons[head]; ok {
		return nil, &BlockedError{Reason: reason}
	}
	if reason, ok := hardBlockReasons[head]; ok {
		return nil, &BlockedError{Reason: reason}
	}
	return nil, &BlockedError{Reason: fmt.Sprintf("unrecognized statement head %q (fail-closed)", head)}
}

func mysqlExecutableComment(sql string) bool {
	for i := 0; i < len(sql); i++ {
		if sql[i] == '\'' || sql[i] == '"' || sql[i] == '`' {
			quote := sql[i]
			for i++; i < len(sql); i++ {
				if sql[i] == '\\' {
					i++
				} else if sql[i] == quote {
					if i+1 < len(sql) && sql[i+1] == quote {
						i++
					} else {
						break
					}
				}
			}
		} else if sql[i] == '#' || (i+2 < len(sql) && sql[i:i+2] == "--" && sql[i+2] <= ' ') {
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
		} else if i+2 < len(sql) && sql[i:i+2] == "/*" {
			if sql[i+2] == '!' || (i+3 < len(sql) && (sql[i+2] == 'M' || sql[i+2] == 'm') && sql[i+3] == '!') {
				return true
			}
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				break
			}
			i += end + 3
		}
	}
	return false
}

func mysqlWritableSet(tokens []token) bool {
	for _, tok := range tokens {
		if tok.upper == "GLOBAL" {
			return true
		}
		if strings.Contains(tok.upper, "@@GLOBAL") {
			return true
		}
		if tok.upper == "PERSIST" || tok.upper == "PERSIST_ONLY" {
			return true
		}
	}
	return false
}
