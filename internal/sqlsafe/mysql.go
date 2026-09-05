package sqlsafe

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// MySQLConn describes how the remote mysql/mariadb client reaches MySQL.
// Credentials never appear in argv: when PasswordStdin is set, MYSQL_PWD is
// read from the first stdin line. Docker uses env passthrough.
type MySQLConn struct {
	Database      string
	User          string
	Host          string
	Port          string
	PasswordStdin bool
	Docker        string
}

func (c MySQLConn) NeedsPasswordLine() bool { return c.PasswordStdin }

func (c MySQLConn) wrap(cmdline string) string {
	if c.PasswordStdin {
		return "IFS= read -r MYSQL_PWD; export MYSQL_PWD; " + cmdline
	}
	return cmdline
}

func (c MySQLConn) connArgs() []string {
	args := []string{"-D", c.Database}
	if c.User != "" {
		args = append(args, "-u", c.User)
	}
	if c.Host != "" {
		args = append(args, "-h", c.Host)
	}
	if c.Port != "" {
		args = append(args, "-P", c.Port)
	}
	return args
}

func (c MySQLConn) dockerArgv(argv []string) []string {
	if c.Docker == "" {
		return argv
	}
	pre := []string{"docker", "exec", "-i"}
	if c.PasswordStdin {
		pre = append(pre, "-e", "MYSQL_PWD")
	}
	pre = append(pre, c.Docker)
	return append(pre, argv...)
}

func (c MySQLConn) mysqlArgv(extra ...string) []string {
	// Reconnect would silently discard the transaction and its locks.
	argv := []string{"mysql", "--no-defaults", "--batch", "--skip-column-names", "--unbuffered", "--skip-reconnect", "--connect-timeout=10"}
	argv = append(argv, extra...)
	if c.Host != "" {
		argv = append(argv, "--protocol=TCP")
	}
	argv = append(argv, c.connArgs()...)
	return argv
}

func (c MySQLConn) rawClient() string {
	return shellJoin(c.dockerArgv(c.mysqlArgv()))
}

func (c MySQLConn) clientCommand() string {
	return c.wrap(c.rawClient())
}

func (c MySQLConn) ExplainCommand(stmt string) RemoteCommand {
	return RemoteCommand{
		// EXPLAIN returns JSON as one text column. Batch escaping turns its
		// formatting newlines into literal \n, which is not valid JSON.
		Command: c.wrap(shellJoin(c.dockerArgv(c.mysqlArgv("--raw")))),
		Stdin:   "EXPLAIN FORMAT=JSON " + stmt + ";\n",
	}
}

func (c MySQLConn) ExecuteCommand(stmt string) RemoteCommand {
	p := newProtocol(EngineMySQL, stmt, true, false)
	lines := []string{p.mysql("start", "1"), "SET autocommit=1;", statementSQL(stmt)}
	if p.Affected {
		lines = append(lines, "SELECT CONCAT('"+p.prefix()+"affected|', ROW_COUNT());")
	}
	lines = append(lines, p.mysql("commit", "acknowledged"))
	return RemoteCommand{
		Command:  c.clientCommand(),
		Stdin:    strings.Join(lines, "\n") + "\n",
		Protocol: p,
	}
}

func (c MySQLConn) ExecuteReadCommand(stmt string) RemoteCommand {
	p := newProtocol(EngineMySQL, stmt, false, false)
	return RemoteCommand{
		Command:  c.clientCommand(),
		Stdin:    p.mysql("start", "1") + "\nSET SESSION TRANSACTION READ ONLY;\nSTART TRANSACTION READ ONLY;\n" + statementSQL(stmt) + "\nCOMMIT;\n" + p.mysql("commit", "acknowledged") + "\n",
		Protocol: p,
	}
}

func (c MySQLConn) ExecuteWithBackupCommand(stmt, table, where, path string, kind BackupKind) (RemoteCommand, error) {
	if err := ValidateTableIdent(table); err != nil {
		return RemoteCommand{}, err
	}
	if kind != BackupRows && kind != BackupTable {
		return RemoteCommand{}, fmt.Errorf("unsupported mysql backup kind %q", kind)
	}
	if kind == BackupRows && containsNewline(where) {
		return RemoteCommand{}, &BlockedError{Reason: "row backup WHERE clause must be single-line"}
	}
	if kind == BackupRows && !stableBackupPredicate(where) {
		return RemoteCommand{}, unsupportedGuard("mysql", "row preimages require a stable predicate; use a table snapshot")
	}
	if err := ValidateBackupDir(path); err != nil {
		return RemoteCommand{}, err
	}
	cls, err := ClassifyMySQL(stmt)
	if err != nil {
		return RemoteCommand{}, err
	}
	if cls.Class != ClassDML || cls.ComplexSource || (cls.Verb != "UPDATE" && cls.Verb != "DELETE") {
		return RemoteCommand{}, unsupportedGuard("mysql", "only simple single-table UPDATE and DELETE on InnoDB are supported (DDL implicitly commits)")
	}
	masked, maskErr := maskNonCode(stmt)
	if maskErr != nil || containsKeyword(masked, "SELECT", "RETURNING") {
		return RemoteCommand{}, unsupportedGuard("mysql", "subqueries and RETURNING are not supported")
	}
	if strings.ContainsAny(table, ".\"`") || cls.Table != table {
		return RemoteCommand{}, unsupportedGuard("mysql", "the target must be one unqualified plain table in the explicit database")
	}
	p := newProtocol(EngineMySQL, stmt, true, true)
	p.BackupForm = "mysql_hex_rows_v1"
	filter := ""
	if kind == BackupRows && strings.TrimSpace(where) != "" {
		filter = " WHERE " + strings.TrimSpace(where)
	}
	unsupported := "NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='" +
		table + "' AND ENGINE='InnoDB' AND TABLE_TYPE='BASE TABLE') OR " + mysqlRelatedEffectsExpression(table, cls.Verb)
	// LOCK TABLES commits an earlier transaction. Set autocommit=0 first and
	// do NOT START TRANSACTION after locking: that would release the locks.
	// Catalog checks run under the metadata/write lock, not in a prior client.
	lines := []string{
		p.mysql("start", "1"),
		"SET SESSION innodb_table_locks=1;",
		"SET autocommit=0;",
		"LOCK TABLES " + table + " WRITE;",
		"SET @sshx_guard_sql = IF(" + unsupported + ", 'SELECT * FROM information_schema.SSHX_UNSUPPORTED_GUARDED_BACKUP', 'DO 0');",
		"PREPARE sshx_guard FROM @sshx_guard_sql;",
		"EXECUTE sshx_guard;",
		"DEALLOCATE PREPARE sshx_guard;",
		// MySQL permits at most 4096 columns with 64-character names. This
		// bound exceeds the generated expression length even with escaping.
		"SET SESSION group_concat_max_len=16777216;",
		"SELECT GROUP_CONCAT(CONCAT('IF(`', REPLACE(COLUMN_NAME,'`','``'), '` IS NULL,''N'',CONCAT(''H'',HEX(CAST(`', REPLACE(COLUMN_NAME,'`','``'), '` AS BINARY))))') ORDER BY ORDINAL_POSITION SEPARATOR ',') INTO @sshx_columns FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='" + table + "';",
		"SET @sshx_snapshot_sql=CONCAT('SELECT CONCAT_WS(''|'',''R'',', @sshx_columns, ') FROM " + table + "', CONVERT(0x" + hex.EncodeToString([]byte(filter+" ")) + " USING utf8mb4));",
		"PREPARE sshx_snapshot FROM @sshx_snapshot_sql;",
		p.mysql("copy", "begin"),
		"SELECT 'SSHX_MYSQL_HEX_ROWS_V1';",
		"SELECT CONCAT('C|', ORDINAL_POSITION, '|', HEX(COLUMN_NAME), '|', HEX(COLUMN_TYPE)) FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='" + table + "' ORDER BY ORDINAL_POSITION;",
		"EXECUTE sshx_snapshot;",
		p.mysql("copy", "end"),
		"DEALLOCATE PREPARE sshx_snapshot;",
	}
	mutation := statementSQL(stmt) + "\nSELECT CONCAT('" + p.prefix() + "affected|', ROW_COUNT());\nCOMMIT;\n" +
		p.mysql("commit", "acknowledged") + "\nUNLOCK TABLES;\n"
	return RemoteCommand{
		Command:  c.wrap(streamLockedBackup(c.rawClient(), strings.Join(lines, "\n")+"\n", mutation, path, p)),
		Protocol: p,
	}, nil
}

func (c MySQLConn) RelatedEffectsCommand(table, verb string) (RemoteCommand, error) {
	if err := ValidateTableIdent(table); err != nil {
		return RemoteCommand{}, err
	}
	expr := mysqlRelatedEffectsExpression(table, verb)
	return RemoteCommand{
		Command: c.wrap(shellJoin(c.dockerArgv(c.mysqlArgv("-N")))),
		Stdin:   "SELECT CASE WHEN " + expr + " THEN 1 ELSE 0 END;\n",
	}, nil
}

func mysqlRelatedEffectsExpression(table, verb string) string {
	name := strings.ReplaceAll(tableIdentName(table), "'", "''")
	fkCol := ""
	switch verb {
	case "UPDATE":
		fkCol = "UPDATE_RULE"
	case "DELETE", "REPLACE":
		fkCol = "DELETE_RULE"
	}
	trigger := "EXISTS (SELECT 1 FROM information_schema.triggers WHERE EVENT_OBJECT_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='" + name + "')"
	expr := trigger
	if fkCol != "" {
		expr += " OR EXISTS (SELECT 1 FROM information_schema.referential_constraints WHERE UNIQUE_CONSTRAINT_SCHEMA=DATABASE()" +
			" AND REFERENCED_TABLE_NAME='" + name + "' AND " + fkCol + " IN ('CASCADE','SET NULL','SET DEFAULT'))"
	}
	return expr
}

func mysqlRestoreHint(plan BackupPlan, path string) string {
	switch plan.Kind {
	case BackupRows, BackupTable:
		return fmt.Sprintf("reconcile %s using %s (SSHX_MYSQL_HEX_ROWS_V1: C|ordinal|hex-column|hex-type headers; R rows contain | separated N for SQL NULL or H followed by hex-encoded value bytes); this data preimage is not a schema or database dump", plan.Table, path)
	default:
		return ""
	}
}

// ParseMySQLExplainRows extracts a conservative row estimate from EXPLAIN
// FORMAT=JSON. A valid plan without a row estimate (notably INSERT ... VALUES)
// returns -1, nil. Malformed JSON, plan structure, or counters still fail.
func ParseMySQLExplainRows(output string) (int64, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return 0, fmt.Errorf("empty EXPLAIN output")
	}
	var payload any
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		start := strings.Index(trimmed, "{")
		end := strings.LastIndex(trimmed, "}")
		if start < 0 || end <= start {
			return 0, fmt.Errorf("EXPLAIN JSON not found")
		}
		if err := json.Unmarshal([]byte(trimmed[start:end+1]), &payload); err != nil {
			return 0, fmt.Errorf("parse EXPLAIN JSON: %w", err)
		}
	}
	document, ok := payload.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("EXPLAIN JSON must be an object")
	}
	block, ok := document["query_block"].(map[string]any)
	if !ok || len(block) == 0 {
		return 0, fmt.Errorf("EXPLAIN JSON contains no query_block plan")
	}
	return maxJSONNumber(block, "rows", "rows_examined_per_scan", "rows_produced_per_join")
}

func maxJSONNumber(v any, keys ...string) (int64, error) {
	switch n := v.(type) {
	case map[string]any:
		var best int64 = -1
		for k, child := range n {
			for _, want := range keys {
				if strings.EqualFold(k, want) {
					switch num := child.(type) {
					case float64:
						if num < 0 || num >= float64(1<<63) || float64(int64(num)) != num {
							return 0, fmt.Errorf("invalid EXPLAIN row estimate %q", k)
						}
						if int64(num) > best {
							best = int64(num)
						}
					case json.Number:
						parsed, err := num.Int64()
						if err != nil || parsed < 0 {
							return 0, fmt.Errorf("invalid EXPLAIN row estimate %q", k)
						}
						if parsed > best {
							best = parsed
						}
					default:
						return 0, fmt.Errorf("invalid EXPLAIN row estimate %q", k)
					}
				}
			}
			nested, err := maxJSONNumber(child, keys...)
			if err != nil {
				return 0, err
			}
			if nested > best {
				best = nested
			}
		}
		return best, nil
	case []any:
		var best int64 = -1
		for _, child := range n {
			nested, err := maxJSONNumber(child, keys...)
			if err != nil {
				return 0, err
			}
			if nested > best {
				best = nested
			}
		}
		return best, nil
	default:
		return -1, nil
	}
}
