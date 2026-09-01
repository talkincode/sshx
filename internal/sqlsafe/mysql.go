package sqlsafe

import (
	"crypto/sha256"
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
	argv := []string{"mysql", "--batch", "--raw", "--connect-timeout=10"}
	argv = append(argv, extra...)
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
		Command: c.clientCommand(),
		Stdin:   "EXPLAIN FORMAT=JSON " + stmt + ";\n",
	}
}

func (c MySQLConn) ExecuteCommand(stmt string) RemoteCommand {
	return RemoteCommand{
		Command: c.clientCommand(),
		Stdin:   stmt + ";\nSELECT ROW_COUNT();\n",
	}
}

func (c MySQLConn) ExecuteReadCommand(stmt string) RemoteCommand {
	return RemoteCommand{
		Command: c.clientCommand(),
		Stdin:   "SET SESSION TRANSACTION READ ONLY;\nSTART TRANSACTION READ ONLY;\n" + stmt + ";\nCOMMIT;\n",
	}
}

func (c MySQLConn) ExecuteWithBackupCommand(stmt, table, where, path string, kind BackupKind) (RemoteCommand, error) {
	if err := ValidateTableIdent(table); err != nil {
		return RemoteCommand{}, err
	}
	if kind != BackupRows && kind != BackupTable {
		return RemoteCommand{}, fmt.Errorf("unsupported mysql backup kind %q", kind)
	}
	if containsNewline(where) {
		return RemoteCommand{}, &BlockedError{Reason: "row backup WHERE clause must be single-line"}
	}
	filter := ""
	if kind == BackupRows && strings.TrimSpace(where) != "" {
		filter = " WHERE " + strings.TrimSpace(where)
	}
	bak := mysqlBackupTable(path)
	if err := ValidateTableIdent(bak); err != nil {
		return RemoteCommand{}, err
	}
	snapshot := "CREATE TABLE " + bak + " AS SELECT * FROM " + table + filter + ";"
	mutate := stmt + ";\nSELECT ROW_COUNT();"
	body := c.rawClient() + " <<'SSHX_MYSQL_SQL'\n" + snapshot + "\nSSHX_MYSQL_SQL\n" +
		"mysql_status=$?; if [ \"$mysql_status\" -ne 0 ]; then exit \"$mysql_status\"; fi; " +
		c.rawClient() + " -e " + shellQuote("SELECT * FROM "+bak) + " > " + maybeQuote(path) + " || exit $?; " +
		c.rawClient() + " <<'SSHX_MYSQL_SQL'\n" + mutate + "\nSSHX_MYSQL_SQL"
	return RemoteCommand{Command: mkdirPrefix(path) + c.wrap(body), Stdin: ""}, nil
}

func (c MySQLConn) RelatedEffectsCommand(table, verb string) (RemoteCommand, error) {
	if err := ValidateTableIdent(table); err != nil {
		return RemoteCommand{}, err
	}
	name := strings.ReplaceAll(tableIdentName(table), "'", "''")
	db := strings.ReplaceAll(c.Database, "'", "''")
	fkCol := ""
	switch verb {
	case "UPDATE":
		fkCol = "UPDATE_RULE"
	case "DELETE", "REPLACE":
		fkCol = "DELETE_RULE"
	}
	trigger := "EXISTS (SELECT 1 FROM information_schema.triggers WHERE EVENT_OBJECT_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='" + name + "')"
	expr := trigger
	if fkCol != "" && db != "" {
		expr += " OR EXISTS (SELECT 1 FROM information_schema.referential_constraints WHERE CONSTRAINT_SCHEMA='" + db +
			"' AND REFERENCED_TABLE_NAME='" + name + "' AND " + fkCol + " IN ('CASCADE','SET NULL','SET DEFAULT'))"
	}
	return RemoteCommand{
		Command: c.clientCommand(),
		Stdin:   "SELECT CASE WHEN " + expr + " THEN 1 ELSE 0 END;\n",
	}, nil
}

func mysqlBackupTable(path string) string {
	sum := sha256.Sum256([]byte(path))
	return "sshxbak_" + hex.EncodeToString(sum[:8])
}

func mysqlRestoreHint(plan BackupPlan, path string) string {
	bak := mysqlBackupTable(path)
	switch plan.Kind {
	case BackupRows, BackupTable:
		return fmt.Sprintf("restore from snapshot table %s (and CSV %s) into %s after reconciling live rows", bak, path, plan.Table)
	default:
		return ""
	}
}

// ParseMySQLExplainRows extracts a conservative row estimate from EXPLAIN FORMAT=JSON.
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
	rows := maxJSONNumber(payload, "rows", "query_cost")
	if rows < 0 {
		return 0, nil
	}
	return rows, nil
}

func maxJSONNumber(v any, keys ...string) int64 {
	switch n := v.(type) {
	case map[string]any:
		var best int64 = -1
		for k, child := range n {
			for _, want := range keys {
				if strings.EqualFold(k, want) {
					switch num := child.(type) {
					case float64:
						if int64(num) > best {
							best = int64(num)
						}
					case json.Number:
						if parsed, err := num.Int64(); err == nil && parsed > best {
							best = parsed
						}
					}
				}
			}
			if nested := maxJSONNumber(child, keys...); nested > best {
				best = nested
			}
		}
		return best
	case []any:
		var best int64 = -1
		for _, child := range n {
			if nested := maxJSONNumber(child, keys...); nested > best {
				best = nested
			}
		}
		return best
	default:
		return -1
	}
}
