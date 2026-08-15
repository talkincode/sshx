package sqlsafe

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// DefaultBackupDir is where remote backups land, relative to the SSH user's
// home directory (the working directory of a fresh SSH exec session).
const DefaultBackupDir = ".sshx/sql-backups"

// Conn describes how the remote psql process reaches PostgreSQL on
// the target host. Credentials are never placed in argv: when PasswordStdin
// is set, the generated command reads PGPASSWORD from the first stdin line.
// When Docker is set, the database clients run inside the container via
// `docker exec -i` (the password crosses only via env passthrough, not argv).
type Conn struct {
	Database      string
	User          string // database role, not the SSH user
	Host          string // database host as seen from the remote machine
	Port          string
	PasswordStdin bool
	Docker        string // container name/ID; empty = clients run on the host
}

// RemoteCommand is one fully assembled remote invocation: the shell command
// for the SSH exec channel plus the stdin payload (SQL text or psql
// meta-commands). The caller prepends the password line when needed.
type RemoteCommand struct {
	Command string
	Stdin   string
}

// NeedsPasswordLine reports whether the command expects a leading PGPASSWORD
// line on stdin before the payload.
func (c Conn) NeedsPasswordLine() bool { return c.PasswordStdin }

// wrap prefixes the credential reader when a password is delivered via stdin.
// The secret never appears in the command line, so it is invisible to remote
// `ps` and to the sshx audit trail.
func (c Conn) wrap(cmdline string) string {
	if c.PasswordStdin {
		return "IFS= read -r PGPASSWORD; export PGPASSWORD; " + cmdline
	}
	return cmdline
}

func (c Conn) connArgs() []string {
	args := []string{"-d", c.Database}
	if c.User != "" {
		args = append(args, "-U", c.User)
	}
	if c.Host != "" {
		args = append(args, "-h", c.Host)
	}
	if c.Port != "" {
		args = append(args, "-p", c.Port)
	}
	return args
}

// dockerArgv wraps a client argv with `docker exec -i <container>` when the
// clients live inside a container. `-e PGPASSWORD` (no value) forwards the
// variable exported by wrap() from the host shell environment into the
// container without ever putting the secret into argv.
func (c Conn) dockerArgv(argv []string) []string {
	if c.Docker == "" {
		return argv
	}
	pre := []string{"docker", "exec", "-i"}
	if c.PasswordStdin {
		pre = append(pre, "-e", "PGPASSWORD")
	}
	pre = append(pre, c.Docker)
	return append(pre, argv...)
}

// psqlArgv builds the psql argument vector. -X skips psqlrc, -w never prompts
// (PGPASSWORD or local auth must succeed), ON_ERROR_STOP makes psql exit
// non-zero on the first SQL error.
func (c Conn) psqlArgv(extra ...string) []string {
	argv := []string{"psql", "-X", "-w", "-v", "ON_ERROR_STOP=1"}
	argv = append(argv, extra...)
	argv = append(argv, c.connArgs()...)
	return argv
}

// ExplainCommand runs EXPLAIN (FORMAT JSON) for stmt and prints the bare JSON
// plan (-q -A -t) so the row estimate can be parsed deterministically.
func (c Conn) ExplainCommand(stmt string) RemoteCommand {
	return RemoteCommand{
		Command: c.wrap(shellJoin(c.dockerArgv(c.psqlArgv("-q", "-A", "-t")))),
		Stdin:   "EXPLAIN (FORMAT JSON) " + stmt + ";\n",
	}
}

// ExecuteCommand runs the statement itself. Command tags (e.g. "UPDATE 3")
// stay on stdout so the affected row count can be parsed afterwards.
func (c Conn) ExecuteCommand(stmt string) RemoteCommand {
	return RemoteCommand{
		Command: c.wrap(shellJoin(c.dockerArgv(c.psqlArgv()))),
		Stdin:   stmt + ";\n",
	}
}

// ExecuteReadCommand enforces PostgreSQL's transaction-level read-only mode so
// SELECT-invoked functions cannot mutate persistent database state.
func (c Conn) ExecuteReadCommand(stmt string) RemoteCommand {
	return RemoteCommand{
		Command: c.wrap(shellJoin(c.dockerArgv(c.psqlArgv()))),
		Stdin:   "BEGIN TRANSACTION READ ONLY;\n" + stmt + ";\nCOMMIT;\n",
	}
}

// ExecuteWithBackupCommand locks the target against concurrent writers,
// snapshots its preimage, and executes the mutation in one PostgreSQL
// transaction. A failed mutation rolls back while the already-written CSV
// remains available for diagnosis or restore.
func (c Conn) ExecuteWithBackupCommand(stmt, table, where, path string, kind BackupKind) (RemoteCommand, error) {
	if err := ValidateTableIdent(table); err != nil {
		return RemoteCommand{}, err
	}
	if kind != BackupRows && kind != BackupTable {
		return RemoteCommand{}, fmt.Errorf("unsupported transactional backup kind %q", kind)
	}
	if containsNewline(where) {
		return RemoteCommand{}, &BlockedError{Reason: "row backup WHERE clause must be single-line"}
	}
	filter := ""
	if kind == BackupRows && strings.TrimSpace(where) != "" {
		filter = " WHERE " + strings.TrimSpace(where)
	}
	lines := []string{
		"BEGIN;",
		"LOCK TABLE " + table + " IN SHARE ROW EXCLUSIVE MODE;",
		"SELECT 1 / (CASE WHEN " + relatedEffectsExpression(table, mutationVerb(stmt)) + " THEN 0 ELSE 1 END);",
	}
	if c.Docker == "" {
		lines = append(lines, fmt.Sprintf(
			"\\copy (SELECT * FROM %s%s) TO '%s' WITH (FORMAT csv, HEADER true, FORCE_QUOTE *)",
			table, filter, psqlString(path)))
		lines = append(lines, stmt+";", "COMMIT;")
		return RemoteCommand{
			Command: c.wrap(mkdirPrefix(path) + shellJoin(c.psqlArgv())),
			Stdin:   strings.Join(lines, "\n") + "\n",
		}, nil
	}

	sum := sha256.Sum256([]byte(path))
	token := hex.EncodeToString(sum[:8])
	startMarker := "__SSHX_BACKUP_BEGIN_" + token + "__"
	endMarker := "__SSHX_BACKUP_END_" + token + "__"
	lines = append(lines,
		"\\echo "+startMarker,
		fmt.Sprintf("COPY (SELECT * FROM %s%s) TO STDOUT WITH (FORMAT csv, HEADER true, FORCE_QUOTE *);", table, filter),
		"\\echo "+endMarker,
	)
	prelude := strings.Join(lines, "\n") + "\n"
	mutation := stmt + ";\nCOMMIT;\n"
	inputFIFO := path + ".stdin"
	outputFIFO := path + ".stdout"
	psqlCommand := shellJoin(c.dockerArgv(c.psqlArgv("-q")))
	command := mkdirPrefix(path) +
		"rm -f " + maybeQuote(inputFIFO) + " " + maybeQuote(outputFIFO) + "; " +
		"mkfifo " + maybeQuote(inputFIFO) + " " + maybeQuote(outputFIFO) + " || exit $?; " +
		"cleanup_sqlx_fifos() { rm -f " + maybeQuote(inputFIFO) + " " + maybeQuote(outputFIFO) + "; }; " +
		"trap cleanup_sqlx_fifos EXIT HUP INT TERM; " +
		psqlCommand + " < " + maybeQuote(inputFIFO) + " > " + maybeQuote(outputFIFO) + " & psql_pid=$!; " +
		"exec 3> " + maybeQuote(inputFIFO) + "; exec 4< " + maybeQuote(outputFIFO) + "; " +
		"exec 5> " + maybeQuote(path) + " || { exec 3>&-; cat <&4 >/dev/null; wait \"$psql_pid\"; exit 1; }; " +
		"printf '%s' " + shellQuote(prelude) + " >&3 || { exec 5>&-; exec 3>&-; cat <&4 >/dev/null; wait \"$psql_pid\"; exit 1; }; " +
		"copying=0; end_seen=0; backup_failed=0; " +
		"while IFS= read -r line <&4; do " +
		"if [ \"$line\" = " + shellQuote(startMarker) + " ]; then copying=1; " +
		"elif [ \"$line\" = " + shellQuote(endMarker) + " ]; then end_seen=1; break; " +
		"elif [ \"$copying\" -eq 1 ]; then printf '%s\\n' \"$line\" >&5 || backup_failed=1; " +
		"else printf '%s\\n' \"$line\"; fi; done; exec 5>&-; " +
		"if [ \"$backup_failed\" -ne 0 ] || [ \"$end_seen\" -ne 1 ]; then " +
		"exec 3>&-; cat <&4 >/dev/null; wait \"$psql_pid\"; exit 1; fi; " +
		"printf '%s' " + shellQuote(mutation) + " >&3 || { exec 3>&-; cat <&4 >/dev/null; wait \"$psql_pid\"; exit 1; }; " +
		"exec 3>&-; cat <&4; output_status=$?; wait \"$psql_pid\"; psql_status=$?; " +
		"if [ \"$psql_status\" -ne 0 ]; then exit \"$psql_status\"; fi; exit \"$output_status\""
	return RemoteCommand{
		Command: c.wrap(command),
		Stdin:   "",
	}, nil
}

func psqlString(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func mutationVerb(stmt string) string {
	masked, err := maskNonCode(stmt)
	if err != nil {
		return ""
	}
	tokens := topLevelTokens(masked)
	if len(tokens) == 0 {
		return ""
	}
	if tokens[0].upper == "WITH" {
		if idx := findKeyword(tokens, 1, "INSERT", "UPDATE", "DELETE", "MERGE"); idx >= 0 {
			return tokens[idx].upper
		}
	}
	return tokens[0].upper
}

// RelatedEffectsCommand checks whether a mutation can invoke user triggers or
// cascading referential actions outside its direct target table.
func (c Conn) RelatedEffectsCommand(table, verb string) (RemoteCommand, error) {
	if err := ValidateTableIdent(table); err != nil {
		return RemoteCommand{}, err
	}
	expression := relatedEffectsExpression(table, verb)
	stmt := "SELECT CASE WHEN " + expression + " THEN 1 ELSE 0 END;"
	return RemoteCommand{
		Command: c.wrap(shellJoin(c.dockerArgv(c.psqlArgv("-q", "-A", "-t")))),
		Stdin:   stmt + "\n",
	}, nil
}

func relatedEffectsExpression(table, verb string) string {
	regclass := strings.ReplaceAll(table, "'", "''")
	constraintPredicate := "FALSE"
	switch verb {
	case "UPDATE":
		constraintPredicate = "confupdtype IN ('c','n','d')"
	case "DELETE":
		constraintPredicate = "confdeltype IN ('c','n','d')"
	case "MERGE":
		constraintPredicate = "(confupdtype IN ('c','n','d') OR confdeltype IN ('c','n','d'))"
	case "TRUNCATE":
		constraintPredicate = "TRUE"
	}
	return fmt.Sprintf(`EXISTS (
  SELECT 1 FROM pg_catalog.pg_trigger
  WHERE tgrelid = '%s'::regclass AND NOT tgisinternal AND tgenabled <> 'D'
) OR EXISTS (
  SELECT 1 FROM pg_catalog.pg_constraint
  WHERE confrelid = '%s'::regclass AND contype = 'f' AND %s
) OR EXISTS (
  SELECT 1 FROM pg_catalog.pg_rewrite
  WHERE ev_class = '%s'::regclass AND rulename <> '_RETURN'
) OR EXISTS (
  SELECT 1 FROM pg_catalog.pg_inherits
  WHERE inhparent = '%s'::regclass
) OR EXISTS (
  SELECT 1 FROM pg_catalog.pg_class
  WHERE oid = '%s'::regclass AND relkind <> 'r'
)`, regclass, regclass, constraintPredicate, regclass, regclass, regclass)
}

func mkdirPrefix(path string) string {
	if idx := strings.LastIndex(path, "/"); idx > 0 {
		dir := maybeQuote(path[:idx])
		return "umask 077; mkdir -p " + dir + " && chmod 700 " + dir + " && "
	}
	return "umask 077; "
}

func maybeQuote(s string) string {
	if safeArgRE.MatchString(s) {
		return s
	}
	return shellQuote(s)
}

// BackupPath builds a unique remote backup file path under dir (default
// DefaultBackupDir, relative to the SSH user's home). The generated path only
// contains shell- and \copy-safe bytes.
func BackupPath(dir, database, table string, kind BackupKind) string {
	if dir == "" {
		dir = DefaultBackupDir
	}
	ext := ".sql"
	if kind == BackupRows || kind == BackupTable {
		ext = ".csv"
	}
	var suffix [4]byte
	token := "0000"
	if _, err := rand.Read(suffix[:]); err == nil {
		token = hex.EncodeToString(suffix[:])
	}
	name := fmt.Sprintf("%s-%s-%s-%s%s",
		sanitizePathComponent(database), sanitizePathComponent(table),
		time.Now().UTC().Format("20060102T150405Z"), token, ext)
	return strings.TrimRight(dir, "/") + "/" + name
}

func sanitizePathComponent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

var tableIdentRE = regexp.MustCompile(`^(?:"[^"';\\]+"|[A-Za-z_][A-Za-z0-9_$]*)(?:\.(?:"[^"';\\]+"|[A-Za-z_][A-Za-z0-9_$]*))?$`)

// ValidateTableIdent accepts plain or quoted, optionally schema-qualified
// table identifiers and rejects anything that could break out of the SQL or
// psql meta-command context the name is embedded into. Fail-closed.
func ValidateTableIdent(table string) error {
	if !tableIdentRE.MatchString(table) {
		return &BlockedError{Reason: fmt.Sprintf("table identifier %q is not a safe plain or quoted identifier", table)}
	}
	return nil
}

// ValidateDatabaseName bounds the database name used in argv and paths.
var databaseNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func ValidateDatabaseName(name string) error {
	if !databaseNameRE.MatchString(name) {
		return &BlockedError{Reason: fmt.Sprintf("database name %q contains unsupported characters", name)}
	}
	return nil
}

// ValidateBackupDir rejects control characters that could escape psql
// meta-command or shell line boundaries.
func ValidateBackupDir(dir string) error {
	if len(dir) > 4096 {
		return &BlockedError{Reason: "backup directory path is too long"}
	}
	if strings.ContainsAny(dir, "\x00\r\n") {
		return &BlockedError{Reason: "backup directory path contains unsupported control characters"}
	}
	return nil
}

// shellQuote single-quotes s for POSIX shells.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellJoin quotes every argv element that needs it and joins with spaces.
func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = maybeQuote(a)
	}
	return strings.Join(parts, " ")
}

var safeArgRE = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// ParseExplainRows extracts the top-level plan row estimate from
// EXPLAIN (FORMAT JSON) output.
func ParseExplainRows(output string) (int64, error) {
	start := strings.Index(output, "[")
	if start < 0 {
		return 0, fmt.Errorf("no JSON plan found in EXPLAIN output")
	}
	var plans []struct {
		Plan map[string]any `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(output[start:]), &plans); err != nil {
		return 0, fmt.Errorf("failed to parse EXPLAIN JSON: %w", err)
	}
	if len(plans) == 0 || plans[0].Plan == nil {
		return 0, fmt.Errorf("EXPLAIN JSON contains no plan")
	}
	rows, ok := plans[0].Plan["Plan Rows"].(float64)
	if !ok {
		return 0, fmt.Errorf("EXPLAIN plan has no Plan Rows estimate")
	}
	return int64(rows), nil
}

var commandTagRE = regexp.MustCompile(`^(INSERT \d+ (\d+)|(UPDATE|DELETE|MERGE|COPY|SELECT) (\d+))\s*$`)

// ParseCommandTag scans psql output (last line first) for a DML command tag
// and returns the affected/copied row count.
func ParseCommandTag(output string) (rows int64, ok bool) {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		m := commandTagRE.FindStringSubmatch(strings.TrimSpace(lines[i]))
		if m == nil {
			continue
		}
		count := m[2]
		if count == "" {
			count = m[4]
		}
		var n int64
		if _, err := fmt.Sscanf(count, "%d", &n); err == nil {
			return n, true
		}
	}
	return 0, false
}

// ParseBooleanOutput parses the terse 0/1 result emitted by catalog preflight
// queries.
func ParseBooleanOutput(output string) (bool, error) {
	switch strings.TrimSpace(output) {
	case "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, fmt.Errorf("expected catalog preflight result 0 or 1")
	}
}

// RestoreHint documents how to restore from the backup artifact.
func RestoreHint(plan BackupPlan, path string) string {
	switch plan.Kind {
	case BackupRows:
		return fmt.Sprintf("restore rows with: psql -d <db> -c \"\\copy %s FROM '%s' WITH (FORMAT csv, HEADER true)\" (for UPDATE, reconcile columns manually)", plan.Table, path)
	case BackupTable:
		return fmt.Sprintf("restore table data with: psql -d <db> -c \"\\copy %s FROM '%s' WITH (FORMAT csv, HEADER true)\" (reconcile existing rows first)", plan.Table, path)
	default:
		return ""
	}
}
