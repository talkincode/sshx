package app

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/talkincode/sshx/internal/execution"
	"github.com/talkincode/sshx/internal/sqlsafe"
	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
)

// sqlBackupJSON is the backup section of the sql-mode JSON result.
type sqlBackupJSON struct {
	Kind        string `json:"kind"`
	Table       string `json:"table,omitempty"`
	Path        string `json:"path,omitempty"`
	Rows        *int64 `json:"rows,omitempty"`
	Reason      string `json:"reason,omitempty"`
	RestoreHint string `json:"restore_hint,omitempty"`
}

// sqlJSONResult is the machine-readable result of one sql-mode invocation.
type sqlJSONResult struct {
	Host           string                `json:"host"`
	Port           string                `json:"port"`
	User           string                `json:"user"`
	Engine         string                `json:"engine"`
	Database       string                `json:"database"`
	Statement      string                `json:"statement"`
	StatementHash  string                `json:"statement_sha256"`
	Class          string                `json:"class,omitempty"`
	Verb           string                `json:"verb,omitempty"`
	Table          string                `json:"table,omitempty"`
	HasWhere       bool                  `json:"has_where"`
	Phase          string                `json:"phase"`
	EstimatedRows  *int64                `json:"estimated_rows,omitempty"`
	ExplainPlan    string                `json:"explain_plan,omitempty"`
	Backup         *sqlBackupJSON        `json:"backup,omitempty"`
	AffectedRows   *int64                `json:"affected_rows,omitempty"`
	Stdout         string                `json:"stdout,omitempty"`
	Stderr         string                `json:"stderr,omitempty"`
	ExitCode       int                   `json:"exit_code"`
	Success        bool                  `json:"success"`
	DurationMs     int64                 `json:"duration_ms"`
	AuthMethod     string                `json:"auth_method,omitempty"`
	CredSource     string                `json:"cred_source,omitempty"`
	CredCache      string                `json:"cred_cache,omitempty"`
	Sudo           bool                  `json:"sudo,omitempty"`
	ErrorKind      string                `json:"error_kind,omitempty"`
	Error          string                `json:"error,omitempty"`
	Evidence       sqlsafe.Evidence      `json:"evidence"`
	ChangeState    string                `json:"change_state"`
	Executed       *bool                 `json:"executed"`
	Verified       bool                  `json:"verified"`
	Verification   string                `json:"verification"`
	Completion     string                `json:"completion"`
	Preconditions  []execution.Condition `json:"preconditions,omitempty"`
	Postconditions []execution.Condition `json:"postconditions,omitempty"`
}

// sqlRun carries the evolving state of one guarded SQL pipeline execution.
type sqlRun struct {
	config *sshclient.Config
	audit  *auditRecorder
	start  time.Time

	cls  *sqlsafe.Classification
	opts sqlsafe.Options
	exec sqlsafe.SQLExecutor
	// password is the database password (stdin-only delivery); empty when the
	// remote side authenticates via peer/ident/.pgpass.
	password string

	client        *sshclient.SSHClient
	phase         string
	estimatedRows *int64
	affectedRows  *int64
	backup        *sqlBackupJSON
	explainPlan   string
	// credSource/credCache describe remote credential resolution for the
	// audit trail and JSON result ("hit", "stored", "resolved").
	credSource string
	credCache  string
	evidence   sqlsafe.Evidence
}

func sqlOptions(config *sshclient.Config) sqlsafe.Options {
	return sqlsafe.Options{
		Force:          config.Force,
		AllowFullTable: config.SQLAllowFullTable,
		NoBackup:       config.SQLNoBackup,
		RowThreshold:   config.SQLRowThreshold,
	}
}

// HandleSQL runs the guarded SQL execution pipeline:
// classify → policy → connect → EXPLAIN gate → backup → execute → report.
// Every phase is fail-closed and the full pipeline is audited.
func HandleSQL(config *sshclient.Config, audit *auditRecorder) (err error) {
	run := &sqlRun{config: config, audit: audit, start: time.Now(), phase: "classify", opts: sqlOptions(config), evidence: sqlsafe.InitialEvidence()}

	if cfgErr := validateSQLConfig(config); cfgErr != nil {
		return run.fail("config", cfgErr)
	}

	cls, clsErr := sqlsafe.ClassifyFor(config.SQLEngine, config.SQLStatement)
	if clsErr != nil {
		return run.fail("blocked", clsErr)
	}
	run.cls = cls

	run.phase = "policy"
	if policyErr := sqlsafe.CheckPolicy(cls, run.opts); policyErr != nil {
		return run.fail("blocked", policyErr)
	}

	// Resolve the target host and open one SSH connection for the pipeline.
	run.phase = "connect"
	if config.Host != "" && !isIPAddress(config.Host) {
		if resolveErr := resolveHostFromSettings(config); resolveErr != nil {
			logger.GetLogger().Info("Note: Could not find host '%s' in settings, using as hostname directly", config.Host)
		}
	}
	if config.SQLUseSudo {
		password, pwdErr := sshclient.GetSudoPassword(config.SudoKey)
		if pwdErr != nil {
			return run.fail("secret", fmt.Errorf("resolve sudo password key %q: %w", config.SudoKey, pwdErr))
		}
		config.SudoPassword = password
	}
	if config.SQLPasswordKey != "" && sqlsafe.NormalizeEngine(config.SQLEngine) != sqlsafe.EngineSQLite {
		password, pwdErr := sshclient.GetSudoPassword(config.SQLPasswordKey)
		if pwdErr != nil {
			return run.fail("config", fmt.Errorf("failed to read database password key %q from keyring: %w", config.SQLPasswordKey, pwdErr))
		}
		run.password = password
	}

	// Remote credential resolution: consult the local temporary cache before
	// connecting; a hit avoids re-reading the production environment.
	var credSource sqlsafe.CredSource
	needExtract := false
	credBestEffort := false
	switch {
	case config.SQLCredFrom != "":
		parsed, srcErr := sqlsafe.ParseCredSource(config.SQLCredFrom)
		if srcErr != nil {
			return run.fail("config", srcErr)
		}
		credSource = parsed
		run.credSource = credSource.String()
		if config.SQLCredRefresh {
			dropCredCache(config.Host, run.credSource)
			needExtract = true
		} else if creds, ok := lookupCredCache(config.Host, run.credSource); config.SQLCredCacheTTL > 0 && ok {
			run.applyCredentials(*creds)
			run.credCache = "hit"
		} else {
			needExtract = true
		}
	case config.SQLDockerContainer != "" && config.SQLUser == "" && config.SQLPasswordKey == "":
		// `--docker` already names the database container, so read its
		// environment for the role and database instead of assuming a
		// "postgres" superuser that many images never create. This is
		// best-effort: if the container cannot be inspected or exposes no
		// credentials, the client defaults still apply.
		credSource = sqlsafe.CredSource{Kind: "docker", Container: config.SQLDockerContainer}
		credBestEffort = true
		run.credSource = credSource.String()
		if creds, ok := lookupCredCache(config.Host, run.credSource); config.SQLCredCacheTTL > 0 && ok && !config.SQLCredRefresh {
			run.applyCredentials(*creds)
			run.credCache = "hit"
		} else {
			needExtract = true
		}
	}

	client, cliErr := sshclient.NewSSHClient(config)
	if cliErr != nil {
		return run.fail("config", fmt.Errorf("failed to create SSH client: %w", cliErr))
	}
	defer errutil.HandleCloseError(&err, client)
	run.client = client
	connErr := client.ConnectDirect()
	run.audit.recordPeer(run.client)
	recordConnectedPeer(config, client, "target")
	if connErr != nil {
		return run.fail(classifyError(connErr), fmt.Errorf("failed to connect: %w", connErr))
	}

	if needExtract {
		if credErr := run.resolveCredentials(credSource, credBestEffort); credErr != nil {
			return credErr
		}
	}
	if config.SQLDatabase == "" {
		return run.fail("config", fmt.Errorf("could not determine the database: pass --db=<name> (the credential source did not provide one)"))
	}
	run.exec = newSQLExecutor(config, run.password)

	// EXPLAIN gate: mandatory for DML (row estimate feeds the backup
	// decision), on demand via --explain for anything EXPLAIN supports.
	if expErr := run.explainPhase(); expErr != nil {
		return expErr
	}
	if config.SQLExplainOnly {
		return run.reportExplainOnly()
	}

	if bkErr := run.backupPhase(); bkErr != nil {
		return bkErr
	}

	return run.executePhase()
}

func newSQLExecutor(config *sshclient.Config, password string) sqlsafe.SQLExecutor {
	engine := sqlsafe.NormalizeEngine(config.SQLEngine)
	if engine == sqlsafe.EngineSQLite {
		return sqlsafe.SQLiteConn{Path: config.SQLDatabase}
	}
	passwordStdin := password != "" || config.SQLPasswordKey != "" || config.SQLCredFrom != ""
	if engine == sqlsafe.EngineMySQL {
		return sqlsafe.MySQLConn{
			Database:      config.SQLDatabase,
			User:          config.SQLUser,
			Host:          config.SQLHost,
			Port:          config.SQLPort,
			PasswordStdin: passwordStdin,
			Docker:        config.SQLDockerContainer,
		}
	}
	return sqlsafe.Conn{
		Database:      config.SQLDatabase,
		User:          config.SQLUser,
		Host:          config.SQLHost,
		Port:          config.SQLPort,
		PasswordStdin: passwordStdin,
		Docker:        config.SQLDockerContainer,
	}
}

func validateSQLConfig(config *sshclient.Config) error {
	if config.ArgumentError != "" {
		return fmt.Errorf("%s", config.ArgumentError)
	}
	config.SQLEngine = sqlsafe.NormalizeEngine(config.SQLEngine)
	switch config.SQLEngine {
	case sqlsafe.EnginePostgres:
	case sqlsafe.EngineSQLite:
	case sqlsafe.EngineMySQL:
	default:
		return fmt.Errorf("unsupported --engine %q (implemented: postgres, sqlite, mysql)", config.SQLEngine)
	}
	if config.Host == "" {
		return fmt.Errorf("host is required (use -h=<host>)")
	}
	if config.SQLStatement == "" {
		return fmt.Errorf("SQL statement is required (positional argument or after --)")
	}
	if config.SQLEngine == sqlsafe.EngineSQLite {
		return validateSQLiteConfig(config)
	}
	if config.ExpectPlan != "" && (config.SQLDatabase == "" || config.SQLUser == "" || config.SQLHost == "" || config.SQLPort == "") {
		return fmt.Errorf("bound SQL requires explicit --db, --db-user, --db-host and --db-port; credential discovery and client defaults cannot determine the target identity")
	}
	if err := sqlsafe.ValidateBackupDir(config.SQLBackupDir); err != nil {
		return err
	}
	if config.SQLFile != "" {
		return fmt.Errorf("--db-file is only valid with --engine=sqlite")
	}
	// --docker names the database container, whose environment can supply the
	// database name, so --db becomes optional in that form too.
	if config.SQLDatabase == "" && config.SQLCredFrom == "" && config.SQLDockerContainer == "" {
		return fmt.Errorf("--db=<database> is required")
	}
	if config.SQLDatabase != "" {
		if err := sqlsafe.ValidateDatabaseName(config.SQLDatabase); err != nil {
			return err
		}
	}
	if config.SQLDockerContainer != "" {
		if err := sqlsafe.ValidateContainerName(config.SQLDockerContainer); err != nil {
			return err
		}
		if err := sqlsafe.ValidateBackupDir(config.SQLBackupDir); err != nil {
			return err
		}
	}
	if config.SQLCredFrom != "" {
		if config.SQLPasswordKey != "" {
			return fmt.Errorf("--db-cred-from and --db-password-key are mutually exclusive")
		}
		if _, err := sqlsafe.ParseCredSource(config.SQLCredFrom); err != nil {
			return err
		}
	}
	if config.Timeout < 0 {
		return fmt.Errorf("invalid --timeout value (use e.g. 30s, 2m, or 30)")
	}
	return nil
}

func validateSQLiteConfig(config *sshclient.Config) error {
	if config.SQLUser != "" || config.SQLHost != "" || config.SQLPort != "" ||
		config.SQLPasswordKey != "" || config.SQLCredFrom != "" || config.SQLDockerContainer != "" {
		return fmt.Errorf("sqlite does not use --db-user/--db-host/--db-port/--db-password-key/--db-cred-from/--docker; pass --db-file=<absolute-path>")
	}
	path := config.SQLFile
	if path == "" {
		path = config.SQLDatabase
	}
	if config.SQLFile != "" && config.SQLDatabase != "" && config.SQLFile != config.SQLDatabase {
		return fmt.Errorf("--db and --db-file disagree (%q vs %q)", config.SQLDatabase, config.SQLFile)
	}
	if err := sqlsafe.ValidateSQLitePath(path); err != nil {
		return err
	}
	if err := sqlsafe.ValidateBackupDir(config.SQLBackupDir); err != nil {
		return err
	}
	config.SQLDatabase = path
	if config.Timeout < 0 {
		return fmt.Errorf("invalid --timeout value (use e.g. 30s, 2m, or 30)")
	}
	return nil
}

// runRemote executes one assembled remote command, prepending the database
// password line to stdin when password delivery is enabled. --sudo wraps the
// whole command in sudo -S and prepends the sudo password so it never enters
// argv; sudo consumes the first line and the client sees the rest.
func (r *sqlRun) runRemote(rc sqlsafe.RemoteCommand) (sshclient.ExecResult, error) {
	command := rc.Command
	stdin := rc.Stdin
	if r.exec != nil && r.exec.NeedsPasswordLine() {
		stdin = r.password + "\n" + stdin
	}
	if r.config.SQLUseSudo {
		if r.config.SudoPassword == "" {
			return sshclient.ExecResult{ExitCode: -1}, fmt.Errorf("sql --sudo requires a resolved sudo password")
		}
		command = sqlsafe.WrapSudoStdin(command)
		stdin = r.config.SudoPassword + "\n" + stdin
	}
	return r.client.RunCommandWithInput(command, []byte(stdin))
}

// applyCredentials fills connection fields that the operator did not set
// explicitly; CLI flags always win over resolved values.
func (r *sqlRun) applyCredentials(creds sqlsafe.Credentials) {
	r.password = creds.Password
	if r.config.SQLUser == "" {
		r.config.SQLUser = creds.User
	}
	if r.config.SQLDatabase == "" {
		r.config.SQLDatabase = creds.Database
	}
	// Host/port from the environment only matter when psql runs on the host;
	// inside the container the local socket is authoritative.
	if r.config.SQLDockerContainer == "" {
		if r.config.SQLHost == "" {
			r.config.SQLHost = creds.Host
		}
		if r.config.SQLPort == "" {
			r.config.SQLPort = creds.Port
		}
		if r.config.SQLHost == "" {
			// Password auth requires TCP; local sockets use peer/ident.
			r.config.SQLHost = "127.0.0.1"
		}
	}
}

// resolveCredentials reads the credential source on the remote host. The
// extraction command carries no secret; its output does and is therefore
// never logged, audited, or embedded in error messages.
// resolveCredentials reads the credential source on the remote host. When
// bestEffort is set the source was inferred from --docker rather than
// requested explicitly, so a container that cannot be inspected or exposes no
// password must not fail the run: the client defaults still apply.
func (r *sqlRun) resolveCredentials(source sqlsafe.CredSource, bestEffort bool) error {
	r.phase = "credentials"
	cmd, cmdErr := source.ExtractionCommand()
	if cmdErr != nil {
		if bestEffort {
			return nil
		}
		return r.fail("config", cmdErr)
	}
	res, execErr := r.runRemote(sqlsafe.RemoteCommand{Command: cmd})
	if execErr != nil || res.ExitCode != 0 {
		if bestEffort {
			logger.GetLogger().Info(
				"Note: could not read %s for the database role; using client defaults", r.credSource)
			return nil
		}
		return r.fail("cred_source_failed", fmt.Errorf(
			"failed to read credential source %s (remote status %d)",
			r.credSource, res.ExitCode))
	}
	var creds sqlsafe.Credentials
	if bestEffort {
		creds = sqlsafe.ParseCredIdentity(res.Stdout)
	} else {
		parsed, parseErr := sqlsafe.ParseCredOutput(res.Stdout)
		if parseErr != nil {
			return r.fail("cred_source_failed", fmt.Errorf("credential source %s: %w", r.credSource, parseErr))
		}
		creds = parsed
	}
	r.applyCredentials(creds)
	if r.config.SQLDatabase != "" {
		if dbErr := sqlsafe.ValidateDatabaseName(r.config.SQLDatabase); dbErr != nil {
			return r.fail("config", dbErr)
		}
	}
	r.credCache = "resolved"
	// Only an explicit source writes the cache: a best-effort result may lack
	// a password and must not shadow a later --db-cred-from resolution.
	if !bestEffort && r.config.SQLCredCacheTTL > 0 {
		if storeErr := storeCredCache(r.config.Host, r.credSource, creds, r.config.SQLCredCacheTTL); storeErr != nil {
			logger.GetLogger().Info("Note: credential cache not updated: %v", storeErr)
		} else {
			r.credCache = "stored"
		}
	}
	return nil
}

var explainableVerbs = map[string]bool{
	"SELECT": true, "VALUES": true, "TABLE": true,
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true,
}

func (r *sqlRun) explainPhase() error {
	needEstimate := r.cls.Class == sqlsafe.ClassDML
	if !needEstimate && !r.config.SQLExplainOnly {
		return nil
	}
	if !explainableVerbs[r.cls.Verb] && r.cls.Verb != "PRAGMA" {
		if r.config.SQLExplainOnly {
			return r.fail("config", fmt.Errorf("%s statements do not support EXPLAIN", r.cls.Verb))
		}
		return nil
	}

	// SQLite EXPLAIN QUERY PLAN has no Plan Rows estimate. L1 uses it only
	// for --explain; DML backup always snapshots the table or the whole file.
	if sqlsafe.NormalizeEngine(r.config.SQLEngine) == sqlsafe.EngineSQLite && !r.config.SQLExplainOnly {
		return nil
	}

	r.phase = "explain"
	res, execErr := r.runRemote(r.exec.ExplainCommand(r.cls.Statement))
	if execErr != nil {
		return r.fail(classifyError(execErr), fmt.Errorf("EXPLAIN failed: %w", execErr))
	}
	if res.ExitCode != 0 {
		return r.fail("explain_failed", fmt.Errorf("EXPLAIN exited with status %d", res.ExitCode))
	}
	r.explainPlan = strings.TrimSpace(res.Stdout)
	if sqlsafe.NormalizeEngine(r.config.SQLEngine) == sqlsafe.EngineSQLite {
		return nil
	}
	var rows int64
	var parseErr error
	if sqlsafe.NormalizeEngine(r.config.SQLEngine) == sqlsafe.EngineMySQL {
		rows, parseErr = sqlsafe.ParseMySQLExplainRows(res.Stdout)
	} else {
		rows, parseErr = sqlsafe.ParseExplainRows(res.Stdout)
	}
	if parseErr != nil {
		return r.fail("explain_failed", fmt.Errorf("cannot parse EXPLAIN output: %w", parseErr))
	}
	if rows < 0 {
		r.estimatedRows = nil
		logger.GetLogger().Info("EXPLAIN does not provide a row estimate")
		return nil
	}
	r.estimatedRows = &rows
	logger.GetLogger().Info("EXPLAIN estimates %d affected row(s)", rows)
	return nil
}

func (r *sqlRun) backupPhase() error {
	estimate := int64(-1)
	if r.estimatedRows != nil {
		estimate = *r.estimatedRows
	}
	var plan sqlsafe.BackupPlan
	var planErr error
	if dialect, dialectErr := sqlsafe.LookupDialect(r.config.SQLEngine); dialectErr != nil {
		planErr = dialectErr
	} else {
		plan, planErr = dialect.DecideBackup(r.cls, estimate, r.opts)
	}
	if planErr != nil {
		return r.fail("blocked", planErr)
	}
	needImpact := !r.opts.NoBackup && plan.Kind != sqlsafe.BackupFile &&
		(plan.Kind != sqlsafe.BackupNone || r.cls.Class == sqlsafe.ClassDML)
	if needImpact {
		related, impactErr := r.checkRelatedEffects()
		if impactErr != nil {
			return impactErr
		}
		if related || r.cls.MayAffectRelated {
			return r.fail("blocked", fmt.Errorf(
				"%s may affect related relations through triggers, rewrite rules, partitions, or cascading constraints; atomic automatic backup is unavailable (use --force --no-backup only after independent backup)",
				r.cls.Verb))
		}
	}
	r.backup = &sqlBackupJSON{Kind: string(plan.Kind), Table: plan.Table, Reason: plan.Reason}
	if plan.Kind == sqlsafe.BackupNone {
		return nil
	}

	path := sqlsafe.BackupPath(r.config.SQLBackupDir, r.config.SQLDatabase, plan.Table, plan.Kind)
	if sqlsafe.NormalizeEngine(r.config.SQLEngine) == sqlsafe.EngineMySQL {
		path = strings.TrimSuffix(path, ".csv") + ".mysql-hex"
	}
	r.backup.Path = path
	r.backup.RestoreHint = sqlsafe.RestoreHintFor(r.config.SQLEngine, plan, path)
	return nil
}

func (r *sqlRun) checkRelatedEffects() (bool, error) {
	switch r.cls.Verb {
	case "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "REPLACE":
	default:
		return r.cls.MayAffectRelated, nil
	}
	if r.cls.Table == "" {
		return false, r.fail("blocked", fmt.Errorf("cannot determine the mutation target for related-effect inspection"))
	}
	rc, buildErr := r.exec.RelatedEffectsCommand(r.cls.Table, r.cls.Verb)
	if buildErr != nil {
		return false, r.fail("blocked", buildErr)
	}
	r.phase = "impact_check"
	res, execErr := r.runRemote(rc)
	if execErr != nil {
		return false, r.fail(classifyError(execErr), fmt.Errorf("related-effect inspection failed: %w", execErr))
	}
	if res.ExitCode != 0 {
		return false, r.fail("impact_check_failed", fmt.Errorf(
			"related-effect inspection exited with status %d", res.ExitCode))
	}
	related, parseErr := sqlsafe.ParseBooleanOutput(res.Stdout)
	if parseErr != nil {
		return false, r.fail("impact_check_failed", parseErr)
	}
	return related || r.cls.MayAffectRelated, nil
}

func (r *sqlRun) executePhase() error {
	r.phase = "execute"
	command := r.exec.ExecuteCommand(r.cls.Statement)
	if r.cls.Class == sqlsafe.ClassRead {
		command = r.exec.ExecuteReadCommand(r.cls.Statement)
	} else if r.backup != nil && r.backup.Kind != string(sqlsafe.BackupNone) {
		var buildErr error
		command, buildErr = r.exec.ExecuteWithBackupCommand(
			r.cls.Statement, r.cls.Table, r.cls.WhereClause, r.backup.Path,
			sqlsafe.BackupKind(r.backup.Kind),
		)
		if buildErr != nil {
			return r.fail("blocked", buildErr)
		}
		r.phase = "backup_execute"
		logger.GetLogger().Info("Backing up (%s) %s -> %s under the mutation lock",
			r.backup.Kind, r.cls.Table, r.backup.Path)
	}
	res, execErr := r.runRemote(command)
	var evidenceErr error
	if command.Protocol != nil {
		observed, parseErr := command.Protocol.Parse(res.Stdout)
		r.affectedRows = observed.AffectedRows
		r.evidence = command.Protocol.Summarize(observed, parseErr == nil)
		res.Stdout = observed.Stdout
		evidenceErr = parseErr
	}
	if execErr != nil {
		return r.failWithExit(classifyError(execErr), res, fmt.Errorf("execution failed: %w", execErr))
	}
	if res.ExitCode != 0 {
		return r.failWithExit("remote_exit", res,
			fmt.Errorf("statement exited with status %d", res.ExitCode))
	}
	if evidenceErr != nil {
		kind := "protocol_error"
		var verificationErr *sqlsafe.VerificationError
		if errors.As(evidenceErr, &verificationErr) {
			kind = "verification_failed"
		}
		r.evidence.Verification = "failed"
		return r.failWithExit(kind, res, evidenceErr)
	}
	if command.Protocol == nil {
		return r.failWithExit("protocol_error", res, &sqlsafe.ProtocolError{Reason: "missing execution protocol"})
	}
	r.phase = "complete"
	r.recordAudit(0, "", nil)

	result := r.baseResult()
	result.Stdout = res.Stdout
	result.ExitCode = 0
	result.Success = true
	if r.config.JSONOutput {
		return emitSQLJSON(r.config, result)
	}
	if finalErr := finalizeSQLHuman(r.config, result); finalErr != nil {
		return finalErr
	}

	if strings.TrimSpace(res.Stdout) != "" {
		output := res.Stdout
		if !strings.HasSuffix(output, "\n") {
			output += "\n"
		}
		if _, writeErr := fmt.Fprint(os.Stdout, output); writeErr != nil {
			return fmt.Errorf("%w: deliver SQL output: %w", execution.ErrLocalIO, writeErr)
		}
	}
	if r.affectedRows != nil {
		logger.GetLogger().Success("%s affected %d row(s)", r.cls.Verb, *r.affectedRows)
	}
	if r.backup != nil && r.backup.Path != "" {
		logger.GetLogger().Success("Backup written: %s", r.backup.Path)
		logger.GetLogger().Info("Backup: %s (%s)", r.backup.Path, r.backup.RestoreHint)
	}
	return nil
}

func (r *sqlRun) reportExplainOnly() error {
	r.phase = "explain_only"
	r.recordAudit(0, "", nil)
	result := r.baseResult()
	result.ExplainPlan = r.explainPlan
	result.ExitCode = 0
	result.Success = true
	if r.config.JSONOutput {
		return emitSQLJSON(r.config, result)
	}
	if finalErr := finalizeSQLHuman(r.config, result); finalErr != nil {
		return finalErr
	}
	if _, writeErr := fmt.Fprintln(os.Stdout, r.explainPlan); writeErr != nil {
		return fmt.Errorf("%w: deliver SQL plan: %w", execution.ErrLocalIO, writeErr)
	}
	if r.estimatedRows != nil {
		logger.GetLogger().Info("Estimated affected rows: %d", *r.estimatedRows)
	}
	return nil
}

// fail records the audit outcome and reports the error, as JSON when
// requested (then suppressing duplicate stderr output via ErrReported).
func (r *sqlRun) fail(kind string, failErr error) error {
	return r.failWithExit(kind, sshclient.ExecResult{ExitCode: -1}, failErr)
}

func (r *sqlRun) failWithExit(kind string, res sshclient.ExecResult, failErr error) error {
	safeErr := failErr
	auditErr := failErr
	if res.ExitCode >= 0 {
		safeErr = fmt.Errorf("database operation failed during %s with status %d", r.phase, res.ExitCode)
		auditErr = safeErr
		if kind == "protocol_error" || kind == "verification_failed" {
			safeErr = failErr
			auditErr = failErr
		} else if detail := firstNonEmptyLine(res.Stderr, res.Stdout); detail != "" {
			// Preserve legacy CLI diagnostics, but never copy arbitrary
			// database data or client stderr into the audit error field.
			safeErr = fmt.Errorf("%s: %s", safeErr.Error(), redactSensitiveText(detail))
		}
	}
	// A missing client is a host configuration problem, not a statement
	// failure. Reporting it as remote_exit 127 forces the caller to decode a
	// shell convention to learn that psql/sqlite3 simply is not installed.
	if missing, ok := missingDatabaseClient(res); ok {
		kind = "config"
		safeErr = fmt.Errorf(
			"%s is not available on the remote host%s: install the client, or use --docker=<container> to run it inside the database container",
			missing, r.clientLocationHint())
		auditErr = safeErr
	}
	r.recordAudit(res.ExitCode, kind, auditErr)
	result := r.baseResult()
	result.ExitCode = res.ExitCode
	result.ErrorKind = kind
	result.Error = redactError(safeErr)
	result.Stdout = res.Stdout
	result.Stderr = res.Stderr
	if r.config.JSONOutput {
		if outputErr := emitSQLJSON(r.config, result); outputErr != nil {
			return outputErr
		}
		return ErrReported
	}
	if finalErr := finalizeSQLHuman(r.config, result); finalErr != nil {
		return finalErr
	}
	if res.ExitCode > 0 {
		if strings.TrimSpace(res.Stderr) != "" {
			if _, writeErr := fmt.Fprint(os.Stderr, res.Stderr); writeErr != nil {
				return fmt.Errorf("%w: deliver SQL diagnostic: %w", execution.ErrLocalIO, writeErr)
			}
		}
		return &ExitError{Code: res.ExitCode}
	}
	return failErr
}

func firstNonEmptyLine(chunks ...string) string {
	for _, chunk := range chunks {
		for _, line := range strings.Split(chunk, "\n") {
			if s := strings.TrimSpace(line); s != "" {
				return s
			}
		}
	}
	return ""
}

// databaseClientNames are the remote binaries sshx drives for each engine.
var databaseClientNames = []string{"psql", "sqlite3", "mysql", "mariadb"}

// missingDatabaseClient reports the client binary the remote shell could not
// find. Shells exit 127 for "command not found", so the exit code alone is
// ambiguous; the message is required to confirm it.
func missingDatabaseClient(res sshclient.ExecResult) (string, bool) {
	if res.ExitCode != 127 {
		return "", false
	}
	text := strings.ToLower(res.Stderr + "\n" + res.Stdout)
	if !strings.Contains(text, "not found") && !strings.Contains(text, "no such file") {
		return "", false
	}
	for _, name := range databaseClientNames {
		if strings.Contains(text, name) {
			return name, true
		}
	}
	return "", false
}

// clientLocationHint names where sshx looked for the client.
func (r *sqlRun) clientLocationHint() string {
	if r.config != nil && r.config.SQLDockerContainer != "" {
		return " or in container " + r.config.SQLDockerContainer
	}
	return ""
}

func (r *sqlRun) baseResult() sqlJSONResult {
	result := sqlJSONResult{
		Host:          r.config.Host,
		Port:          r.config.Port,
		User:          r.config.User,
		Engine:        r.config.SQLEngine,
		Database:      r.config.SQLDatabase,
		Statement:     sqlsafe.RedactForAudit(r.config.SQLStatement),
		StatementHash: sqlStatementDigest(r.config.SQLStatement),
		Phase:         r.phase,
		DurationMs:    time.Since(r.start).Milliseconds(),
		Evidence:      r.evidence,
	}
	if result.Evidence.Commit == "" {
		result.Evidence = sqlsafe.InitialEvidence()
	}
	result.ChangeState = result.Evidence.StateChange
	result.Completion = "unknown"
	// Client-protocol validation is not effect verification; Verified stays
	// false even when the database acknowledged a successful mutation.
	result.Verification = result.Evidence.EffectVerification
	if result.Evidence.Verification == "failed" || result.Evidence.Verification == "unknown" {
		result.Verification = result.Evidence.Verification
	}
	switch {
	case result.Evidence.Commit == "acknowledged" || r.affectedRows != nil:
		executed := true
		result.Executed = &executed
		if result.Evidence.Commit == "acknowledged" {
			result.Completion = "completed"
		}
	case result.Evidence.Commit == "not_started":
		executed := false
		result.Executed = &executed
		result.Completion = "not_started"
		result.ChangeState = "unchanged"
	}
	if r.phase == "explain_only" {
		executed := true
		result.Executed = &executed
		result.Completion = "completed"
		result.ChangeState = "unchanged"
		result.Verification = "not_required"
	}
	if r.client != nil {
		result.AuthMethod = string(r.client.AuthMethodUsed())
	}
	result.CredSource = r.credSource
	result.CredCache = r.credCache
	result.Sudo = r.config.SQLUseSudo
	if r.cls != nil {
		result.Class = string(r.cls.Class)
		result.Verb = r.cls.Verb
		result.Table = r.cls.Table
		result.HasWhere = r.cls.HasWhere
	}
	result.EstimatedRows = r.estimatedRows
	result.AffectedRows = r.affectedRows
	result.Backup = r.backup
	addSQLEvidenceConditions(&result)
	return result
}

func addSQLEvidenceConditions(result *sqlJSONResult) {
	evidence := result.Evidence
	engine := sqlsafe.NormalizeEngine(result.Engine)
	target := engine + ":" + result.Database
	result.Postconditions = []execution.Condition{
		{Kind: "sql_commit", Subject: target, Expected: "acknowledged", Observed: evidence.Commit, Status: sqlObservationStatus(evidence.Commit, "acknowledged")},
		{Kind: "sql_protocol", Subject: target, Expected: "protocol_verified", Observed: evidence.Verification, Status: sqlObservationStatus(evidence.Verification, "protocol_verified")},
	}
	if result.AffectedRows != nil || evidence.AffectedRowsSemantics != "" {
		rows, status := "", "unknown"
		if result.AffectedRows != nil {
			rows, status = strconv.FormatInt(*result.AffectedRows, 10), "passed"
		} else if evidence.Commit == "not_started" {
			status = "not_performed"
		}
		semantics := map[string]string{
			sqlsafe.EnginePostgres: "postgres_command_tag", sqlsafe.EngineSQLite: "sqlite_changes", sqlsafe.EngineMySQL: "mysql_row_count",
		}[engine]
		semanticsStatus := status
		if status == "passed" {
			semanticsStatus = sqlObservationStatus(evidence.AffectedRowsSemantics, semantics)
		}
		result.Postconditions = append(result.Postconditions,
			execution.Condition{Kind: "sql_affected_rows", Subject: target + ":" + result.Table, Observed: rows, Status: status},
			execution.Condition{Kind: "sql_affected_rows_semantics", Subject: target + ":" + result.Table, Expected: semantics, Observed: evidence.AffectedRowsSemantics, Status: semanticsStatus},
		)
	}
	if result.Backup == nil || result.Backup.Kind == string(sqlsafe.BackupNone) {
		return
	}
	backupStatus := evidence.BackupStatus
	if backupStatus == "" || backupStatus == "not_required" {
		backupStatus = "planned"
	}
	status := sqlObservationStatus(backupStatus, "ready")
	observedKind := ""
	if backupStatus == "ready" {
		observedKind = result.Backup.Kind
	} else if evidence.Commit == "not_started" {
		status = "not_performed"
	}
	expectedFormat := "csv"
	switch engine {
	case sqlsafe.EngineMySQL:
		expectedFormat = "mysql_hex_rows_v1"
	case sqlsafe.EngineSQLite:
		if result.Backup.Kind == string(sqlsafe.BackupFile) {
			expectedFormat = "sqlite_database"
		}
	}
	consistencyStatus, formatStatus := status, status
	if status == "passed" {
		consistencyStatus = sqlObservationStatus(evidence.BackupConsistency, "locked_preimage")
		formatStatus = sqlObservationStatus(evidence.BackupFormat, expectedFormat)
	}
	result.Preconditions = []execution.Condition{
		{Kind: "sql_backup", Subject: result.Backup.Path, Expected: "ready", Observed: backupStatus, Status: status},
		{Kind: "sql_backup_kind", Subject: result.Backup.Path, Expected: result.Backup.Kind, Observed: observedKind, Status: status},
		{Kind: "sql_backup_consistency", Subject: result.Backup.Path, Expected: "locked_preimage", Observed: evidence.BackupConsistency, Status: consistencyStatus},
		{Kind: "sql_backup_format", Subject: result.Backup.Path, Expected: expectedFormat, Observed: evidence.BackupFormat, Status: formatStatus},
	}
}

func sqlObservationStatus(observed, expected string) string {
	if observed == "" || expected == "" {
		return "unknown"
	}
	switch observed {
	case expected:
		return "passed"
	case "not_started", "not_performed", "not_required":
		return "not_performed"
	case "failed":
		return "failed"
	default:
		return "unknown"
	}
}

func (r *sqlRun) recordAudit(exitCode int, kind string, failErr error) {
	meta := sqlAuditMeta{Phase: r.phase, Mutates: false}
	evidence := r.baseResult().Evidence
	meta.Evidence = &evidence
	if r.cls != nil {
		meta.Class = string(r.cls.Class)
		meta.Verb = r.cls.Verb
		meta.Table = r.cls.Table
		meta.HasWhere = r.cls.HasWhere
		meta.Mutates = r.cls.Class != sqlsafe.ClassRead && r.phase != "explain_only"
	}
	meta.EstimatedRows = r.estimatedRows
	meta.AffectedRows = r.affectedRows
	meta.CredSource = r.credSource
	meta.CredCache = r.credCache
	if r.backup != nil {
		meta.BackupKind = r.backup.Kind
		meta.BackupPath = r.backup.Path
		meta.BackupRows = r.backup.Rows
	}
	authMethod := sshclient.AuthMethodUnknown
	if r.client != nil {
		authMethod = r.client.AuthMethodUsed()
	}
	r.audit.recordSQLOutcome(r.config, authMethod, meta, exitCode, kind, failErr)
}

func emitSQLJSON(config *sshclient.Config, result sqlJSONResult) error {
	return emitLifecycleJSON(config, result)
}

func finalizeSQLHuman(config *sshclient.Config, result sqlJSONResult) error {
	_, err := finalizeLifecycle(config, result)
	return err
}
