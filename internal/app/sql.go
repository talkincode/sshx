package app

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

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
	Host          string         `json:"host"`
	Port          string         `json:"port"`
	User          string         `json:"user"`
	Engine        string         `json:"engine"`
	Database      string         `json:"database"`
	Statement     string         `json:"statement"`
	StatementHash string         `json:"statement_sha256"`
	Class         string         `json:"class,omitempty"`
	Verb          string         `json:"verb,omitempty"`
	Table         string         `json:"table,omitempty"`
	HasWhere      bool           `json:"has_where"`
	Phase         string         `json:"phase"`
	EstimatedRows *int64         `json:"estimated_rows,omitempty"`
	ExplainPlan   string         `json:"explain_plan,omitempty"`
	Backup        *sqlBackupJSON `json:"backup,omitempty"`
	AffectedRows  *int64         `json:"affected_rows,omitempty"`
	Stdout        string         `json:"stdout,omitempty"`
	Stderr        string         `json:"stderr,omitempty"`
	ExitCode      int            `json:"exit_code"`
	Success       bool           `json:"success"`
	DurationMs    int64          `json:"duration_ms"`
	AuthMethod    string         `json:"auth_method,omitempty"`
	CredSource    string         `json:"cred_source,omitempty"`
	CredCache     string         `json:"cred_cache,omitempty"`
	ErrorKind     string         `json:"error_kind,omitempty"`
	Error         string         `json:"error,omitempty"`
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
	run := &sqlRun{config: config, audit: audit, start: time.Now(), phase: "classify", opts: sqlOptions(config)}

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
	if config.SQLCredFrom != "" {
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
	}

	client, cliErr := sshclient.NewSSHClient(config)
	if cliErr != nil {
		return run.fail("config", fmt.Errorf("failed to create SSH client: %w", cliErr))
	}
	defer errutil.HandleCloseError(&err, client)
	if connErr := client.ConnectDirect(); connErr != nil {
		return run.fail(classifyError(connErr), fmt.Errorf("failed to connect: %w", connErr))
	}
	run.client = client

	if needExtract {
		if credErr := run.resolveCredentials(credSource); credErr != nil {
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
	if sqlsafe.NormalizeEngine(config.SQLEngine) == sqlsafe.EngineSQLite {
		return sqlsafe.SQLiteConn{Path: config.SQLDatabase}
	}
	return sqlsafe.Conn{
		Database:      config.SQLDatabase,
		User:          config.SQLUser,
		Host:          config.SQLHost,
		Port:          config.SQLPort,
		PasswordStdin: password != "" || config.SQLPasswordKey != "" || config.SQLCredFrom != "",
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
	default:
		return fmt.Errorf("unsupported --engine %q (implemented: postgres, sqlite)", config.SQLEngine)
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
	if config.SQLFile != "" {
		return fmt.Errorf("--db-file is only valid with --engine=sqlite")
	}
	if config.SQLDatabase == "" && config.SQLCredFrom == "" {
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
// password line to stdin when password delivery is enabled.
func (r *sqlRun) runRemote(rc sqlsafe.RemoteCommand) (sshclient.ExecResult, error) {
	stdin := rc.Stdin
	if r.exec != nil && r.exec.NeedsPasswordLine() {
		stdin = r.password + "\n" + stdin
	}
	return r.client.RunCommandWithInput(rc.Command, []byte(stdin))
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
func (r *sqlRun) resolveCredentials(source sqlsafe.CredSource) error {
	r.phase = "credentials"
	cmd, cmdErr := source.ExtractionCommand()
	if cmdErr != nil {
		return r.fail("config", cmdErr)
	}
	res, execErr := r.client.RunCommandWithInput(cmd, nil)
	if execErr != nil || res.ExitCode != 0 {
		return r.fail("cred_source_failed", fmt.Errorf(
			"failed to read credential source %s (remote status %d)",
			r.credSource, res.ExitCode))
	}
	creds, parseErr := sqlsafe.ParseCredOutput(res.Stdout)
	if parseErr != nil {
		return r.fail("cred_source_failed", fmt.Errorf("credential source %s: %w", r.credSource, parseErr))
	}
	r.applyCredentials(creds)
	if r.config.SQLDatabase != "" {
		if dbErr := sqlsafe.ValidateDatabaseName(r.config.SQLDatabase); dbErr != nil {
			return r.fail("config", dbErr)
		}
	}
	r.credCache = "resolved"
	if r.config.SQLCredCacheTTL > 0 {
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
	rows, parseErr := sqlsafe.ParseExplainRows(res.Stdout)
	if parseErr != nil {
		return r.fail("explain_failed", fmt.Errorf("cannot parse EXPLAIN output: %w", parseErr))
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
	if sqlsafe.NormalizeEngine(r.config.SQLEngine) == sqlsafe.EngineSQLite {
		plan, planErr = sqlsafe.DecideSQLiteBackup(r.cls, r.opts)
	} else {
		plan, planErr = sqlsafe.DecideBackup(r.cls, estimate, r.opts)
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
		logger.GetLogger().Info("Backing up (%s) %s -> %s in the mutation transaction",
			r.backup.Kind, r.cls.Table, r.backup.Path)
	}
	res, execErr := r.runRemote(command)
	if execErr != nil {
		return r.fail(classifyError(execErr), fmt.Errorf("execution failed: %w", execErr))
	}
	if res.ExitCode != 0 {
		return r.failWithExit("remote_exit", res,
			fmt.Errorf("statement exited with status %d", res.ExitCode))
	}
	if r.cls.Class == sqlsafe.ClassDML {
		if rows, ok := sqlsafe.ParseCommandTag(res.Stdout); ok {
			r.affectedRows = &rows
		} else if rows, ok := sqlsafe.ParseChangesOutput(res.Stdout); ok {
			r.affectedRows = &rows
		}
	}
	r.phase = "complete"
	r.recordAudit(0, "", nil)

	if r.config.JSONOutput {
		result := r.baseResult()
		result.Stdout = res.Stdout
		result.ExitCode = 0
		result.Success = true
		emitSQLJSON(result)
		return nil
	}

	if strings.TrimSpace(res.Stdout) != "" {
		fmt.Print(res.Stdout)
		if !strings.HasSuffix(res.Stdout, "\n") {
			fmt.Println()
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
	if r.config.JSONOutput {
		result := r.baseResult()
		result.ExplainPlan = r.explainPlan
		result.ExitCode = 0
		result.Success = true
		emitSQLJSON(result)
		return nil
	}
	fmt.Println(r.explainPlan)
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
	if res.ExitCode >= 0 {
		safeErr = fmt.Errorf("database operation failed during %s with status %d", r.phase, res.ExitCode)
	}
	r.recordAudit(res.ExitCode, kind, safeErr)
	if r.config.JSONOutput {
		result := r.baseResult()
		result.ExitCode = res.ExitCode
		result.ErrorKind = kind
		result.Error = redactError(safeErr)
		emitSQLJSON(result)
		return ErrReported
	}
	if res.ExitCode > 0 {
		if strings.TrimSpace(res.Stderr) != "" {
			fmt.Fprint(os.Stderr, res.Stderr)
		}
		return &ExitError{Code: res.ExitCode}
	}
	return failErr
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
	}
	if r.client != nil {
		result.AuthMethod = string(r.client.AuthMethodUsed())
	}
	result.CredSource = r.credSource
	result.CredCache = r.credCache
	if r.cls != nil {
		result.Class = string(r.cls.Class)
		result.Verb = r.cls.Verb
		result.Table = r.cls.Table
		result.HasWhere = r.cls.HasWhere
	}
	result.EstimatedRows = r.estimatedRows
	result.AffectedRows = r.affectedRows
	result.Backup = r.backup
	return result
}

func (r *sqlRun) recordAudit(exitCode int, kind string, failErr error) {
	meta := sqlAuditMeta{Phase: r.phase, Mutates: false}
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

func emitSQLJSON(result sqlJSONResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		logger.GetLogger().Error("failed to encode JSON result: %v", err)
	}
}
