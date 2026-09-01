package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/talkincode/sshx/internal/sqlsafe"
	"github.com/talkincode/sshx/internal/sshclient"
)

func TestParseArgs_SQLBasic(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "sql", "-h=db1", "--db=app", "--db-user=app",
		"--db-password-key=app-db", "--json",
		"UPDATE users SET active=false WHERE id=42",
	})
	if config.Mode != "sql" {
		t.Fatalf("expected mode sql, got %s", config.Mode)
	}
	if config.Host != "db1" || config.SQLDatabase != "app" || config.SQLUser != "app" {
		t.Fatalf("unexpected sql routing: %#v", config)
	}
	if config.SQLPasswordKey != "app-db" {
		t.Fatalf("expected password key app-db, got %s", config.SQLPasswordKey)
	}
	if config.SQLHost != "127.0.0.1" {
		t.Fatalf("expected --db-password-key to default SQLHost to 127.0.0.1, got %q", config.SQLHost)
	}
	if config.SQLStatement != "UPDATE users SET active=false WHERE id=42" {
		t.Fatalf("unexpected statement: %q", config.SQLStatement)
	}
	if config.SQLEngine != sqlsafe.EnginePostgres {
		t.Fatalf("expected default engine postgres, got %s", config.SQLEngine)
	}
	if !config.JSONOutput {
		t.Fatal("json flag was not parsed")
	}
}

func TestParseArgs_SQLSQLite(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "sql", "-h=app1", "--engine=SQLite3", "--db-file=/var/lib/app/app.db",
		"--sudo", "--json", "SELECT 1",
	})
	if !config.SQLUseSudo {
		t.Fatal("expected --sudo to set SQLUseSudo")
	}
	if config.SQLEngine != sqlsafe.EngineSQLite {
		t.Fatalf("expected sqlite engine, got %s", config.SQLEngine)
	}
	if config.SQLFile != "/var/lib/app/app.db" {
		t.Fatalf("expected db-file path, got %s", config.SQLFile)
	}
	if err := validateSQLConfig(config); err != nil {
		t.Fatalf("sqlite config rejected: %v", err)
	}
	if config.SQLDatabase != "/var/lib/app/app.db" {
		t.Fatalf("expected path copied into database field, got %s", config.SQLDatabase)
	}
}

func TestParseArgs_SQLAfterDoubleDash(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "sql", "-h=db1", "--db=app", "--",
		"SELECT", "count(*)", "FROM", "users",
	})
	if config.SQLStatement != "SELECT count(*) FROM users" {
		t.Fatalf("unexpected statement: %q", config.SQLStatement)
	}
}

func TestParseArgs_SQLSafetyFlags(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "sql", "-h=db1", "--db=app", "--allow-full-table",
		"--no-backup", "--force", "--explain", "--row-threshold=50",
		"--backup-dir=/tmp/bk", "--dry-run",
		"DELETE FROM users",
	})
	if !config.SQLAllowFullTable || !config.SQLNoBackup || !config.Force || !config.SQLExplainOnly {
		t.Fatalf("safety flags not parsed: %#v", config)
	}
	if config.SQLRowThreshold != 50 {
		t.Fatalf("expected row threshold 50, got %d", config.SQLRowThreshold)
	}
	if config.SQLBackupDir != "/tmp/bk" || !config.DryRun {
		t.Fatalf("backup-dir/dry-run not parsed: %#v", config)
	}
}

func TestParseArgs_SQLUnknownOption(t *testing.T) {
	config := ParseArgs([]string{"sshx", "sql", "-h=db1", "--db=app", "--bogus", "SELECT 1"})
	if config.ArgumentError == "" {
		t.Fatal("expected an argument error for unknown option")
	}
}

func TestParseArgs_SQLDockerAndCredFrom(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "sql", "-h=db1", "--docker=pg-prod", "--db-cred-from=docker:pg-prod",
		"SELECT 1",
	})
	if config.SQLDockerContainer != "pg-prod" || config.SQLCredFrom != "docker:pg-prod" {
		t.Fatalf("docker/cred-from not parsed: %#v", config)
	}
	if config.SQLCredCacheTTL != DefaultCredCacheTTL {
		t.Fatalf("expected default cred cache TTL %v, got %v", DefaultCredCacheTTL, config.SQLCredCacheTTL)
	}
	if config.SQLHost != "" {
		t.Fatalf("docker mode must keep the container-local socket, got host %q", config.SQLHost)
	}

	config = ParseArgs([]string{
		"sshx", "sql", "-h=db1", "--db-cred-from=env-file:/opt/.env",
		"--cred-cache=off", "--cred-refresh", "SELECT 1",
	})
	if config.SQLCredCacheTTL != 0 {
		t.Fatalf("--cred-cache=off must disable caching, got %v", config.SQLCredCacheTTL)
	}
	if !config.SQLCredRefresh {
		t.Fatal("--cred-refresh not parsed")
	}

	config = ParseArgs([]string{
		"sshx", "sql", "-h=db1", "--db-cred-from=docker:pg", "--cred-cache=1h", "SELECT 1",
	})
	if config.SQLCredCacheTTL != time.Hour {
		t.Fatalf("expected 1h TTL, got %v", config.SQLCredCacheTTL)
	}

	config = ParseArgs([]string{"sshx", "sql", "-h=db1", "--cred-cache=nonsense", "SELECT 1"})
	if config.ArgumentError == "" {
		t.Fatal("expected argument error for invalid --cred-cache")
	}
}

func TestValidateSQLConfig_CredFrom(t *testing.T) {
	// --db becomes optional when a credential source can provide it.
	config := ParseArgs([]string{"sshx", "sql", "-h=db1", "--db-cred-from=docker:pg", "SELECT 1"})
	if err := validateSQLConfig(config); err != nil {
		t.Fatalf("cred-from without --db must validate: %v", err)
	}

	config = ParseArgs([]string{
		"sshx", "sql", "-h=db1", "--db=app", "--db-cred-from=docker:pg",
		"--db-password-key=k", "SELECT 1",
	})
	if err := validateSQLConfig(config); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}

	config = ParseArgs([]string{"sshx", "sql", "-h=db1", "--db=app", "--db-cred-from=vault:x", "SELECT 1"})
	if err := validateSQLConfig(config); err == nil {
		t.Fatal("expected error for unsupported cred source kind")
	}

	config = ParseArgs([]string{"sshx", "sql", "-h=db1", "--db=app", "--docker=bad name", "SELECT 1"})
	if err := validateSQLConfig(config); err == nil {
		t.Fatal("expected error for invalid container name")
	}
}

func TestValidateSQLConfig(t *testing.T) {
	base := func() []string {
		return []string{"sshx", "sql", "-h=db1", "--db=app", "SELECT 1"}
	}

	if err := validateSQLConfig(ParseArgs(base())); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing host", []string{"sshx", "sql", "--db=app", "SELECT 1"}, "host is required"},
		{"missing db", []string{"sshx", "sql", "-h=db1", "SELECT 1"}, "--db="},
		{"missing statement", []string{"sshx", "sql", "-h=db1", "--db=app"}, "SQL statement is required"},
		{"bad engine", []string{"sshx", "sql", "-h=db1", "--db=app", "--engine=oracle", "SELECT 1"}, "unsupported --engine"},
		{"sqlite missing path", []string{"sshx", "sql", "-h=db1", "--engine=sqlite", "SELECT 1"}, "absolute-path"},
		{"sqlite postgres flags", []string{"sshx", "sql", "-h=db1", "--engine=sqlite", "--db-file=/tmp/app.db", "--db-user=app", "SELECT 1"}, "does not use"},
		{"db-file on postgres", []string{"sshx", "sql", "-h=db1", "--db=app", "--db-file=/tmp/app.db", "SELECT 1"}, "--db-file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSQLConfig(ParseArgs(tc.args))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestFillDryRunSQL(t *testing.T) {
	t.Run("dml with where plans row backup", func(t *testing.T) {
		config := ParseArgs([]string{
			"sshx", "sql", "-h=db1", "--db=app", "--db-password-key=k", "--dry-run",
			"UPDATE users SET active=false WHERE id=42",
		})
		plan := buildDryRunPlan(config)
		if plan.SQL == nil {
			t.Fatal("expected sql plan")
		}
		if plan.SQL.Class != string(sqlsafe.ClassDML) || plan.SQL.Verb != "UPDATE" || plan.SQL.Table != "users" {
			t.Fatalf("unexpected classification: %#v", plan.SQL)
		}
		if plan.SQL.BackupKind != string(sqlsafe.BackupRows) {
			t.Fatalf("expected row backup, got %s", plan.SQL.BackupKind)
		}
		if plan.SQL.ExplainCommand == "" || plan.SQL.ExecuteCommand == "" {
			t.Fatalf("expected command previews: %#v", plan.SQL)
		}
		if strings.Contains(plan.SQL.ExecuteCommand, "PGPASSWORD=") {
			t.Fatal("password must never appear in the command preview")
		}
		if !plan.WouldConnect || !plan.WouldExecute || !plan.WouldMutateRemote || !plan.WouldReadSecret {
			t.Fatalf("unexpected effects: %#v", plan)
		}
	})

	t.Run("full table delete is blocked", func(t *testing.T) {
		config := ParseArgs([]string{
			"sshx", "sql", "-h=db1", "--db=app", "--dry-run", "DELETE FROM users",
		})
		plan := buildDryRunPlan(config)
		if plan.SafetyCheck.Status != "blocked" {
			t.Fatalf("expected blocked safety check, got %#v", plan.SafetyCheck)
		}
		if plan.WouldConnect || plan.WouldExecute || plan.WouldMutateRemote {
			t.Fatalf("blocked plan must not report side effects: %#v", plan)
		}
	})

	t.Run("hard blocked statement", func(t *testing.T) {
		config := ParseArgs([]string{
			"sshx", "sql", "-h=db1", "--db=app", "--dry-run", "DROP DATABASE app",
		})
		plan := buildDryRunPlan(config)
		if plan.SafetyCheck.Status != "blocked" {
			t.Fatalf("expected blocked safety check, got %#v", plan.SafetyCheck)
		}
	})

	t.Run("docker cred-from plans remote resolution and local cache", func(t *testing.T) {
		config := ParseArgs([]string{
			"sshx", "sql", "-h=db1", "--docker=pg-prod", "--db-cred-from=docker:pg-prod",
			"--dry-run", "UPDATE users SET x=1 WHERE id=1",
		})
		plan := buildDryRunPlan(config)
		if plan.SQL == nil {
			t.Fatal("expected sql plan")
		}
		if plan.SQL.Docker != "pg-prod" || plan.SQL.CredSource != "docker:pg-prod" {
			t.Fatalf("docker/cred plan missing: %#v", plan.SQL)
		}
		if plan.SQL.CredCache != DefaultCredCacheTTL.String() {
			t.Fatalf("expected default cache TTL in plan, got %q", plan.SQL.CredCache)
		}
		if !strings.Contains(plan.SQL.ExecuteCommand, "docker exec -i -e PGPASSWORD pg-prod psql") {
			t.Fatalf("execute preview must run inside the container: %s", plan.SQL.ExecuteCommand)
		}
		if !plan.WouldReadSecret || !plan.WouldWriteLocalState {
			t.Fatalf("cred resolution effects missing: %#v", plan)
		}
	})

	t.Run("sqlite dml plans table backup", func(t *testing.T) {
		config := ParseArgs([]string{
			"sshx", "sql", "-h=app1", "--engine=sqlite", "--db-file=/var/lib/app/app.db",
			"--dry-run", "UPDATE users SET active=0 WHERE id=42",
		})
		plan := buildDryRunPlan(config)
		if plan.SQL == nil {
			t.Fatal("expected sql plan")
		}
		if plan.SQL.Engine != sqlsafe.EngineSQLite || plan.SQL.Database != "/var/lib/app/app.db" {
			t.Fatalf("unexpected sqlite identity: %#v", plan.SQL)
		}
		if plan.SQL.Class != string(sqlsafe.ClassDML) || plan.SQL.BackupKind != string(sqlsafe.BackupTable) {
			t.Fatalf("unexpected sqlite plan: %#v", plan.SQL)
		}
		if !strings.Contains(plan.SQL.ExecuteCommand, "sqlite3 -batch -bail /var/lib/app/app.db") {
			t.Fatalf("execute preview must use sqlite3: %s", plan.SQL.ExecuteCommand)
		}
		if strings.Contains(plan.SQL.ExecuteCommand, "-readonly") {
			t.Fatalf("sqlite DML must not use the non-portable -readonly flag: %s", plan.SQL.ExecuteCommand)
		}
		if strings.Contains(plan.SQL.ExecuteCommand, "psql") {
			t.Fatal("sqlite plan must not assemble psql")
		}
		if !plan.WouldConnect || !plan.WouldMutateRemote || plan.WouldReadSecret {
			t.Fatalf("unexpected sqlite effects: %#v", plan)
		}
	})
	t.Run("sqlite attach is blocked", func(t *testing.T) {
		config := ParseArgs([]string{
			"sshx", "sql", "-h=app1", "--engine=sqlite", "--db-file=/var/lib/app/app.db",
			"--dry-run", "ATTACH DATABASE '/tmp/x.db' AS extra",
		})
		plan := buildDryRunPlan(config)
		if plan.SafetyCheck.Status != "blocked" {
			t.Fatalf("expected blocked safety check, got %#v", plan.SafetyCheck)
		}
		if plan.WouldConnect || plan.WouldExecute {
			t.Fatalf("blocked sqlite plan must not connect: %#v", plan)
		}
	})
	t.Run("read skips backup and mutation", func(t *testing.T) {
		config := ParseArgs([]string{
			"sshx", "sql", "-h=db1", "--db=app", "--dry-run", "SELECT count(*) FROM users",
		})
		plan := buildDryRunPlan(config)
		if plan.SQL == nil || plan.SQL.Class != string(sqlsafe.ClassRead) {
			t.Fatalf("expected read classification: %#v", plan.SQL)
		}
		if plan.SQL.BackupKind != string(sqlsafe.BackupNone) {
			t.Fatalf("expected no backup, got %s", plan.SQL.BackupKind)
		}
		if plan.WouldMutateRemote || plan.WouldWriteRemoteState {
			t.Fatalf("read must not mutate: %#v", plan)
		}
	})
	t.Run("sqlite sudo wraps execute command", func(t *testing.T) {
		config := ParseArgs([]string{
			"sshx", "sql", "-h=app1", "--engine=sqlite", "--db-file=/var/lib/app/app.db",
			"--sudo", "--dry-run", "SELECT 1",
		})
		plan := buildDryRunPlan(config)
		if !plan.UsesSudo || plan.SQL == nil || !plan.SQL.UseSudo {
			t.Fatalf("expected sudo in sql plan: %#v", plan)
		}
		if !plan.WouldReadSecret {
			t.Fatal("sql --sudo must report would_read_secret")
		}
		if !strings.HasPrefix(plan.SQL.ExecuteCommand, "sudo -S -p '' sh -c ") {
			t.Fatalf("execute preview must wrap sudo -S: %s", plan.SQL.ExecuteCommand)
		}
		if strings.Contains(plan.SQL.ExecuteCommand, "PGPASSWORD=") {
			t.Fatal("sudo wrap must not embed secrets in argv")
		}
	})
	t.Run("sqlite read uses portable file uri", func(t *testing.T) {
		config := ParseArgs([]string{
			"sshx", "sql", "-h=app1", "--engine=sqlite", "--db-file=/var/lib/app/app.db",
			"--dry-run", "SELECT 1",
		})
		plan := buildDryRunPlan(config)
		if plan.SQL == nil || plan.SQL.Class != string(sqlsafe.ClassRead) {
			t.Fatalf("expected sqlite read plan: %#v", plan.SQL)
		}
		if !strings.Contains(plan.SQL.ExecuteCommand, "file:/var/lib/app/app.db?mode=ro") {
			t.Fatalf("sqlite read must open a mode=ro URI: %s", plan.SQL.ExecuteCommand)
		}
		if strings.Contains(plan.SQL.ExecuteCommand, "-readonly") {
			t.Fatalf("sqlite read must not use the non-portable -readonly flag: %s", plan.SQL.ExecuteCommand)
		}
	})
}

func TestSQLJSONFailureIncludesRemoteStderr(t *testing.T) {
	config := ParseArgs([]string{
		"sshx", "sql", "-h=app1", "--engine=sqlite", "--db-file=/tmp/x.db", "--json", "SELECT 1",
	})
	run := &sqlRun{config: config, start: time.Now(), phase: "execute"}

	stdout := captureStdout(t, func() {
		err := run.failWithExit("remote_exit", sshclient.ExecResult{
			ExitCode: 1,
			Stderr:   "sqlite3: Error: unknown option: -readonly\nUse -help for a list of options.\n",
		}, nil)
		if err != ErrReported {
			t.Fatalf("expected ErrReported, got %v", err)
		}
	})

	var result sqlJSONResult
	if err := json.Unmarshal(stdout, &result); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout, err)
	}
	if result.ErrorKind != "remote_exit" || result.ExitCode != 1 {
		t.Fatalf("unexpected failure envelope: %#v", result)
	}
	if !strings.Contains(result.Error, "unknown option: -readonly") {
		t.Fatalf("error should include remote stderr: %q", result.Error)
	}
	if !strings.Contains(result.Stderr, "unknown option: -readonly") {
		t.Fatalf("JSON stderr missing remote client output: %q", result.Stderr)
	}
}
