package sqlsafe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests never discover or start a server. Enabling them authorizes
// fixture tables in an explicitly named, disposable database only.
// SSHX_SQL_INTEGRATION_POSTGRES=1 / SSHX_SQL_INTEGRATION_MYSQL=1
// SSHX_SQL_INTEGRATION_{DATABASE,USER,HOST,PORT,PASSWORD}
func realSQLFixture(t *testing.T, engine string) (SQLExecutor, string, string) {
	t.Helper()
	flag := "SSHX_SQL_INTEGRATION_" + strings.ToUpper(engine)
	if os.Getenv(flag) != "1" {
		t.Skip("real database test requires " + flag + "=1 and explicit disposable database connection variables")
	}
	client := "psql"
	if engine == EngineMySQL {
		client = "mysql"
	}
	if _, err := exec.LookPath(client); err != nil {
		t.Fatalf("explicit real-engine test requires installed %s", client)
	}
	values := map[string]string{}
	for _, key := range []string{"DATABASE", "USER", "HOST", "PORT"} {
		values[key] = os.Getenv("SSHX_SQL_INTEGRATION_" + key)
		require.NotEmpty(t, values[key], "explicit real database target requires SSHX_SQL_INTEGRATION_"+key)
	}
	require.NoError(t, ValidateDatabaseName(values["DATABASE"]))
	password := os.Getenv("SSHX_SQL_INTEGRATION_PASSWORD")
	var executor SQLExecutor = Conn{
		Database: values["DATABASE"], User: values["USER"], Host: values["HOST"], Port: values["PORT"], PasswordStdin: true,
	}
	if engine == EngineMySQL {
		executor = MySQLConn{
			Database: values["DATABASE"], User: values["USER"], Host: values["HOST"], Port: values["PORT"], PasswordStdin: true,
		}
	}
	table := "sshx_it_" + strings.ToLower(rand.Text()[:12])
	create := "CREATE TABLE " + table + " (id INTEGER PRIMARY KEY, x VARCHAR(80) UNIQUE)"
	if engine == EngineMySQL {
		create += " ENGINE=InnoDB"
	}
	runRealSQL(t, executor.ExecuteCommand(create), password, true)
	t.Cleanup(func() { runRealSQL(t, executor.ExecuteCommand("DROP TABLE "+table), password, true) })
	runRealSQL(t, executor.ExecuteCommand("INSERT INTO "+table+" VALUES (1, 'old'), (2, 'other')"), password, true)
	return executor, password, table
}

func runRealSQL(t *testing.T, rc RemoteCommand, password string, success bool) string {
	t.Helper()
	rc.Stdin = password + "\n" + rc.Stdin
	output, err := runSQLFixture(t, rc)
	if success {
		require.NoError(t, err, output)
	} else {
		require.Error(t, err, output)
	}
	return output
}

func TestSQLRealEngineRollbackAndCommit(t *testing.T) {
	for _, engine := range []string{EnginePostgres, EngineMySQL} {
		t.Run(engine, func(t *testing.T) {
			executor, password, table := realSQLFixture(t, engine)
			for _, fail := range []bool{true, false} {
				backup := filepath.Join(t.TempDir(), "preimage.data")
				value := "new"
				if fail {
					value = "other"
				}
				rc, err := executor.ExecuteWithBackupCommand("UPDATE "+table+" SET x='"+value+"' WHERE id=1", table, "id=1", backup, BackupRows)
				require.NoError(t, err)
				output := runRealSQL(t, rc, password, !fail)
				o, evidenceErr := rc.Protocol.Parse(output)
				assert.True(t, o.BackupReady, output)
				assert.Equal(t, !fail, o.Committed, output)
				if fail {
					require.Error(t, evidenceErr)
				} else {
					require.NoError(t, evidenceErr)
				}
				data, readErr := os.ReadFile(backup) // #nosec G304 -- isolated real-engine preimage
				require.NoError(t, readErr)
				expectedOld := "old"
				if engine == EngineMySQL {
					expectedOld = "H6F6C64"
				}
				assert.Contains(t, string(data), expectedOld)
				read := executor.ExecuteReadCommand("SELECT x FROM " + table + " WHERE id=1")
				state := runRealSQL(t, read, password, true)
				assert.Contains(t, state, map[bool]string{true: "old", false: "new"}[fail])
			}
		})
	}
}

func TestSQLRealEngineConcurrentWriterExcludedFromPreimage(t *testing.T) {
	for _, engine := range []string{EnginePostgres, EngineMySQL, EngineSQLite} {
		t.Run(engine, func(t *testing.T) {
			var executor SQLExecutor
			var password, table string
			kind := BackupRows
			if engine == EngineSQLite {
				conn, _ := sqliteFixture(t)
				executor, table, kind = conn, "t", BackupTable
			} else {
				executor, password, table = realSQLFixture(t, engine)
			}
			dir := t.TempDir()
			backup := filepath.Join(dir, "preimage.data")
			gate := filepath.Join(dir, "release")
			rc, err := executor.ExecuteWithBackupCommand("UPDATE "+table+" SET x='new' WHERE id=1", table, "id=1", backup, kind)
			require.NoError(t, err)
			readyPrint := "printf '%s\\n' " + shellQuote(rc.Protocol.frame("backup", "ready")) + "; "
			require.Contains(t, rc.Command, readyPrint)
			rc.Command = strings.Replace(rc.Command, readyPrint, readyPrint+"while [ ! -f "+shellQuote(gate)+" ]; do sleep 0.02; done; ", 1)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "sh", "-c", rc.Command) // #nosec G204 -- isolated generated SQL fixture
			cmd.Stdin = strings.NewReader(password + "\n" + rc.Stdin)
			stdout, pipeErr := cmd.StdoutPipe()
			require.NoError(t, pipeErr)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			require.NoError(t, cmd.Start())
			var output strings.Builder
			scanner := bufio.NewScanner(stdout)
			ready := false
			for scanner.Scan() {
				line := scanner.Text()
				output.WriteString(line + "\n")
				if line == rc.Protocol.frame("backup", "ready") {
					ready = true
					break
				}
			}
			if ready {
				prefix := "SET lock_timeout='200ms'; "
				switch engine {
				case EngineMySQL:
					prefix = "SET SESSION lock_wait_timeout=1; SET SESSION innodb_lock_wait_timeout=1; "
				case EngineSQLite:
					prefix = "PRAGMA busy_timeout=100; "
				}
				// A second connection must not change the table between the
				// saved preimage and the first connection's eventual COMMIT.
				other := executor.ExecuteCommand(prefix + "UPDATE " + table + " SET x='concurrent' WHERE id=1")
				runRealSQL(t, other, password, false)
			}
			require.NoError(t, os.WriteFile(gate, []byte("release"), 0o600))
			for scanner.Scan() {
				output.WriteString(scanner.Text() + "\n")
			}
			require.NoError(t, scanner.Err())
			require.NoError(t, cmd.Wait(), stderr.String())
			require.True(t, ready, output.String()+stderr.String())
			o, parseErr := rc.Protocol.Parse(output.String())
			require.NoError(t, parseErr)
			assert.True(t, o.Committed)
			read := executor.ExecuteReadCommand("SELECT x FROM " + table + " WHERE id=1")
			assert.Contains(t, runRealSQL(t, read, password, true), "new")
		})
	}
}
