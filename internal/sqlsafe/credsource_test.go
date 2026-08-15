package sqlsafe

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCredSource(t *testing.T) {
	s, err := ParseCredSource("docker:pg-prod")
	require.NoError(t, err)
	assert.Equal(t, CredSource{Kind: "docker", Container: "pg-prod"}, s)
	assert.Equal(t, "docker:pg-prod", s.String())

	s, err = ParseCredSource("env-file:/opt/app/.env")
	require.NoError(t, err)
	assert.Equal(t, CredSource{Kind: "env-file", Path: "/opt/app/.env"}, s)
	assert.Equal(t, "env-file:/opt/app/.env", s.String())

	for _, bad := range []string{"", "docker:", "docker:bad name", "docker:-leading", "vault:x", "env-file:", "plain", "env-file:relative.env", "env-file:./.env", "env-file:opt/app/.env", "env-file:/opt/../etc/passwd", "env-file:/tmp/../.env"} {
		_, err := ParseCredSource(bad)
		assert.Error(t, err, "spec %q must be rejected", bad)
	}
}

func TestCredSourceExtractionCommand(t *testing.T) {
	s := CredSource{Kind: "docker", Container: "pg-prod"}
	cmd, err := s.ExtractionCommand()
	require.NoError(t, err)
	assert.Equal(t, "docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' pg-prod", cmd)

	s = CredSource{Kind: "env-file", Path: "/opt/my app/.env"}
	cmd, err = s.ExtractionCommand()
	require.NoError(t, err)
	assert.Equal(t, "cat '/opt/my app/.env'", cmd)

	_, err = CredSource{Kind: "docker", Container: "a;b"}.ExtractionCommand()
	assert.Error(t, err)
}

func TestParseCredOutputPostgresEnv(t *testing.T) {
	out := `
PATH=/usr/local/sbin:/usr/local/bin
GOSU_VERSION=1.17
POSTGRES_USER=app
POSTGRES_PASSWORD=s3cr3t!
POSTGRES_DB=appdb
LANG=en_US.utf8
`
	creds, err := ParseCredOutput(out)
	require.NoError(t, err)
	assert.Equal(t, "app", creds.User)
	assert.Equal(t, "s3cr3t!", creds.Password)
	assert.Equal(t, "appdb", creds.Database)
}

func TestParseCredOutputPriorityAndQuoting(t *testing.T) {
	out := `
export PGUSER="admin"
POSTGRES_USER=ignored
PGPASSWORD='p w'
# comment line
DB_NAME=alsoignored
PGDATABASE=maindb
PGHOST=10.0.0.5
PGPORT=5433
`
	creds, err := ParseCredOutput(out)
	require.NoError(t, err)
	assert.Equal(t, Credentials{User: "admin", Password: "p w", Database: "maindb", Host: "10.0.0.5", Port: "5433"}, creds)
}

func TestParseCredOutputDatabaseURL(t *testing.T) {
	creds, err := ParseCredOutput("DATABASE_URL=postgres://svc:urlpass@db.internal:6432/prod\n")
	require.NoError(t, err)
	assert.Equal(t, "svc", creds.User)
	assert.Equal(t, "urlpass", creds.Password)
	assert.Equal(t, "prod", creds.Database)
	assert.Equal(t, "db.internal", creds.Host)
	assert.Equal(t, "6432", creds.Port)
}

func TestParseCredOutputMissingPasswordNeverEchoesOutput(t *testing.T) {
	out := "SOME_TOKEN=super-secret-value\nOTHER=x\n"
	_, err := ParseCredOutput(out)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret-value")
}

func TestDockerExplainAndExecuteCommands(t *testing.T) {
	conn := Conn{Database: "app", User: "app", PasswordStdin: true, Docker: "pg-prod"}
	rc := conn.ExplainCommand("UPDATE t SET x=1 WHERE id=2")
	assert.True(t, strings.HasPrefix(rc.Command, "IFS= read -r PGPASSWORD; export PGPASSWORD; docker exec -i -e PGPASSWORD pg-prod psql"), rc.Command)
	assert.NotContains(t, rc.Command, "-h", "docker mode must default to the container-local socket")

	rc = conn.ExecuteCommand("SELECT 1")
	assert.Contains(t, rc.Command, "docker exec -i -e PGPASSWORD pg-prod psql")

	// Without a password no env passthrough is added.
	noPw := Conn{Database: "app", Docker: "pg-prod"}
	rc = noPw.ExecuteCommand("SELECT 1")
	assert.Contains(t, rc.Command, "docker exec -i pg-prod psql")
	assert.NotContains(t, rc.Command, "PGPASSWORD")
}

func TestDockerTransactionalBackupStreamsToHost(t *testing.T) {
	conn := Conn{Database: "app", User: "app", PasswordStdin: true, Docker: "pg-prod"}
	rc, err := conn.ExecuteWithBackupCommand(
		"UPDATE users SET active=false WHERE id=42", "users", "id=42",
		".sshx/sql-backups/x.csv", BackupRows,
	)
	require.NoError(t, err)
	assert.Contains(t, rc.Command, "COPY (SELECT * FROM users WHERE id=42) TO STDOUT")
	assert.Contains(t, rc.Command, "docker exec -i -e PGPASSWORD pg-prod psql")
	assert.Contains(t, rc.Command, ".sshx/sql-backups/x.csv.stdin")
	assert.Empty(t, rc.Stdin)
	assert.NotContains(t, rc.Command, "password")
}
