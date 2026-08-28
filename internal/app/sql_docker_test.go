package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/talkincode/sshx/internal/sshclient"
)

// A remote shell exits 127 for "command not found". Reporting that verbatim as
// remote_exit forces the caller to decode a shell convention just to learn the
// client is not installed, so sshx classifies it as a config problem.
func TestMissingDatabaseClientClassification(t *testing.T) {
	tests := []struct {
		name     string
		res      sshclient.ExecResult
		wantName string
		wantOK   bool
	}{
		{
			name:     "bash reports sqlite3 missing",
			res:      sshclient.ExecResult{ExitCode: 127, Stderr: "bash: line 1: sqlite3: command not found\n"},
			wantName: "sqlite3",
			wantOK:   true,
		},
		{
			name:     "dash reports sqlite3 missing",
			res:      sshclient.ExecResult{ExitCode: 127, Stderr: "sh: 1: sqlite3: not found\n"},
			wantName: "sqlite3",
			wantOK:   true,
		},
		{
			name:     "psql missing",
			res:      sshclient.ExecResult{ExitCode: 127, Stderr: "bash: psql: command not found\n"},
			wantName: "psql",
			wantOK:   true,
		},
		{
			name:   "127 from the statement itself is not a missing client",
			res:    sshclient.ExecResult{ExitCode: 127, Stderr: "ERROR:  relation \"users\" does not exist\n"},
			wantOK: false,
		},
		{
			name:   "unrelated missing command is not attributed to a client",
			res:    sshclient.ExecResult{ExitCode: 127, Stderr: "bash: docker: command not found\n"},
			wantOK: false,
		},
		{
			name:   "non-127 exit is a real statement failure",
			res:    sshclient.ExecResult{ExitCode: 3, Stderr: "psql: FATAL: role does not exist\n"},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := missingDatabaseClient(tt.res)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantName, got)
			}
		})
	}
}

func TestClientLocationHint(t *testing.T) {
	plain := &sqlRun{config: &sshclient.Config{}}
	assert.Equal(t, "", plain.clientLocationHint())

	inContainer := &sqlRun{config: &sshclient.Config{SQLDockerContainer: "tsdb"}}
	assert.Equal(t, " or in container tsdb", inContainer.clientLocationHint())
}

// --docker names the database container, so --db may come from its
// environment; without --docker a database is still required.
func TestValidateSQLConfigDatabaseRequirement(t *testing.T) {
	withDocker := &sshclient.Config{
		Mode:               "sql",
		Host:               "db1",
		SQLStatement:       "SELECT 1",
		SQLDockerContainer: "tsdb",
	}
	require.NoError(t, validateSQLConfig(withDocker))

	withoutDocker := &sshclient.Config{
		Mode:         "sql",
		Host:         "db1",
		SQLStatement: "SELECT 1",
	}
	err := validateSQLConfig(withoutDocker)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--db=<database> is required")
}
