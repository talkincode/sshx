package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every subcommand answers `sshx <verb> --help` with its own usage document
// instead of rejecting --help as an unknown option.
func TestParseArgsVerbHelp(t *testing.T) {
	for _, verb := range helpVerbs {
		t.Run(verb, func(t *testing.T) {
			config := ParseArgs([]string{"sshx", verb, "--help"})
			require.Empty(t, config.ArgumentError)
			require.Equal(t, verb, config.HelpVerb)
			require.False(t, config.JSONOutput)
		})
	}

	jsonHelp := ParseArgs([]string{"sshx", "apply", "--help", "--json"})
	require.Equal(t, "apply", jsonHelp.HelpVerb)
	require.True(t, jsonHelp.JSONOutput)
}

// A usage request is answered in every option position, including after other
// sshx options in compatibility mode: it must never fall through to a connection
// or a trust-store write, and it must never be mistaken for an unknown option.
func TestParseArgsHelpInEveryOptionPosition(t *testing.T) {
	for _, args := range [][]string{
		{"sshx", "-h=host", "--help"},
		{"sshx", "-h=host", "-p=1", "--json", "--help"},
		{"sshx", "--timeout=5s", "--help"},
		{"sshx", "-f", "--help"},
		{"sshx", "--quiet", "--help"},
		{"sshx", "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			config := ParseArgs(args)
			require.Empty(t, config.ArgumentError)
			require.Empty(t, config.HelpVerb, "compatibility mode answers with the global usage")
			require.True(t, config.ShowUsage)
			require.NotEqual(t, "sftp", config.Mode)
		})
	}

	// A subcommand answers with its own document in the same positions.
	apply := ParseArgs([]string{"sshx", "apply", "-h=host", "--path=/a", "--from=/b", "--help"})
	require.Equal(t, "apply", apply.HelpVerb)
	require.Empty(t, apply.ArgumentError)
}

// The notice flag is accepted in first position too; a first-position option is
// an sshx option, not a remote command.
func TestParseArgsQuietFlagInFirstPosition(t *testing.T) {
	for _, args := range [][]string{
		{"sshx", "--quiet", "-h=host", "uptime"},
		{"sshx", "--no-notices", "-h=host", "uptime"},
		{"sshx", "--quiet", "run", "--target=prod", "--", "true"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			config := ParseArgs(args)
			require.Empty(t, config.ArgumentError)
			require.True(t, config.Quiet)
		})
	}
}

// --help is an sshx option only while the payload has not started: once the
// remote command or SQL statement begins, the token belongs to that payload.
func TestParseArgsHelpStopsAtPayload(t *testing.T) {
	run := ParseArgs([]string{"sshx", "run", "--target=prod", "--", "--help"})
	require.Empty(t, run.HelpVerb)
	require.Equal(t, "--help", run.Command)

	sql := ParseArgs([]string{"sshx", "sql", "-h=db", "--db=app", "select 1", "--help"})
	require.Empty(t, sql.HelpVerb)
	require.Equal(t, "select 1 --help", sql.SQLStatement)

	compat := ParseArgs([]string{"sshx", "-h=host", "grep", "--help", "x"})
	require.Empty(t, compat.HelpVerb)
	require.Equal(t, "grep --help x", compat.Command)
}

// Compatibility mode rejects an option-shaped token it does not know. Before
// this rule the token was forwarded as part of the remote command, so a typo
// ran with defaults and the failure named the wrong cause.
func TestCompatModeRejectsUnknownOptions(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		message string
	}{
		{"unknown long option", []string{"-h=host", "--bogus-flag=1"}, `unknown option "--bogus-flag=1"`},
		{"near miss suggests the option", []string{"-h=host", "--dwnload=/tmp/x"}, `did you mean "--download"`},
		{"guessed transfer option names the real surface", []string{"--local=/tmp/x", "--remote=/tmp/y"}, "--upload=<local-file>"},
		{"unknown short option", []string{"-h=host", "-j=x"}, `unknown option "-j=x"`},
		{"short near miss suggests the option", []string{"-h=host", "-pj=x", "uptime"}, `did you mean "-pk"`},
		{"bare -h is not a host selector", []string{"-h", "host", "uptime"}, `unknown option "-h"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := ParseArgs(append([]string{"sshx"}, test.args...))
			require.Contains(t, config.ArgumentError, "unknown option")
			require.Contains(t, config.ArgumentError, test.message)
		})
	}
}

// Option position ends where the payload starts: everything after the first
// command token (or the -- separator) belongs to the remote command.
func TestCompatModeKeepsPayloadTokens(t *testing.T) {
	payload := ParseArgs([]string{"sshx", "-h=host", "grep", "-v", "foo"})
	require.Empty(t, payload.ArgumentError)
	require.Equal(t, "grep -v foo", payload.Command)

	afterSeparator := ParseArgs([]string{"sshx", "-h=host", "--", "-la"})
	require.Empty(t, afterSeparator.ArgumentError)
	require.Equal(t, "-la", afterSeparator.Command)

	sftp := ParseArgs([]string{"sshx", "-h=host", "--upload=/tmp/x", "--to=/tmp/y"})
	require.Empty(t, sftp.ArgumentError)
	require.Equal(t, "sftp", sftp.Mode)
}

// --quiet suppresses human notices without changing the parsed payload, and it
// is likewise recognized in option position only.
func TestParseArgsQuietFlag(t *testing.T) {
	compat := ParseArgs([]string{"sshx", "-h=host", "--quiet", "uptime"})
	require.True(t, compat.Quiet)
	require.Equal(t, "uptime", compat.Command)

	alias := ParseArgs([]string{"sshx", "run", "--no-notices", "--target=prod", "--", "true"})
	require.True(t, alias.Quiet)
	require.Equal(t, []string{"prod"}, alias.RunTargets)

	verb := ParseArgs([]string{"sshx", "apply", "-h=host", "--quiet", "--path=/a", "--from=/b"})
	require.True(t, verb.Quiet)
	require.Empty(t, verb.ArgumentError)

	payload := ParseArgs([]string{"sshx", "-h=host", "grep", "--quiet", "x"})
	require.False(t, payload.Quiet)
	require.Equal(t, "grep --quiet x", payload.Command)
}

// A statement that opens with a comment cannot be an option token, so sql takes
// it as statement text; option-shaped typos are still rejected.
func TestParseArgsSQLStatementSources(t *testing.T) {
	comment := ParseArgs([]string{"sshx", "sql", "-h=db", "--db=app", "-- SELECT 1"})
	require.Empty(t, comment.ArgumentError)
	require.Equal(t, "-- SELECT 1", comment.SQLStatement)

	multiLine := ParseArgs([]string{"sshx", "sql", "-h=db", "--db=app", "-- header\nselect 1;\n"})
	require.Empty(t, multiLine.ArgumentError)
	require.Equal(t, "-- header\nselect 1;", multiLine.SQLStatement)

	path := filepath.Join(t.TempDir(), "query.sql")
	require.NoError(t, os.WriteFile(path, []byte("-- header\nselect 2;\n"), 0o600))
	fromFile := ParseArgs([]string{"sshx", "sql", "-h=db", "--db=app", "--statement-file=" + path})
	require.Empty(t, fromFile.ArgumentError)
	require.Equal(t, "-- header\nselect 2;", fromFile.SQLStatement)

	conflict := ParseArgs([]string{"sshx", "sql", "-h=db", "--db=app", "--statement-file=" + path, "select 3"})
	require.Contains(t, conflict.ArgumentError, "--statement-file cannot be combined")

	typo := ParseArgs([]string{"sshx", "sql", "-h=db", "--dbb=app", "select 1"})
	require.Contains(t, typo.ArgumentError, `did you mean "--db"`)

	missing := ParseArgs([]string{"sshx", "sql", "-h=db", "--statement-file=/nonexistent/query.sql"})
	require.Contains(t, missing.ArgumentError, "read --statement-file")
}

func TestParseArgsSQLTargetAlias(t *testing.T) {
	for _, selector := range []string{"--target=db", "--host=db", "-h=db"} {
		t.Run(selector, func(t *testing.T) {
			config := ParseArgs([]string{"sshx", "sql", selector, "--db=app", "SELECT 1"})
			require.Empty(t, config.ArgumentError)
			require.Equal(t, "db", config.Host)
			require.Equal(t, "SELECT 1", config.SQLStatement)
		})
	}
}

// The suggestion lists must describe options the parser really accepts, so a
// typo never points at a name that does not exist.
func TestCompatOptionNamesAreRecognized(t *testing.T) {
	for _, name := range compatOptionNames {
		t.Run(name, func(t *testing.T) {
			for _, arg := range []string{name, name + "=x"} {
				if !strings.Contains(ParseArgs([]string{"sshx", "-h=host", arg}).ArgumentError, "unknown option") {
					return
				}
			}
			t.Fatalf("compatOptionNames entry %q is not parsed", name)
		})
	}
}

func TestSQLOptionNamesAreRecognized(t *testing.T) {
	for _, name := range sqlOptionNames {
		t.Run(name, func(t *testing.T) {
			for _, arg := range []string{name, name + "=x"} {
				if !strings.Contains(ParseArgs([]string{"sshx", "sql", "-h=db", arg, "select 1"}).ArgumentError, "unknown sql option") {
					return
				}
			}
			t.Fatalf("sqlOptionNames entry %q is not parsed", name)
		})
	}
}
