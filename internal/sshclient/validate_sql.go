package sshclient

import (
	"strings"
)

// This file detects direct database-client invocations inside `sshx run`
// commands and scripts so they can be redirected to the guarded `sshx sql`
// pipeline (classification, policy gates, atomic backups, redacted audit).
//
// Like ValidateCommand, this is a guardrail against accidental bypass, NOT a
// security boundary: shell obfuscation can evade it. It matches only tokens in
// command position (never arbitrary arguments), so `grep psql`, `which psql`,
// or `docker logs db | grep psql` remain allowed.

// guardedDBClients maps the basename of a client binary to the engine name
// used in the block reason. Only clients covered by `sshx sql` are listed.
var guardedDBClients = map[string]string{
	"psql":    "PostgreSQL",
	"pgcli":   "PostgreSQL",
	"sqlite3": "SQLite",
	"mysql":   "MySQL",
	"mariadb": "MySQL",
	"mycli":   "MySQL",
}

// dbClientHarmlessArgs are client arguments that cannot execute SQL. A client
// invocation whose arguments are all harmless (for example `psql --version`)
// is allowed so availability probes keep working. Matching is case-sensitive:
// psql treats -V as version but -v as a variable assignment.
var dbClientHarmlessArgs = map[string]bool{
	"--version": true,
	"-V":        true,
	"--help":    true,
	"-?":        true,
}

// commandWrappers are prefixes that keep the following token in command
// position. The value set lists wrapper flags that consume a following value.
var commandWrappers = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-p": true, "-h": true, "-C": true, "-D": true, "-R": true, "-T": true, "-U": true},
	"doas":    {"-u": true, "-C": true},
	"env":     {"-u": true, "-S": true, "-C": true, "-P": true},
	"nohup":   nil,
	"nice":    {"-n": true},
	"ionice":  {"-c": true, "-n": true, "-p": true},
	"stdbuf":  {"-i": true, "-o": true, "-e": true},
	"setsid":  nil,
	"time":    nil,
	"exec":    {"-a": true},
	"timeout": {"-k": true, "-s": true, "--kill-after": true, "--signal": true},
}

var shellNames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true,
}

const maxDBDetectDepth = 6

// detectGuardedDBClient reports whether the command line invokes a database
// client that must go through `sshx sql`. It returns the engine name and the
// client binary that matched.
func detectGuardedDBClient(command string, depth int) (engine, client string, found bool) {
	if depth > maxDBDetectDepth {
		return "", "", false
	}
	for _, seg := range splitShellSegments(command) {
		if e, c, ok := analyzeSegment(seg, depth); ok {
			return e, c, true
		}
	}
	return "", "", false
}

// analyzeSegment walks one pipeline segment, skipping environment assignments
// and command wrappers, and inspects whatever lands in command position.
func analyzeSegment(tokens []string, depth int) (string, string, bool) {
	if depth > maxDBDetectDepth {
		return "", "", false
	}
	i := 0
	for i < len(tokens) {
		tok := tokens[i]
		if isEnvAssignment(tok) {
			i++
			continue
		}
		name := strings.ToLower(commandBasename(tok))
		if engine, ok := guardedDBClients[name]; ok {
			if dbArgsAllHarmless(tokens[i+1:]) {
				return "", "", false
			}
			return engine, name, true
		}
		if valueFlags, ok := commandWrappers[name]; ok {
			i++
			i = skipFlags(tokens, i, valueFlags)
			if name == "timeout" && i < len(tokens) && looksLikeDuration(tokens[i]) {
				i++
			}
			continue
		}
		switch name {
		case "command":
			// `command psql ...` executes; `command -v psql` only resolves.
			i++
			if i < len(tokens) && (tokens[i] == "-v" || tokens[i] == "-V") {
				return "", "", false
			}
			continue
		case "su":
			return suCommand(tokens[i+1:], depth)
		case "docker", "podman", "nerdctl":
			return containerCommand(tokens[i+1:], depth)
		case "kubectl", "oc":
			return kubectlCommand(tokens[i+1:], depth)
		default:
			if shellNames[name] {
				return shellDashC(tokens[i+1:], depth)
			}
			return "", "", false
		}
	}
	return "", "", false
}

// shellDashC recurses into the string argument of `sh -c '...'` (including
// combined flags such as -lc or -ec).
func shellDashC(args []string, depth int) (string, string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "--" {
			continue
		}
		if strings.Contains(a[1:], "c") && i+1 < len(args) {
			return detectGuardedDBClient(args[i+1], depth+1)
		}
	}
	return "", "", false
}

// suCommand recurses into the -c/--command value of `su`.
func suCommand(args []string, depth int) (string, string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-c" || a == "--command" {
			if i+1 < len(args) {
				return detectGuardedDBClient(args[i+1], depth+1)
			}
			return "", "", false
		}
		if v, ok := strings.CutPrefix(a, "--command="); ok {
			return detectGuardedDBClient(v, depth+1)
		}
	}
	return "", "", false
}

// containerGlobalValueFlags are docker/podman global flags that consume a value.
var containerGlobalValueFlags = map[string]bool{
	"-H": true, "--host": true, "--context": true, "--config": true,
	"-l": true, "--log-level": true, "--url": true, "-c": true, "--connection": true,
}

// containerExecValueFlags are `docker exec` / `compose exec` flags that
// consume a value.
var containerExecValueFlags = map[string]bool{
	"-u": true, "--user": true, "-e": true, "--env": true, "--env-file": true,
	"-w": true, "--workdir": true, "--detach-keys": true, "--index": true,
}

// containerCommand handles `docker|podman|nerdctl [global flags] SUBCOMMAND ...`.
func containerCommand(args []string, depth int) (string, string, bool) {
	i := skipFlags(args, 0, containerGlobalValueFlags)
	if i >= len(args) {
		return "", "", false
	}
	sub := strings.ToLower(args[i])
	i++
	switch sub {
	case "compose":
		// docker compose [flags] exec|run SERVICE CMD...
		i = skipFlags(args, i, map[string]bool{"-f": true, "--file": true, "-p": true, "--project-name": true, "--project-directory": true, "--env-file": true, "--profile": true})
		if i >= len(args) {
			return "", "", false
		}
		composeSub := strings.ToLower(args[i])
		if composeSub != "exec" && composeSub != "run" {
			return "", "", false
		}
		i++
		return execTarget(args, i, depth)
	case "exec":
		return execTarget(args, i, depth)
	case "run":
		// Too many flags to parse reliably; scan for a client in any argument
		// position, which is precise enough for `docker run image psql ...`.
		for _, a := range args[i:] {
			name := strings.ToLower(commandBasename(a))
			if engine, ok := guardedDBClients[name]; ok {
				return engine, name, true
			}
		}
		return "", "", false
	default:
		return "", "", false
	}
}

// execTarget skips exec-style flags plus the container/service name, then
// analyzes the remaining tokens as a nested command.
func execTarget(args []string, i int, depth int) (string, string, bool) {
	i = skipFlags(args, i, containerExecValueFlags)
	i++ // container or service name
	if i >= len(args) {
		return "", "", false
	}
	return analyzeSegment(args[i:], depth+1)
}

// kubectlValueFlags are kubectl/oc flags (global and exec) that consume a value.
var kubectlValueFlags = map[string]bool{
	"-n": true, "--namespace": true, "-c": true, "--container": true,
	"--context": true, "--kubeconfig": true, "--cluster": true,
	"-s": true, "--server": true, "--pod-running-timeout": true,
}

// kubectlCommand handles `kubectl [flags] exec [flags] POD [--] CMD...`.
func kubectlCommand(args []string, depth int) (string, string, bool) {
	i := skipFlags(args, 0, kubectlValueFlags)
	if i >= len(args) || strings.ToLower(args[i]) != "exec" {
		return "", "", false
	}
	i++
	// Preferred form: everything after `--` is the command.
	for j := i; j < len(args); j++ {
		if args[j] == "--" {
			return analyzeSegment(args[j+1:], depth+1)
		}
	}
	// Legacy form without `--`: skip flags and the pod name.
	i = skipFlags(args, i, kubectlValueFlags)
	i++ // pod name
	if i >= len(args) {
		return "", "", false
	}
	return analyzeSegment(args[i:], depth+1)
}

// skipFlags advances past leading flag tokens, consuming a following value for
// flags listed in valueFlags (unless the value is attached with `=`).
func skipFlags(tokens []string, i int, valueFlags map[string]bool) int {
	for i < len(tokens) {
		tok := tokens[i]
		if !strings.HasPrefix(tok, "-") || tok == "-" || tok == "--" {
			return i
		}
		i++
		if valueFlags == nil || strings.Contains(tok, "=") {
			continue
		}
		if valueFlags[tok] && i < len(tokens) {
			i++
		}
	}
	return i
}

func dbArgsAllHarmless(args []string) bool {
	if len(args) == 0 {
		return false // bare client would open an interactive SQL session
	}
	for _, a := range args {
		if !dbClientHarmlessArgs[a] {
			return false
		}
	}
	return true
}

// isEnvAssignment reports whether tok looks like NAME=value.
func isEnvAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := tok[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// commandBasename strips any directory prefix so /usr/lib/postgresql/16/bin/psql
// matches psql.
func commandBasename(tok string) string {
	if idx := strings.LastIndexByte(tok, '/'); idx >= 0 {
		return tok[idx+1:]
	}
	return tok
}

func looksLikeDuration(tok string) bool {
	return len(tok) > 0 && tok[0] >= '0' && tok[0] <= '9'
}

// splitShellSegments splits a command line into simple-command token lists,
// respecting single/double quotes and backslash escapes. Segment boundaries
// are unquoted `;`, `|`, `&`, `(`, `)`, and newlines. Command substitution
// (`$(` and backticks) always starts a new segment — even inside double
// quotes, where it still executes.
func splitShellSegments(s string) [][]string {
	var segments [][]string
	var current []string
	var word strings.Builder
	wordStarted := false

	flushWord := func() {
		if wordStarted {
			current = append(current, word.String())
			word.Reset()
			wordStarted = false
		}
	}
	flushSegment := func() {
		flushWord()
		if len(current) > 0 {
			segments = append(segments, current)
			current = nil
		}
	}

	var quote byte // 0, '\'' or '"'
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				word.WriteByte(c)
				wordStarted = true
			}
		case c == '\\' && quote != '\'':
			if i+1 < len(s) {
				i++
				word.WriteByte(s[i])
				wordStarted = true
			}
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			// command substitution runs even inside double quotes
			flushSegment()
			quote = 0
			i++
		case c == '`':
			flushSegment()
			quote = 0
		case quote == '"':
			if c == '"' {
				quote = 0
			} else {
				word.WriteByte(c)
				wordStarted = true
			}
		case c == '\'' || c == '"':
			quote = c
			wordStarted = true
		case c == ';' || c == '|' || c == '&' || c == '(' || c == ')' || c == '\n':
			flushSegment()
		case c == ' ' || c == '\t' || c == '\r':
			flushWord()
		default:
			word.WriteByte(c)
			wordStarted = true
		}
	}
	flushSegment()
	return segments
}
