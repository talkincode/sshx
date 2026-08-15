package sqlsafe

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// CredSource describes where database credentials live on the remote host.
// Production databases frequently keep credentials in a container's
// environment or an env file next to the deployment instead of any local
// keyring; sshx resolves them remotely at execution time and never asks the
// operator to copy secrets around.
type CredSource struct {
	// Kind is "docker" (read the container's environment via docker inspect)
	// or "env-file" (read a KEY=VALUE file on the remote host).
	Kind string
	// Container is the docker container name or ID (Kind == "docker").
	Container string
	// Path is the remote env file path (Kind == "env-file").
	Path string
}

// Credentials is the outcome of resolving a CredSource. Every field is
// optional except Password; explicit CLI flags always win over these values.
type Credentials struct {
	User     string `json:"user,omitempty"`
	Password string `json:"password"`
	Database string `json:"database,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     string `json:"port,omitempty"`
}

var containerNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// ParseCredSource parses a --db-cred-from specification.
// Supported forms: "docker:<container>" and "env-file:<remote path>".
func ParseCredSource(spec string) (CredSource, error) {
	kind, rest, ok := strings.Cut(spec, ":")
	if !ok || rest == "" {
		return CredSource{}, fmt.Errorf("invalid --db-cred-from %q (use docker:<container> or env-file:<path>)", spec)
	}
	switch kind {
	case "docker":
		if !containerNameRE.MatchString(rest) {
			return CredSource{}, fmt.Errorf("invalid container name %q in --db-cred-from", rest)
		}
		return CredSource{Kind: "docker", Container: rest}, nil
	case "env-file":
		if strings.ContainsAny(rest, "\n\r") {
			return CredSource{}, fmt.Errorf("invalid env file path in --db-cred-from")
		}
		return CredSource{Kind: "env-file", Path: rest}, nil
	default:
		return CredSource{}, fmt.Errorf("unsupported --db-cred-from kind %q (use docker: or env-file:)", kind)
	}
}

// String returns the canonical spec form (also used as the cache identity).
func (s CredSource) String() string {
	switch s.Kind {
	case "docker":
		return "docker:" + s.Container
	case "env-file":
		return "env-file:" + s.Path
	default:
		return ""
	}
}

// ExtractionCommand returns the remote command that prints the credential
// environment, one KEY=VALUE per line. The command itself contains no secret;
// its stdout does and must never be logged or audited.
func (s CredSource) ExtractionCommand() (string, error) {
	switch s.Kind {
	case "docker":
		if !containerNameRE.MatchString(s.Container) {
			return "", fmt.Errorf("invalid container name %q", s.Container)
		}
		return "docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' " + s.Container, nil
	case "env-file":
		if s.Path == "" || strings.ContainsAny(s.Path, "\n\r") {
			return "", fmt.Errorf("invalid env file path")
		}
		return "cat " + maybeQuote(s.Path), nil
	default:
		return "", fmt.Errorf("unsupported credential source kind %q", s.Kind)
	}
}

// Credential environment keys in priority order (first match wins).
var (
	credUserKeys     = []string{"PGUSER", "POSTGRES_USER", "DB_USER", "DATABASE_USER"}
	credPasswordKeys = []string{"PGPASSWORD", "POSTGRES_PASSWORD", "DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD"}
	credDatabaseKeys = []string{"PGDATABASE", "POSTGRES_DB", "DB_NAME", "DATABASE_NAME"}
	credHostKeys     = []string{"PGHOST", "DB_HOST", "DATABASE_HOST"}
	credPortKeys     = []string{"PGPORT", "DB_PORT", "DATABASE_PORT"}
	credURLKeys      = []string{"DATABASE_URL", "POSTGRES_URL", "POSTGRESQL_URL", "PG_URL"}
)

// ParseCredOutput extracts credentials from KEY=VALUE lines (docker inspect
// env output or an env file). Discrete keys win over a connection URL. The
// error never embeds raw output, which may contain unrelated secrets.
func ParseCredOutput(output string) (Credentials, error) {
	env := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if _, dup := env[key]; dup {
			continue // first occurrence wins
		}
		env[key] = unquoteEnvValue(strings.TrimSpace(value))
	}

	creds := Credentials{
		User:     firstEnv(env, credUserKeys),
		Password: firstEnv(env, credPasswordKeys),
		Database: firstEnv(env, credDatabaseKeys),
		Host:     firstEnv(env, credHostKeys),
		Port:     firstEnv(env, credPortKeys),
	}
	if creds.Password == "" {
		if u := firstEnv(env, credURLKeys); u != "" {
			if fromURL, err := parseDatabaseURL(u); err == nil {
				merge(&creds, fromURL)
			}
		}
	}
	if creds.Password == "" {
		return Credentials{}, fmt.Errorf(
			"no database password found in credential source (looked for %s and a connection URL)",
			strings.Join(credPasswordKeys, ", "))
	}
	return creds, nil
}

func firstEnv(env map[string]string, keys []string) string {
	for _, k := range keys {
		if v := env[k]; v != "" {
			return v
		}
	}
	return ""
}

func merge(dst *Credentials, src Credentials) {
	if dst.User == "" {
		dst.User = src.User
	}
	if dst.Password == "" {
		dst.Password = src.Password
	}
	if dst.Database == "" {
		dst.Database = src.Database
	}
	if dst.Host == "" {
		dst.Host = src.Host
	}
	if dst.Port == "" {
		dst.Port = src.Port
	}
}

func parseDatabaseURL(raw string) (Credentials, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Credentials{}, fmt.Errorf("invalid connection URL")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return Credentials{}, fmt.Errorf("unsupported connection URL scheme %q", u.Scheme)
	}
	creds := Credentials{
		Host:     u.Hostname(),
		Port:     u.Port(),
		Database: strings.TrimPrefix(u.Path, "/"),
	}
	if u.User != nil {
		creds.User = u.User.Username()
		creds.Password, _ = u.User.Password()
	}
	return creds, nil
}

func unquoteEnvValue(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// ValidateContainerName bounds the docker container reference used in argv.
func ValidateContainerName(name string) error {
	if !containerNameRE.MatchString(name) {
		return &BlockedError{Reason: fmt.Sprintf("container name %q contains unsupported characters", name)}
	}
	return nil
}
