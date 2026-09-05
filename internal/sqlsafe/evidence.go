package sqlsafe

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
)

// Evidence separates a client's row count from a committed, observed change.
// Protocol verification acknowledges completion; it is not a postimage check.
type Evidence struct {
	AffectedRowsSemantics string `json:"affected_rows_semantics,omitempty"`
	StateChange           string `json:"state_change"`
	Commit                string `json:"commit"`
	Verification          string `json:"verification"`
	VerificationMethod    string `json:"verification_method,omitempty"`
	EffectVerification    string `json:"effect_verification"`
	BackupStatus          string `json:"backup_status"`
	BackupConsistency     string `json:"backup_consistency,omitempty"`
	BackupFormat          string `json:"backup_format,omitempty"`
	OutcomeUncertain      bool   `json:"outcome_uncertain"`
}

// Protocol describes a single invocation's private, nonce-bound output frames.
// Neither SQL result rows nor unframed command tags are trusted as evidence.
type Protocol struct {
	Token      string
	Engine     string
	Verb       string
	Mutation   bool
	Affected   bool
	Backup     bool
	BackupForm string
}

type Observation struct {
	Started      bool
	BackupReady  bool
	AffectedRows *int64
	Committed    bool
	Stdout       string
}

type ProtocolError struct{ Reason string }

func (e *ProtocolError) Error() string { return "SQL output protocol: " + e.Reason }

type VerificationError struct{ Reason string }

func (e *VerificationError) Error() string { return "SQL evidence verification: " + e.Reason }

func newProtocol(engine, stmt string, mutation, backup bool) *Protocol {
	p := &Protocol{
		Token: rand.Text(), Engine: engine, Verb: mutationVerb(stmt),
		Mutation: mutation, Backup: backup,
	}
	if cls, err := ClassifyFor(engine, stmt); err == nil {
		p.Verb = cls.Verb
		p.Affected = cls.Class == ClassDML
	}
	return p
}

func (p *Protocol) prefix() string { return "__SSHX_SQL_V1_" + p.Token + "__|" }

func (p *Protocol) frame(event, value string) string {
	return p.prefix() + event + "|" + value
}

func (p *Protocol) psql(event, value string) string {
	return "\\echo " + p.frame(event, value)
}

func (p *Protocol) sqlite(event, value string) string {
	return ".print " + p.frame(event, value)
}

func (p *Protocol) mysql(event, value string) string {
	return "SELECT '" + p.frame(event, value) + "';"
}

// Parse validates ordering and uniqueness, preserving only facts seen before a
// damaged frame. Missing acknowledgements never become evidence of rollback.
func (p *Protocol) Parse(output string) (Observation, error) {
	var o Observation
	var visible strings.Builder
	var parseErr error
	for _, line := range strings.SplitAfter(output, "\n") {
		text := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if !strings.HasPrefix(text, p.prefix()) {
			visible.WriteString(line)
			continue
		}
		if parseErr != nil {
			continue
		}
		event, value, ok := strings.Cut(strings.TrimPrefix(text, p.prefix()), "|")
		if !ok || strings.Contains(value, "|") {
			parseErr = &ProtocolError{Reason: "malformed frame"}
			continue
		}
		switch event {
		case "start":
			if value != "1" || o.Started {
				parseErr = &ProtocolError{Reason: "invalid or repeated start"}
			} else {
				o.Started = true
			}
		case "backup":
			if value != "ready" || !p.Backup || !o.Started || o.BackupReady || o.AffectedRows != nil || o.Committed {
				parseErr = &ProtocolError{Reason: "unexpected backup acknowledgement"}
			} else {
				o.BackupReady = true
			}
		case "affected":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 || !p.Affected || !o.Started || o.AffectedRows != nil || o.Committed {
				parseErr = &ProtocolError{Reason: "invalid or repeated affected-row count"}
			} else if p.Backup && !o.BackupReady {
				parseErr = &VerificationError{Reason: "mutation count precedes required backup"}
			} else {
				o.AffectedRows = &n
			}
		case "commit":
			if value != "acknowledged" || !o.Started || o.Committed {
				parseErr = &ProtocolError{Reason: "invalid or repeated commit acknowledgement"}
			} else {
				o.Committed = true
			}
		default:
			parseErr = &ProtocolError{Reason: "unknown frame"}
		}
	}
	o.Stdout = visible.String()
	if parseErr != nil {
		return o, parseErr
	}
	if !o.Started {
		return o, &ProtocolError{Reason: "missing start frame"}
	}
	if p.Backup && !o.BackupReady {
		return o, &VerificationError{Reason: "required backup was not acknowledged"}
	}
	if p.Affected && o.AffectedRows == nil {
		return o, &VerificationError{Reason: "affected-row evidence was not acknowledged"}
	}
	if !o.Committed {
		return o, &VerificationError{Reason: "commit was not acknowledged"}
	}
	return o, nil
}

// Summarize is deliberately conservative about zero/matched rows. Unguarded
// mutations may have triggers or effects that the direct row count cannot see.
func (p *Protocol) Summarize(o Observation, verified bool) Evidence {
	e := Evidence{
		StateChange: "unknown", Commit: "unknown", Verification: "unknown",
		BackupStatus: "not_required", VerificationMethod: "client_protocol",
		EffectVerification: "unsupported",
		OutcomeUncertain:   p.Mutation && !o.Committed,
	}
	if !p.Mutation {
		e.StateChange = "unchanged"
		e.EffectVerification = "not_required"
	}
	if p.Affected {
		switch p.Engine {
		case EnginePostgres:
			e.AffectedRowsSemantics = "postgres_command_tag"
		case EngineSQLite:
			e.AffectedRowsSemantics = "sqlite_changes"
		case EngineMySQL:
			e.AffectedRowsSemantics = "mysql_row_count"
		}
	}
	if p.Backup {
		e.BackupStatus = "planned"
		e.BackupFormat = p.BackupForm
		if o.BackupReady {
			e.BackupStatus = "ready"
			e.BackupConsistency = "locked_preimage"
		}
	}
	if o.Committed {
		e.Commit = "acknowledged"
	}
	if verified {
		e.Verification = "protocol_verified"
	}
	return e
}

func initialEvidence() Evidence {
	return Evidence{StateChange: "unknown", Commit: "not_started", Verification: "not_performed", EffectVerification: "not_performed", BackupStatus: "not_required"}
}

// InitialEvidence is useful when admission fails before a SQL client starts.
func InitialEvidence() Evidence { return initialEvidence() }

func protocolFailureCommand() RemoteCommand {
	return RemoteCommand{Command: "false"}
}

func statementSQL(stmt string) string {
	lastLine := stmt[strings.LastIndex(stmt, "\n")+1:]
	if strings.Contains(lastLine, "--") || strings.Contains(lastLine, "#") {
		// Never let a trailing comment swallow the terminator and defer the
		// statement until after a client meta-command acknowledgement.
		return stmt + "\n;"
	}
	return stmt + ";"
}

func unsupportedGuard(engine, reason string) error {
	return &BlockedError{Reason: fmt.Sprintf("%s guarded backup is unsupported: %s; use --force --no-backup only after an independent backup", engine, reason)}
}
