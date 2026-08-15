package sqlsafe

import "fmt"

// Options carries the caller-controlled safety levers for one execution.
type Options struct {
	// Force allows DDL statements (still never the hard-blocked ones).
	Force bool
	// AllowFullTable allows UPDATE/DELETE without a top-level WHERE clause.
	AllowFullTable bool
	// NoBackup disables pre-change backups. It requires Force.
	NoBackup bool
	// RowThreshold is the estimated-row boundary between a row-level CSV
	// backup and a full table dump. Zero uses DefaultRowThreshold.
	RowThreshold int64
}

// DefaultRowThreshold bounds row-level backups: estimates above it switch to a
// full table dump.
const DefaultRowThreshold = 1000

func (o Options) rowThreshold() int64 {
	if o.RowThreshold > 0 {
		return o.RowThreshold
	}
	return DefaultRowThreshold
}

// CheckPolicy enforces the execution gates on a classified statement. It
// returns a *BlockedError describing the first violated gate, or nil.
func CheckPolicy(cls *Classification, opts Options) error {
	switch cls.Class {
	case ClassRead:
		return nil
	case ClassDML:
		if (cls.Verb == "UPDATE" || cls.Verb == "DELETE") && !cls.HasWhere && !opts.AllowFullTable {
			return &BlockedError{Reason: fmt.Sprintf(
				"%s without a top-level WHERE clause affects every row in %q; add a WHERE clause or pass --allow-full-table",
				cls.Verb, cls.Table)}
		}
		if opts.NoBackup && !opts.Force {
			return &BlockedError{Reason: "--no-backup on a data-modifying statement requires --force"}
		}
		return nil
	case ClassDDL:
		if !opts.Force {
			return &BlockedError{Reason: fmt.Sprintf(
				"%s is a DDL/maintenance statement; re-run with --force to confirm", cls.Verb)}
		}
		if cls.Destructive && !opts.NoBackup {
			return &BlockedError{Reason: fmt.Sprintf(
				"%s cannot be paired with an atomic pre-change backup; guarded execution requires --force --no-backup for this operation",
				cls.Verb)}
		}
		return nil
	default:
		return &BlockedError{Reason: fmt.Sprintf("statement class %q is not executable", cls.Class)}
	}
}

// BackupKind names the backup strategy chosen for one statement.
type BackupKind string

const (
	// BackupNone means no pre-change backup is taken.
	BackupNone BackupKind = "none"
	// BackupRows snapshots exactly the affected rows to a CSV file before the
	// change using the statement's own WHERE clause.
	BackupRows BackupKind = "rows"
	// BackupTable snapshots the whole target table to CSV before the change.
	BackupTable BackupKind = "table"
)

// BackupPlan describes the pre-change backup decided for one statement.
type BackupPlan struct {
	Kind   BackupKind `json:"kind"`
	Table  string     `json:"table,omitempty"`
	Reason string     `json:"reason"`
}

// DecideBackup chooses the backup strategy for a classified statement given
// the EXPLAIN row estimate (pass a negative estimate when unknown, e.g. for a
// local dry-run plan). It is fail-closed: when a backup is required but the
// target table could not be extracted, it returns a *BlockedError.
func DecideBackup(cls *Classification, estimatedRows int64, opts Options) (BackupPlan, error) {
	if opts.NoBackup {
		return BackupPlan{Kind: BackupNone, Reason: "backups disabled by --no-backup"}, nil
	}

	switch {
	case cls.Class == ClassRead:
		return BackupPlan{Kind: BackupNone, Reason: "read-only statement"}, nil
	case cls.Verb == "INSERT" && !cls.ComplexSource:
		return BackupPlan{Kind: BackupNone, Reason: "INSERT is reversible by deleting the inserted rows"}, nil
	case cls.Class == ClassDDL && !cls.Destructive:
		return BackupPlan{Kind: BackupNone, Reason: "non-destructive DDL/maintenance statement"}, nil
	}

	// Everything below destroys or replaces existing data and needs a backup
	// target. Fail closed when no single table could be extracted.
	if cls.Table == "" {
		return BackupPlan{}, &BlockedError{Reason: fmt.Sprintf(
			"cannot determine the backup target table for this %s statement; simplify the statement or re-run with --force --no-backup to explicitly skip the backup",
			cls.Verb)}
	}

	if cls.Destructive || cls.ComplexSource {
		return BackupPlan{Kind: BackupTable, Table: cls.Table,
			Reason: "affected rows cannot be reproduced by a simple SELECT; taking a full-table CSV snapshot"}, nil
	}
	if !cls.HasWhere {
		return BackupPlan{Kind: BackupTable, Table: cls.Table,
			Reason: "full-table change; taking a full-table CSV snapshot"}, nil
	}
	if containsNewline(cls.WhereClause) {
		return BackupPlan{Kind: BackupTable, Table: cls.Table,
			Reason: "WHERE clause spans multiple lines; taking a full-table CSV snapshot instead of a row snapshot"}, nil
	}
	if estimatedRows >= 0 && estimatedRows > opts.rowThreshold() {
		return BackupPlan{Kind: BackupTable, Table: cls.Table,
			Reason: fmt.Sprintf("estimated %d affected rows exceeds the row-backup threshold (%d); taking a full-table CSV snapshot", estimatedRows, opts.rowThreshold())}, nil
	}
	return BackupPlan{Kind: BackupRows, Table: cls.Table,
		Reason: "snapshotting affected rows selected by the statement's WHERE clause"}, nil
}

func containsNewline(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return true
		}
	}
	return false
}
