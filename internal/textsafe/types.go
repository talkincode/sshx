// Package textsafe is the fail-closed remote text dissection engine used by
// sshx text. It classifies log lines, extracts exception blocks, applies
// bounded filters, and redacts secret-shaped spans. It never shells out.
package textsafe

import (
	"fmt"
	"strings"
)

const (
	SchemaVersion     = "sshx.text.v1"
	HelpSchemaVersion = "sshx.text.help.v1"

	DefaultMaxHits      = 20
	DefaultMaxBytes     = 64 << 10
	DefaultMaxScanBytes = 8 << 20
	MaxContext          = 20
	MaxBlockLines       = 80
	MaxLineBytes        = 16 << 10
	DefaultJournalLines = 2000

	KindExceptionBlock = "exception_block"
	KindErrorLine      = "error_line"
	KindPanicLine      = "panic_line"
	KindOOMLine        = "oom_line"
	KindHTTP5xx        = "http5xx"
	KindPattern        = "pattern"
	KindSlice          = "slice"

	SourceFile    = "file"
	SourceJournal = "journal"

	ScanEnd   = "end"
	ScanStart = "start"

	LineOriginWindow = "scanned_window"
	LineOriginFile   = "file"
)

// Request is the local dissection plan. Call Normalize before Scan.
type Request struct {
	Kind             string
	Path             string
	JournalUnit      string
	Since            string
	Until            string
	Presets          []string
	Pattern          string
	Context          int
	AroundLine       int
	Offset           int
	Limit            int
	Tail             int
	Scan             string
	MaxHits          int
	MaxBytes         int
	MaxScanBytes     int64
	Redact           bool
	JournalLines     int
	SkipPartialFirst bool
	WindowStartByte  int64
	FileSize         int64
	defaultedScan    bool
}

// Hit is one returned extraction. Text is already redacted when requested.
type Hit struct {
	Kind      string `json:"kind"`
	Level     string `json:"level,omitempty"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Text      string `json:"text"`
}

// Stats reports scan bounds. TotalHitsExact is false when the scan stopped early.
type Stats struct {
	LinesScanned    int   `json:"lines_scanned"`
	BytesScanned    int64 `json:"bytes_scanned"`
	TotalHits       int   `json:"total_hits"`
	Returned        int   `json:"returned"`
	ExceptionBlocks int   `json:"exception_blocks"`
	TotalHitsExact  bool  `json:"total_hits_exact"`
	WindowStartByte int64 `json:"window_start_byte,omitempty"`
	FileSize        int64 `json:"file_size,omitempty"`
}

// Result is the engine output before host/lifecycle wrapping.
type Result struct {
	Source          SourceInfo `json:"source"`
	Filter          FilterInfo `json:"filter"`
	Stats           Stats      `json:"stats"`
	Hits            []Hit      `json:"hits"`
	Truncated       bool       `json:"truncated"`
	TruncatedReason string     `json:"truncated_reason,omitempty"`
	Redacted        bool       `json:"redacted"`
	LineOrigin      string     `json:"line_origin"`
}

// SourceInfo identifies what was scanned.
type SourceInfo struct {
	Kind            string `json:"kind"`
	Path            string `json:"path,omitempty"`
	JournalUnit     string `json:"journal_unit,omitempty"`
	Since           string `json:"since,omitempty"`
	Until           string `json:"until,omitempty"`
	Scan            string `json:"scan,omitempty"`
	BytesScanned    int64  `json:"bytes_scanned"`
	WindowStartByte int64  `json:"window_start_byte,omitempty"`
	FileSize        int64  `json:"file_size,omitempty"`
}

// FilterInfo records the applied presets and pattern.
type FilterInfo struct {
	Presets []string `json:"presets,omitempty"`
	Pattern string   `json:"pattern,omitempty"`
	Context int      `json:"context,omitempty"`
}

var allowedPresets = map[string]struct{}{
	"exception": {},
	"error":     {},
	"panic":     {},
	"oom":       {},
	"http5xx":   {},
}

// Normalize fills defaults and rejects contradictory options.
func (r *Request) Normalize() error {
	if r == nil {
		return fmt.Errorf("text request is required")
	}
	r.Kind = strings.TrimSpace(r.Kind)
	r.Path = strings.TrimSpace(r.Path)
	r.JournalUnit = strings.TrimSpace(r.JournalUnit)
	r.Since = strings.TrimSpace(r.Since)
	r.Until = strings.TrimSpace(r.Until)
	r.Pattern = strings.TrimSpace(r.Pattern)
	r.Scan = strings.ToLower(strings.TrimSpace(r.Scan))

	switch r.Kind {
	case SourceFile:
		if r.Path == "" {
			return fmt.Errorf("--path is required for a file source")
		}
		if err := ValidateTextPath(r.Path); err != nil {
			return err
		}
		if r.JournalUnit != "" {
			return fmt.Errorf("--path and --journal are mutually exclusive")
		}
	case SourceJournal:
		if r.JournalUnit == "" {
			return fmt.Errorf("--journal is required for a journal source")
		}
		if r.Path != "" {
			return fmt.Errorf("--path and --journal are mutually exclusive")
		}
		if err := ValidateJournalUnit(r.JournalUnit); err != nil {
			return err
		}
		if err := ValidateTimeBound(r.Since); err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
		if err := ValidateTimeBound(r.Until); err != nil {
			return fmt.Errorf("invalid --until: %w", err)
		}
	default:
		return fmt.Errorf("source must be file (--path) or journal (--journal)")
	}

	if r.Scan == "" {
		if r.Kind == SourceFile {
			r.Scan = ScanEnd
			r.defaultedScan = true
		} else {
			r.Scan = ScanStart
		}
	}
	if r.Scan != ScanEnd && r.Scan != ScanStart {
		return fmt.Errorf("--scan must be start or end")
	}

	presets := make([]string, 0, len(r.Presets))
	seen := map[string]struct{}{}
	for _, raw := range r.Presets {
		for _, part := range strings.Split(raw, ",") {
			p := strings.ToLower(strings.TrimSpace(part))
			if p == "" {
				continue
			}
			if _, ok := allowedPresets[p]; !ok {
				return fmt.Errorf("unknown --preset %q (exception, error, panic, oom, http5xx)", p)
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			presets = append(presets, p)
		}
	}
	if len(presets) == 0 && r.Pattern == "" && r.AroundLine == 0 && r.Offset == 0 {
		presets = []string{"exception", "error", "panic", "oom"}
	}
	r.Presets = presets

	if r.Context < 0 {
		return fmt.Errorf("--context cannot be negative")
	}
	if r.Context > MaxContext {
		r.Context = MaxContext
	}
	if r.AroundLine < 0 || r.Offset < 0 || r.Limit < 0 || r.Tail < 0 {
		return fmt.Errorf("line window values cannot be negative")
	}
	if r.AroundLine > 0 && (r.Offset > 0 || r.Limit > 0 || r.Tail > 0) {
		return fmt.Errorf("--around-line cannot be combined with --offset, --limit, or --tail")
	}
	if r.Tail > 0 && (r.Offset > 0 || r.Limit > 0) {
		return fmt.Errorf("--tail cannot be combined with --offset or --limit")
	}
	if r.Offset > 0 && r.Limit == 0 {
		r.Limit = 200
	}
	if r.Limit > 0 && r.Offset == 0 {
		r.Offset = 1
	}

	if r.MaxHits <= 0 {
		r.MaxHits = DefaultMaxHits
	}
	if r.MaxBytes <= 0 {
		r.MaxBytes = DefaultMaxBytes
	}
	if r.MaxScanBytes <= 0 {
		r.MaxScanBytes = DefaultMaxScanBytes
	}
	if r.JournalLines <= 0 {
		r.JournalLines = DefaultJournalLines
	}
	if r.Tail > 0 {
		r.JournalLines = r.Tail
	}
	return nil
}

func (r Request) wantsPreset(name string) bool {
	for _, p := range r.Presets {
		if p == name {
			return true
		}
	}
	return false
}

func (r Request) wantsAnyFilter() bool {
	return len(r.Presets) > 0 || r.Pattern != ""
}
