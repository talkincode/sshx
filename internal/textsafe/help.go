package textsafe

// HelpDocument is the machine-readable usage surface for sshx text --help --json.
type HelpDocument struct {
	SchemaVersion string       `json:"schema_version"`
	Verb          string       `json:"verb"`
	Summary       string       `json:"summary"`
	Workflow      []string     `json:"workflow"`
	Sources       []HelpFlag   `json:"sources"`
	Filters       []HelpFlag   `json:"filters"`
	Windows       []HelpFlag   `json:"windows"`
	Bounds        []HelpFlag   `json:"bounds"`
	Presets       []HelpPreset `json:"presets"`
	Examples      []string     `json:"examples"`
}

// HelpFlag documents one CLI flag.
type HelpFlag struct {
	Flag        string `json:"flag"`
	Description string `json:"description"`
}

// HelpPreset documents a lexical preset.
type HelpPreset struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Help returns the canonical Agent-facing usage document.
func Help() HelpDocument {
	return HelpDocument{
		SchemaVersion: HelpSchemaVersion,
		Verb:          "text",
		Summary:       "Dissect a remote text file or systemd journal into bounded, redacted hits. Prefer this over sshx run grep/journalctl pipelines.",
		Workflow: []string{
			"sshx text --help or sshx text --help --json — read sources, presets, and bounds",
			"sshx text -h=<host> --path=/var/log/app.log --preset=exception --json — take exception blocks and counts first",
			"sshx text -h=<host> --path=/var/log/app.log --around-line=<hit.start_line> --context=5 --json — slice the interesting window",
			"sshx --download only when you need an incident archive, not for live diagnosis",
		},
		Sources: []HelpFlag{
			{Flag: "--path=/abs/file", Description: "Stream a remote regular file over SFTP (default scan=end, last 8MiB). Symlinks, directories, and binary files are refused."},
			{Flag: "--journal=UNIT", Description: "Stream sshx-owned journalctl for one systemd unit. Agent does not compose journalctl flags."},
			{Flag: "--sudo", Description: "Read with sudo -S when the SSH user cannot open the file or journal. Password is never interpolated."},
		},
		Filters: []HelpFlag{
			{Flag: "--preset=exception,error,panic,oom,http5xx", Description: "Lexical presets. Default when no preset/pattern/window is set: exception,error,panic,oom."},
			{Flag: "--pattern=RE2", Description: "Optional linear-time regexp applied after presets. Go regexp (RE2), not PCRE."},
		},
		Windows: []HelpFlag{
			{Flag: "--context=N", Description: "Neighbor lines around line hits (0..20), like grep -C."},
			{Flag: "--around-line=L", Description: "Exact slice around a previous hit line (window-relative unless --scan=start)."},
			{Flag: "--offset=L --limit=N", Description: "Line window inside the scanned bytes."},
			{Flag: "--tail=N", Description: "Keep only the last N lines of the scanned window."},
			{Flag: "--scan=start|end", Description: "File scan origin. Default end. start assigns file-absolute line numbers."},
			{Flag: "--since= --until=", Description: "Journal time bounds (journalctl syntax without shell metacharacters)."},
		},
		Bounds: []HelpFlag{
			{Flag: "--max-hits=N", Description: "Returned hits cap (default 20). stats.total_hits may be larger."},
			{Flag: "--max-bytes=N", Description: "Returned hit text cap (default 64KiB)."},
			{Flag: "--max-scan-bytes=N", Description: "Remote bytes scanned (default 8MiB)."},
			{Flag: "--no-redact", Description: "Keep secret-shaped spans. Default redacts password=/token=/bearer/JWT."},
		},
		Presets: []HelpPreset{
			{Name: "exception", Description: "Python/Java/Go/Node/Rust exception blocks as one hit, not per-line fragments."},
			{Name: "error", Description: "ERROR/FATAL/CRITICAL/emerg lines outside an exception block."},
			{Name: "panic", Description: "panic / fatal runtime abort lines."},
			{Name: "oom", Description: "Out-of-memory killer and language OOM signatures."},
			{Name: "http5xx", Description: "HTTP 5xx status tokens in common access-log shapes."},
		},
		Examples: []string{
			"sshx text --help --json",
			"sshx text -h=prod-web --path=/var/log/nginx/error.log --preset=exception --json",
			"sshx text -h=prod-web --journal=nginx.service --since=1h --preset=error --json",
			"sshx text -h=prod-web --path=/var/log/app.log --around-line=8821 --context=8 --json",
			"sshx text -h=prod-web --path=/var/log/app.log --pattern='timeout after' --context=2 --json",
		},
	}
}
