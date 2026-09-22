# Text Dissection

`sshx text` is the Agent-facing way to extract exception blocks and error
lines from a remote file or systemd journal. It is not a remote `grep`
wrapper and does not accept `--command`.

```bash
sshx text --help
sshx text --help --json
sshx text -h=prod-web --path=/var/log/app.log --preset=exception --json
sshx text -h=prod-web --path=/var/log/app.log --around-line=8821 --context=5 --json
sshx text -h=prod-web --journal=nginx.service --since=1h --preset=error --json
```

## Workflow

1. Read `sshx text --help` (or `--help --json`) for sources, presets, and bounds.
2. Take exception blocks and counts first: `--preset=exception --json`.
3. Slice a hit with `--around-line` and `--context`.
4. Download whole files only when you need an incident archive.

## Sources

Exactly one of:

- `--path=/abs/file` — SFTP stream of a regular file. Default `--scan=end`
  reads the last 8MiB. Symlinks, directories, and binary files are refused.
- `--journal=UNIT` — sshx-owned `journalctl` argv (`--no-pager`,
  `--output=short-iso`, `--unit`, optional `--since`/`--until`). The Agent
  does not compose journalctl flags.

`--sudo` uses `sudo -S` with the host sudo keyring secret on stdin.

## Result

JSON schema `sshx.text.v1`. Branch on `success`, `hits[].kind`,
`stats.total_hits` vs `stats.returned`, `truncated`, `truncated_reason`,
`redacted`, and `line_origin` (`file` or `scanned_window`). Secret-shaped
spans are redacted unless `--no-redact`. Audit events omit hit text.

`stats` also carries the window accounting a caller needs to judge coverage:

| Field                 | Meaning                                                          |
| --------------------- | ---------------------------------------------------------------- |
| `file_size`           | Remote file size when the source is a file (omitted for journal) |
| `window_start_byte`   | First byte the window reads                                      |
| `expected_scan_bytes` | Window budget: the window capped by `--max-scan-bytes`           |

`expected_scan_bytes` is additive and omitted when the source size is unknown
(journal). Compare it with `bytes_scanned`: a scan that stopped early reports
less than it expected, and a scan that hit its budget sets
`truncated_reason=max_scan_bytes` with `total_hits_exact=false`.

## Monitoring

A wide window over a slow link used to look like a hang. `sshx text` now
narrates progress on **stderr** while it scans:

```text
sshx text: scanning 2.0MiB/2097152B of 61.3MiB/64296766B (3%) lines=10240 elapsed=4.1s matches=0
sshx text: warning: scan stopped at its --max-scan-bytes budget after 12.0s (8.0MiB/8388608B scanned, 8.0MiB/8388608B in window); results are partial (total_hits_exact=false). Narrow with --offset=N or --tail=N, pre-filter with --pattern=..., or raise --max-scan-bytes=N.
```

- Progress appears only after a grace period, at most once per second, and
  never for a scan that finishes quickly.
- A scan that stops at its byte budget always warns, so partial results are
  never mistaken for complete ones. A slow scan closes with the same
  `--offset`/`--tail` advice.
- **stdout stays exactly one JSON document.** Progress and advice go to stderr
  only, so `--json` parsing is unaffected.

```bash
# Narrow the window instead of scanning 8MiB to answer a small question
sshx text -h=prod-web --path=/var/log/app.log --offset=41000 --limit=200 --json
```
