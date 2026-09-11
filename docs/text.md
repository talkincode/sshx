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
