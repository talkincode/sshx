# Guarded File Apply

`sshx apply` replaces one remote regular file. It is the file equivalent of `sshx sql`: classify the target, check a hash precondition, write a backup, then atomically replace the file. Reload and restart stay outside this command.

```bash
sshx apply -h=prod-web --path=/etc/nginx/nginx.conf --from=./nginx.conf \
    --expect-sha256=<current> --sudo --json
```

## What Apply Does

1. Refuse anything that is not a clean absolute regular-file path.
2. Block `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` unless `--force --bypass-reason=` is explicit.
3. Read the current file (if it exists) and compare `--expect-sha256` when provided.
4. Copy the current file to `~/.sshx/file-backups/` unless `--no-backup --force` is set.
5. Write a same-directory temp file, preserve mode and owner, then rename over the target.
6. Return `changed`, `before_sha256`, `after_sha256`, `backup.path`, and `completion`.

If the remote content already matches the payload, apply succeeds with `changed=false` and does not write a backup.

## Privileged Paths

SFTP runs as the SSH user. Use `--sudo` when the target is not writable by that user. sshx stages the payload under the remote home directory, then runs a privileged stdin script to install it. The script is never left on the host.

```bash
sshx apply --target=prod-web --path=/etc/nginx/nginx.conf \
    --from=./nginx.conf --sudo --json
```

Validation and service reload are separate `sshx run` invocations:

```bash
sshx run --target=prod-web --json -- "sudo nginx -t"
sshx run --target=prod-web --json -- "sudo systemctl reload nginx"
```

## Preview

```bash
sshx apply -h=prod-web --path=/etc/nginx/nginx.conf --from=./nginx.conf --dry-run --json
```

Dry-run hashes the local file and prints the local plan. It does not connect or mutate the remote file.

## When To Keep Using SFTP

Use `--upload` / `--download` for moving bytes without a backup contract. Use `apply` when an existing remote file may be overwritten and the caller needs a hash, a backup, and a decidable `changed` result.
