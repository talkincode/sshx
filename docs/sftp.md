# SFTP Workflows

`sshx` supports one-shot SFTP actions for common file tasks. It is not an interactive file manager; each invocation performs one clear upload, download, list, mkdir, or remove operation.

## Upload A File

```bash
sshx -h=prod-web --upload=./deploy/nginx.conf --to=/tmp/nginx.conf
```

Safe production pattern:

```bash
# Upload to a temporary path first
sshx -h=prod-web --upload=./deploy/nginx.conf --to=/tmp/nginx.conf

# Inspect the uploaded file before moving it into place
sshx -h=prod-web "sudo install -m 0644 /tmp/nginx.conf /etc/nginx/nginx.conf"
sshx -h=prod-web "sudo nginx -t"
sshx -h=prod-web "sudo systemctl reload nginx"
```

## Download A File

```bash
sshx -h=prod-web --download=/var/log/nginx/error.log --to=./error.log
```

Incident collection example:

```bash
mkdir -p incident-2026-07-01/prod-web
sshx -h=prod-web --download=/var/log/nginx/error.log --to=incident-2026-07-01/prod-web/error.log
sshx -h=prod-web --download=/etc/os-release --to=incident-2026-07-01/prod-web/os-release
```

## List And Create Directories

```bash
sshx -h=prod-web --list=/var/log
sshx -h=prod-web --mkdir=/tmp/sshx-upload
```

## Remove A Remote File

```bash
sshx -h=prod-web --rm=/tmp/old-upload.txt
```

Treat remote deletion as production change. Prefer listing the parent directory first:

```bash
sshx -h=prod-web --list=/tmp
sshx -h=prod-web --rm=/tmp/old-upload.txt
```

## Path Boundary

Local paths use your local operating system rules. Remote paths are SFTP paths and should be written as slash-separated remote paths, even when `sshx` is run from Windows.

```bash
# Local Windows path, remote POSIX path
sshx -h=prod-web --upload=C:\Users\alice\release.zip --to=/tmp/release.zip
```

## When To Use Plain SSH Instead

Use an SSH command when the operation needs remote validation or privilege changes:

```bash
sshx -h=prod-web "sudo ls -l /etc/nginx"
sshx -h=prod-web "sudo install -m 0644 /tmp/nginx.conf /etc/nginx/nginx.conf"
```

Use SFTP for direct file movement. Use remote commands for checks, ownership changes, service reloads, and cleanup that requires sudo.
