# Troubleshooting

Use the failure boundary first: did `sshx` fail before the remote command ran, or did the remote command run and exit non-zero?

## Get Structured Error Details

```bash
sshx -h=prod-web --json "systemctl is-active nginx"
```

Look at:

- `success`
- `exit_code`
- `error_kind`
- `stderr`
- `auth_method`

An `sshx`-level failure in JSON mode has `exit_code: -1` and a non-empty `error_kind`.

## Host Key Errors

Symptoms:

- Unknown host key.
- Changed host key.
- Connection aborts before authentication.

Checks:

```bash
ssh-keygen -F prod-web
ssh-keyscan -H prod-web
```

Fix only after confirming the host is expected. Do not jump straight to `--insecure-hostkey`.

## Authentication Errors

Check the resolved host and selected key:

```bash
sshx -h=prod-web --dry-run --json "whoami"
```

Common causes:

- Wrong user in `~/.sshx/settings.json`.
- Wrong per-host key path.
- Key file has bad permissions.
- Server does not allow the selected authentication method.
- You expected keyring sudo password to act as an SSH login password.

Keyring passwords are for sudo auto-fill. They are not silently used as SSH login passwords.

## Sudo Does Not Auto-Fill

`sshx` only auto-fills sudo when the command starts with `sudo`.

Works:

```bash
sshx -h=prod-web -pk=prod-web-sudo "sudo whoami"
```

Does not trigger auto-fill:

```bash
sshx -h=prod-web "sh -c 'sudo whoami'"
```

Check that the password key exists:

```bash
sshx --password-check=prod-web-sudo
```

## A Command Is Blocked

Blocked commands are usually safety-check failures.

```bash
sshx -h=prod-web --dry-run --json "sudo rm -rf /"
```

If a privileged or destructive command is genuinely intended, review it, record the reason, and use `--force` only for that invocation.

## Script Hangs

Set a timeout:

```bash
sshx -h=prod-web --timeout=30s --json "long-running-command"
```

If the command requires terminal behavior, use `--pty`, but remember that PTY mode is less suitable for structured automation.

## JSON Output Is Not Parseable

In normal JSON mode, stdout should contain one JSON object and diagnostics should stay on stderr. Check for these issues:

- The command was run with `--pty`.
- A wrapper script printed extra text around the `sshx` call.
- The caller mixed stdout and stderr.

## SFTP Path Problems

Use local path rules only for local files. Use slash-separated remote paths for remote targets:

```bash
sshx -h=prod-web --upload=./file.txt --to=/tmp/file.txt
```

## Audit Events Are Missing

Check whether audit was disabled:

```bash
env | grep SSHX_NO_AUDIT
```

Check the output location:

```bash
ls ~/.sshx/audit
```

If using a project-local location:

```bash
sshx -h=prod-web --audit-output=./.sshx-audit "uptime"
ls ./.sshx-audit
```

## Command Not Found

Check installation:

```bash
command -v sshx
sshx --version
```

If installed with Go, confirm `~/go/bin` or your `GOPATH/bin` is in `PATH`.
