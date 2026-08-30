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

On a headless host, Secret Service is often missing. sshx will not silently
write a file. Opt in:

```bash
export SSHX_SECRET_BACKEND=local-vault
export SSHX_VAULT_PASSPHRASE='…'
sshx --password-set=prod-web-sudo
sshx --password-check=prod-web-sudo
```

`--password-get` is refused for the local vault. Dry-run JSON should show
`secret_backend: "local-vault"`.

## A Command Is Blocked

Blocked commands are usually safety-check failures.

```bash
sshx -h=prod-web --dry-run --json "sudo rm -rf /"
```

If a privileged or destructive command is genuinely intended, review it, record the reason, and use `--force` only for that invocation.

## Login Types Extra Characters

Symptoms: after `sshx login`, each keystroke appears more than once. Extra
copies are often dim, gray, or pink. Tab completion or zsh-autosuggestions
look garbled.

Update sshx first. Older builds sent a sparse PTY mode list (echo only), which
can make remote zsh reprint typed characters.

If it still happens in the Cursor or VS Code integrated terminal, that
emulator's **local echo** (type-ahead) draws predicted keystrokes in a dim
color. It turns itself off for `vim`/`tmux`, but not for `sshx`, and it
fights zsh-autosuggestions:

```json
{
  "terminal.integrated.localEchoExcludePrograms": [
    "vim",
    "vi",
    "nano",
    "tmux",
    "ssh",
    "sshx"
  ]
}
```

To disable the feature entirely: `"terminal.integrated.localEchoEnabled": false`.

Compare with `ssh` in the **same** terminal. If OpenSSH glitches too, this is
the emulator, not sshx.

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

## macOS Keychain Prompts During Development

Symptoms (contributors building sshx from source on macOS):

- Every rebuilt binary triggers a Keychain authorization dialog when it reads
  a stored password.
- Real-keyring E2E runs interrupt with GUI prompts.

Cause: Keychain item ACLs are bound to the binary's code signature. Each
rebuild produces a new ad-hoc signature, so previously granted access no
longer matches. macOS has no global per-app allowlist; the two supported
mechanisms are a stable signing identity or an ephemeral test keychain.

Fix 1 — ephemeral test keychain for E2E runs (recommended for tests):

```bash
make test-keychain-macos
```

This mirrors CI: it creates a throwaway keychain, makes it the user default,
sets the key partition list so command-line tools need no GUI approval, runs
the E2E suite with `SSHX_E2E_REAL_KEYRING=1`, and always restores your
original keychain configuration afterwards.

Fix 2 — stable self-signed identity for day-to-day manual use:

1. Open Keychain Access → Certificate Assistant → Create a Certificate.
   Name it `sshx-dev`, set Certificate Type to `Code Signing`.
2. Sign every dev build with it:

   ```bash
   codesign -f -s sshx-dev ./bin/sshx
   ```

3. On the next Keychain prompt choose "Always Allow". Because the signing
   identity now stays constant across rebuilds, the approval persists.

Note: routine unit tests never touch the real Keychain — the `sshx_e2e` build
tag swaps in a file-backed isolated keyring, and the E2E harness only uses the
OS keyring when `SSHX_E2E_REAL_KEYRING=1` is set.
