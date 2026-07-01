# AGENT.md

Operating guide for humans and AI coding agents working on **sshx**. It defines
what this project is, what it deliberately is *not*, how it is built, and how to
make changes that fit. Read this before making non-trivial changes.

Module: `github.com/talkincode/sshx` · Language: Go 1.24 · License: MIT

---

## 1. Mission

`sshx` is a barrier-free, cross-platform **SSH/SFTP command-line client** with a
built-in **OS-keyring password manager** and **named host configuration**. It
exists to make ad-hoc operations across many remote servers fast and safe:

> One command, multiple servers, zero password hassle.

The core value proposition:

- Run a command (or transfer a file) on a remote host in a single invocation.
- Never type or store passwords in plaintext — they live in the OS keyring and
  sudo passwords are auto-filled.
- Address hosts by a short name instead of full connection details.
- Be secure by default (strict host-key verification, command safety guardrails).

## 2. Goals

1. **Single self-contained binary** — no runtime dependencies, installable via
   `go install`, an install script, or a downloaded release artifact.
2. **Cross-platform parity** — Linux, macOS, and Windows are all first-class.
3. **Secure by default** — strict `known_hosts` verification, keyring-backed
   secrets, sudo password delivered over stdin (never interpolated), and command
   safety checks that block obviously destructive operations.
4. **Low cognitive load** — sensible defaults, named hosts, key-first auth with
   password fallback only when an SSH login password is already provided, and
   helpful error messages.
5. **Multi-server ergonomics** — per-host SSH keys and per-host/per-server
   password keys so one tool covers a whole fleet.
6. **Execution preview** — `--dry-run` explains the local execution plan without
   connecting, executing, reading keyring secrets, or mutating state.
7. **Auditability** — non-dry-run invocations write structured JSONL audit
   events under `~/.sshx/audit` by default, with secrets and stdout/stderr
   excluded.

## 3. Scope & Boundaries (Non-Goals)

`sshx` is intentionally a **focused CLI**. Keeping the surface small is a feature.
Do **not** add the following without an explicit, deliberate decision to expand
the project's mission:

**Out of scope (will not be accepted by default):**

- ❌ **MCP server / Model Context Protocol** — removed on purpose. `sshx` is
  CLI-only. Do not reintroduce an `mcp-stdio` mode or MCP tools.
- ❌ **Daemons / long-running services / connection pools** — every command opens
  a connection, does its work, and exits. There is no background process.
- ❌ **GUI / TUI** — interaction is through flags and stdout/stderr only.
- ❌ **Full OpenSSH replacement** — no interactive login shell multiplexing,
  port forwarding / tunneling, SOCKS proxy, X11 forwarding, or agent forwarding.
- ❌ **Plaintext secret storage** — secrets only ever live in the OS keyring.
  Inline passwords are supported for convenience but warned against.
- ❌ **Bespoke config formats** — configuration is `~/.sshx/settings.json`,
  environment variables, and CLI flags. Nothing else.

**In scope (welcome):** command execution, SFTP file ops, password/secret
management, named host management, authentication UX, safety checks, and
cross-platform correctness.

## 4. Architecture

Entry point is thin; all logic lives in packages.

```
cmd/sshx/main.go          → app.Run(os.Args); maps errors to exit codes
internal/app/             → CLI surface (argument parsing, routing, sub-commands)
  config.go               → ParseArgs: flags + env → sshclient.Config
  app.go                  → Run(): dispatch by Config.Mode + host resolution
  host_manager.go         → --host-* handlers (add/update/list/test/test-all/remove)
  settings.go             → ~/.sshx/settings.json load/save (atomic, 0600)
  password.go             → keyring-backed password get/set/list + secure input
  usage.go                → PrintUsage() help text (keep in sync with flags)
  dryrun.go               → --dry-run local execution plan preview
  audit.go                → local structured JSONL audit events + redaction
internal/sshclient/       → SSH/SFTP core
  client.go               → SSHClient: dial, auth, exec, SFTP, sudo-over-stdin
  validate.go             → command safety checks + CommandUsesSudo
pkg/errutil/              → error helpers (e.g. ignore benign close/EOF errors)
pkg/logger/              → leveled logger (SSHX_LOG_LEVEL)
```

### Execution modes

`ParseArgs` sets `Config.Mode`, and `Run()` dispatches on it:

| Mode       | Trigger                                   | Responsibility                          |
|------------|-------------------------------------------|-----------------------------------------|
| `ssh`      | default; a command argument is present    | run a remote command (sudo auto-fill)   |
| `sftp`     | `--upload/--download/--list/--mkdir/--rm` | file transfer & remote FS ops           |
| `password` | `--password-*`                            | manage keyring secrets                  |
| `host`     | `--host-*`                                | manage `settings.json` host entries     |

### State & storage

- **Host config:** `~/.sshx/settings.json`, written atomically (temp file →
  `chmod 0600` → `rename`) so a crash can never truncate it. A top-level `key`
  is the default SSH key; a per-host `key` overrides it.
- **Secrets:** OS keyring under service name `sshx`
  (macOS Keychain / Linux Secret Service / Windows Credential Manager).
- **Trust store:** `~/.ssh/known_hosts` (or `--known-hosts` / `SSH_KNOWN_HOSTS`).
- **Audit trail:** `~/.sshx/audit/sshx-YYYY-MM-DD.jsonl` by default; override
  with `--audit-output=<dir>` / `SSHX_AUDIT_OUTPUT`, or disable with
  `--no-audit` / `SSHX_NO_AUDIT=true`.

## 5. Tech Stack

- **Language:** Go (module directive pinned to **`go 1.24`** — see constraint below).
- **SSH/crypto:** `golang.org/x/crypto/ssh`
- **SFTP:** `github.com/pkg/sftp`
- **Keyring:** `github.com/zalando/go-keyring`
- **Terminal input:** `golang.org/x/term` (no-echo password prompts)
- **Dotenv:** `github.com/joho/godotenv`
- **Tests:** `github.com/stretchr/testify`

> ⚠️ **Toolchain constraint:** CI's test/lint/security jobs run on **Go 1.24**.
> The `go` directive in `go.mod` must stay at `1.24.0`. When adding a dependency,
> pin it to a version whose own `go` directive is ≤ 1.24 (e.g. `x/term v0.37.0`,
> `x/sys v0.38.0`). Do not let `go get` silently bump the directive to 1.25+.

## 6. Development Workflow (Methods)

Use the `Makefile`; it encodes the canonical commands.

```bash
make setup-hooks   # one-time: install Git hooks (.githooks → commit-msg/pre-commit/pre-push)
make check         # fmt + vet + test  ← run before every commit
make test          # go test ./...
make test-coverage # coverage report
make lint          # golangci-lint (v2)
make build         # build ./cmd/sshx
make build-all     # cross-compile all platforms
make ci            # deps + check + coverage (mirrors CI)
```

Minimum bar before any commit: **`gofmt`, `go vet`, `go test ./...`, and
`golangci-lint run` must all pass.**

### Quality gates / linters

`.golangci.yml` (golangci-lint **v2**) enables: `errcheck`
(`check-blank: true`, `check-type-assertions: true`), `govet` (with `shadow`),
`staticcheck`, `unused`, `ineffassign`, `misspell` (US locale), `unconvert`,
`gosec`.

Notes:

- Because `errcheck` has `check-blank: true`, even `_ = f()` is flagged. Follow
  the repo convention and annotate deliberate ignores with
  `//nolint:errcheck // <reason>`.
- `govet` shadow checking is on — avoid shadowing `err` and friends.

### CI (`.github/workflows/`)

- `ci.yml`: **Test** (ubuntu + macOS, Go 1.24, `-race -cover`), **Lint**
  (golangci-lint), **Security Scan** (`gosec` via golangci-lint and the
  standalone scanner), **Analyze** (CodeQL, Go).
- `release.yml`: builds release artifacts (Go 1.25 in the release job only).

All `ci.yml` checks must be green before merge.

### Commit & PR conventions

- **Conventional Commits**, enforced by `.githooks/commit-msg`. Allowed types:
  `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `build`,
  `ci`, `revert`. Subject ≤ 72 chars: `type(scope): subject`.
- Keep PRs focused and small. Update `CHANGELOG.md` (`[Unreleased]`) for any
  user-facing change.
- When changing flags or behavior, update **both** `internal/app/usage.go` and
  `README.md` / `README_CN.md`.

## 7. Security Principles

These are load-bearing. Changes that weaken them need explicit justification and
tests.

1. **Strict host-key verification.** Unknown or changed host keys abort the
   connection (OpenSSH-like). Bypasses are opt-in and loud: `--accept-unknown-host`
   (records the key once), `--insecure-hostkey` (last resort), or the matching
   `SSH_*` env vars.
2. **Secrets never in plaintext.** Passwords live only in the OS keyring. Inline
   `--password-set=key:value` and `SSH_PASSWORD` are supported but warned about.
3. **Sudo password over stdin.** Never interpolate the password into the command
   string. `sudoStdinCommand` rewrites a leading `sudo` to `sudo -S -p ''` and the
   password is fed via `session.Stdin`. This avoids quote breakage and injection.
4. **Sudo auto-fill only supports leading `sudo`.** `CommandUsesSudo` returns
   true only when the remote command starts with `sudo`, matching the exact
   form `sudoStdinCommand` can safely rewrite. Non-leading sudo inside shell
   wrappers or pipelines is left untouched.
5. **Command safety checks.** Destructive patterns (`rm -rf /`, `mkfs`, `dd`,
   fork bombs, `curl | sh`, critical file edits, shutdown/reboot) are blocked
   unless `--force`/`-f` or `--no-safety-check` is given. The validator is a
   guardrail against mistakes, **not** a security sandbox.
6. **Auth order.** SSH key first; password fallback happens only when an SSH
   login password is already provided (for example through `SSH_PASSWORD`).
   Keyring passwords are for sudo auto-fill, not ordinary SSH login.
   `--no-key`/`SSH_DISABLE_KEY` forces password-only.
7. **Config file is `0600`** and written atomically.

## 8. Boundary Contracts

Most expensive bugs in this project come from crossing boundaries that look
similar in code but mean different things to users. Before changing any logic in
these areas, name the boundary and add a regression test or explicit manual
verification for it:

- **Local CLI flags vs remote command tokens.** Once the remote command starts,
  tokens such as `-v`, `--help`, `--force`, and `--` belong to the remote
  command unless a documented separator says otherwise.
- **Local filesystem paths vs remote/SFTP paths.** Use local OS path semantics
  only for local files. Remote SFTP paths use slash-separated remote path
  semantics even when sshx is built or run on Windows.
- **SSH login password vs sudo password.** `SSH_PASSWORD` is an SSH login
  credential. Keyring `password_key` / `SSH_SUDO_KEY` values are sudo secrets
  unless a future change explicitly introduces a separate SSH password key.
- **Documented behavior vs implemented behavior.** If README, `usage.go`,
  `skills/sshx/SKILL.md`, or `docs/roadmap.md` says a behavior exists, verify
  the code path actually implements it.
- **Installer platform detection vs release artifacts.** Any platform an
  installer can select must have a matching release artifact, checksum entry,
  and build path.

## 9. Testing Strategy

- **Table-driven unit tests** per package, colocated (`*_test.go`).
- **No network in unit tests** — SSH/SFTP behavior is exercised with local
  servers/mocks (`mock_test.go`) and the keyring is mocked.
- **Boundary-sensitive logic must be tested** — e.g. command parsing keeps
  remote flags intact, `--` separators work, SFTP remote paths stay POSIX-like,
  docs examples match implemented flags, and installer platform detection
  matches release artifacts.
- **Security-relevant logic must be tested** — e.g. `CommandUsesSudo`,
  `sudoStdinCommand`, command validation, atomic settings save (perms + no temp
  leftovers), and platform detection.
- Coverage is tracked (Codecov). Coverage is currently modest; **raising it is an
  ongoing goal** — prefer adding tests alongside any change you make.

## 10. Roadmap

A living, maintainer-adjustable plan. Items must respect the boundaries in §3.

**Now / recently shipped**

- ✅ CLI-only refactor (MCP server + connection pool removed).
- ✅ Per-host SSH keys and per-host password keys.
- ✅ Strict host-key verification with opt-in overrides.
- ✅ Hardened sudo password handling (stdin), atomic config writes, secure
  password input.

**Near-term**

- ⬜ Raise test coverage across `internal/app` and `internal/sshclient`.
- ⬜ Host config UX: tags/groups, richer `--host-list` output, edit ergonomics.
- ⬜ Better `--password-list` discovery and consistent keyring key naming.
- ⬜ Shell completion (bash/zsh/fish) and `--version`/build-info polish.

**Mid-term**

- ⬜ SFTP enhancements: recursive upload/download and glob support.
- ⬜ Parallel fan-out: run one command across many named hosts with an aggregated
   report (an extension of `--host-test-all`). *In scope — no daemon required.*
- ⬜ Bastion/jump-host (`ProxyJump`-style) support for reaching private hosts.

**Long-term / under consideration**

- ⬜ Pluggable secret backends behind the existing keyring abstraction.

Anything implying a daemon, MCP, tunneling, or a GUI is explicitly **rejected**
unless the mission in §1–§3 is formally revised.

## 11. Release Process

- Semantic Versioning; changes recorded in `CHANGELOG.md` (Keep a Changelog).
- Tagging is scripted (`scripts/tag.sh`, `make tag`); release notes via
  `scripts/release-note.sh` (`make renote`).
- `release.yml` cross-compiles and publishes artifacts on tag push.
- Install paths: `go install`, `install.sh` (Linux/macOS), `install.ps1`
  (Windows), or manual binary download.

## 12. Guidelines for AI Coding Agents

When working in this repo:

1. **Stay within the mission.** Re-read §3 before adding features. Default to a
   smaller change. Never reintroduce MCP, a daemon, a connection pool, tunneling,
   or a GUI.
2. **Hold the toolchain line.** Keep `go.mod` at `go 1.24.0`. If a dependency
   forces a newer directive, pin an older compatible version instead of bumping
   the directive (CI runs Go 1.24).
3. **Verify before declaring done.** Run `make check` (and `golangci-lint run`)
   locally; reproduce the original symptom and confirm it is gone. For PR work,
   watch CI to green (`gh pr checks <n> --watch`).
4. **Respect the security invariants in §7.** Any change touching auth, sudo,
   host-key handling, or secret storage must keep secrets out of process args /
   plaintext and must come with tests.
5. **Keep docs in lock-step.** New/changed flags → update `usage.go`, `README.md`,
   `README_CN.md`, and `CHANGELOG.md [Unreleased]`.
6. **Follow house style.** Conventional Commits (enforced by the commit-msg hook),
   `gofmt`, no shadowed `err`, annotate deliberate ignored errors with
   `//nolint:errcheck // reason`. Comment only what needs clarifying.
7. **Prefer surgical edits.** Don't refactor unrelated code or "drive-by" fix
   pre-existing issues outside the task's scope.
8. **Do the completion self-check.** Before declaring work complete, list the
   original failure or risk, the regression test or manual reproduction, and
   the commands run.

### Completion self-check

Before declaring a change done:

1. Reproduce the original failure or risk case, or explain why it cannot be
   reproduced locally.
2. Add or update a regression test for the bug class, not only the exact input.
3. Check adjacent adversarial examples when relevant:
   - Remote command flags: `-v`, `--help`, `--force`, `--`.
   - Remote paths under Windows builds.
   - README / usage examples against actual parsed flags.
   - Installer-supported platforms against release artifacts.
4. Run the relevant verification commands. For code changes this normally means
   `go test ./...`, `go test -race ./...`, and `go vet ./...`. For installer or
   release changes, also run shell syntax checks and at least one cross-build
   smoke test.
5. Confirm no generated binaries, coverage reports, or unrelated files are left
   in the working tree.

### Bugfix reflection

For every non-trivial bug fix, include this short reflection in the PR body or
final agent summary:

```text
Bug class:
Missing invariant:
Why existing tests missed it:
Regression test added:
Docs or AGENT.md update needed:
Verification run:
```

When committing on behalf of an agent, include the trailer:

```
Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```
