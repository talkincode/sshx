# AGENT.md

Operating guide for humans and AI coding agents working on **sshx**. It defines
what this project is, what it deliberately is *not*, how it is built, and how to
make changes that fit. Read this before making non-trivial changes.

Module: `github.com/talkincode/sshx` · Language: Go 1.25.13 · License: MIT

---

## 1. Mission

`sshx` is an **agent-native remote host execution tool over SSH**. SSH/SFTP is
the trusted transport; execution is the product. It turns an agent's intent
into a one-shot remote operation whose target and side effects are explicit,
whose result is machine-decidable, and whose security context is auditable:

> SSH is the channel. X is execution.

The core value proposition:

- Give agents one stable process contract for target resolution, preview,
  execution, structured results, failure classification, and audit evidence.
- Run a command or file action on an existing SSH host in one invocation, with
  no resident remote agent and no long-running control plane.
- Reduce decision and retry cost through named hosts, JSON, exit codes,
  `error_kind`, timeout, dry-run plans, and reusable host inspection.
- Protect credentials and trust boundaries through the OS keyring, strict
  host-key verification, sudo over stdin, explicit bypasses, and audit redaction.

Human operators use the same CLI, preview, safety, and audit semantics to
supervise agents and troubleshoot operations.

## 2. Goals

1. **Stable agent execution contract** — predictable stdout/stderr, exit codes,
   JSON results, failure kinds, previews, and audit semantics.
2. **Single self-contained binary** — no runtime dependencies, installable via
   `go install`, an install script, or a downloaded release artifact.
3. **Cross-platform parity** — Linux, macOS, and Windows are all first-class.
4. **Secure by default** — strict `known_hosts` verification, keyring-backed
   secrets, sudo password delivered over stdin (never interpolated), and command
   safety checks that block obviously destructive operations.
5. **Low agent decision cost** — sensible defaults, named hosts, key-first auth with
   password fallback only when an SSH login password is already provided, and
   classified failures rather than prose-only errors.
6. **Multi-server ergonomics** — per-host SSH keys and per-host/per-server
   password keys so one tool covers a whole fleet.
7. **Execution preview** — `--dry-run` explains the local execution plan without
   connecting, executing, reading keyring secrets, or mutating state.
8. **Auditability** — non-dry-run invocations write structured JSONL audit
   events under `~/.sshx/audit` by default, with secrets and stdout/stderr
   excluded.
9. **Reusable host knowledge** — stable system/network probes are built in;
   editable application probes live as versioned local plugins under the sshx
   runtime root and may reuse freshness-bounded, redacted observations.

## 3. Scope & Boundaries (Non-Goals)

`sshx` is intentionally a **focused CLI**. Keeping the surface small is a feature.
Do **not** add the following without an explicit, deliberate decision to expand
the project's mission:

**Out of scope (will not be accepted by default):**

- ❌ **HTTP/SSE MCP server, daemons, or resident protocol services** — the
  stdio MCP server (`sshx mcp`) is in scope: it is spawned and owned by an MCP
  client, lives for exactly one client session, and re-enters sshx as one-shot
  child processes per tool call. Do not add an HTTP/SSE transport, a listening
  socket, or any server that outlives its client.
- ❌ **Daemons / long-running services / connection pools** — every command opens
  a connection, does its work, and exits. There is no background process.
- ❌ **Resident remote agent / control plane** — do not require a service to be
  installed on managed hosts and do not turn sshx into a fleet control plane.
- ❌ **Desired-state configuration / workflow orchestration** — bounded fan-out
  execution is in scope; playbooks, schedulers, reconciliation, and long-lived
  workflow state are not. `sshx apply` may replace one file; it must not
  validate-and-reload a service in the same invocation.
- ❌ **GUI / TUI** — interaction is through flags and stdout/stderr only.
- ❌ **Full OpenSSH replacement** — no interactive login shell multiplexing,
  port forwarding / tunneling, SOCKS proxy, X11 forwarding, or agent forwarding.
  A single human `sshx login` session is in scope; it is not a multiplexer,
  jump host, or Agent-driven interactive shell.
- ❌ **Plaintext secret storage** — secrets only ever live in the OS keyring.
  Inline passwords are supported for convenience but warned against.
- ❌ **Bespoke operator config formats** — host configuration remains
  `~/.sshx/settings.json`, environment variables, and CLI flags. Versioned
  plugin manifests, result schemas, trust locks, and observation envelopes are
  capability data contracts rather than alternate host configuration.

**In scope (welcome):** agent execution contracts, command execution, SFTP file
actions, bounded multi-host execution, password/secret references, named host
management, authentication UX, safety checks, auditing, and cross-platform
correctness. Read-only host inspection, local plugin lifecycle, explicit plugin
trust, and bounded observation reuse are also in scope. Guarded SQL execution
(`sshx sql`) and guarded file apply (`sshx apply`) are deliberate scope
expansions: they absorb mutation risk (classify → precondition → backup →
atomic change → structured result) without becoming a workflow engine.
`sshx login` is a human-only TTY escape hatch onto a named host (optional
`--sudo` privileged login shell); it is not part of the Agent/MCP contract. The
stdio MCP server (`sshx mcp`) is a thin adapter over the same contract: tools
map 1:1 to CLI verbs, results are the CLI's versioned JSON, every call is a
one-shot child invocation audited with `entry=mcp`, and password management is
never exposed as a tool.

**Convergence test:** every new sshx feature must remove an Agent judgment, not
add a command the Agent has to learn. Absorb remote tax (host, credential,
sudo, timeout, error class, backup). Do not wrap local Unix tools as new verbs.

## 4. Architecture

Entry point is thin; all logic lives in packages.

```
cmd/sshx/main.go          → app.Run(os.Args); maps errors to exit codes
internal/app/             → CLI surface (argument parsing, routing, sub-commands)
  config.go               → ParseArgs: flags + env → sshclient.Config
  app.go                  → Run(): dispatch by Config.Mode + host resolution
  host_manager.go         → --host-* handlers (add/import/update/list/test/test-all/remove)
  sshconfig.go            → ~/.ssh/config parsing + selective import planning
  settings.go             → ~/.sshx/settings.json load/save (atomic, 0600)
  password.go             → keyring-backed password get/set/list + secure input
  usage.go                → PrintUsage() help text (keep in sync with flags)
  dryrun.go               → --dry-run local execution plan preview
  audit.go                → local structured JSONL audit events + redaction
  run.go                  → sshx run: selectors, scripts, fan-out, versioned results
  skill.go                → install the canonical Agent skill embedded in sshx
  plugin.go               → local plugin create/list/show/validate/test/trust/remove
  inspect.go              → one-shot capability execution + observation caching
  sql.go                  → sshx sql: guarded SQL pipeline (classify → gate → explain → backup → execute)
  apply.go                → sshx apply: guarded single-file mutation (hash → backup → atomic write)
  login.go                → sshx login: human TTY session, optional sudo privileged shell
  mcp.go                  → sshx mcp: stdio MCP server; tools self-exec sshx as one-shot children
internal/execution/       → versioned request/result model, selectors, executor
internal/plugin/          → manifests, schemas, scaffolds, trust, built-ins
internal/runtimepath/     → ~/.sshx / SSHX_HOME runtime-root resolution
internal/skillinstall/    → conflict-safe, atomic Agent skill installation
internal/sqlsafe/         → fail-closed SQL classification, policy gates, transactional backup decisions, psql/sqlite3 assembly
internal/sshclient/       → SSH/SFTP core
  client.go               → SSHClient: dial, auth, exec, SFTP, sudo-over-stdin
  remote_state.go         → restrictive atomic remote observation I/O
  validate.go             → command safety checks + CommandUsesSudo
pkg/errutil/              → error helpers (e.g. ignore benign close/EOF errors)
pkg/logger/              → leveled logger (SSHX_LOG_LEVEL)
skills/                  → canonical Agent skill plus its embedded asset package
```

### Execution modes

`ParseArgs` sets `Config.Mode`, and `Run()` dispatches on it:

| Mode       | Trigger                                   | Responsibility                          |
|------------|-------------------------------------------|-----------------------------------------|
| `ssh`      | default; a command argument is present    | run a remote command (sudo auto-fill)   |
| `run`      | `sshx run ...`                            | canonical multi-host/script execution   |
| `sftp`     | `--upload/--download/--list/--mkdir/--rm` | file transfer & remote FS ops           |
| `password` | `--password-*`                            | manage keyring secrets                  |
| `host`     | `--host-*`                                | manage `settings.json` host entries     |
| `skill`    | `sshx skill install`                      | install/update the embedded Agent skill |
| `plugin`   | `sshx plugin <action>`                    | manage local inspection plugins         |
| `inspect`  | `sshx inspect ... <capability-id>`        | collect/reuse one host observation      |
| `sql`      | `sshx sql ... "<statement>"`              | guarded SQL via remote psql or sqlite3  |
| `apply`    | `sshx apply --path= --from=`              | guarded single-file remote replace      |

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
- **Runtime root:** all sshx-owned local state follows `~/.sshx` by default or
  the explicit `SSHX_HOME` override for isolated Agent/CI runs.
- **Local plugins and trust:** editable assets live under
  `$SSHX_HOME/plugins/<id>`; trusted digests live in
  `$SSHX_HOME/plugin-lock.json`. Plugin code never belongs in an Agent skill.
- **Agent skill:** the canonical `skills/sshx/SKILL.md` is embedded in the
  binary. `sshx skill install` writes it atomically to
  `~/.agents/skills/sshx/SKILL.md` (or the explicit `--dir`); differing content
  needs explicit `--force` unless its `.sshx-managed.json` digest proves it was
  installed by sshx, and symlink targets are rejected.
- **Remote observations:** opt-in cache mode stores only normalized, redacted
  JSON under the authenticated user's `~/.sshx/observations/v1/`. Collector
  code remains local and is streamed only for the SSH session.

## 5. Tech Stack

- **Language:** Go (module directive pinned to **`go 1.25.13`** — see constraint below).
- **SSH/crypto:** `golang.org/x/crypto/ssh`
- **SFTP:** `github.com/pkg/sftp`
- **Keyring:** `github.com/zalando/go-keyring`
- **Terminal input:** `golang.org/x/term` (no-echo password prompts)
- **Dotenv:** `github.com/joho/godotenv`
- **Tests:** `github.com/stretchr/testify`

> ⚠️ **Toolchain constraint:** CI's test/lint/security jobs run on **Go 1.25.13**.
> The `go` directive in `go.mod` must stay at `1.25.13` unless a deliberate
> security or compatibility review changes the baseline. New dependencies must
> support that toolchain; do not let `go get` silently bump the directive.

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

- `ci.yml`: **Test** (ubuntu + macOS, Go 1.25.13, `-race -cover`), **Lint**
  (golangci-lint), **Security Scan** (`gosec` plus `govulncheck`), **Analyze**
  (CodeQL, Go).
- `release.yml`: builds release artifacts with Go 1.25.13 and bundles the matching
  Agent skill in every archive.

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
   unless `--force`/`-f` or `--no-safety-check` is given. Direct database
   client execution (`psql`/`pgcli` in command position, including
   `docker exec`, `sudo -u`, `sh -c`, `kubectl exec`, and pipe wrappers) is
   also blocked and redirected to `sshx sql`; availability probes such as
   `which psql` and `psql --version` stay allowed. The validator is a
   guardrail against mistakes, **not** a security sandbox.
6. **Auth order.** SSH key first; password fallback happens only when an SSH
   login password is already provided (for example through `SSH_PASSWORD`).
   Keyring passwords are for sudo auto-fill, not ordinary SSH login.
   `--no-key`/`SSH_DISABLE_KEY` forces password-only.
7. **Config file is `0600`** and written atomically.
8. **Local plugin trust is digest-bound.** New or changed plugins fail closed
   before network access until explicitly trusted. Trust is admission metadata,
   not a sandbox; only trust code that may run with the selected remote identity.
9. **Observation cache is untrusted input.** Reads enforce schema/size, owner,
   permissions, path and symlink checks. Reuse is bound to plugin identity,
   host key, target identity, privilege, parameters, boot ID, and freshness.

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
- **Agent skill guidance vs executable plugin assets.** A skill teaches an Agent
  when and how to call sshx. Custom collectors, schemas, fixtures, and trust
  state belong under `SSHX_HOME`, never inside the skill.
- **Local plugin code vs remote observation data.** Collectors may be streamed
  for one session but are never installed remotely. Remote cache entries contain
  only normalized and redacted observation JSON.

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
  leftovers), plugin path/digest trust, observation invalidation, remote cache
  owner/permission/symlink checks, and platform detection.
- Coverage is tracked (Codecov). Coverage is currently modest; **raising it is an
  ongoing goal** — prefer adding tests alongside any change you make.

### Capability coverage matrix (mandatory)

The source of truth is the acceptance matrix in
[`docs/roadmap.md`](docs/roadmap.md). These requirements are **MUST-level**:

1. Every top-level product capability MUST have at least one Happy Path E2E.
2. Every high-risk capability MUST cover at least one failure path.
3. Every permission-sensitive capability MUST verify at least two roles or
   permission states.
4. Every state-changing operation MUST verify recovery or rollback after a
   failure.
5. Adding a top-level capability MUST include its E2E and an updated matrix row;
   otherwise the change is incomplete.

Existing unit, component, or local-server tests do not count as CLI E2E unless
they exercise the compiled `sshx` process across the documented external
boundary. Record real evidence paths in the matrix and mark missing coverage as
a gap rather than inferring it.

Canonical commands:

```bash
make test-short  # unit/component suite without compiled-binary E2E
make test-e2e    # compiled sshx process across real SSH/SFTP protocol boundaries
```

The E2E source of evidence is `tests/e2e`. Native OS-keyring lifecycle tests are
opt-in locally and run against an ephemeral macOS Keychain in CI; never enable
them against a keyring that cannot be safely isolated and cleaned up.

## 10. Roadmap

A living, maintainer-adjustable plan. The authoritative product profile,
directions, and acceptance matrix are in [`docs/roadmap.md`](docs/roadmap.md).
Items must respect the boundaries in §3.

**Now / recently shipped**

- ✅ CLI-only refactor (resident MCP server + connection pool removed), later
  followed by the deliberate reintroduction of a **stdio-only** MCP adapter
  (`sshx mcp`) over the same one-shot execution contract.
- ✅ Per-host SSH keys and per-host password keys.
- ✅ Strict host-key verification with opt-in overrides.
- ✅ Hardened sudo password handling (stdin), atomic config writes, secure
  password input.
- ✅ Built-in host inspection, sshx-owned local plugin lifecycle, digest trust,
  and freshness-bounded remote observations.

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

Anything implying a daemon, a resident protocol server (including HTTP/SSE
MCP), tunneling, or a GUI is explicitly **rejected** unless the mission in
§1–§3 is formally revised.

## 11. Release Process

- Semantic Versioning; changes recorded in `CHANGELOG.md` (Keep a Changelog).
- Tagging is scripted (`scripts/tag.sh`, `make tag TAG=vX.Y.Z`); release notes via
  `scripts/release-note.sh` (`make renote`).
- `release.yml` cross-compiles and publishes artifacts on tag push.
- Install paths: `go install`, `install.sh` (Linux/macOS), `install.ps1`
  (Windows), a Homebrew tap (`talkincode/homebrew-tap`, opt-in via the
  `HOMEBREW_TAP_TOKEN` secret), or manual binary download.

## 12. Guidelines for AI Coding Agents

When working in this repo:

1. **Stay within the mission.** Re-read §3 before adding features. Default to a
   smaller change. Never introduce a daemon, a connection pool, an HTTP/SSE
   protocol server, tunneling, or a GUI.
2. **Hold the toolchain line.** Keep `go.mod` at `go 1.25.13`. If a dependency
   forces a newer directive, pin an older compatible version instead of bumping
   the directive (CI runs Go 1.25.13).
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
