# Contributing to sshx

Thanks for your interest in improving sshx. This guide covers the practical
workflow; **read [AGENT.md](./AGENT.md) first** — it defines the project's
mission, scope boundaries (non-goals), and architecture, and every change is
reviewed against it.

## Ground Rules

- **Scope discipline**: features listed as non-goals in AGENT.md §3 (daemons,
  resident remote agents, orchestration, GUI/TUI, plaintext secrets, …) will
  not be accepted without a prior discussion issue. When in doubt, open an
  issue before writing code.
- **Convergence test**: a new feature must remove an Agent judgment, not add a
  command an Agent has to learn.
- **Security first**: never weaken host-key verification, secret-backend
  isolation (OS keyring or explicit local vault), safety-check, or audit
  semantics for convenience. Do not add plaintext secret files or silent
  keyring fallbacks.

## Development Setup

Requirements: Go (version pinned in `go.mod`), `make`, and optionally
`golangci-lint`.

```bash
git clone https://github.com/talkincode/sshx.git
cd sshx
make setup-hooks   # install pre-commit/pre-push hooks (fmt, vet, tests)
make build         # build ./bin/sshx
```

## Testing

| Command | What it runs |
| --- | --- |
| `make test-short` | unit tests only (`-short`) |
| `make test` | all Go tests including the E2E package |
| `make test-e2e` | compiled-binary E2E suite against an in-process SSH/SFTP server |
| `make test-keychain-macos` | E2E with the real macOS Keychain, in an ephemeral keychain, no GUI prompts |
| `make check` | fmt + vet + tests |

Notes:

- **`sshx_e2e` build tag**: tests and E2E binaries built with `-tags sshx_e2e`
  swap the OS keyring for a file-backed isolated keyring
  (`internal/keyringstore/backend_e2e.go`, keyed by `SSHX_E2E_KEYRING_FILE`).
  This keeps routine test runs off your real Keychain/Credential Manager. The
  real OS keyring path is only exercised when `SSHX_E2E_REAL_KEYRING=1`.
- The E2E suite compiles the actual binary and talks real TCP SSH/SFTP to an
  isolated in-process server; it observes exit codes, stdout/stderr JSON,
  remote state, `known_hosts`, settings, keyring, and audit JSONL.
- macOS contributors: see "macOS Keychain Prompts During Development" in
  [docs/troubleshooting.md](./docs/troubleshooting.md).

## Acceptance-Matrix Rule (required for new first-level features)

`docs/roadmap.md` defines hard coverage minimums. Any new first-level
capability must ship with:

1. at least one happy-path E2E through the compiled binary,
2. at least one failure-path E2E if the feature is high-risk,
3. two role/permission states if the feature touches permissions,
4. one failure-recovery/rollback proof if the feature mutates state,
5. an updated acceptance matrix row in `docs/roadmap.md`.

Component tests alone do not count as completion evidence.

## Pull Requests

- Use conventional commit titles (`feat(scope): …`, `fix: …`, `docs: …`,
  `ci: …`, `chore: …`), matching the existing history.
- Keep PRs focused; separate refactors from behavior changes.
- Update user-facing docs in the same PR: `README.md`, `README_CN.md`,
  `docs/`, `internal/app/usage.go` (help text must stay in sync with flags),
  and `CHANGELOG.md` under `[Unreleased]`.
- CI must be green: unit tests (Linux/macOS/Windows), E2E (Linux/macOS), lint,
  and security scans.

## Reporting Issues

- Bugs: include the sshx version, OS, the exact command (redact hosts and
  secrets), and `--json` output when possible.
- Security vulnerabilities: **do not open a public issue** — follow
  [SECURITY.md](./SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
[MIT License](./LICENSE).
