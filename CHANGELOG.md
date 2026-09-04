# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial release: a local, offline flight recorder for AI coding agents. No
  network calls, no account, no API key — everything stays on your machine.
- **Recording via Claude Code hooks**: `agentrec init` installs `PreToolUse` /
  `PostToolUse` hooks; each tool call is captured — file edits (before/after
  content snapshotted into a content-addressed blob store) and shell commands.
- **Recording any agent via `agentrec watch`**: a filesystem watcher that records
  every create/modify/delete under a directory — with before/after content and
  network intent — into the same tamper-evident log, no matter which tool (or
  human) made the change. Agent-agnostic, since every agent writes files to disk.
  Observe-only: it records but does not block, and does not capture shell commands.
  Behind an optional `watch` feature (enabled by `cli`).
- **Tamper-evident log**: an append-only, hash-chained log where each entry's hash
  binds the previous, so any modification or reordering of a past entry is
  detectable with `agentrec verify`.
- **Review**: `log`, `show`, `diff` (before/after), and a self-contained HTML
  `review` page (inline styles and script, no CDN — it opens locally and sends
  nothing anywhere).
- **Revert**: `agentrec revert <n>` restores a file to its content before that
  action, recording the revert as its own re-revertible entry (`--dry-run` to
  preview).
- **Network intent**: each entry records the hosts its action reaches out to,
  extracted from the text — `https://…` URLs in a command, a `git@host:` remote,
  and URLs an edit adds to a file — shown as `→ host`. Intent from the text, not an
  observed connection.
- **Host policy** in the guardrail: `deny_hosts` blocks any command or edit that
  reaches a listed domain (or subdomain); a non-empty `allow_hosts` makes it
  default-deny, blocking every host not on the list.
- **Guardrail**: in `PreToolUse`, catastrophic actions (a broad `rm -rf`, a
  download piped into a shell, a fork bomb, `mkfs`/`dd` to a device, writes to
  sensitive files) are **blocked** (the hook exits 2 so Claude Code refuses them)
  and recorded; riskier-but-legitimate ones (`sudo`, force pushes, writes outside
  the project) are warned about. A project `.agentrec/policy.toml` adds patterns,
  an allow-list escape hatch, or a warn-only mode.
- Project stores are keyed by a normalized hash of the working directory, so the
  agent and the CLI resolve to the same recording regardless of path spelling.
- Library-first design with an optional `cli` feature.

[Unreleased]: https://github.com/nico-perales/agentrec/commits/main
