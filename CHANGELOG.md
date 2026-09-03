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
- **Tamper-evident log**: an append-only, hash-chained log where each entry's hash
  binds the previous, so any modification or reordering of a past entry is
  detectable with `agentrec verify`.
- **Review**: `log`, `show`, `diff` (before/after), and a self-contained HTML
  `review` page (inline styles and script, no CDN — it opens locally and sends
  nothing anywhere).
- **Revert**: `agentrec revert <n>` restores a file to its content before that
  action, recording the revert as its own re-revertible entry (`--dry-run` to
  preview).
- Project stores are keyed by a normalized hash of the working directory, so the
  agent and the CLI resolve to the same recording regardless of path spelling.
- Library-first design with an optional `cli` feature.

[Unreleased]: https://github.com/nico-perales/agentrec/commits/main
