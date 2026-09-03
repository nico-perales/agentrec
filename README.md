# agentrec

**A local, offline flight recorder for AI coding agents.** It records every action
an agent takes — file edits (with before/after content) and shell commands — into
a tamper-evident, hash-chained log, so you can review exactly what an agent did to
your machine, prove the record wasn't altered, and (soon) revert it.

It makes **no network calls, needs no account or API key, and never transmits what
it records.** Everything stays on your disk. That is the whole point: the cloud
"AI observability" tools upload your agent's activity to their servers; agentrec
keeps it yours.

```text
$ agentrec log
     1 21:17:13  Edit       ~ src/main.rs
     2 21:17:13  Bash       cargo test --all

$ agentrec verify
OK — 2 entries, hash chain intact

$ agentrec diff 1
#1 src/main.rs
  fn main() {
- 	println!("hi");
+ 	println!("hello, world");
  }
```

## How it works

agentrec plugs into **Claude Code's hooks**. `agentrec init` writes a
`PreToolUse`/`PostToolUse` hook into `.claude/settings.json`; from then on Claude
Code pipes each tool call to `agentrec hook`, which:

- snapshots a file's content **before** and **after** an edit into a
  content-addressed blob store (deduplicated),
- appends one entry per action to an **append-only, hash-chained log** — each
  entry's hash binds the previous one, so any edit, reorder, or deletion of a past
  entry is detectable with `agentrec verify`,
- records shell commands (with output) too.

The store lives under `~/.agentrec/` (override with `$AGENTREC_HOME`), keyed by a
normalized hash of the project directory.

## Usage

```bash
agentrec init            # install the hooks into this project's .claude/settings.json
agentrec log             # list recorded actions
agentrec show <n>        # one action in detail
agentrec diff <n>        # before/after diff of a file change
agentrec verify          # check the tamper-evident chain
agentrec revert <n>      # undo action <n>, restoring the file (--dry-run to preview)
agentrec review          # write a self-contained HTML timeline (--open to launch it)
```

Reverting restores a file to the content it had *before* that action, and the
revert is itself recorded as a new entry — so it is auditable, re-revertible, and
the hash chain stays unbroken.

## Status & scope

Early. Working today: recording (via Claude Code hooks), the tamper-evident log,
`init`, `log`/`show`/`diff`/`verify`, `revert`, and a self-contained HTML `review`
page (no CDN, no fonts, no network — it opens locally and sends nothing anywhere).

- **Records, does not prevent.** Blocking dangerous actions (a guardrail) is
  planned, not here yet.
- **Claude Code only** for now; the core is agent-agnostic, so other agents come
  later via their hooks.
- Network/process capture is planned.
- A hash chain detects tampering with any entry that has something after it;
  closing the tail-deletion gap (anchoring/signing) is future work.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
