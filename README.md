# agentrec

**A local, offline flight recorder and guardrail for AI coding agents.** It records
every action an agent takes — file edits (with before/after content) and shell
commands — into a tamper-evident, hash-chained log, so you can review exactly what
an agent did to your machine, prove the record wasn't altered, and revert it. It
can also **block** catastrophic actions before they run.

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

> For a diagrammed walkthrough — the two capture paths, the guardrail decision,
> and the hash chain — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

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

## Recording any agent, without hooks

Hooks give the fullest record — edits *and* commands, plus the guardrail — but
they only exist for Claude Code. Every other agent (aider, Cursor, Cline, …) and
every human still writes files to disk, so agentrec can record those edits by
watching the filesystem directly:

```bash
agentrec watch    # run in your project; records every file change, Ctrl+C to stop
```

`watch` snapshots the project up front, then records each create/modify/delete —
with before/after content and network intent — into the **same** tamper-evident
log, whoever made the change. So `log`, `diff`, `verify`, `revert`, and `review`
work on watched changes exactly as they do on hook-captured ones.

It is deliberately **observe-only**: it sees a change *after* it lands on disk, so
it records but cannot block (blocking needs the Claude Code `PreToolUse` hook), and
it does not capture shell commands (the filesystem doesn't carry them). What it
gives you is a faithful record of *what changed in your files*, agent-agnostic.

## Usage

```bash
agentrec init            # install the hooks into this project's .claude/settings.json
agentrec watch           # record file changes by any tool, hooks or not (Ctrl+C to stop)
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
`init`, `log`/`show`/`diff`/`verify`, `revert`, a self-contained HTML `review`
page (no CDN, no fonts, no network), and the **guardrail** below.

- **Network intent.** Each entry records the hosts its action reaches out to,
  read from the text — the `https://…` URLs a command hits, the `git@host:` remote
  it pushes to, and any URL an *edit* adds to a file — shown as `→ host` in the log
  and review. This is intent from the text, **not** an observed connection: a
  compiled binary or an obfuscated script could reach somewhere the text never
  names. (True packet capture would need a kernel/proxy layer that breaks the
  observe-via-hooks, no-privilege model — deliberately out of scope.)
- **Guardrail.** In `PreToolUse`, agentrec assesses each action and **denies**
  (exit 2, so Claude Code refuses it) a small set of high-confidence catastrophic
  ones — a broad `rm -rf`, a download piped into a shell, a fork bomb, disk-wiping
  commands, writes to sensitive files (`~/.ssh`, `/etc`, …) — while **warning**
  about riskier-but-legitimate ones (`sudo`, force pushes, writes outside the
  project). Blocked attempts are still recorded, so they're auditable. Scoped
  deletes like `rm -rf node_modules` are left alone.
- **Host policy.** Using the network intent above, the guardrail can block by
  host: `deny_hosts` blocks any action (command *or* edit) that reaches a listed
  domain or its subdomains, and a non-empty `allow_hosts` flips it to default-deny
  — only the listed hosts are permitted, everything else is blocked.
- **Configurable.** A project `.agentrec/policy.toml`:
  ```toml
  enforce = true                     # false = warn-only, never blocks
  allow  = ["rm -rf /opt/mycache"]   # command substrings that override a deny
  deny   = ["terraform destroy"]     # extra command substrings that block
  warn   = ["docker system prune"]   # extra command substrings that warn
  deny_hosts  = ["evil.example.com"] # block actions reaching these hosts
  allow_hosts = ["github.com"]       # if set, block every other host
  ```
- **Any agent, via `watch`.** Full recording (edits *and* commands) and the
  guardrail run on Claude Code hooks; `agentrec watch` records *file edits* by any
  tool or human, hooks or not, by watching the filesystem — observe-only, and no
  commands. Command recording for other agents (a wrapper they run through) is
  future work.
- Network/process capture is planned.
- A hash chain detects tampering with any entry that has something after it;
  closing the tail-deletion gap (anchoring/signing) is future work.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
