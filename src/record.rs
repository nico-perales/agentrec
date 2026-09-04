//! Turns a hook event into a recorded action.
//!
//! `PreToolUse` for a file-mutating tool snapshots the target's current content
//! (the "before"); `PostToolUse` snapshots the result (the "after"), links the
//! two, and appends a chained log entry. Every other tool call is still recorded
//! as a timeline entry, so the record is complete.

use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::event::HookEvent;
use crate::network;
use crate::policy::{self, Config};
use crate::store::{CommandRecord, FileChange, LogEntry, Store, now_ms};

// Bash output is truncated in the log; the point is triage, not archival.
const MAX_OUTPUT: usize = 8 * 1024;

/// What the caller (the hook entrypoint) should do after handling an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookOutcome {
    /// Let the tool call proceed.
    Proceed,
    /// Block the tool call; the string is the reason to show the agent.
    Blocked(String),
}

/// Handles one hook event. A missing `cwd` (no project to anchor to) is a no-op.
pub fn handle(event: &HookEvent) -> Result<HookOutcome, Error> {
    if event.cwd.is_empty() {
        return Ok(HookOutcome::Proceed);
    }
    let store = Store::for_cwd(&event.cwd)?;
    let config = Config::load(&event.cwd);

    if event.is_pre() {
        // Guardrail: block a denied action and record the blocked attempt.
        if let Some(reason) = policy::assess(event, &config).deny {
            let (file, command, _) = classify(event, &store);
            store.append(blocked_entry(event, file, command, reason.clone()))?;
            return Ok(HookOutcome::Blocked(reason));
        }
        if event.is_file_tool() {
            if let Some(path) = event.file_path() {
                let before = snapshot(&store, &event.cwd, path);
                store.put_pending(&event.correlation_key(), before.as_deref())?;
            }
        }
        return Ok(HookOutcome::Proceed);
    }

    if event.is_post() {
        let (file, command, summary) = classify(event, &store);
        let warnings = policy::assess(event, &config).warnings;
        let network = hosts(&store, file.as_ref(), command.as_ref());
        store.append(LogEntry {
            seq: 0,
            ts_ms: now_ms(),
            session: event.session_id.clone(),
            tool: event.tool_name.clone(),
            cwd: event.cwd.clone(),
            summary,
            file,
            command,
            warnings,
            network,
            blocked: None,
            prev_hash: String::new(),
            hash: String::new(),
        })?;
    }
    Ok(HookOutcome::Proceed)
}

// Hosts an action reaches out to: from a command's text, or from the content a
// file edit produced.
fn hosts(store: &Store, file: Option<&FileChange>, command: Option<&CommandRecord>) -> Vec<String> {
    if let Some(c) = command {
        return network::extract_hosts(&c.command);
    }
    if let Some(hash) = file.and_then(|f| f.after.as_ref()) {
        if let Ok(bytes) = store.get_blob(hash) {
            return network::extract_hosts(&String::from_utf8_lossy(&bytes));
        }
    }
    Vec::new()
}

// A log entry for an action the guardrail refused to let run. It captures what
// was attempted (command / target) but no "after", since nothing executed.
fn blocked_entry(
    event: &HookEvent,
    file: Option<FileChange>,
    command: Option<CommandRecord>,
    reason: String,
) -> LogEntry {
    // For a blocked file write there is no snapshot to link.
    let file = file.map(|f| FileChange {
        path: f.path,
        before: None,
        after: None,
    });
    let network = command
        .as_ref()
        .map(|c| network::extract_hosts(&c.command))
        .unwrap_or_default();
    LogEntry {
        seq: 0,
        ts_ms: now_ms(),
        session: event.session_id.clone(),
        tool: event.tool_name.clone(),
        cwd: event.cwd.clone(),
        summary: format!("BLOCKED {} — {reason}", event.tool_name),
        file,
        command,
        warnings: Vec::new(),
        network,
        blocked: Some(reason),
        prev_hash: String::new(),
        hash: String::new(),
    }
}

fn classify(
    event: &HookEvent,
    store: &Store,
) -> (Option<FileChange>, Option<CommandRecord>, String) {
    if event.is_file_tool() {
        if let Some(path) = event.file_path() {
            let after = snapshot(store, &event.cwd, path);
            let before = store.take_pending(&event.correlation_key());
            let summary = format!("{} {}", event.tool_name, display_path(&event.cwd, path));
            return (
                Some(FileChange {
                    path: path.to_owned(),
                    before,
                    after,
                }),
                None,
                summary,
            );
        }
    }

    if event.tool_name == "Bash" {
        if let Some(cmd) = event.command() {
            let command = CommandRecord {
                command: cmd.to_owned(),
                exit: event.response_exit(),
                output: event.response_output().map(|o| truncate(&o, MAX_OUTPUT)),
            };
            return (None, Some(command), format!("Bash: {}", first_line(cmd)));
        }
    }

    let summary = match event.file_path() {
        Some(p) => format!("{} {}", event.tool_name, display_path(&event.cwd, p)),
        None => event.tool_name.clone(),
    };
    (None, None, summary)
}

// Reads the file's current content into a blob, returning its hash (None if the
// file does not exist — e.g. a fresh Write, or a deletion).
fn snapshot(store: &Store, cwd: &str, path: &str) -> Option<String> {
    let full = resolve(cwd, path);
    let bytes = std::fs::read(full).ok()?;
    store.put_blob(&bytes).ok()
}

fn resolve(cwd: &str, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new(cwd).join(p)
    }
}

fn display_path(cwd: &str, path: &str) -> String {
    Path::new(path)
        .strip_prefix(cwd)
        .map_or(path, |p| p.to_str().unwrap_or(path))
        .replace('\\', "/")
}

fn first_line(s: &str) -> String {
    truncate(s.lines().next().unwrap_or("").trim(), 200)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… (truncated)", &s[..end])
}
