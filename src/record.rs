//! Turns a hook event into a recorded action.
//!
//! `PreToolUse` for a file-mutating tool snapshots the target's current content
//! (the "before"); `PostToolUse` snapshots the result (the "after"), links the
//! two, and appends a chained log entry. Every other tool call is still recorded
//! as a timeline entry, so the record is complete.

use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::event::HookEvent;
use crate::store::{CommandRecord, FileChange, LogEntry, Store, now_ms};

// Bash output is truncated in the log; the point is triage, not archival.
const MAX_OUTPUT: usize = 8 * 1024;

/// Handles one hook event. A missing `cwd` (no project to anchor to) is a no-op.
pub fn handle(event: &HookEvent) -> Result<(), Error> {
    if event.cwd.is_empty() {
        return Ok(());
    }
    let store = Store::for_cwd(&event.cwd)?;

    if event.is_pre() {
        if event.is_file_tool() {
            if let Some(path) = event.file_path() {
                let before = snapshot(&store, &event.cwd, path);
                store.put_pending(&event.correlation_key(), before.as_deref())?;
            }
        }
        return Ok(());
    }

    if event.is_post() {
        let (file, command, summary) = classify(event, &store);
        store.append(LogEntry {
            seq: 0,
            ts_ms: now_ms(),
            session: event.session_id.clone(),
            tool: event.tool_name.clone(),
            cwd: event.cwd.clone(),
            summary,
            file,
            command,
            prev_hash: String::new(),
            hash: String::new(),
        })?;
    }
    Ok(())
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
