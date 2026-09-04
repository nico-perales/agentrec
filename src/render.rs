//! Human-readable rendering of the timeline.

use std::fmt::Write as _;

use anstyle::{AnsiColor, Color, Style};
use similar::{ChangeTag, TextDiff};

use crate::error::Error;
use crate::revert::{RevertKind, RevertOutcome};
use crate::store::{LogEntry, Store};
use crate::timeline::Integrity;

const RED: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red)));
const GREEN: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)));
const YELLOW: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
const DIM: Style = Style::new().dimmed();
const BOLD: Style = Style::new().bold();

#[must_use]
pub fn log(entries: &[LogEntry], color: bool) -> String {
    if entries.is_empty() {
        return "no actions recorded yet\n".to_owned();
    }
    let mut out = String::new();
    for e in entries {
        let _ = write!(out, "  ");
        paint(
            &mut out,
            DIM,
            &format!("{:>4} {}", e.seq, fmt_time(e.ts_ms)),
            color,
        );
        let _ = write!(out, "  ");
        paint(&mut out, BOLD, &format!("{:<10}", e.tool), color);
        out.push(' ');
        if e.blocked.is_some() {
            paint(&mut out, RED, "[blocked] ", color);
        } else if !e.warnings.is_empty() {
            paint(&mut out, YELLOW, "[warn] ", color);
        }
        let _ = writeln!(out, "{}", detail(e));
    }
    out
}

#[must_use]
pub fn show(entry: &LogEntry, color: bool) -> String {
    let mut out = String::new();
    paint(
        &mut out,
        BOLD,
        &format!("#{} {}", entry.seq, entry.tool),
        color,
    );
    let _ = writeln!(out, "  ({})", fmt_time(entry.ts_ms));
    let _ = writeln!(out, "  session: {}", entry.session);
    let _ = writeln!(out, "  cwd:     {}", entry.cwd);
    let _ = writeln!(out, "  summary: {}", entry.summary);
    if let Some(f) = &entry.file {
        let state = match (&f.before, &f.after) {
            (None, Some(_)) => "created",
            (Some(_), None) => "deleted",
            _ => "modified",
        };
        let _ = writeln!(out, "  file:    {} ({state})", f.path);
    }
    if let Some(c) = &entry.command {
        let _ = writeln!(out, "  command: {}", c.command);
        if let Some(x) = c.exit {
            let _ = writeln!(out, "  exit:    {x}");
        }
        if let Some(o) = &c.output {
            let _ = writeln!(out, "  output:\n{}", indent(o));
        }
    }
    if let Some(reason) = &entry.blocked {
        out.push_str("  ");
        paint(&mut out, RED, &format!("blocked: {reason}"), color);
        out.push('\n');
    }
    for w in &entry.warnings {
        out.push_str("  ");
        paint(&mut out, YELLOW, &format!("warning: {w}"), color);
        out.push('\n');
    }
    paint(&mut out, DIM, &format!("  hash: {}", entry.hash), color);
    out.push('\n');
    out
}

/// Renders the before/after diff of a file entry.
pub fn diff(store: &Store, entry: &LogEntry, color: bool) -> Result<String, Error> {
    let Some(file) = &entry.file else {
        return Ok(format!("#{} is not a file change\n", entry.seq));
    };
    let before = blob_text(store, file.before.as_deref())?;
    let after = blob_text(store, file.after.as_deref())?;

    let mut out = String::new();
    paint(
        &mut out,
        BOLD,
        &format!("#{} {}", entry.seq, file.path),
        color,
    );
    out.push('\n');
    let text_diff = TextDiff::from_lines(&before, &after);
    for change in text_diff.iter_all_changes() {
        let (style, sign) = match change.tag() {
            ChangeTag::Delete => (RED, "-"),
            ChangeTag::Insert => (GREEN, "+"),
            ChangeTag::Equal => (DIM, " "),
        };
        paint(
            &mut out,
            style,
            &format!("{sign} {}", change.value().trim_end_matches('\n')),
            color,
        );
        out.push('\n');
    }
    Ok(out)
}

#[must_use]
pub fn verify(integrity: &Integrity, color: bool) -> String {
    let mut out = String::new();
    match integrity {
        Integrity::Ok { entries } => {
            paint(&mut out, GREEN, "OK", color);
            let _ = writeln!(out, " — {entries} entries, hash chain intact");
        }
        Integrity::Broken { seq, reason } => {
            paint(&mut out, RED, "TAMPERED", color);
            let _ = writeln!(out, " — chain breaks at entry #{seq}: {reason}");
        }
    }
    out
}

#[must_use]
pub fn revert(outcome: &RevertOutcome, color: bool) -> String {
    let (label, style) = match outcome.kind {
        RevertKind::Restored => ("restored", GREEN),
        RevertKind::Recreated => ("re-created", GREEN),
        RevertKind::Deleted => ("deleted", RED),
        RevertKind::AlreadyGone => ("nothing to do (already gone)", DIM),
    };
    let effect = match outcome.kind {
        RevertKind::Restored => "restore earlier content",
        RevertKind::Recreated => "re-create the file",
        RevertKind::Deleted => "delete the file",
        RevertKind::AlreadyGone => "do nothing (already gone)",
    };
    let mut out = String::new();
    if outcome.dry_run {
        paint(&mut out, DIM, "[dry-run] ", color);
        let _ = writeln!(
            out,
            "would revert #{}: {} — {effect}",
            outcome.seq, outcome.path
        );
    } else {
        paint(&mut out, style, label, color);
        let _ = writeln!(
            out,
            " {}  (revert of #{}, recorded)",
            outcome.path, outcome.seq
        );
    }
    out
}

fn detail(e: &LogEntry) -> String {
    if let Some(f) = &e.file {
        let state = match (&f.before, &f.after) {
            (None, Some(_)) => "+",
            (Some(_), None) => "-",
            _ => "~",
        };
        format!("{state} {}", display(&f.path, &e.cwd))
    } else if let Some(c) = &e.command {
        c.command.lines().next().unwrap_or("").to_owned()
    } else {
        e.summary.clone()
    }
}

fn display(path: &str, cwd: &str) -> String {
    std::path::Path::new(path)
        .strip_prefix(cwd)
        .map_or(path, |p| p.to_str().unwrap_or(path))
        .replace('\\', "/")
}

fn blob_text(store: &Store, hash: Option<&str>) -> Result<String, Error> {
    match hash {
        Some(h) => Ok(String::from_utf8_lossy(&store.get_blob(h)?).into_owned()),
        None => Ok(String::new()),
    }
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("    {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

// Wall-clock time of day (UTC) from a unix-millis stamp; no date, which keeps the
// log readable without pulling in a calendar dependency.
fn fmt_time(ts_ms: u128) -> String {
    let secs = (ts_ms / 1000) % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn paint(out: &mut String, style: Style, text: &str, color: bool) {
    if color {
        let _ = write!(out, "{style}{text}{style:#}");
    } else {
        out.push_str(text);
    }
}
