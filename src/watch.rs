//! `agentrec watch`: record every file change under a directory — whoever makes
//! it — by watching the filesystem, with no hooks and no cooperation from the
//! tool doing the editing.
//!
//! Every coding agent (Claude Code, aider, Cursor, Cline, …) and every human
//! ultimately writes files to disk, so a filesystem watcher captures their edits
//! agent-agnostically. This is the multi-agent half of recording.
//!
//! It is deliberately *observe-only*. Unlike the Claude Code `PreToolUse`
//! guardrail, the watcher sees a change only after it has landed on disk, so it
//! records but can never block. It also does not see shell commands — the
//! filesystem doesn't carry them — which stay with the hook recorder. What it
//! gives you is a faithful, tamper-evident record of *what changed in your
//! files*, no matter which tool changed them.

use std::collections::{BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use notify::{EventKind, RecursiveMode, Watcher};

use crate::error::Error;
use crate::network;
use crate::store::{FileChange, LogEntry, Store, now_ms};

// Directories never worth recording: version-control internals and build/dep
// caches. Matched by name at any depth.
const IGNORE_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".agentrec",
    "target",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".turbo",
    ".gradle",
];

// Files larger than this aren't snapshotted — the watcher is for source, not
// build artifacts or media, and re-reading a huge file on every save is wasteful.
const MAX_FILE: u64 = 5 * 1024 * 1024;

// How long the tree must be quiet before a burst of events is flushed. Editors
// and agents touch a file several times per save; coalescing avoids recording
// half-written intermediate states.
const DEBOUNCE: Duration = Duration::from_millis(400);

/// Watches `root` and records every file change into the project's store until
/// the process is interrupted. Blocks the calling thread.
pub fn watch(root: &Path) -> Result<(), Error> {
    let root = clean_root(root);
    let cwd = root.to_string_lossy().into_owned();
    let store = Store::for_cwd(&cwd)?;
    let session = format!("watch-{}", now_ms());

    let mut w = Watch {
        store,
        root,
        session,
        tracked: HashMap::new(),
    };

    let n = w.scan();
    println!(
        "agentrec: watching {} — {n} files tracked. Records file changes by any tool; Ctrl+C to stop.",
        w.root.display()
    );

    // The watcher pushes filesystem events onto a channel; we drain it on the
    // main thread so recording stays single-threaded and ordered.
    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| Error::Watch(e.to_string()))?;
    watcher
        .watch(&w.root, RecursiveMode::Recursive)
        .map_err(|e| Error::Watch(e.to_string()))?;

    let mut pending: BTreeSet<PathBuf> = BTreeSet::new();
    loop {
        match rx.recv_timeout(DEBOUNCE) {
            // A real change: remember the path, but wait for the tree to go quiet
            // before recording, so a multi-write save collapses into one entry.
            Ok(Ok(event)) => {
                if !matches!(event.kind, EventKind::Access(_)) {
                    pending.extend(event.paths);
                }
            }
            Ok(Err(e)) => eprintln!("agentrec watch: {e}"),
            Err(RecvTimeoutError::Timeout) => {
                if !pending.is_empty() {
                    let batch: Vec<PathBuf> = std::mem::take(&mut pending).into_iter().collect();
                    w.flush(&batch);
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

// A detected change to one file, ready to be recorded.
struct Change {
    file: FileChange,
    network: Vec<String>,
    mark: char,
}

struct Watch {
    store: Store,
    root: PathBuf,
    session: String,
    // path -> content hash of what we last saw, so we can tell a real edit from a
    // metadata-only touch and supply the "before" of the next change.
    tracked: HashMap<PathBuf, String>,
}

impl Watch {
    // Snapshot every tracked file up front so the first change to any of them has
    // a real "before". Returns the number of files now tracked.
    fn scan(&mut self) -> usize {
        let mut stack = vec![self.root.clone()];
        let mut count = 0;
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in rd.flatten() {
                let path = entry.path();
                let Ok(ft) = entry.file_type() else { continue };
                if ft.is_dir() {
                    if !ignored_dir(&path) {
                        stack.push(path);
                    }
                } else if ft.is_file() && self.track_initial(&path) {
                    count += 1;
                }
            }
        }
        count
    }

    fn track_initial(&mut self, path: &Path) -> bool {
        if is_temp(path) {
            return false;
        }
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        if meta.len() > MAX_FILE {
            return false;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return false;
        };
        let Ok(hash) = self.store.put_blob(&bytes) else {
            return false;
        };
        self.tracked.insert(path.to_path_buf(), hash);
        true
    }

    fn flush(&mut self, batch: &[PathBuf]) {
        for path in batch {
            if !self.relevant(path) {
                continue;
            }
            match self.detect(path) {
                Ok(Some(change)) => self.record(change),
                Ok(None) => {}
                Err(e) => eprintln!("agentrec watch: {e}"),
            }
        }
    }

    // Compares a changed path against what we last saw and, if it is a genuine
    // create/modify/delete, produces the change to record (updating our state).
    fn detect(&mut self, path: &Path) -> Result<Option<Change>, Error> {
        let path_str = path.to_string_lossy().into_owned();
        if path.is_file() {
            // Skip races/oversize gracefully — a vanished or huge file is a no-op,
            // not an error worth surfacing.
            let Ok(meta) = std::fs::metadata(path) else {
                return Ok(None);
            };
            if meta.len() > MAX_FILE {
                return Ok(None);
            }
            let Ok(bytes) = std::fs::read(path) else {
                return Ok(None);
            };
            let after = self.store.put_blob(&bytes)?;
            let before = self.tracked.get(path).cloned();
            if before.as_deref() == Some(after.as_str()) {
                return Ok(None); // touched, but the content is identical
            }
            self.tracked.insert(path.to_path_buf(), after.clone());
            let network = network::extract_hosts(&String::from_utf8_lossy(&bytes));
            let mark = if before.is_none() { '+' } else { '~' };
            Ok(Some(Change {
                file: FileChange {
                    path: path_str,
                    before,
                    after: Some(after),
                },
                network,
                mark,
            }))
        } else if path.exists() {
            Ok(None) // a directory or special file: nothing to record
        } else {
            // Gone — a deletion, but only meaningful if we were tracking it.
            match self.tracked.remove(path) {
                Some(before) => Ok(Some(Change {
                    file: FileChange {
                        path: path_str,
                        before: Some(before),
                        after: None,
                    },
                    network: Vec::new(),
                    mark: '-',
                })),
                None => Ok(None),
            }
        }
    }

    fn record(&self, change: Change) {
        let display = self.rel_display(&change.file.path);
        let state = describe(change.file.before.as_deref(), change.file.after.as_deref());
        let entry = LogEntry {
            seq: 0,
            ts_ms: now_ms(),
            session: self.session.clone(),
            tool: "Watch".to_owned(),
            cwd: self.root.to_string_lossy().into_owned(),
            summary: format!("Watch {display} ({state})"),
            file: Some(change.file),
            command: None,
            warnings: Vec::new(),
            network: change.network,
            blocked: None,
            prev_hash: String::new(),
            hash: String::new(),
        };
        match self.store.append(entry) {
            Ok(_) => println!("  {} {display}", change.mark),
            Err(e) => eprintln!("agentrec watch: could not record {display}: {e}"),
        }
    }

    // Whether a path is inside the watched tree and not in an ignored dir or a
    // known editor temp file.
    fn relevant(&self, path: &Path) -> bool {
        let Ok(rel) = path.strip_prefix(&self.root) else {
            return false;
        };
        !is_temp(path)
            && rel.components().all(|c| match c {
                Component::Normal(os) => os.to_str().is_none_or(|s| !IGNORE_DIRS.contains(&s)),
                _ => true,
            })
    }

    fn rel_display(&self, path_str: &str) -> String {
        Path::new(path_str)
            .strip_prefix(&self.root)
            .map_or(path_str, |p| p.to_str().unwrap_or(path_str))
            .replace('\\', "/")
    }
}

fn describe(before: Option<&str>, after: Option<&str>) -> &'static str {
    match (before, after) {
        (None, Some(_)) => "created",
        (Some(_), None) => "deleted",
        _ => "modified",
    }
}

fn ignored_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| IGNORE_DIRS.contains(&n))
}

fn is_temp(path: &Path) -> bool {
    let temp_ext = path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        ["tmp", "swp", "swx"]
            .iter()
            .any(|t| e.eq_ignore_ascii_case(t))
    });
    if temp_ext {
        return true;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.ends_with('~') || name.starts_with(".#") || name.starts_with("4913") // vim probe
}

// Resolve to an absolute path and drop the Windows extended-length prefix, so the
// watched root, the event paths under it, and the recorded paths all share one
// clean spelling. Store keying canonicalizes independently, so this only affects
// display and prefix-stripping, never which store we open.
fn clean_root(root: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let s = canonical.to_string_lossy().into_owned();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => canonical,
    }
}

#[cfg(test)]
mod tests {
    use super::{describe, ignored_dir, is_temp};
    use std::path::Path;

    #[test]
    fn describes_transitions() {
        assert_eq!(describe(None, Some("a")), "created");
        assert_eq!(describe(Some("a"), Some("b")), "modified");
        assert_eq!(describe(Some("a"), None), "deleted");
    }

    #[test]
    fn ignores_vcs_and_build_dirs() {
        assert!(ignored_dir(Path::new("/x/.git")));
        assert!(ignored_dir(Path::new("/x/target")));
        assert!(ignored_dir(Path::new("/x/node_modules")));
        assert!(!ignored_dir(Path::new("/x/src")));
    }

    #[test]
    fn skips_editor_temp_files() {
        assert!(is_temp(Path::new("/x/main.rs.tmp")));
        assert!(is_temp(Path::new("/x/main.rs~")));
        assert!(is_temp(Path::new("/x/.#main.rs")));
        assert!(!is_temp(Path::new("/x/main.rs")));
    }
}
