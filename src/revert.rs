//! Reverting a recorded file change.
//!
//! Because every file edit captured its *before* content into the blob store,
//! undoing one is just restoring that blob (or deleting the file, if the action
//! had created it). The revert is itself recorded as a new `Revert` entry — with
//! the just-replaced content as its own *before* — so reverts are auditable and
//! can themselves be reverted, and the tamper-evident chain stays unbroken.

use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::store::{FileChange, LogEntry, Store, now_ms};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevertKind {
    /// The file existed and was restored to its earlier content.
    Restored,
    /// The file was gone and has been re-created with its earlier content.
    Recreated,
    /// The action had created the file; reverting removes it.
    Deleted,
    /// The action had created the file and it is already gone — nothing to do.
    AlreadyGone,
}

#[derive(Debug, Clone)]
pub struct RevertOutcome {
    pub seq: u64,
    pub path: String,
    pub kind: RevertKind,
    pub dry_run: bool,
}

/// Reverts the file change recorded by `entry`, restoring the file to the state
/// it had *before* that action. With `dry_run`, reports what would happen without
/// touching the file or the log.
pub fn revert(store: &Store, entry: &LogEntry, dry_run: bool) -> Result<RevertOutcome, Error> {
    let Some(file) = &entry.file else {
        return Err(Error::NotRevertible(entry.seq));
    };

    let target = resolve(&entry.cwd, &file.path);
    let current = std::fs::read(&target).ok();
    let existed = current.is_some();

    let kind = match (&file.before, existed) {
        (Some(_), true) => RevertKind::Restored,
        (Some(_), false) => RevertKind::Recreated,
        (None, true) => RevertKind::Deleted,
        (None, false) => RevertKind::AlreadyGone,
    };

    let outcome = RevertOutcome {
        seq: entry.seq,
        path: file.path.clone(),
        kind,
        dry_run,
    };
    if dry_run || kind == RevertKind::AlreadyGone {
        return Ok(outcome);
    }

    // Apply the restore.
    match &file.before {
        Some(hash) => {
            let content = store.get_blob(hash)?;
            if let Some(parent) = target.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&target, &content).map_err(|e| Error::io(&target, e))?;
        }
        None => std::fs::remove_file(&target).map_err(|e| Error::io(&target, e))?,
    }

    // Record the revert itself: from the content we just replaced, to the
    // restored content — making it a first-class, re-revertible action.
    let replaced = match &current {
        Some(bytes) => Some(store.put_blob(bytes)?),
        None => None,
    };
    store.append(LogEntry {
        seq: 0,
        ts_ms: now_ms(),
        session: "agentrec".to_owned(),
        tool: "Revert".to_owned(),
        cwd: entry.cwd.clone(),
        summary: format!("revert #{} {}", entry.seq, file.path),
        file: Some(FileChange {
            path: file.path.clone(),
            before: replaced,
            after: file.before.clone(),
        }),
        command: None,
        warnings: Vec::new(),
        blocked: None,
        prev_hash: String::new(),
        hash: String::new(),
    })?;

    Ok(outcome)
}

fn resolve(cwd: &str, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new(cwd).join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::{RevertKind, revert};
    use crate::store::{FileChange, LogEntry, Store};

    fn temp() -> (Store, std::path::PathBuf, guard::Guard) {
        let guard = guard::Guard::new();
        let proj = guard.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let store = Store::for_cwd_in(&guard.path().join("home"), &proj.to_string_lossy()).unwrap();
        (store, proj, guard)
    }

    fn entry(cwd: &str, path: &str, before: Option<String>, after: Option<String>) -> LogEntry {
        LogEntry {
            seq: 1,
            ts_ms: 0,
            session: "s".to_owned(),
            tool: "Edit".to_owned(),
            cwd: cwd.to_owned(),
            summary: "Edit".to_owned(),
            file: Some(FileChange {
                path: path.to_owned(),
                before,
                after,
            }),
            command: None,
            warnings: Vec::new(),
            blocked: None,
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    #[test]
    fn restores_prior_content_and_records_the_revert() {
        let (store, proj, _g) = temp();
        let target = proj.join("f.txt");
        std::fs::write(&target, b"AFTER").unwrap();
        let before = store.put_blob(b"BEFORE").unwrap();
        let after = store.put_blob(b"AFTER").unwrap();

        let e = entry(
            &proj.to_string_lossy(),
            &target.to_string_lossy(),
            Some(before),
            Some(after),
        );
        let out = revert(&store, &e, false).unwrap();

        assert_eq!(out.kind, RevertKind::Restored);
        assert_eq!(std::fs::read(&target).unwrap(), b"BEFORE");
        // The revert is itself logged.
        let last = store.entries().unwrap().pop().unwrap();
        assert_eq!(last.tool, "Revert");
    }

    #[test]
    fn dry_run_changes_nothing() {
        let (store, proj, _g) = temp();
        let target = proj.join("f.txt");
        std::fs::write(&target, b"AFTER").unwrap();
        let before = store.put_blob(b"BEFORE").unwrap();

        let e = entry(
            &proj.to_string_lossy(),
            &target.to_string_lossy(),
            Some(before),
            None,
        );
        let out = revert(&store, &e, true).unwrap();

        assert!(out.dry_run);
        assert_eq!(std::fs::read(&target).unwrap(), b"AFTER");
        assert!(store.entries().unwrap().is_empty());
    }

    // A minimal RAII temp directory, self-contained (no external crate).
    mod guard {
        use std::path::{Path, PathBuf};
        pub struct Guard(PathBuf);
        impl Guard {
            pub fn new() -> Self {
                let n = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let p = std::env::temp_dir().join(format!("agentrec-revert-{n}"));
                std::fs::create_dir_all(&p).unwrap();
                Guard(p)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
