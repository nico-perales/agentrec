//! Reading and verifying the recorded timeline.

use crate::error::Error;
use crate::store::{GENESIS, LogEntry, Store};

/// The result of checking the hash chain.
#[derive(Debug, Clone)]
pub enum Integrity {
    /// Every entry hashes and chains correctly.
    Ok { entries: usize },
    /// The chain breaks at `seq`.
    Broken { seq: u64, reason: String },
}

/// Loads the full timeline for a project store.
pub fn load(store: &Store) -> Result<Vec<LogEntry>, Error> {
    store.entries()
}

/// Walks the chain, confirming each entry's hash and its link to the previous.
///
/// Note: a hash chain detects any modification, reordering, or deletion of an
/// entry that has something after it. Deleting only the most recent entries
/// cannot be detected by the chain alone (nothing binds them) — an anchoring or
/// signing step, tracked for a later version, would close that gap.
pub fn verify(store: &Store) -> Result<Integrity, Error> {
    let entries = store.entries()?;
    let mut prev_hash = GENESIS.to_owned();
    let mut prev_seq = 0u64;

    for entry in &entries {
        if entry.prev_hash != prev_hash {
            return Ok(Integrity::Broken {
                seq: entry.seq,
                reason: "prev_hash does not match the previous entry".to_owned(),
            });
        }
        if entry.compute_hash() != entry.hash {
            return Ok(Integrity::Broken {
                seq: entry.seq,
                reason: "entry contents do not match its hash (tampered)".to_owned(),
            });
        }
        if entry.seq != prev_seq + 1 {
            return Ok(Integrity::Broken {
                seq: entry.seq,
                reason: format!("sequence gap (expected {})", prev_seq + 1),
            });
        }
        prev_hash.clone_from(&entry.hash);
        prev_seq = entry.seq;
    }

    Ok(Integrity::Ok {
        entries: entries.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::{Integrity, verify};
    use crate::store::{LogEntry, Store};

    fn temp_store() -> (Store, tempdir::Guard) {
        let guard = tempdir::Guard::new();
        let store = Store::for_cwd_in(guard.path(), "/proj/x").unwrap();
        (store, guard)
    }

    fn entry(tool: &str) -> LogEntry {
        LogEntry {
            seq: 0,
            ts_ms: 0,
            session: "s".to_owned(),
            tool: tool.to_owned(),
            cwd: "/proj/x".to_owned(),
            summary: tool.to_owned(),
            file: None,
            command: None,
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    #[test]
    fn a_clean_chain_verifies() {
        let (store, _g) = temp_store();
        store.append(entry("Read")).unwrap();
        store.append(entry("Edit")).unwrap();
        assert!(matches!(
            verify(&store).unwrap(),
            Integrity::Ok { entries: 2 }
        ));
    }

    // A minimal RAII temp directory so tests don't need an external crate.
    mod tempdir {
        use std::path::{Path, PathBuf};
        pub struct Guard(PathBuf);
        impl Guard {
            pub fn new() -> Self {
                let n = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let p = std::env::temp_dir().join(format!("agentrec-test-{n}"));
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
