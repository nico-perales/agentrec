//! On-disk store: a content-addressed blob store plus a hash-chained,
//! append-only log — entirely under the user's home, never the network.
//!
//! Layout (per project, keyed by a hash of its cwd):
//! ```text
//! $AGENTREC_HOME (or ~/.agentrec)/projects/<key>/
//!   meta.json          { cwd }
//!   blobs/<sha256>     raw file contents, deduplicated
//!   pending/<key>      a PreToolUse snapshot awaiting its PostToolUse record
//!   log.jsonl          one JSON entry per action
//!   head.json          { seq, hash } of the last entry (O(1) appends)
//! ```

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Error;

// The genesis hash the first entry chains from.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    /// Blob hash of the file before the edit (`None` if it was newly created).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    /// Blob hash of the file after the edit (`None` if it no longer exists).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub ts_ms: u128,
    pub session: String,
    pub tool: String,
    pub cwd: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<CommandRecord>,
    /// Non-blocking guardrail concerns about this action.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Hosts this action reaches out to, inferred from its text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Present when the action was blocked by the guardrail; the reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

impl LogEntry {
    // The entry's hash binds every field, including `prev_hash`, so any edit or
    // reordering of the log is detectable. Computed with `hash` blanked.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let mut bare = self.clone();
        bare.hash = String::new();
        let json = serde_json::to_string(&bare).unwrap_or_default();
        sha256_hex(json.as_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Head {
    pub seq: u64,
    pub hash: String,
}

impl Default for Head {
    fn default() -> Self {
        Head {
            seq: 0,
            hash: GENESIS.to_owned(),
        }
    }
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Opens (creating) the store for the project at `cwd`.
    pub fn for_cwd(cwd: &str) -> Result<Store, Error> {
        Self::for_cwd_in(&base_dir(), cwd)
    }

    /// As [`Store::for_cwd`] but under an explicit base directory (used by tests).
    pub fn for_cwd_in(base: &Path, cwd: &str) -> Result<Store, Error> {
        let root = base.join("projects").join(project_key(cwd));
        mkdir(&root.join("blobs"))?;
        mkdir(&root.join("pending"))?;
        let store = Store { root };
        // Record the human-readable cwd once, for project listing tooling.
        let meta = store.root.join("meta.json");
        if !meta.is_file() {
            write_atomic(
                &meta,
                format!("{{\"cwd\":{}}}", json_string(cwd)).as_bytes(),
            )?;
        }
        Ok(store)
    }

    /// Opens the existing store for `cwd`, or errors if nothing was recorded.
    pub fn open(cwd: &str) -> Result<Store, Error> {
        let root = base_dir().join("projects").join(project_key(cwd));
        if root.join("log.jsonl").is_file() {
            Ok(Store { root })
        } else {
            Err(Error::NoStore)
        }
    }

    /// Stores `bytes` as a blob and returns its content hash (deduplicated).
    pub fn put_blob(&self, bytes: &[u8]) -> Result<String, Error> {
        let hash = sha256_hex(bytes);
        let path = self.root.join("blobs").join(&hash);
        if !path.is_file() {
            write_atomic(&path, bytes)?;
        }
        Ok(hash)
    }

    pub fn get_blob(&self, hash: &str) -> Result<Vec<u8>, Error> {
        let path = self.root.join("blobs").join(hash);
        fs::read(&path).map_err(|e| Error::io(path, e))
    }

    pub fn head(&self) -> Result<Head, Error> {
        let path = self.root.join("head.json");
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(Error::Log),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Head::default()),
            Err(e) => Err(Error::io(path, e)),
        }
    }

    /// Chains and appends an entry, returning it with its computed seq/hash.
    pub fn append(&self, mut entry: LogEntry) -> Result<LogEntry, Error> {
        let head = self.head()?;
        entry.seq = head.seq + 1;
        entry.prev_hash = head.hash;
        entry.hash = entry.compute_hash();

        let line = format!("{}\n", serde_json::to_string(&entry).map_err(Error::Log)?);
        let log = self.root.join("log.jsonl");
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .and_then(|mut f| f.write_all(line.as_bytes()))
            .map_err(|e| Error::io(&log, e))?;

        let head = Head {
            seq: entry.seq,
            hash: entry.hash.clone(),
        };
        write_atomic(
            &self.root.join("head.json"),
            serde_json::to_vec(&head).map_err(Error::Log)?.as_slice(),
        )?;
        Ok(entry)
    }

    pub fn entries(&self) -> Result<Vec<LogEntry>, Error> {
        let path = self.root.join("log.jsonl");
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::io(path, e)),
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).map_err(Error::Log))
            .collect()
    }

    // --- pending PreToolUse snapshots ---

    pub fn put_pending(&self, key: &str, before: Option<&str>) -> Result<(), Error> {
        let value = before.map_or_else(|| "null".to_owned(), json_string);
        write_atomic(&self.pending_path(key), value.as_bytes())
    }

    /// Reads and removes the pending snapshot for `key`, if any.
    pub fn take_pending(&self, key: &str) -> Option<String> {
        let path = self.pending_path(key);
        let bytes = fs::read(&path).ok()?;
        let _ = fs::remove_file(&path);
        serde_json::from_slice::<Option<String>>(&bytes)
            .ok()
            .flatten()
    }

    fn pending_path(&self, key: &str) -> PathBuf {
        self.root.join("pending").join(sha256_hex(key.as_bytes()))
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

// The store key for a project. The cwd is canonicalized first so the same
// directory always maps to the same store, even if the agent passes it in a
// different string form (forward vs back slashes, relative segments) than the
// CLI sees. Falls back to the raw string when the path can't be canonicalized.
fn project_key(cwd: &str) -> String {
    let resolved = std::fs::canonicalize(cwd)
        .map_or_else(|_| cwd.to_owned(), |p| p.to_string_lossy().into_owned());
    sha256_hex(normalize_path(&resolved).as_bytes())[..16].to_owned()
}

// Reduces a path to a stable form so the same directory keys the same store
// regardless of how the agent vs the CLI spelled it: strip the Windows
// extended-length prefix, unify separators, drop a trailing slash, and (on
// Windows, whose filesystem is case-insensitive) lowercase.
fn normalize_path(path: &str) -> String {
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    let mut out = path.replace('\\', "/");
    while out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    if cfg!(windows) {
        out = out.to_lowercase();
    }
    out
}

/// Milliseconds since the Unix epoch, for timestamping entries.
pub(crate) fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

pub fn base_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("AGENTREC_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_default();
    PathBuf::from(home).join(".agentrec")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn mkdir(path: &Path) -> Result<(), Error> {
    fs::create_dir_all(path).map_err(|e| Error::io(path, e))
}

// Write via a temp file + rename so a crash never leaves a half-written file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| Error::io(&tmp, e))?;
    fs::rename(&tmp, path).map_err(|e| Error::io(path, e))
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned())
}
