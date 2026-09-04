//! agentrec: a local, offline flight recorder for AI coding agents.
//!
//! It plugs into an agent's tool hooks and records every action — file edits
//! (with before/after content) and shell commands — into a tamper-evident,
//! hash-chained log under the user's home directory. It makes no network calls,
//! needs no account or API key, and never transmits what it records.

mod error;
mod event;
mod policy;
mod record;
mod revert;
mod store;
mod timeline;
mod web;

pub mod render;

pub use error::Error;
pub use event::HookEvent;
pub use record::{HookOutcome, handle};
pub use revert::{RevertKind, RevertOutcome, revert};
pub use store::{CommandRecord, FileChange, LogEntry, Store};
pub use timeline::{Integrity, load, verify};
pub use web::review_html;
