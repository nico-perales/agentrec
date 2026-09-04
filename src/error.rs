//! Error type for the recorder.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error at {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid hook event JSON: {0}")]
    Event(#[source] serde_json::Error),

    #[error("corrupt log entry: {0}")]
    Log(#[source] serde_json::Error),

    #[error("no recorder store for this project (nothing recorded yet)")]
    NoStore,

    #[error("entry #{0} is not a revertible file change")]
    NotRevertible(u64),

    #[error("filesystem watch error: {0}")]
    Watch(String),
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}
