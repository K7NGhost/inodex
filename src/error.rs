//! Structured errors for callers that need to distinguish corruption from I/O.

use std::{io, path::PathBuf};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid E01 data at segment offset {offset:#x}: {reason}")]
    InvalidFormat { offset: u64, reason: String },
    #[error("unsupported image format: {0}")]
    Unsupported(String),
    #[error("corrupt {layer} data at offset {offset:#x}: {reason}")]
    Corrupt {
        layer: &'static str,
        offset: u64,
        reason: String,
    },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("not a directory: {0}")]
    NotDirectory(String),
    #[error(
        "{context} checksum mismatch at offset {offset:#x}: stored {stored:08x}, calculated {calculated:08x}"
    )]
    Checksum {
        context: &'static str,
        offset: u64,
        stored: u32,
        calculated: u32,
    },
    #[error("missing segment {number}: {path}")]
    MissingSegment { number: u16, path: PathBuf },
    #[error("parser resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("{algorithm} media digest mismatch: stored {stored}, calculated {calculated}")]
    DigestMismatch {
        algorithm: &'static str,
        stored: String,
        calculated: String,
    },
}

pub(crate) fn invalid(offset: u64, reason: impl Into<String>) -> Error {
    Error::InvalidFormat {
        offset,
        reason: reason.into(),
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Io(error) => error,
            error => Self::new(io::ErrorKind::InvalidData, error),
        }
    }
}
