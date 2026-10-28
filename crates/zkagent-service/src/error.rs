//! Failures the service layer can report.
//!
//! Every variant carries the *path* or the *value* that caused it, because an
//! embedding host (a Tauri app, an MCP harness, a CLI) has to show the user
//! something actionable. A bare "I/O error" is not actionable.

use std::path::PathBuf;

/// Anything that can go wrong in the service layer.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// A file could not be read or written.
    #[error("io error on {path}: {detail}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying cause.
        detail: String,
    },

    /// A JSON artifact could not be parsed or written.
    #[error("malformed artifact {path}: {detail}")]
    Malformed {
        /// The file involved.
        path: PathBuf,
        /// What was wrong with it.
        detail: String,
    },

    /// The requested policy is not a valid policy.
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    /// The authority key could not be produced or read.
    #[error("authority key: {0}")]
    Authority(String),

    /// The replay state could not be loaded or persisted.
    ///
    /// Deliberately fatal. A verifier that cannot read the set of executions it
    /// has already accepted must not proceed as though the set were empty.
    #[error("replay state: {0}")]
    Replay(String),

    /// The verifying key or proof artifact was unusable.
    #[error("verification material: {0}")]
    Verification(String),
}

impl ServiceError {
    /// Build an I/O error for `path`.
    pub fn io(path: impl Into<PathBuf>, detail: impl std::fmt::Display) -> Self {
        ServiceError::Io {
            path: path.into(),
            detail: detail.to_string(),
        }
    }

    /// Build a malformed-artifact error for `path`.
    pub fn malformed(path: impl Into<PathBuf>, detail: impl std::fmt::Display) -> Self {
        ServiceError::Malformed {
            path: path.into(),
            detail: detail.to_string(),
        }
    }
}
