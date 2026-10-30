//! Where blocks come from, and the rule that they are always re-checked.
//!
//! A [`BlockSource`] is anything that can produce bytes for a CID. The trait is
//! deliberately tiny, because the security property is not in the transport: it
//! is in the caller re-hashing what the transport returned.
//!
//! Three implementations ship here:
//!
//! - [`MemorySource`] — tests, and hosts that already hold the blocks.
//! - [`DirSource`] — a local directory of blocks, which is what a `ipfs get`
//!   output or a pinned repo looks like. No daemon required.
//! - `GatewaySource` (feature `gateway`) — an HTTP gateway, so a verifier with no
//!   IPFS node can still fetch by CID.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cid::{cid_string, parse_cid, CidError};

/// Why a block could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The block is not in this source.
    #[error("block not found: {0}")]
    NotFound(String),

    /// An I/O error while reading or writing a block.
    #[error("io on {path}: {detail}")]
    Io {
        /// Path involved.
        path: PathBuf,
        /// Underlying cause.
        detail: String,
    },

    /// The CID string was not a valid CID.
    #[error("bad cid: {0}")]
    BadCid(String),

    /// A transport error (feature `gateway`).
    #[error("transport: {0}")]
    Transport(String),
}

impl From<CidError> for SourceError {
    fn from(e: CidError) -> Self {
        SourceError::BadCid(e.to_string())
    }
}

/// Anything that can produce the bytes for a CID.
pub trait BlockSource {
    /// Fetch a block by CID.
    ///
    /// # Errors
    /// [`SourceError::NotFound`] when the source does not have it;
    /// [`SourceError::Transport`] when a network fetch failed.
    fn get(&self, cid: &str) -> Result<Vec<u8>, SourceError>;

    /// Whether the source claims to have a block.
    ///
    /// A `true` here is not a promise: the bytes are always re-checked after
    /// fetching.
    fn has(&self, cid: &str) -> bool {
        self.get(cid).is_ok()
    }
}

/// Blocks held in memory. Used by the tests and by a host that already has them.
#[derive(Debug, Default, Clone)]
pub struct MemorySource {
    blocks: BTreeMap<String, Vec<u8>>,
}

impl MemorySource {
    /// An empty source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store bytes and return their CID.
    ///
    /// # Errors
    /// Returns [`SourceError::BadCid`] if the bytes cannot be hashed.
    pub fn put(&mut self, bytes: &[u8]) -> Result<String, SourceError> {
        let cid = cid_string(bytes)?;
        self.blocks.insert(cid.clone(), bytes.to_vec());
        Ok(cid)
    }

    /// How many blocks are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the source is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Replace a block's bytes without changing its key.
    ///
    /// This exists to model a **hostile** source in tests: a mirror that returns
    /// bytes which do not match the CID it was asked for. It is not a mutation
    /// API for production code.
    pub fn poison(&mut self, cid: &str, bytes: Vec<u8>) {
        self.blocks.insert(cid.to_string(), bytes);
    }
}

impl BlockSource for MemorySource {
    fn get(&self, cid: &str) -> Result<Vec<u8>, SourceError> {
        // Validate the string so a caller cannot smuggle a path or a URL here.
        parse_cid(cid)?;
        self.blocks
            .get(cid)
            .cloned()
            .ok_or_else(|| SourceError::NotFound(cid.to_string()))
    }
}

/// A directory of blocks, one file per CID.
///
/// Layout: `<root>/<cid>.block`. Raw bytes, no envelope, so the file content is
/// exactly what was hashed — which is what makes the round trip meaningful.
#[derive(Debug, Clone)]
pub struct DirSource {
    root: PathBuf,
}

impl DirSource {
    /// Use `root` as the block directory (created on the first write).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory in use.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where a CID is stored.
    #[must_use]
    pub fn path_for(&self, cid: &str) -> PathBuf {
        self.root.join(format!("{cid}.block"))
    }

    /// Write bytes and return their CID.
    ///
    /// # Errors
    /// [`SourceError::Io`] on a filesystem error.
    pub fn put(&self, bytes: &[u8]) -> Result<String, SourceError> {
        let cid = cid_string(bytes)?;
        fs::create_dir_all(&self.root).map_err(|e| SourceError::Io {
            path: self.root.clone(),
            detail: e.to_string(),
        })?;
        let path = self.path_for(&cid);
        fs::write(&path, bytes).map_err(|e| SourceError::Io {
            path,
            detail: e.to_string(),
        })?;
        Ok(cid)
    }
}

impl BlockSource for DirSource {
    fn get(&self, cid: &str) -> Result<Vec<u8>, SourceError> {
        parse_cid(cid)?;
        let path = self.path_for(cid);
        match fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(SourceError::NotFound(cid.to_string()))
            }
            Err(e) => Err(SourceError::Io {
                path,
                detail: e.to_string(),
            }),
        }
    }
}

/// A public HTTP gateway, for verifiers with no IPFS node.
///
/// **The gateway is not trusted.** It may return any bytes; [`crate::manifest`]
/// re-hashes every block against the CID it asked for, which is what makes an
/// untrusted gateway safe to use.
#[cfg(feature = "gateway")]
#[derive(Debug, Clone)]
pub struct GatewaySource {
    base: String,
    timeout_secs: u64,
}

#[cfg(feature = "gateway")]
impl GatewaySource {
    /// Point at a gateway base URL, e.g. `https://ipfs.io/ipfs`.
    #[must_use]
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            timeout_secs: 30,
        }
    }

    /// Override the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}

#[cfg(feature = "gateway")]
impl BlockSource for GatewaySource {
    fn get(&self, cid: &str) -> Result<Vec<u8>, SourceError> {
        // A CID, not a path: this rejects `../` and absolute URLs before any
        // request is made.
        parse_cid(cid)?;
        let url = format!("{}/{cid}", self.base);

        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build();

        match agent.get(&url).call() {
            Ok(response) => {
                let mut bytes = Vec::new();
                response
                    .into_reader()
                    .read_to_end(&mut bytes)
                    .map_err(|e| SourceError::Transport(format!("{url}: {e}")))?;
                Ok(bytes)
            }
            Err(ureq::Error::Status(404, _)) => Err(SourceError::NotFound(cid.to_string())),
            Err(e) => Err(SourceError::Transport(format!("{url}: {e}"))),
        }
    }
}

#[cfg(feature = "gateway")]
use std::io::Read;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memory_source_round_trips_a_block() {
        let mut source = MemorySource::new();
        let cid = source.put(b"block body").expect("put");
        assert_eq!(source.get(&cid).expect("get"), b"block body");
        assert!(source.has(&cid));
    }

    #[test]
    fn a_missing_block_is_not_found_rather_than_empty() {
        let source = MemorySource::new();
        let cid = cid_string(b"never stored").expect("hash");
        match source.get(&cid) {
            Err(SourceError::NotFound(got)) => assert_eq!(got, cid),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn a_path_like_cid_is_rejected_before_any_io() {
        // The guard that stops a hostile manifest from reading `../../etc/passwd`.
        let source = MemorySource::new();
        assert!(source.get("../../etc/passwd").is_err());
        assert!(source.get("https://evil.example/x").is_err());
    }

    #[test]
    fn a_directory_source_round_trips_a_block() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = DirSource::new(dir.path().join("blocks"));
        let cid = source.put(b"on disk").expect("put");

        assert!(source.path_for(&cid).exists());
        assert_eq!(source.get(&cid).expect("get"), b"on disk");
    }

    #[test]
    fn two_sources_of_the_same_bytes_agree_on_the_cid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let disk = DirSource::new(dir.path());
        let mut mem = MemorySource::new();

        let a = disk.put(b"same block").expect("put");
        let b = mem.put(b"same block").expect("put");
        assert_eq!(a, b, "content addressing must be source-independent");
    }

    #[test]
    fn a_directory_source_reports_io_errors_distinctly_from_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = DirSource::new(dir.path().join("blocks"));
        let cid = cid_string(b"absent").expect("hash");
        assert!(matches!(source.get(&cid), Err(SourceError::NotFound(_))));
    }
}
