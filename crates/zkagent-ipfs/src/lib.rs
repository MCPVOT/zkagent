//! `zkagent-ipfs` — content addressing for attestation artifacts.
//!
//! # Why this exists
//!
//! A zero-knowledge proof gives you two things: it is **sound** (a false
//! statement cannot be proven) and it is **private** (the witness stays hidden).
//! It gives you nothing about **where the bytes live** or **whether the bytes you
//! received are the bytes that were attested**. That is the other half.
//!
//! IPFS supplies exactly that: address a block by the hash of its contents, so the
//! name *is* the integrity check. Fetch the same CID from a hostile gateway and the
//! hash still tells you whether you got the right bytes.
//!
//! | | ZK alone | IPFS alone | both |
//! |---|---|---|---|
//! | the statement is true | yes | no | yes |
//! | the bytes are unmodified | no | yes | yes |
//! | the witness stays private | yes | no | yes |
//! | anyone can fetch the artifact | no | yes | yes |
//!
//! # What this crate is, precisely
//!
//! It computes **CIDv1 (raw codec, sha2-256)** over artifact bytes, defines a
//! manifest that names every artifact by CID, and fetches and validates blocks
//! from a content-addressed source.
//!
//! It is **not** a libp2p node: no DHT, no bitswap, no pinning, no IPNS. A full
//! node is a different dependency with a very different cost profile
//! (`dariusc93/rust-ipfs` builds in tens of minutes and pulls libp2p), and a
//! library that has to embed in a Tauri app or an MCP server cannot carry that by
//! default. What a verifier needs is narrower: *given a CID, get the bytes and
//! check the hash*. That is what this crate does.
//!
//! # The rule this crate enforces
//!
//! **Never trust the transport.** A gateway, a mirror, or a peer can return any
//! bytes it likes. Every fetch is re-hashed and compared against the CID that was
//! requested, and a mismatch is a hard error, not a warning.
//!
//! # Circuit identity
//!
//! `docs/TESTING.md` requires every attestation to record which circuit it belongs
//! to, because a proof is only meaningful relative to a circuit. The manifest
//! carries the verifying key **by CID**, so circuit identity is not a comment that
//! can drift from the bytes: it is the bytes.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod cid;
pub mod manifest;
pub mod source;

pub use cid::{cid_for_bytes, cid_string, parse_cid, sha256_hex, CidError, RAW_CODEC, SHA2_256};
pub use manifest::{
    ArtifactRef, AttestationManifest, CircuitRef, ManifestError, VerifiedBundle, MANIFEST_KIND,
    MANIFEST_VERSION,
};
pub use source::{BlockSource, DirSource, MemorySource, SourceError};

#[cfg(feature = "gateway")]
pub use source::GatewaySource;

/// The crate version, for hosts that report it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
