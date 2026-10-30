//! CID computation and parsing.
//!
//! A CIDv1 for a raw block is:
//!
//! ```text
//!   <multibase 'b'> <0x01 version> <0x55 raw codec> <0x12 sha2-256> <0x20 len(32)> <32-byte digest>
//! ```
//!
//! encoded in lowercase base32, which is why every one of these strings starts
//! with `bafkrei`. The bytes are produced by the `cid` crate (the reference Rust
//! implementation) rather than hand-assembled here; this module only chooses the
//! codec and the hash, and exposes the result.

use cid::Cid;
use sha2::{Digest, Sha256};

/// The multicodec code for a raw block (`0x55`).
///
/// Raw means "the block is exactly the bytes that were hashed", with no UnixFS or
/// dag-pb envelope. For artifacts this is the honest choice: a verifier that
/// fetches the block gets the file, not a structure to unpack.
pub const RAW_CODEC: u64 = 0x55;

/// The multihash code for sha2-256 (`0x12`).
pub const SHA2_256: u64 = 0x12;

/// Why a CID could not be produced or parsed.
#[derive(Debug, thiserror::Error)]
pub enum CidError {
    /// The digest length was not 32 bytes.
    #[error("sha2-256 must produce 32 bytes, got {0}")]
    DigestLength(usize),

    /// The string was not a valid CID.
    #[error("not a valid CID: {0}")]
    Parse(String),
}

/// The CIDv1 (raw, sha2-256) for `bytes`.
///
/// Deterministic: the same bytes always produce the same CID, on every machine
/// and in every process. That is the whole property being relied on.
///
/// # Errors
/// In practice infallible for a 32-byte digest, but returns a `Result` so a
/// future hash change cannot silently produce a malformed CID.
pub fn cid_for_bytes(bytes: &[u8]) -> Result<Cid, CidError> {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mh = cid::multihash::Multihash::<64>::wrap(SHA2_256, &digest)
        .map_err(|_| CidError::DigestLength(digest.len()))?;
    Ok(Cid::new_v1(RAW_CODEC, mh))
}

/// The CID as the string a human or another system will quote.
///
/// # Errors
/// Returns [`CidError`] if the bytes cannot be hashed.
pub fn cid_string(bytes: &[u8]) -> Result<String, CidError> {
    Ok(cid_for_bytes(bytes)?.to_string())
}

/// Parse a CID string (any supported multibase) into a [`Cid`].
///
/// # Errors
/// Returns [`CidError::Parse`] for anything that is not a CID.
pub fn parse_cid(text: &str) -> Result<Cid, CidError> {
    text.trim()
        .parse::<Cid>()
        .map_err(|e| CidError::Parse(e.to_string()))
}

/// The lowercase hex sha2-256 of `bytes`.
///
/// This is the human-readable companion to a CID: the same digest, in a form
/// anybody can check with `sha256sum`. A manifest carries both so a reviewer can
/// verify an artifact without knowing what a CID is.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_encoding_family_is_cidv1_raw_sha256_base32() {
        // b = multibase base32, a = CIDv1, f = ... and the raw codec produces the
        // distinctive `bafkrei` prefix. Asserting the family catches a codec or
        // version mistake, which is the only thing that can go wrong here.
        let cid = cid_string(b"hello world").expect("hash");
        assert!(
            cid.starts_with("bafkrei"),
            "expected a CIDv1 raw sha2-256 base32 string, got {cid}"
        );
    }

    #[test]
    fn the_same_bytes_always_produce_the_same_cid() {
        let a = cid_string(b"attestation").expect("hash");
        let b = cid_string(b"attestation").expect("hash");
        assert_eq!(a, b);
    }

    #[test]
    fn one_flipped_bit_changes_the_cid() {
        let a = cid_string(b"attestation").expect("hash");
        let b = cid_string(b"attestatioN").expect("hash");
        assert_ne!(a, b);
    }

    #[test]
    fn an_empty_block_still_has_a_cid() {
        let cid = cid_string(b"").expect("hash");
        assert!(cid.starts_with("bafkrei"));
    }

    #[test]
    fn a_cid_round_trips_through_its_string_form() {
        let original = cid_for_bytes(b"round trip").expect("hash");
        let parsed = parse_cid(&original.to_string()).expect("parse");
        assert_eq!(original, parsed);
    }

    #[test]
    fn a_non_cid_string_is_an_error_not_a_guess() {
        assert!(parse_cid("not-a-cid").is_err());
        assert!(parse_cid("").is_err());
    }

    #[test]
    fn the_hex_digest_matches_the_cid_digest() {
        // The two must describe the same hash, or the manifest would carry a
        // "human-checkable" value that disagrees with the machine-checked one.
        let bytes = b"same digest";
        let cid = cid_for_bytes(bytes).expect("hash");
        let digest_hex = sha256_hex(bytes);
        let cid_hex: String = cid
            .hash()
            .digest()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(digest_hex, cid_hex);
    }
}
