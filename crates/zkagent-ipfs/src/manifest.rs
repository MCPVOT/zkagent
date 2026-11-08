//! The attestation manifest: every artifact named by CID, and the check that the
//! bytes you received are the bytes that were attested.
//!
//! # Why a manifest and not four files
//!
//! A verifier needs four things: the verifying key, the signed policy, the
//! receipt, and the proof. Publishing them as four loose files means four
//! opportunities to mix up a version — and a proof verified against the wrong
//! verifying key fails in a way that looks like a broken prover.
//!
//! The manifest binds them:
//!
//! ```json
//! {
//!   "kind": "zkagent/attestation",
//!   "version": 1,
//!   "circuit": {
//!     "vk": { "cid": "bafkrei…", "bytes": 712, "sha256": "…" },
//!     "constraints": 7442,
//!     "public_inputs": 16,
//!     "format_version": 2
//!   },
//!   "policy":  { "cid": "bafkrei…", "bytes": 421, "sha256": "…" },
//!   "receipt": { "cid": "bafkrei…", "bytes": 118, "sha256": "…" },
//!   "proof":   { "cid": "bafkrei…", "bytes": 2170, "sha256": "…" },
//!   "created_at": 1761700000
//! }
//! ```
//!
//! # The property this gives you
//!
//! [`AttestationManifest::collect`] fetches each block and **recomputes its CID**.
//! A block that does not hash to the CID the manifest names is refused, so the
//! manifest is a commitment to the exact bytes of the whole bundle. Combined with
//! the proof, that means a verifier knows both *"these bytes are what was
//! attested"* and *"the attestation is true"*.
//!
//! The `constraints` / `public_inputs` / `format_version` fields are recorded for
//! the same reason `docs/TESTING.md` demands them: a proof is meaningless without
//! saying which circuit it belongs to.

use serde::{Deserialize, Serialize};

use crate::cid::{cid_for_bytes, parse_cid, sha256_hex, CidError};
use crate::source::{BlockSource, SourceError};

/// The manifest's `kind` field. Anything else is not an attestation manifest.
pub const MANIFEST_KIND: &str = "zkagent/attestation";

/// The manifest format version this crate writes and understands.
pub const MANIFEST_VERSION: u32 = 1;

/// A reference to one artifact, by content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// CIDv1 (raw, sha2-256) of the artifact bytes.
    pub cid: String,
    /// Length of the artifact in bytes.
    pub bytes: u64,
    /// Lowercase hex sha2-256, so a human can check it with `sha256sum`.
    pub sha256: String,
}

impl ArtifactRef {
    /// Describe `bytes` as an artifact reference.
    ///
    /// # Errors
    /// Returns [`CidError`] if the bytes cannot be hashed.
    pub fn of(bytes: &[u8]) -> Result<Self, CidError> {
        Ok(Self {
            cid: cid_for_bytes(bytes)?.to_string(),
            bytes: bytes.len() as u64,
            sha256: sha256_hex(bytes),
        })
    }
}

/// Which circuit an attestation belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitRef {
    /// The verifying key, by content. This *is* the circuit identity.
    pub vk: ArtifactRef,
    /// Constraint count the circuit was measured at.
    pub constraints: usize,
    /// Public-input count.
    pub public_inputs: usize,
    /// Proof artifact format version.
    pub format_version: u32,
}

/// A published attestation: four content-addressed artifacts plus circuit identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationManifest {
    /// Always [`MANIFEST_KIND`].
    pub kind: String,
    /// The manifest format version.
    pub version: u32,
    /// Circuit identity.
    pub circuit: CircuitRef,
    /// The signed policy artifact.
    pub policy: ArtifactRef,
    /// The receipt artifact.
    pub receipt: ArtifactRef,
    /// The proof artifact.
    pub proof: ArtifactRef,
    /// Unix seconds when the manifest was built.
    pub created_at: u64,
}

/// Everything fetched and checked, ready to hand to the verifier.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    /// Verifying key bytes.
    pub vk: Vec<u8>,
    /// Signed policy bytes.
    pub policy: Vec<u8>,
    /// Receipt bytes.
    pub receipt: Vec<u8>,
    /// Proof bytes.
    pub proof: Vec<u8>,
}

/// Why a manifest could not be built or honoured.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// A CID could not be computed.
    #[error("cid: {0}")]
    Cid(#[from] CidError),

    /// A block could not be fetched.
    #[error("source: {0}")]
    Source(#[from] SourceError),

    /// The block that came back does not hash to the CID that was asked for.
    ///
    /// This is the attack the whole crate exists to stop: a mirror or gateway
    /// returning different bytes under a known name.
    #[error("{artifact}: content does not match its CID (expected {expected}, got {got})")]
    Integrity {
        /// Which artifact.
        artifact: &'static str,
        /// The CID the manifest named.
        expected: String,
        /// The CID the received bytes actually hash to.
        got: String,
    },

    /// The artifact was a different length than the manifest said.
    #[error("{artifact}: expected {expected} bytes, got {got}")]
    Size {
        /// Which artifact.
        artifact: &'static str,
        /// Declared length.
        expected: u64,
        /// Actual length.
        got: usize,
    },

    /// The document is not an attestation manifest.
    #[error("not a zkagent attestation manifest (kind {0:?})")]
    Kind(String),

    /// The manifest version is not supported.
    #[error("unsupported manifest version {0}; this build understands {MANIFEST_VERSION}")]
    Version(u32),
}

impl AttestationManifest {
    /// Build a manifest for a bundle.
    ///
    /// # Errors
    /// Returns [`ManifestError::Cid`] if an artifact cannot be hashed.
    pub fn build(
        circuit: CircuitRef,
        policy: &[u8],
        receipt: &[u8],
        proof: &[u8],
        created_at: u64,
    ) -> Result<Self, ManifestError> {
        Ok(Self {
            kind: MANIFEST_KIND.to_string(),
            version: MANIFEST_VERSION,
            circuit,
            policy: ArtifactRef::of(policy)?,
            receipt: ArtifactRef::of(receipt)?,
            proof: ArtifactRef::of(proof)?,
            created_at,
        })
    }

    /// The circuit reference, built from a verifying key.
    ///
    /// # Errors
    /// Returns [`ManifestError::Cid`] if the key cannot be hashed.
    pub fn circuit_ref(
        vk: &[u8],
        constraints: usize,
        public_inputs: usize,
        format_version: u32,
    ) -> Result<CircuitRef, ManifestError> {
        Ok(CircuitRef {
            vk: ArtifactRef::of(vk)?,
            constraints,
            public_inputs,
            format_version,
        })
    }

    /// Every artifact reference with its label.
    #[must_use]
    pub fn refs(&self) -> [(&'static str, &ArtifactRef); 4] {
        [
            ("verifying key", &self.circuit.vk),
            ("policy", &self.policy),
            ("receipt", &self.receipt),
            ("proof", &self.proof),
        ]
    }

    /// Check the document is one we can honour.
    ///
    /// # Errors
    /// [`ManifestError::Kind`] or [`ManifestError::Version`].
    pub fn check_shape(&self) -> Result<(), ManifestError> {
        if self.kind != MANIFEST_KIND {
            return Err(ManifestError::Kind(self.kind.clone()));
        }
        if self.version != MANIFEST_VERSION {
            return Err(ManifestError::Version(self.version));
        }
        // Every CID must parse before we start fetching, so a hostile manifest
        // cannot make us request arbitrary paths.
        for (label, artifact) in self.refs() {
            parse_cid(&artifact.cid)
                .map_err(|e| ManifestError::Source(SourceError::BadCid(format!("{label}: {e}"))))?;
        }
        Ok(())
    }

    /// Fetch every artifact and verify it hashes to the CID the manifest names.
    ///
    /// # Errors
    /// [`ManifestError::Integrity`] when the received bytes do not match,
    /// [`ManifestError::Size`] when the declared length is wrong, and
    /// [`ManifestError::Source`] when a block cannot be fetched.
    pub fn collect(&self, source: &dyn BlockSource) -> Result<VerifiedBundle, ManifestError> {
        self.check_shape()?;

        let fetch =
            |label: &'static str, artifact: &ArtifactRef| -> Result<Vec<u8>, ManifestError> {
                let bytes = source.get(&artifact.cid)?;

                if bytes.len() as u64 != artifact.bytes {
                    return Err(ManifestError::Size {
                        artifact: label,
                        expected: artifact.bytes,
                        got: bytes.len(),
                    });
                }

                let actual = cid_for_bytes(&bytes)?;
                if actual.to_string() != artifact.cid {
                    return Err(ManifestError::Integrity {
                        artifact: label,
                        expected: artifact.cid.clone(),
                        got: actual.to_string(),
                    });
                }

                Ok(bytes)
            };

        Ok(VerifiedBundle {
            vk: fetch("verifying key", &self.circuit.vk)?,
            policy: fetch("policy", &self.policy)?,
            receipt: fetch("receipt", &self.receipt)?,
            proof: fetch("proof", &self.proof)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;

    fn bundle() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            b"vk-bytes".to_vec(),
            b"policy-bytes".to_vec(),
            b"receipt-bytes".to_vec(),
            b"proof-bytes".to_vec(),
        )
    }

    fn manifest_for(vk: &[u8], p: &[u8], r: &[u8], pf: &[u8]) -> AttestationManifest {
        let circuit = AttestationManifest::circuit_ref(vk, 3_333, 15, 2).expect("circuit ref");
        AttestationManifest::build(circuit, p, r, pf, 1_761_700_000).expect("manifest")
    }

    #[test]
    fn a_manifest_round_trips_and_collects_from_a_source() {
        let (vk, policy, receipt, proof) = bundle();
        let manifest = manifest_for(&vk, &policy, &receipt, &proof);

        let mut source = MemorySource::new();
        source.put(&vk).expect("put vk");
        source.put(&policy).expect("put policy");
        source.put(&receipt).expect("put receipt");
        source.put(&proof).expect("put proof");

        let bundle = manifest.collect(&source).expect("collect");
        assert_eq!(bundle.vk, vk);
        assert_eq!(bundle.policy, policy);
        assert_eq!(bundle.receipt, receipt);
        assert_eq!(bundle.proof, proof);
    }

    #[test]
    fn a_poisoned_block_is_refused_as_an_integrity_failure() {
        // The attack: the source returns the right CID but different bytes.
        let (vk, policy, receipt, proof) = bundle();
        let manifest = manifest_for(&vk, &policy, &receipt, &proof);

        let mut source = MemorySource::new();
        source.put(&vk).expect("put vk");
        source.put(&policy).expect("put policy");
        source.put(&receipt).expect("put receipt");
        source.put(&proof).expect("put proof");

        // Same length, different content: only the hash can catch this.
        let mut poisoned = proof.clone();
        poisoned[0] ^= 0xff;
        source.poison(&manifest.proof.cid, poisoned);

        match manifest.collect(&source) {
            Err(ManifestError::Integrity { artifact, .. }) => assert_eq!(artifact, "proof"),
            other => panic!("expected an integrity failure, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_block_is_refused_by_length_before_hashing() {
        let (vk, policy, receipt, proof) = bundle();
        let manifest = manifest_for(&vk, &policy, &receipt, &proof);

        let mut source = MemorySource::new();
        source.put(&vk).expect("put vk");
        source.put(&policy).expect("put policy");
        source.put(&receipt).expect("put receipt");
        source.put(&proof).expect("put proof");

        source.poison(&manifest.proof.cid, b"short".to_vec());
        match manifest.collect(&source) {
            Err(ManifestError::Size { artifact, .. }) => assert_eq!(artifact, "proof"),
            other => panic!("expected a size failure, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_block_is_reported_by_name() {
        let (vk, policy, receipt, proof) = bundle();
        let manifest = manifest_for(&vk, &policy, &receipt, &proof);

        let mut source = MemorySource::new();
        source.put(&vk).expect("put vk");
        source.put(&policy).expect("put policy");
        // receipt and proof deliberately absent

        match manifest.collect(&source) {
            Err(ManifestError::Source(SourceError::NotFound(cid))) => {
                assert_eq!(cid, manifest.receipt.cid, "the missing artifact is named")
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn a_foreign_document_is_refused_before_any_fetch() {
        let (vk, policy, receipt, proof) = bundle();
        let mut manifest = manifest_for(&vk, &policy, &receipt, &proof);
        manifest.kind = "something/else".to_string();

        let source = MemorySource::new();
        match manifest.collect(&source) {
            Err(ManifestError::Kind(k)) => assert_eq!(k, "something/else"),
            other => panic!("expected a kind rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_future_version_is_refused_rather_than_guessed_at() {
        let (vk, policy, receipt, proof) = bundle();
        let mut manifest = manifest_for(&vk, &policy, &receipt, &proof);
        manifest.version = 99;

        match manifest.collect(&MemorySource::new()) {
            Err(ManifestError::Version(99)) => {}
            other => panic!("expected a version rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_manifest_carries_the_circuit_identity() {
        let (vk, policy, receipt, proof) = bundle();
        let manifest = manifest_for(&vk, &policy, &receipt, &proof);

        assert_eq!(manifest.circuit.constraints, 3_333);
        assert_eq!(manifest.circuit.public_inputs, 15);
        assert_eq!(manifest.circuit.format_version, 2);
        assert_eq!(
            manifest.circuit.vk.cid,
            crate::cid::cid_string(&vk).expect("hash"),
            "the circuit identity is the verifying key's CID, not a comment"
        );
    }

    #[test]
    fn the_manifest_serialises_to_json_and_back() {
        let (vk, policy, receipt, proof) = bundle();
        let manifest = manifest_for(&vk, &policy, &receipt, &proof);

        let text = serde_json::to_string_pretty(&manifest).expect("serialise");
        assert!(text.contains("\"kind\": \"zkagent/attestation\""));
        let back: AttestationManifest = serde_json::from_str(&text).expect("parse");
        assert_eq!(back, manifest);
    }
}
