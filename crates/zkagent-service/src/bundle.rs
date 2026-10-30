//! Publishing and fetching attestation bundles over content-addressed storage.
//!
//! This module is the join between the two halves of the system:
//!
//! - the **protocol** (`zkagent-service`) says a proof is sound and the artifacts
//!   behind it are the ones a human authorised;
//! - **content addressing** (`zkagent-ipfs`) says the bytes you received are the
//!   bytes that were attested.
//!
//! [`publish`] writes nothing to the network. It hashes the four artifacts and
//! returns the manifest plus the blocks, so a host decides where they live (an
//! IPFS node, a gateway, a directory, a chain). [`verify_bundle`] fetches them
//! back through whatever source it is given, re-checks every hash, and then runs
//! the normal verification path.
//!
//! The ordering matters and is not negotiable: **integrity first, then
//! verification.** A proof that verifies against bytes you did not intend to
//! verify is not a verification.

use std::path::Path;

use zkagent_core::{Action, Receipt, SeenExecutions};
use zkagent_ipfs::{AttestationManifest, BlockSource, ManifestError};
use zkagent_proofs::prover::ProofBytes;

use crate::error::ServiceError;
use crate::ops;
use crate::wire::SignedPolicyFile;
use crate::VerifyOutcome;

/// A manifest plus the blocks it names.
///
/// The host publishes `blocks` however it likes; the `manifest` is what a
/// verifier is given. Keeping them together is what stops a publisher from
/// handing out a manifest whose blocks were never stored.
#[derive(Debug, Clone)]
pub struct PublishedBundle {
    /// The manifest, naming every artifact by CID.
    pub manifest: AttestationManifest,
    /// `(cid, bytes)` for each artifact, ready to hand to a block store.
    pub blocks: Vec<(String, Vec<u8>)>,
}

/// Hash four artifacts into a manifest.
///
/// Takes the **files** rather than parsed values on purpose: a CID must describe
/// the exact bytes a verifier will fetch, so the publisher hashes what is on disk
/// rather than a re-serialisation that might differ by a space.
///
/// `actions` is needed only to measure the circuit shape, and it is never
/// published — it is the private witness.
///
/// # Errors
/// Returns [`ServiceError::Io`] when a file cannot be read,
/// [`ServiceError::InvalidPolicy`] when the policy does not parse, and
/// [`ServiceError::Verification`] when the shape cannot be measured (which means
/// the witness does not satisfy the circuit, so there is no proof to describe).
pub fn publish(
    keys_dir: &Path,
    policy_path: &Path,
    receipt_path: &Path,
    proof_path: &Path,
    actions: &[Action],
    created_at: u64,
) -> Result<PublishedBundle, ServiceError> {
    let policy_bytes = std::fs::read(policy_path).map_err(|e| ServiceError::io(policy_path, e))?;
    let receipt_bytes =
        std::fs::read(receipt_path).map_err(|e| ServiceError::io(receipt_path, e))?;
    let proof_bytes = std::fs::read(proof_path).map_err(|e| ServiceError::io(proof_path, e))?;
    let vk_bytes = std::fs::read(keys_dir.join("vk.bin"))
        .map_err(|e| ServiceError::io(keys_dir.join("vk.bin"), e))?;

    // Parse what we just read, so the shape is measured for THESE artifacts.
    let signed: SignedPolicyFile = serde_json::from_slice(&policy_bytes)
        .map_err(|e| ServiceError::malformed(policy_path, e))?;
    let policy = signed
        .policy
        .to_policy()
        .map_err(ServiceError::InvalidPolicy)?;
    let receipt: Receipt = serde_json::from_slice::<crate::wire::ReceiptJson>(&receipt_bytes)
        .map(|r| Receipt::from(&r))
        .map_err(|e| ServiceError::malformed(receipt_path, e))?;

    let (constraints, public_inputs) =
        zkagent_proofs::circuit::measure_shape(&policy, &receipt, actions)
            .map_err(|e| ServiceError::Verification(e.to_string()))?;

    let circuit = AttestationManifest::circuit_ref(
        &vk_bytes,
        constraints,
        public_inputs,
        zkagent_proofs::prover::FORMAT_VERSION,
    )
    .map_err(|e| ServiceError::Verification(e.to_string()))?;

    let manifest = AttestationManifest::build(
        circuit,
        &policy_bytes,
        &receipt_bytes,
        &proof_bytes,
        created_at,
    )
    .map_err(|e| ServiceError::Verification(e.to_string()))?;

    let blocks = vec![
        (manifest.circuit.vk.cid.clone(), vk_bytes),
        (manifest.policy.cid.clone(), policy_bytes),
        (manifest.receipt.cid.clone(), receipt_bytes),
        (manifest.proof.cid.clone(), proof_bytes),
    ];

    Ok(PublishedBundle { manifest, blocks })
}

/// Fetch a bundle by manifest, check every hash, then verify the attestation.
///
/// The three steps, in this order:
///
/// 1. **collect** — fetch each block and re-hash it against the CID the manifest
///    names, so a lying gateway cannot substitute bytes;
/// 2. **parse** — reject anything that is not the artifact it claims to be;
/// 3. **verify** — the normal path: authority signature, input binding, proof,
///    freshness, replay gate.
///
/// # Errors
/// Returns [`ServiceError::Verification`] for an integrity failure (the received
/// bytes do not match their CID), [`ServiceError::Malformed`] for an artifact
/// that will not parse, and [`ServiceError::Replay`] when the replay ledger
/// cannot be read or written.
pub fn verify_bundle(
    manifest: &AttestationManifest,
    source: &dyn BlockSource,
    now: Option<u64>,
    seen: Option<&Path>,
) -> Result<VerifyOutcome, ServiceError> {
    let bundle = manifest.collect(source).map_err(|e| match e {
        // An integrity failure is the interesting one: it means the
        // transport lied, which is a security event and must not be
        // reported as a generic parse error.
        ManifestError::Integrity { .. } | ManifestError::Size { .. } => {
            ServiceError::Verification(e.to_string())
        }
        other => ServiceError::Verification(other.to_string()),
    })?;

    let signed: SignedPolicyFile =
        serde_json::from_slice(&bundle.policy).map_err(|e| ServiceError::Malformed {
            path: std::path::PathBuf::from(format!("policy@{}", manifest.policy.cid)),
            detail: e.to_string(),
        })?;

    let receipt: Receipt = serde_json::from_slice::<crate::wire::ReceiptJson>(&bundle.receipt)
        .map(|r| Receipt::from(&r))
        .map_err(|e| ServiceError::Malformed {
            path: std::path::PathBuf::from(format!("receipt@{}", manifest.receipt.cid)),
            detail: e.to_string(),
        })?;

    let proof: ProofBytes =
        serde_json::from_slice(&bundle.proof).map_err(|e| ServiceError::Malformed {
            path: std::path::PathBuf::from(format!("proof@{}", manifest.proof.cid)),
            detail: e.to_string(),
        })?;

    // The manifest says which circuit this belongs to. Refuse a bundle whose
    // proof was made for a different one: verifying it would be meaningless and
    // the failure would look like a broken prover.
    if proof.format_version != manifest.circuit.format_version {
        return Err(ServiceError::Verification(format!(
            "bundle names circuit format v{} but the proof is v{}",
            manifest.circuit.format_version, proof.format_version
        )));
    }

    let mut state = match seen {
        Some(path) => {
            Some(SeenExecutions::load(path).map_err(|e| ServiceError::Replay(e.to_string()))?)
        }
        None => None,
    };

    let outcome = ops::verify_with_vk(&bundle.vk, &signed, &receipt, &proof, now, state.as_mut())?;

    Ok(outcome)
}
