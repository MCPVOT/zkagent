//! The statement and the artifact encoding — everything a verifier needs and
//! nothing a prover does.
//!
//! This crate exists because of a measured layering defect: `zkagent-verifier`
//! compiled **261 crates** and pulled `ark-r1cs-std`, `ark-relations` and
//! `ark-poly`, because the artifact types and the public-input order lived inside
//! the proving crate. A verifier needs the *wire format* and the *statement*; it
//! never builds a constraint system.
//!
//! What lives here:
//!
//! * [`CircuitField`] — the scalar field both sides compute in;
//! * [`public_inputs`] — the **only** definition of the public-input order;
//! * [`FORMAT_VERSION`] — the artifact format, bumped on any change to the circuit,
//!   the order, or the encoding;
//! * [`ProofBytes`] — the on-disk proof envelope;
//! * [`verifying_key_from_bytes`] and [`prepare`] — parsing a verifying key from
//!   untrusted bytes, without panicking.
//!
//! What deliberately does **not** live here: the circuit, the prover, the proving
//! key. Those stay in `zkagent-proofs`, which depends on this crate.
//!
//! # The order is allocation order
//!
//! [`public_inputs`] mirrors the order in which the circuit allocates its public
//! inputs, not the semantically tidy order. `execution_id` is appended after the
//! allow-list for that reason: moving it next to the other receipt scalars
//! permutes the vector, keeps every individual input correct, and makes every
//! honest proof fail with `InvalidProof`. `zkagent-proofs` asserts this element by
//! element against the constraint system.

#![deny(missing_docs)]

use ark_bn254::Bn254;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use serde::{Deserialize, Serialize};

use zkagent_core::{Policy, Receipt, MAX_POLICY_TARGETS};

/// The scalar field the circuit and the verifier both compute in.
pub type CircuitField = ark_bn254::Fr;

/// On-disk artifact format version. Bump on any change to the circuit, the
/// public-input order, or the encoding.
///
/// v3 added `trace_root`: the receipt carries a Merkle root over the private
/// action digests and the circuit constrains it. An artifact from v2 has no such
/// input and must be refused rather than reinterpreted.
pub const FORMAT_VERSION: u32 = 3;

/// The number of instance variables for the current circuit, including the
/// leading constant-one slot.
///
/// Seven scalars (three policy, three receipt, the execution id), the padded
/// allow-list, and the trace root. Kept next to the function that builds the
/// vector so the two cannot disagree silently; the proving crate asserts it
/// against the constraint system's arity.
pub const PUBLIC_INPUT_COUNT: usize = 7 + MAX_POLICY_TARGETS + 1 + 1;

/// The ordered public-input vector a verifier must supply to
/// `Groth16::verify_proof`.
///
/// Keep this the ONLY definition of the public-input order. A verifier that
/// assembles the vector by hand can silently reorder it, and a mis-ordered
/// vector makes a valid proof fail — or, worse, makes a proof about different
/// values pass.
#[must_use]
pub fn public_inputs(policy: &Policy, receipt: &Receipt) -> Vec<CircuitField> {
    let mut out = Vec::with_capacity(PUBLIC_INPUT_COUNT);
    out.push(CircuitField::from(policy.max_amount));
    out.push(CircuitField::from(policy.max_per_action));
    out.push(CircuitField::from(policy.expires_at));
    out.push(CircuitField::from(receipt.completed_at));
    out.push(CircuitField::from(receipt.total_amount));
    out.push(CircuitField::from(receipt.action_count as u64));
    for i in 0..MAX_POLICY_TARGETS {
        let v = policy
            .allowed_targets
            .get(i)
            .copied()
            .or_else(|| policy.allowed_targets.first().copied())
            .unwrap_or(0);
        out.push(CircuitField::from(v));
    }
    // Anti-replay id, so the earlier positions keep their meaning for anyone
    // reading an older artifact's public inputs.
    out.push(CircuitField::from(receipt.execution_id));
    // The trace root is LAST, for the same reason: every existing index keeps
    // its meaning. It is a full field element — never truncated to 64 bits,
    // which would leave only ~2^32 collision work.
    out.push(CircuitField::from_le_bytes_mod_order(&receipt.trace_root));
    out
}

/// A serialised proof plus the public inputs it commits to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBytes {
    /// Artifact format version.
    pub format_version: u32,
    /// The public inputs, in circuit order, as hex-encoded canonical field
    /// encodings. Hex rather than decimal so the bytes are unambiguous and a
    /// reader can diff two artifacts without parsing big integers.
    pub public_inputs: Vec<String>,
    /// Compressed proof bytes.
    pub proof: Vec<u8>,
}

impl ProofBytes {
    /// Parses the raw proof back into a `Proof`.
    ///
    /// # Errors
    /// [`WireError::Serialise`] when the bytes are not a compressed proof over
    /// BN254, which is a rejection rather than a panic: the input is untrusted.
    pub fn to_proof(&self) -> Result<Proof<Bn254>, WireError> {
        Proof::<Bn254>::deserialize_compressed(&self.proof[..])
            .map_err(|e| WireError::Serialise(e.to_string()))
    }

    /// Parses the public inputs back into field elements.
    ///
    /// # Errors
    /// [`WireError::Serialise`] when an entry is not valid hex or not a canonical
    /// field encoding.
    pub fn public_inputs_fr(&self) -> Result<Vec<CircuitField>, WireError> {
        self.public_inputs
            .iter()
            .map(|s| {
                let bytes = hex::decode(s).map_err(|e| WireError::Serialise(e.to_string()))?;
                CircuitField::deserialize_compressed(&bytes[..])
                    .map_err(|e| WireError::Serialise(e.to_string()))
            })
            .collect()
    }
}

/// Encodes field elements as hex canonical bytes, for the artifact.
///
/// # Errors
/// [`WireError::Serialise`] when a field element cannot be serialised (it always
/// can; the signature is honest about the possibility rather than unwrapping).
pub fn encode_inputs(inputs: &[CircuitField]) -> Result<Vec<String>, WireError> {
    inputs
        .iter()
        .map(|f| {
            let mut bytes = Vec::new();
            f.serialize_compressed(&mut bytes)
                .map_err(|e| WireError::Serialise(e.to_string()))?;
            Ok(hex::encode(bytes))
        })
        .collect()
}

/// Deserialises a verifying key from its compressed bytes.
///
/// # Errors
/// [`WireError::Serialise`] when the bytes are not a compressed verifying key.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, WireError> {
    VerifyingKey::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| WireError::Serialise(e.to_string()))
}

/// Prepares a verifying key for repeated verification.
///
/// Returns a `Result` rather than panicking: a verifier processes artifacts from
/// untrusted peers, and a hostile or corrupted verifying key must be a rejection,
/// not a crash. (An earlier version used `expect` here, which broke the "never
/// panics on hostile input" invariant.)
///
/// # Errors
/// [`WireError::VerifyingKey`] when the key cannot be prepared.
pub fn prepare(vk: &VerifyingKey<Bn254>) -> Result<PreparedVerifyingKey<Bn254>, WireError> {
    Groth16::<Bn254>::process_vk(vk).map_err(|e| WireError::VerifyingKey(format!("{e:?}")))
}

/// Why an artifact could not be read.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// (De)serialisation failed.
    #[error("{0}")]
    Serialise(String),
    /// The verifying key could not be prepared.
    #[error("{0}")]
    VerifyingKey(String),
}

// A field element is only ever encoded through `serialize_compressed`; this keeps
// the `PrimeField` import meaningful for the generic bound in `public_inputs`.
const _: fn() = || {
    fn assert_field<F: PrimeField>() {}
    assert_field::<CircuitField>();
};
