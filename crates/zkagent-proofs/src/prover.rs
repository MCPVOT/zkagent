//! Prover: trusted setup, proof generation, and the on-disk artifact format.
//!
//! # Trusted setup, honestly
//!
//! Groth16 needs a circuit-specific trusted setup. This module performs it
//! **locally** and discards the toxic waste (the randomness used to build it
//! never leaves the function's scope). That is fine for development and for a
//! single-operator deployment where the operator is the only party who could
//! exploit a bad setup — but it is **not** a public ceremony, and a production
//! deployment must use a multi-party ceremony or a universal-setup system.
//! This is stated here because a Groth16 setup that is quietly single-party is
//! the most common way a "ZK" system ends up unsound in practice.
//!
//! # Artifact format
//!
//! Keys and proofs are serialised with arkworks' compressed canonical
//! encoding, wrapped in a small JSON envelope that records the format version
//! and the circuit's public-input arity. The version field exists so that a
//! verifier fails loudly on a mismatched artifact instead of
//! misinterpreting bytes.

use ark_bn254::Bn254;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use serde::{Deserialize, Serialize};

use zkagent_core::{Action, Policy, Receipt, MAX_ACTIONS};

use crate::circuit::{build_circuit, public_inputs, CircuitField};

/// On-disk artifact format version. Bump on any change to the circuit, the
/// public-input order, or the encoding.
pub const FORMAT_VERSION: u32 = 2;

/// A Groth16 proving key plus the verifier's key, produced by a setup run.
pub struct Keys {
    /// Proving key.
    pub proving: ProvingKey<Bn254>,
    /// Verifying key.
    pub verifying: VerifyingKey<Bn254>,
}

impl Keys {
    /// Serialised verifying key, for publication.
    pub fn verifying_key_bytes(&self) -> Result<Vec<u8>, ProverError> {
        let mut out = Vec::new();
        self.verifying
            .serialize_compressed(&mut out)
            .map_err(|e| ProverError::Serialise(e.to_string()))?;
        Ok(out)
    }

    /// Serialised proving key, for the prover only. Treat as sensitive-ish:
    /// it is not a secret, but it is large and it fixes the circuit.
    pub fn proving_key_bytes(&self) -> Result<Vec<u8>, ProverError> {
        let mut out = Vec::new();
        self.proving
            .serialize_compressed(&mut out)
            .map_err(|e| ProverError::Serialise(e.to_string()))?;
        Ok(out)
    }
}

/// Runs a circuit-specific trusted setup.
///
/// `seed` makes the setup reproducible for tests. In production, pass a seed
/// from a real entropy source and destroy it afterwards; even better, replace
/// this with a multi-party ceremony.
pub fn setup(seed: u64) -> Result<Keys, ProverError> {
    // The circuit shape is fixed by the protocol constants, so any well-formed
    // policy/receipt produces the same constraint system. We use a minimal
    // dummy instance purely to fix the shape.
    let policy =
        Policy::new(1, 1, 1, 1, vec![0]).map_err(|e| ProverError::Policy(e.to_string()))?;
    let receipt = Receipt {
        total_amount: 0,
        action_count: 0,
        completed_at: 0,
        chain_id: 1,
        execution_id: 1,
    };
    let circuit = build_circuit(&policy, &receipt, &[]);
    let mut rng = StdRng::seed_from_u64(seed);
    let (proving, verifying) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
        .map_err(|e| ProverError::Setup(format!("{e:?}")))?;
    Ok(Keys { proving, verifying })
}

/// Produces a proof that `actions` explain `receipt` inside `policy`.
///
/// Returns an error rather than a proof when the actions do not satisfy the
/// policy — the plain check runs first so the caller gets a useful message
/// instead of a constraint-system failure.
pub fn prove(
    keys: &Keys,
    policy: &Policy,
    receipt: &Receipt,
    actions: &[Action],
) -> Result<ProofBytes, ProverError> {
    // Fail fast with a readable reason.
    receipt
        .check_against(policy)
        .map_err(|v| ProverError::PolicyRejected(format!("{v:?}")))?;
    if actions.len() > MAX_ACTIONS {
        // `build_circuit` pads/truncates to MAX_ACTIONS, so an over-long list
        // would otherwise fail later as an unexplained "witness does not
        // satisfy the circuit" (the truncated sum no longer matches the
        // receipt). Name the real cause instead.
        return Err(ProverError::PolicyRejected(format!(
            "{} actions supplied, maximum is {}",
            actions.len(),
            MAX_ACTIONS
        )));
    }
    for a in actions {
        if a.amount > policy.max_per_action {
            return Err(ProverError::PolicyRejected(format!(
                "action amount {} exceeds per-action cap {}",
                a.amount, policy.max_per_action
            )));
        }
        if !policy.permits_target(a.target) {
            return Err(ProverError::PolicyRejected(format!(
                "target {} is not in the allow-list",
                a.target
            )));
        }
    }

    let circuit = build_circuit(policy, receipt, actions);

    // Prove against a constraint system that we also check, so a witness that
    // does not satisfy the circuit fails here rather than producing a proof
    // nobody can verify.
    let cs = ark_relations::r1cs::ConstraintSystem::<CircuitField>::new_ref();
    {
        use ark_relations::r1cs::ConstraintSynthesizer;
        build_circuit(policy, receipt, actions)
            .generate_constraints(cs.clone())
            .map_err(|e| ProverError::Synthesis(format!("{e:?}")))?;
        if !cs
            .is_satisfied()
            .map_err(|e| ProverError::Synthesis(format!("{e:?}")))?
        {
            return Err(ProverError::PolicyRejected(
                "witness does not satisfy the circuit".to_string(),
            ));
        }
    }

    let mut rng = StdRng::seed_from_u64(0xA6E7);
    let proof = Groth16::<Bn254>::prove(&keys.proving, circuit, &mut rng)
        .map_err(|e| ProverError::Prove(format!("{e:?}")))?;

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| ProverError::Serialise(e.to_string()))?;

    Ok(ProofBytes {
        format_version: FORMAT_VERSION,
        public_inputs: encode_inputs(&public_inputs(policy, receipt))?,
        proof: proof_bytes,
    })
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
    pub fn to_proof(&self) -> Result<Proof<Bn254>, ProverError> {
        Proof::<Bn254>::deserialize_compressed(&self.proof[..])
            .map_err(|e| ProverError::Serialise(e.to_string()))
    }

    /// Parses the public inputs back into field elements.
    pub fn public_inputs_fr(&self) -> Result<Vec<CircuitField>, ProverError> {
        self.public_inputs
            .iter()
            .map(|s| {
                let bytes = hex::decode(s).map_err(|e| ProverError::Serialise(e.to_string()))?;
                CircuitField::deserialize_compressed(&bytes[..])
                    .map_err(|e| ProverError::Serialise(e.to_string()))
            })
            .collect()
    }
}

/// Encodes field elements as hex canonical bytes, for the artifact.
fn encode_inputs(inputs: &[CircuitField]) -> Result<Vec<String>, ProverError> {
    inputs
        .iter()
        .map(|f| {
            let mut bytes = Vec::new();
            f.serialize_compressed(&mut bytes)
                .map_err(|e| ProverError::Serialise(e.to_string()))?;
            Ok(hex::encode(bytes))
        })
        .collect()
}

/// Deserialises a verifying key from its compressed bytes.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, ProverError> {
    VerifyingKey::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| ProverError::Serialise(e.to_string()))
}

/// Deserialises a proving key from its compressed bytes.
pub fn proving_key_from_bytes(bytes: &[u8]) -> Result<ProvingKey<Bn254>, ProverError> {
    ProvingKey::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| ProverError::Serialise(e.to_string()))
}

/// Prepares a verifying key for repeated verification.
///
/// Returns a `Result` rather than panicking: a verifier processes artifacts
/// from untrusted peers, and a hostile or corrupted verifying key must be a
/// rejection, not a crash. (An earlier version used `expect` here, which broke
/// the "never panics on hostile input" invariant.)
pub fn prepare(vk: &VerifyingKey<Bn254>) -> Result<PreparedVerifyingKey<Bn254>, ProverError> {
    Groth16::<Bn254>::process_vk(vk).map_err(|e| ProverError::VerifyingKey(format!("{e:?}")))
}

/// Errors from the prover.
#[derive(Debug)]
pub enum ProverError {
    /// The policy/receipt pair violates the protocol rules.
    PolicyRejected(String),
    /// Policy construction failed.
    Policy(String),
    /// Trusted setup failed.
    Setup(String),
    /// Constraint synthesis failed.
    Synthesis(String),
    /// Proving failed.
    Prove(String),
    /// The verifying key could not be prepared.
    VerifyingKey(String),
    /// (De)serialisation failed.
    Serialise(String),
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyRejected(m) => write!(f, "policy rejected: {m}"),
            Self::Policy(m) => write!(f, "policy error: {m}"),
            Self::Setup(m) => write!(f, "setup error: {m}"),
            Self::Synthesis(m) => write!(f, "synthesis error: {m}"),
            Self::Prove(m) => write!(f, "prove error: {m}"),
            Self::VerifyingKey(m) => write!(f, "verifying key error: {m}"),
            Self::Serialise(m) => write!(f, "serialise error: {m}"),
        }
    }
}

impl std::error::Error for ProverError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::new(1_000, 300, 2_000, 1, vec![3, 7, 9]).unwrap()
    }

    fn actions() -> Vec<Action> {
        vec![
            Action {
                target: 3,
                amount: 250,
                trace_digest: 1,
            },
            Action {
                target: 7,
                amount: 150,
                trace_digest: 2,
            },
        ]
    }

    fn receipt() -> Receipt {
        Receipt {
            total_amount: 400,
            action_count: 2,
            completed_at: 1_500,
            chain_id: 1,
            execution_id: 1,
        }
    }

    #[test]
    fn setup_and_prove_produces_a_proof() {
        let keys = setup(7).unwrap();
        let proof = prove(&keys, &policy(), &receipt(), &actions()).unwrap();
        assert_eq!(proof.format_version, FORMAT_VERSION);
        assert!(!proof.proof.is_empty());
        assert_eq!(proof.public_inputs.len(), 7 + 8);
        // The proof must round-trip through its serialised form.
        assert!(proof.to_proof().is_ok());
    }

    #[test]
    fn prove_rejects_a_disallowed_target() {
        let keys = setup(7).unwrap();
        let bad = vec![Action {
            target: 42,
            amount: 10,
            trace_digest: 0,
        }];
        let r = Receipt {
            total_amount: 10,
            action_count: 1,
            completed_at: 1_500,
            chain_id: 1,
            execution_id: 1,
        };
        assert!(matches!(
            prove(&keys, &policy(), &r, &bad),
            Err(ProverError::PolicyRejected(_))
        ));
    }

    #[test]
    fn prove_rejects_an_over_cap_action() {
        let keys = setup(7).unwrap();
        let bad = vec![Action {
            target: 3,
            amount: 301,
            trace_digest: 0,
        }];
        let r = Receipt {
            total_amount: 301,
            action_count: 1,
            completed_at: 1_500,
            chain_id: 1,
            execution_id: 1,
        };
        assert!(matches!(
            prove(&keys, &policy(), &r, &bad),
            Err(ProverError::PolicyRejected(_))
        ));
    }

    #[test]
    fn keys_round_trip_through_bytes() {
        let keys = setup(7).unwrap();
        let vkb = keys.verifying_key_bytes().unwrap();
        let pkb = keys.proving_key_bytes().unwrap();
        assert!(verifying_key_from_bytes(&vkb).is_ok());
        assert!(proving_key_from_bytes(&pkb).is_ok());
    }
}
