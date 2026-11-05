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
use ark_ff::UniformRand;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;

use zkagent_core::{Action, Policy, Receipt, MAX_ACTIONS};

use crate::circuit::{build_circuit, public_inputs, CircuitField};
use crate::merkle;

// The artifact format, the proof envelope, verifying-key parsing and the
// public-input order all live in `zkagent-wire` now. They are re-exported here so
// existing call sites keep working, but a verifier should import them from
// `zkagent_wire` directly — that is what lets a checking-only build drop the
// prover from its dependency tree.
pub use zkagent_wire::{prepare, verifying_key_from_bytes, ProofBytes, FORMAT_VERSION};

use zkagent_wire::{encode_inputs, WireError};

/// What a successful [`prove`] produced: the receipt completed with its trace
/// root, and the proof over it.
///
/// The receipt is returned rather than left for the caller to finish because the
/// root is derived from the *private* witness. A caller that had to compute it
/// by hand would either duplicate the hash (and drift) or publish a receipt the
/// proof does not match.
#[derive(Clone, Debug)]
pub struct ProvenExecution {
    /// The receipt as proven, with `trace_root` filled in from the witness.
    pub receipt: Receipt,
    /// The proof artifact, whose public inputs commit to `receipt`.
    pub proof: ProofBytes,
}

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
        trace_root: [0u8; 32],
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
) -> Result<ProvenExecution, ProverError> {
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

    // The trace root is the prover's job, not the caller's: it is a commitment
    // over the private digests, so only the prover can compute it. Filling it in
    // here is what makes an honest run self-consistent end to end — the receipt
    // that comes back is exactly the one the public inputs commit to.
    let mut proven_receipt = receipt.clone();
    proven_receipt.trace_root = merkle::root_bytes_for_actions(actions);
    let receipt = &proven_receipt;

    let circuit = build_circuit(policy, receipt, actions);

    // Synthesize the circuit ONCE, and prove from that same constraint system.
    //
    // `Groth16::prove` synthesizes the circuit itself, so the previous shape —
    // build a constraint system, synthesize, check `is_satisfied()`, then hand
    // the circuit to `prove` — did the whole witness generation twice (measured:
    // 26 ms of 175 ms of prover CPU). Synthesizing here and calling
    // `create_proof_with_reduction_and_matrices` with this system's matrices and
    // full assignment keeps the check *and* the proof on the same witness
    // values, which is strictly stronger than trusting two independent
    // syntheses to agree. The reduction is the same one `prove` uses
    // (`LibsnarkReduction`) and the optimization goal is set explicitly to the
    // value `prove` sets, so the matrices — and therefore the proof — are
    // unchanged.
    let cs = ark_relations::r1cs::ConstraintSystem::<CircuitField>::new_ref();
    cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
    {
        use ark_relations::r1cs::ConstraintSynthesizer;
        circuit
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

    cs.finalize();
    let matrices = cs
        .to_matrices()
        .ok_or_else(|| ProverError::Prove("constraint matrices are unavailable".to_string()))?;
    let num_inputs = cs.num_instance_variables();
    let num_constraints = cs.num_constraints();
    let full_assignment = {
        let borrowed = cs
            .borrow()
            .ok_or_else(|| ProverError::Prove("constraint system is unavailable".to_string()))?;
        [
            borrowed.instance_assignment.as_slice(),
            borrowed.witness_assignment.as_slice(),
        ]
        .concat()
    };

    let mut rng = StdRng::seed_from_u64(0xA6E7);
    let r = CircuitField::rand(&mut rng);
    let s = CircuitField::rand(&mut rng);
    let proof = Groth16::<Bn254>::create_proof_with_reduction_and_matrices(
        &keys.proving,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        &full_assignment,
    )
    .map_err(|e| ProverError::Prove(format!("{e:?}")))?;

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| ProverError::Serialise(e.to_string()))?;

    let public = encode_inputs(&public_inputs(policy, &proven_receipt))?;
    Ok(ProvenExecution {
        receipt: proven_receipt,
        proof: ProofBytes {
            format_version: FORMAT_VERSION,
            public_inputs: public,
            proof: proof_bytes,
        },
    })
}

/// Deserialises a proving key from its compressed bytes.
///
/// Stays here rather than in `zkagent-wire`: a proving key is a prover artifact,
/// and moving it would drag the prover's concerns back into the wire crate.
///
/// The parse itself lives in [`crate::keyfile`]: the same bytes, the same field
/// order and the same per-point validation, with the square roots decompressed in
/// parallel. That loop was measured at 734 ms of a 920 ms `prove`, so it is worth
/// a thread pool; the arithmetic it feeds is 175 ms.
pub fn proving_key_from_bytes(bytes: &[u8]) -> Result<ProvingKey<Bn254>, ProverError> {
    crate::keyfile::proving_key_from_bytes(bytes).map_err(|e| ProverError::Serialise(e.to_string()))
}

impl From<WireError> for ProverError {
    fn from(e: WireError) -> Self {
        ProverError::Serialise(e.to_string())
    }
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
            trace_root: [0u8; 32],
        }
    }

    #[test]
    fn setup_and_prove_produces_a_proof() {
        let keys = setup(7).unwrap();
        let proven = prove(&keys, &policy(), &receipt(), &actions()).unwrap();
        assert_eq!(proven.proof.format_version, FORMAT_VERSION);
        assert!(!proven.proof.proof.is_empty());
        assert_eq!(proven.proof.public_inputs.len(), 8 + 8);
        // The proof must round-trip through its serialised form.
        assert!(proven.proof.to_proof().is_ok());
        // The prover fills in the root: the receipt it returns is the one the
        // proof commits to, not the zero placeholder the caller passed in.
        assert_eq!(
            proven.receipt.trace_root,
            merkle::root_bytes_for_actions(&actions())
        );
        assert_ne!(proven.receipt.trace_root, [0u8; 32]);
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
            trace_root: [0u8; 32],
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
            trace_root: [0u8; 32],
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
