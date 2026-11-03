//! MiMC-2n/n over BN254's scalar field, used as the Merkle root that binds the
//! private trace digests to a public value.
//!
//! # Why a hash at all, and why this one
//!
//! Before this module, `trace_digest` was a witness that the circuit
//! bit-decomposed and then threw away: an honest prover put a value there, a
//! dishonest one could put anything, and the verifier learned nothing. The fix
//! is a commitment the circuit itself builds: the receipt publishes a Merkle root
//! over the eight padded digests, the root is a public input, and
//! [`root`] rebuilds the tree from the private leaves and is constrained
//! to equal that input. Now the digests are bound: change one and no proof
//! exists for the published root.
//!
//! MiMC is chosen because the statement already runs in a SNARK: a field-native
//! hash with an `x^5` S-box costs three constraints per round, where SHA-256 in
//! a circuit costs tens of thousands of constraints. This is not a claim that
//! MiMC is the best general-purpose hash — it is not, and the round constants and
//! domain are versioned here (`zkagent-mimc-v1`) precisely because a new
//! instantiation must be a new domain, not a silent change.
//!
//! # The construction
//!
//! * one field element, 110 rounds, round `i` is `x <- (x + c_i)^5`;
//! * `c_i = SHA256("zkagent-mimc-v1" || i as u32 LE)` reduced into the field;
//! * 2-to-1 compression `H(a, b) = P(P(a) + b)` with `P` the permutation above;
//! * exactly [`MAX_ACTIONS`] leaves, padded with zero digests, so the tree is a
//!   fixed depth-3 shape with seven internal nodes.
//!
//! The native and the in-circuit implementations share [`round_constants`] and
//! the same round loop; a unit test asserts they produce the same root, because
//! a prover and a circuit that disagree here would reject every honest proof
//! with `InvalidProof`.

use std::sync::OnceLock;

use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::SynthesisError;
use sha2::{Digest, Sha256};

use zkagent_core::{Action, MAX_ACTIONS};
use zkagent_wire::CircuitField;

/// Number of MiMC rounds in the permutation.
pub const ROUNDS: usize = 110;

/// Domain separator for the round constants.
///
/// Bumping this is a new hash function, not a parameter tweak: an artifact made
/// under one domain must never verify under another.
pub const DOMAIN: &[u8] = b"zkagent-mimc-v1";

/// Depth of the Merkle tree: `log2(MAX_ACTIONS)`.
pub const TREE_DEPTH: usize = 3;

/// Width of the native root's byte encoding (one BN254 scalar, little-endian).
pub const ROOT_BYTES: usize = 32;

static ROUND_CONSTANTS: OnceLock<[CircuitField; ROUNDS]> = OnceLock::new();

/// The round constants, computed once per process.
///
/// Both the native hash and the gadget read from this array, which is the point:
/// two separately-derived constant tables are the classic way a prover and a
/// circuit end up computing different hashes.
pub fn round_constants() -> &'static [CircuitField; ROUNDS] {
    ROUND_CONSTANTS.get_or_init(|| {
        let mut out = [CircuitField::from(0u64); ROUNDS];
        for (i, slot) in out.iter_mut().enumerate() {
            let mut h = Sha256::new();
            h.update(DOMAIN);
            h.update((i as u32).to_le_bytes());
            *slot = CircuitField::from_le_bytes_mod_order(&h.finalize());
        }
        out
    })
}

/// The native MiMC permutation `P`.
#[must_use]
pub fn permute(x: CircuitField) -> CircuitField {
    let mut acc = x;
    for c in round_constants() {
        acc += c;
        let square = acc.square();
        let fourth = square.square();
        acc = fourth * acc;
    }
    acc
}

/// The native 2-to-1 compression `P(P(a) + b)`.
#[must_use]
pub fn hash_pair(a: CircuitField, b: CircuitField) -> CircuitField {
    permute(permute(a) + b)
}

/// Pads arbitrary digests to exactly [`MAX_ACTIONS`] field leaves.
///
/// Padding is a zero digest, matching `build_circuit`, which pads unused action
/// slots with `trace_digest: 0`. Truncation past [`MAX_ACTIONS`] is deliberate:
/// the prover rejects an over-long action list before it gets here, and the tree
/// has a fixed shape that the verifying key depends on.
#[must_use]
pub fn leaves_from_digests(digests: &[u64]) -> [CircuitField; MAX_ACTIONS] {
    let mut leaves = [CircuitField::from(0u64); MAX_ACTIONS];
    for (slot, digest) in leaves.iter_mut().zip(digests.iter()) {
        *slot = CircuitField::from(*digest);
    }
    leaves
}

/// The native Merkle root over at most [`MAX_ACTIONS`] leaves, zero-padded.
#[must_use]
pub fn root_native(leaves: &[CircuitField]) -> CircuitField {
    let mut level: Vec<CircuitField> = leaves.iter().take(MAX_ACTIONS).copied().collect();
    level.resize(MAX_ACTIONS, CircuitField::from(0u64));
    while level.len() > 1 {
        let (pairs, rest) = level.as_chunks::<2>();
        debug_assert!(rest.is_empty(), "the level width is always a power of two");
        level = pairs.iter().map(|[a, b]| hash_pair(*a, *b)).collect();
    }
    level[0]
}

/// The native root over a digest slice, padded to [`MAX_ACTIONS`].
#[must_use]
pub fn root_from_digests(digests: &[u64]) -> CircuitField {
    let leaves = leaves_from_digests(digests);
    root_native(&leaves)
}

/// The native root's little-endian bytes over a digest slice.
#[must_use]
pub fn root_bytes_from_digests(digests: &[u64]) -> [u8; ROOT_BYTES] {
    root_bytes(root_from_digests(digests))
}

/// The native root's little-endian bytes, as the receipt stores them.
#[must_use]
pub fn root_bytes(root: CircuitField) -> [u8; ROOT_BYTES] {
    let bytes = root.into_bigint().to_bytes_le();
    let mut out = [0u8; ROOT_BYTES];
    // BN254's scalar field is 254 bits, so its canonical encoding is 32 bytes.
    assert_eq!(bytes.len(), ROOT_BYTES, "unexpected field width");
    out.copy_from_slice(&bytes);
    out
}

/// The root over the padded trace digests of `actions`.
///
/// This is the function the prover uses to fill in `Receipt::trace_root`, so no
/// caller has to compute it by hand.
#[must_use]
pub fn root_bytes_for_actions(actions: &[Action]) -> [u8; ROOT_BYTES] {
    let digests: Vec<u64> = actions.iter().map(|a| a.trace_digest).collect();
    root_bytes_from_digests(&digests)
}

/// The native MiMC permutation, as a gadget.
fn permute_var(x: &FpVar<CircuitField>) -> Result<FpVar<CircuitField>, SynthesisError> {
    let mut acc = x.clone();
    for c in round_constants() {
        // Adding a constant is a linear combination: no constraint. The three
        // multiplications below cost one constraint each, which is the 3-per-round
        // budget this hash is chosen for (110 rounds -> 330 per permutation).
        let shifted = acc + FpVar::constant(*c);
        let square = shifted.square()?;
        let fourth = square.square()?;
        acc = fourth * shifted;
    }
    Ok(acc)
}

/// The 2-to-1 compression `P(P(a) + b)`, as a gadget.
///
/// # Errors
/// Propagates constraint-synthesis failures from the underlying field gadgets.
pub fn hash_pair_var(
    a: &FpVar<CircuitField>,
    b: &FpVar<CircuitField>,
) -> Result<FpVar<CircuitField>, SynthesisError> {
    let inner = permute_var(a)? + b;
    permute_var(&inner)
}

/// Builds the Merkle root over `leaves`, in-circuit.
///
/// `leaves` must be exactly [`MAX_ACTIONS`] elements — the same padded list the
/// native root is taken over — because the tree shape is part of the circuit, not
/// of the witness. A shorter or longer list is a programming error, not a
/// statement about the execution, so it fails synthesis rather than being padded
/// silently.
///
/// # Errors
/// [`SynthesisError::Unsatisfiable`] when the length is not exactly
/// [`MAX_ACTIONS`] (a programming error: this arkworks line has no
/// "malformed circuit" variant, so the shape mismatch is reported as an
/// unsatisfiable system rather than panic), and any failure from the field
/// gadgets.
pub fn root(leaves: &[FpVar<CircuitField>]) -> Result<FpVar<CircuitField>, SynthesisError> {
    if leaves.len() != MAX_ACTIONS {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut level: Vec<FpVar<CircuitField>> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        let (pairs, rest) = level.as_chunks::<2>();
        debug_assert!(rest.is_empty(), "the level width is always a power of two");
        for pair in pairs {
            next.push(hash_pair_var(&pair[0], &pair[1])?);
        }
        level = next;
    }
    Ok(level.remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    fn sample_digests() -> [u64; MAX_ACTIONS] {
        [11, 22, 33, 44, 55, 66, 77, 88]
    }

    /// Allocates the leaves as witnesses, rebuilds the root in-circuit, and
    /// compares it to a public input holding the native root.
    fn variable_root(inputs: &[u64]) -> (ConstraintSystemRef<CircuitField>, FpVar<CircuitField>) {
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        let leaves: Vec<FpVar<CircuitField>> = inputs
            .iter()
            .map(|d| FpVar::new_witness(cs.clone(), || Ok(CircuitField::from(*d))).unwrap())
            .collect();
        let computed = root(&leaves).unwrap();
        let public = FpVar::new_input(cs.clone(), || Ok(root_from_digests(inputs))).unwrap();
        computed.enforce_equal(&public).unwrap();
        (cs, computed)
    }

    #[test]
    fn in_circuit_and_native_roots_agree() {
        // THE guard against a gadget that drifts from the native hash: if these
        // disagree, every honest proof fails with `InvalidProof` and nothing in
        // the circuit looks wrong.
        let digests = sample_digests();
        let (cs, computed) = variable_root(&digests);
        assert!(
            cs.is_satisfied().unwrap(),
            "the constraint system must accept the honest root"
        );
        let native = root_from_digests(&digests);
        assert_eq!(
            computed.value().unwrap(),
            native,
            "in-circuit root differs from the native root"
        );
    }

    #[test]
    fn tampering_with_a_leaf_changes_the_root() {
        let mut digests = sample_digests();
        let honest = root_from_digests(&digests);
        digests[3] ^= 1;
        assert_ne!(
            honest,
            root_from_digests(&digests),
            "a one-bit change in a leaf must change the root"
        );
    }

    #[test]
    fn field_order_matters() {
        let a = root_from_digests(&[1, 2, 0, 0, 0, 0, 0, 0]);
        let b = root_from_digests(&[2, 1, 0, 0, 0, 0, 0, 0]);
        assert_ne!(a, b, "the compression must not be commutative");
    }

    #[test]
    fn the_tree_is_fixed_depth_three() {
        // Eight leaves, four + two + one internal nodes: seven 2-to-1 compressions.
        assert_eq!(1 << TREE_DEPTH, MAX_ACTIONS);
        let mut count = 0;
        let mut width = MAX_ACTIONS;
        while width > 1 {
            width /= 2;
            count += width;
        }
        assert_eq!(count, 7);
    }

    #[test]
    fn the_gadget_refuses_a_wrong_leaf_count() {
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        let leaves: Vec<FpVar<CircuitField>> = (0..4)
            .map(|d| FpVar::new_witness(cs.clone(), || Ok(CircuitField::from(d as u64))).unwrap())
            .collect();
        assert!(root(&leaves).is_err());
    }

    #[test]
    fn a_root_two_permutations_on_costs_660_constraints() {
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(CircuitField::from(1u64))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(CircuitField::from(2u64))).unwrap();
        let before = cs.num_constraints();
        let _ = hash_pair_var(&a, &b).unwrap();
        let used = cs.num_constraints() - before;
        assert_eq!(
            used,
            3 * ROUNDS * 2,
            "one compression should be two 110-round permutations at 3 constraints per round"
        );
    }
}
