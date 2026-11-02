//! The Groth16 circuit: "there exists a set of actions inside the authorised
//! bounds that exactly explains the published receipt".
//!
//! # Statement
//!
//! **Public (what the verifier sees, and what the human signed):**
//!   * `max_amount` — total cap,
//!   * `max_per_action` — per-action cap,
//!   * `expires_at` — policy expiry,
//!   * `completed_at` — when the execution finished,
//!   * `allowed[0..8]` — the allow-list, padded with [`TARGET_SENTINEL`],
//!   * `receipt_total` — total value the agent claims to have moved,
//!   * `receipt_action_count` — how many actions the agent claims.
//!
//! **Private (what the proof hides):**
//!   * the actions themselves: each action's `target`, `amount` and
//!     `trace_digest`.
//!
//! A verifier therefore learns *that a conforming execution happened* and its
//! aggregate cost — never which tools were called, in what order, or what the
//! per-action amounts were.
//!
//! # Why nothing in this circuit hashes
//!
//! An earlier draft hashed the policy inside the circuit so the policy itself
//! could stay hidden. That needs a SHA-256 or Poseidon gadget, and the first
//! attempt computed rotations from the *witness value* instead of constraining
//! them — a circuit that produces the right digest for an honest prover while
//! constraining nothing at all, i.e. no soundness.
//!
//! The fix is a design change rather than a better hash: **the policy is
//! public** (it is the human's published delegation, and a verifier must check
//! the proof against exactly those values) and **the execution is private**
//! (the thing actually worth hiding). That removes the in-circuit hash, and
//! with it a whole class of soundness bugs, while preserving the privacy
//! property that matters.
//!
//! # Soundness notes that matter
//!
//! * Every integer compared in-circuit is a `UInt<64, u64, _>`: a bit
//!   decomposition. That is what blocks the classic attack on field-arithmetic
//!   comparisons, where a prover supplies `amount = p - k` so that
//!   `amount + k == 0` holds in the field while real value moved.
//! * Sums are compared after conversion *from bits*, so both sides are bound
//!   to their 64-bit decompositions.
//! * Target equality is field equality, which is integer equality here because
//!   every value is far below the modulus.

use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::cmp::CmpGadget;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::uint::UInt;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};

use zkagent_core::{Action, Policy, Receipt, MAX_ACTIONS, MAX_POLICY_TARGETS};

/// The field the circuit is defined over (BN254's scalar field).
///
/// Re-exported from `zkagent-wire` so the statement and the constraints cannot
/// disagree about which field they compute in.
pub use zkagent_wire::CircuitField;

/// The public-input order, defined once in `zkagent-wire`.
///
/// The circuit allocates its inputs in exactly this order; keeping the definition
/// in the wire crate is what lets a verifier assemble the vector without
/// depending on the prover.
pub use zkagent_wire::public_inputs;

/// A 64-bit unsigned variable.
pub type U64Var = UInt<64, u64, CircuitField>;

/// The circuit.
pub struct PolicyConformanceCircuit {
    /// Public policy values.
    pub policy: PolicyPublic,
    /// Public receipt values.
    pub receipt: ReceiptPublic,
    /// Private actions, padded to exactly [`MAX_ACTIONS`] entries.
    pub actions: Vec<ActionWitness>,
}

/// Public policy values fed to the circuit.
#[derive(Clone, Debug)]
pub struct PolicyPublic {
    /// Total cap.
    pub max_amount: u64,
    /// Per-action cap.
    pub max_per_action: u64,
    /// Expiry timestamp.
    pub expires_at: u64,
    /// Allow-list padded to [`MAX_POLICY_TARGETS`].
    pub allowed_targets: Vec<u64>,
}

/// Public receipt values fed to the circuit.
#[derive(Clone, Debug)]
pub struct ReceiptPublic {
    /// Total value moved.
    pub total_amount: u64,
    /// Number of actions.
    pub action_count: u64,
    /// Completion timestamp.
    pub completed_at: u64,
    /// Unique execution id (anti-replay). Must be non-zero.
    pub execution_id: u64,
}

/// Private witness for one action.
#[derive(Clone, Debug)]
pub struct ActionWitness {
    /// Target touched.
    pub target: u64,
    /// Value moved.
    pub amount: u64,
    /// Per-action trace commitment (bound but not compared in v1).
    pub trace_digest: u64,
}

impl ConstraintSynthesizer<CircuitField> for PolicyConformanceCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        // ------------------------------------------------------------------
        // Public policy values.
        // ------------------------------------------------------------------
        // NOTE: none of these uses `UInt::new_input`. In this arkworks line a
        // `UInt` input allocates ONE PUBLIC INPUT PER BIT (64 per value, 896 in
        // total for this statement), which makes `verify_proof` expect a
        // 896-element input vector and fail with `MalformedVerifyingKey` when
        // the verifier supplies the 14 values it actually has.
        //
        // Instead each public value is a single `FpVar` input, and a 64-bit
        // witness decomposition is *bound* to it. That both keeps the public
        // input count at 14 and range-checks the value: the recomposition of 64
        // bits cannot equal an input that is >= 2^64, so an out-of-range public
        // value makes the circuit unsatisfiable rather than wrapping.
        let max_amount = pub_u64(&cs, self.policy.max_amount)?;
        let max_per_action = pub_u64(&cs, self.policy.max_per_action)?;
        let expires_at = pub_u64(&cs, self.policy.expires_at)?;
        let completed_at = pub_u64(&cs, self.receipt.completed_at)?;
        let receipt_total = pub_u64(&cs, self.receipt.total_amount)?;
        let receipt_count = pub_u64(&cs, self.receipt.action_count)?;

        let mut allowed = Vec::with_capacity(MAX_POLICY_TARGETS);
        for i in 0..MAX_POLICY_TARGETS {
            // Padding repeats the first real target rather than using a
            // sentinel. A sentinel would be a value that an action could match
            // by supplying it directly, which would let a prover claim a
            // forbidden target was "in the list"; repeating a real target
            // cannot widen the allowed set.
            let v = self
                .policy
                .allowed_targets
                .get(i)
                .copied()
                .or_else(|| self.policy.allowed_targets.first().copied())
                .unwrap_or(0);
            allowed.push(pub_u64(&cs, v)?);
        }

        // The execution id is allocated LAST, after the allow-list, because the
        // public-input vector is ordered by ALLOCATION here, not by semantics.
        // `public_inputs()` appends it last to match. Allocating it earlier (a
        // natural place, next to the other receipt scalars) permutes the
        // vector against what the verifier computes, and the only symptom is
        // `InvalidProof` on an honest witness — with every input individually
        // correct. Keep these two orders in lockstep.
        let execution_id = pub_u64(&cs, self.receipt.execution_id)?;

        // ------------------------------------------------------------------
        // Private actions.
        // ------------------------------------------------------------------
        let mut action_vars = Vec::with_capacity(MAX_ACTIONS);
        for a in &self.actions {
            action_vars.push((
                U64Var::new_witness(cs.clone(), || Ok(a.target))?,
                U64Var::new_witness(cs.clone(), || Ok(a.amount))?,
                U64Var::new_witness(cs.clone(), || Ok(a.trace_digest))?,
            ));
        }

        // ------------------------------------------------------------------
        // 1. Per-action cap.
        // ------------------------------------------------------------------
        for (_, amount, _) in &action_vars {
            amount
                .is_le(&max_per_action)?
                .enforce_equal(&Boolean::TRUE)?;
        }

        // ------------------------------------------------------------------
        // 2. Total cap.
        // ------------------------------------------------------------------
        receipt_total
            .is_le(&max_amount)?
            .enforce_equal(&Boolean::TRUE)?;

        // ------------------------------------------------------------------
        // 3. Coherent policy.
        // ------------------------------------------------------------------
        max_per_action
            .is_le(&max_amount)?
            .enforce_equal(&Boolean::TRUE)?;

        // ------------------------------------------------------------------
        // 4. Allow-list membership.
        // ------------------------------------------------------------------
        // Membership is proved algebraically: the product over the allow-list
        // of (target - slot) is zero. In a field, a product is zero exactly
        // when one of its factors is zero, so this holds precisely when the
        // target equals some allowed slot.
        //
        // An OR-of-equalities gadget would say the same thing but needs
        // `Boolean::or`, which this version of `ark-r1cs-std` only exposes on
        // its allocated variant; the product is both shorter and harder to get
        // subtly wrong.
        for (target, _, _) in &action_vars {
            let target_fp = uint_to_fp(target)?;
            let mut product = FpVar::<CircuitField>::one();
            for slot in &allowed {
                product *= target_fp.clone() - uint_to_fp(slot)?;
            }
            product.enforce_equal(&FpVar::<CircuitField>::zero())?;
        }

        // ------------------------------------------------------------------
        // 5. The actions explain the receipt.
        // ------------------------------------------------------------------
        let mut sum = FpVar::<CircuitField>::zero();
        for (_, amount, _) in &action_vars {
            sum += uint_to_fp(amount)?;
        }
        sum.enforce_equal(&uint_to_fp(&receipt_total)?)?;

        // ------------------------------------------------------------------
        // 6. Action count equals the number of non-zero actions.
        // ------------------------------------------------------------------
        let mut live = FpVar::<CircuitField>::zero();
        for (_, amount, _) in &action_vars {
            let is_zero = uint_to_fp(amount)?.is_zero()?;
            // `1 - is_zero` as a field element; avoids relying on
            // `Boolean::not`, which is only on the allocated variant here.
            live += FpVar::<CircuitField>::one() - FpVar::<CircuitField>::from(is_zero);
        }
        live.enforce_equal(&uint_to_fp(&receipt_count)?)?;

        // ------------------------------------------------------------------
        // 7. Freshness: completed_at < expires_at.
        // ------------------------------------------------------------------
        completed_at
            .is_lt(&expires_at)?
            .enforce_equal(&Boolean::TRUE)?;

        // ------------------------------------------------------------------
        // 8. The execution id is present.
        // ------------------------------------------------------------------
        // The circuit cannot detect replay (freshness is stateful), but it CAN
        // refuse the reserved "unset" value. Without this, a receipt with id 0
        // would silently disable a verifier's anti-replay set, because every
        // zero-id receipt would look like the same (already-seen) execution.
        execution_id
            .is_eq(&U64Var::constant(0))?
            .enforce_equal(&Boolean::FALSE)?;

        // ------------------------------------------------------------------
        // 9. Trace digests are real witness values.
        // ------------------------------------------------------------------
        // Not compared to anything public in v1. Decomposing them keeps the
        // compiler from eliding them and turns the v2 upgrade (binding a
        // transcript root) into one extra comparison rather than a change of
        // witness shape.
        for (_, _, digest) in &action_vars {
            let _bits = digest.to_bits_le()?;
        }

        Ok(())
    }
}

/// Allocates a public 64-bit value as ONE public input, and binds a 64-bit
/// witness decomposition to it.
///
/// The binding is what makes this sound and range-checked: the recomposition of
/// the 64 bits must equal the public field element, so a public value `>= 2^64`
/// has no satisfying witness. Using `UInt::new_input` instead would allocate 64
/// public inputs per value and break the verifier's input vector.
fn pub_u64(cs: &ConstraintSystemRef<CircuitField>, value: u64) -> Result<U64Var, SynthesisError> {
    let public = FpVar::<CircuitField>::new_input(cs.clone(), || Ok(CircuitField::from(value)))?;
    let uint = U64Var::new_witness(cs.clone(), || Ok(value))?;
    let bits = uint.to_bits_le()?;
    Boolean::le_bits_to_fp(&bits)?.enforce_equal(&public)?;
    Ok(uint)
}

/// Converts a `UInt` to a field variable **through its bits**, so the result is
/// bound to the range-checked decomposition rather than to a raw field element.
fn uint_to_fp(v: &U64Var) -> Result<FpVar<CircuitField>, SynthesisError> {
    let bits = v.to_bits_le()?;
    Boolean::le_bits_to_fp(&bits)
}

/// Assembles the circuit from protocol types.
///
/// `actions` is padded to [`MAX_ACTIONS`] with zero-amount entries whose target
/// is the first allowed target, so the membership constraint holds for padding
/// without weakening anything: a zero-amount action moves no value and is not
/// counted as live.
pub fn build_circuit(
    policy: &Policy,
    receipt: &Receipt,
    actions: &[Action],
) -> PolicyConformanceCircuit {
    let first_target = policy.allowed_targets.first().copied().unwrap_or(0);

    let mut padded: Vec<ActionWitness> = actions
        .iter()
        .take(MAX_ACTIONS)
        .map(|a| ActionWitness {
            target: a.target,
            amount: a.amount,
            trace_digest: a.trace_digest,
        })
        .collect();
    while padded.len() < MAX_ACTIONS {
        padded.push(ActionWitness {
            target: first_target,
            amount: 0,
            trace_digest: 0,
        });
    }

    // Pad the allow-list by repeating its first entry: never by a sentinel,
    // which an action could match directly.
    let mut allowed_targets = policy.allowed_targets.clone();
    allowed_targets.truncate(MAX_POLICY_TARGETS);
    while allowed_targets.len() < MAX_POLICY_TARGETS {
        allowed_targets.push(first_target);
    }

    PolicyConformanceCircuit {
        policy: PolicyPublic {
            max_amount: policy.max_amount,
            max_per_action: policy.max_per_action,
            expires_at: policy.expires_at,
            allowed_targets,
        },
        receipt: ReceiptPublic {
            total_amount: receipt.total_amount,
            action_count: receipt.action_count as u64,
            completed_at: receipt.completed_at,
            execution_id: receipt.execution_id,
        },
        actions: padded,
    }
}

// The public-input order lives in `zkagent-wire` and is re-exported above. It used
// to live here, which is why every verifier had to depend on the proving crate to
// learn the order of the vector it verifies.

/// Why a circuit shape could not be measured.
#[derive(Debug, thiserror::Error)]
pub enum ShapeError {
    /// The witness did not satisfy the circuit, or synthesis failed.
    ///
    /// Not a hypothetical: a witness outside the policy legitimately fails
    /// synthesis, which is why the caller must be able to see the difference
    /// between "no proof" and "cannot describe the proof".
    #[error("synthesis failed: {0}")]
    Synthesis(String),
}

/// Measure the constraint system for this exact policy, receipt and witness.
///
/// Returns `(constraints, public_inputs)`. This is how an attestation records
/// circuit identity: measured from the same inputs the proof was made for, not
/// copied from a document that can drift away from the code.
///
/// # Errors
/// [`ShapeError::Synthesis`] if the witness does not satisfy the circuit — in
/// which case there would be no proof to describe anyway.
pub fn measure_shape(
    policy: &Policy,
    receipt: &Receipt,
    actions: &[Action],
) -> Result<(usize, usize), ShapeError> {
    let cs = ConstraintSystem::<CircuitField>::new_ref();
    build_circuit(policy, receipt, actions)
        .generate_constraints(cs.clone())
        .map_err(|e| ShapeError::Synthesis(e.to_string()))?;

    // The ref exposes both counters directly; instance 0 is the constant `one`,
    // so the public-input count is one less than the instance count.
    let public_inputs = cs.num_instance_variables().saturating_sub(1);
    Ok((cs.num_constraints(), public_inputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    fn sample_policy() -> Policy {
        Policy::new(1_000, 300, 2_000, 1, vec![7, 3, 9]).unwrap()
    }

    fn sample_actions() -> Vec<Action> {
        vec![
            Action {
                target: 3,
                amount: 250,
                trace_digest: 111,
            },
            Action {
                target: 7,
                amount: 150,
                trace_digest: 222,
            },
        ]
    }

    fn sample_receipt() -> Receipt {
        Receipt {
            total_amount: 400,
            action_count: 2,
            completed_at: 1_500,
            chain_id: 1,
            execution_id: 1,
        }
    }

    fn is_satisfied(policy: &Policy, receipt: &Receipt, actions: &[Action]) -> bool {
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        build_circuit(policy, receipt, actions)
            .generate_constraints(cs.clone())
            .unwrap();
        cs.is_satisfied().unwrap()
    }

    #[test]
    fn happy_path_satisfies_the_circuit() {
        assert!(is_satisfied(
            &sample_policy(),
            &sample_receipt(),
            &sample_actions()
        ));
    }

    #[test]
    fn per_action_overrun_fails() {
        let actions = vec![
            Action {
                target: 3,
                amount: 301,
                trace_digest: 1,
            },
            Action {
                target: 7,
                amount: 99,
                trace_digest: 2,
            },
        ];
        assert!(!is_satisfied(&sample_policy(), &sample_receipt(), &actions));
    }

    #[test]
    fn total_over_cap_fails() {
        let receipt = Receipt {
            total_amount: 1_001,
            action_count: 3,
            completed_at: 1_500,
            chain_id: 1,
            execution_id: 1,
        };
        let actions = vec![
            Action {
                target: 3,
                amount: 300,
                trace_digest: 1,
            },
            Action {
                target: 7,
                amount: 300,
                trace_digest: 2,
            },
            Action {
                target: 9,
                amount: 300,
                trace_digest: 3,
            },
        ];
        // Each action is within the per-action cap and the sum matches the
        // inflated receipt, so only the TOTAL cap catches this.
        assert!(!is_satisfied(&sample_policy(), &receipt, &actions));
    }

    #[test]
    fn disallowed_target_fails() {
        let actions = vec![
            Action {
                target: 4,
                amount: 100,
                trace_digest: 1,
            },
            Action {
                target: 7,
                amount: 300,
                trace_digest: 2,
            },
        ];
        assert!(!is_satisfied(&sample_policy(), &sample_receipt(), &actions));
    }

    #[test]
    fn expired_execution_fails() {
        let receipt = Receipt {
            total_amount: 400,
            action_count: 2,
            completed_at: 2_000, // == expires_at; must be strictly before
            chain_id: 1,
            execution_id: 1,
        };
        assert!(!is_satisfied(&sample_policy(), &receipt, &sample_actions()));
    }

    #[test]
    fn action_count_mismatch_fails() {
        let receipt = Receipt {
            total_amount: 400,
            action_count: 3,
            completed_at: 1_500,
            chain_id: 1,
            execution_id: 1,
        };
        assert!(!is_satisfied(&sample_policy(), &receipt, &sample_actions()));
    }

    #[test]
    fn sum_mismatch_fails() {
        let receipt = Receipt {
            total_amount: 401,
            action_count: 2,
            completed_at: 1_500,
            chain_id: 1,
            execution_id: 1,
        };
        assert!(!is_satisfied(&sample_policy(), &receipt, &sample_actions()));
    }

    #[test]
    fn public_input_order_matches_the_allocation_order() {
        // THE guard against a permuted public-input vector. The circuit's public
        // inputs are ordered by the order `new_input` is called, while the
        // verifier builds its vector in `public_inputs()`. When those two
        // disagree, every individual input is correct and the proof still fails
        // with `InvalidProof` — which reads like a broken prover, not a
        // mis-ordered vector. This asserts they are the same list, element by
        // element, so the mistake surfaces at its real cause.
        let policy = sample_policy();
        let receipt = sample_receipt();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        build_circuit(&policy, &receipt, &sample_actions())
            .generate_constraints(cs.clone())
            .unwrap();

        let assigned = cs
            .borrow()
            .expect("constraint system outlives the borrow")
            .instance_assignment
            .clone();
        // Slot 0 is the constant one.
        let expected = public_inputs(&policy, &receipt);
        assert_eq!(assigned.len(), expected.len() + 1);
        assert_eq!(&assigned[1..], expected.as_slice());
    }

    #[test]
    fn circuit_shape_is_data_independent() {
        // Groth16 is circuit-specific: the constraint system produced at SETUP
        // must be identical to the one used to PROVE. If any constraint is
        // added conditionally on witness values, a setup run with a different
        // policy produces a key pair whose proofs never verify — and the only
        // symptom is `InvalidProof` on a perfectly honest witness.
        //
        // This test pins that invariant against the exact dummy instance
        // `prover::setup` uses.
        fn shape(p: &Policy, r: &Receipt, a: &[Action]) -> (usize, usize) {
            let cs = ConstraintSystem::<CircuitField>::new_ref();
            build_circuit(p, r, a)
                .generate_constraints(cs.clone())
                .unwrap();
            (cs.num_constraints(), cs.num_instance_variables())
        }

        let setup_policy = Policy::new(1, 1, 1, 1, vec![0]).unwrap();
        let setup_receipt = Receipt {
            total_amount: 0,
            action_count: 0,
            completed_at: 0,
            chain_id: 1,
            execution_id: 1,
        };

        let setup_shape = shape(&setup_policy, &setup_receipt, &[]);
        let real_shape = shape(&sample_policy(), &sample_receipt(), &sample_actions());
        assert_eq!(
            setup_shape, real_shape,
            "setup and proving circuits differ — setup shape {setup_shape:?}, proving shape {real_shape:?}"
        );
    }

    #[test]
    fn zero_execution_id_fails() {
        // The circuit refuses the reserved id 0 even though the constraint
        // system cannot detect an actual replay.
        let mut receipt = sample_receipt();
        receipt.execution_id = 0;
        assert!(!is_satisfied(&sample_policy(), &receipt, &sample_actions()));
    }

    #[test]
    fn public_input_vector_has_the_expected_shape() {
        let v = public_inputs(&sample_policy(), &sample_receipt());
        assert_eq!(v.len(), 7 + MAX_POLICY_TARGETS);
        assert_eq!(v[0], CircuitField::from(1_000u64));
        assert_eq!(v[5], CircuitField::from(2u64));
    }

    #[test]
    fn constraint_count_is_sane() {
        // A regression guard on circuit size: a change that accidentally
        // allocates per-bit public inputs (see `pub_u64`) or explodes the
        // constraint count shows up here instead of in a proving-time mystery.
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        build_circuit(&sample_policy(), &sample_receipt(), &sample_actions())
            .generate_constraints(cs.clone())
            .unwrap();
        let constraints = cs.num_constraints();
        let instances = cs.num_instance_variables();
        println!("constraints = {constraints}, instance variables = {instances}");
        // 14 public inputs plus the constant-one slot.
        assert_eq!(instances, 7 + MAX_POLICY_TARGETS + 1);
        assert!(
            (500..50_000).contains(&constraints),
            "constraint count {constraints} outside the expected band"
        );
    }

    #[test]
    fn padding_never_widens_the_allowed_set() {
        // Padding repeats a real target, so a forbidden target stays forbidden
        // even though the table has 8 slots.
        let p = sample_policy();
        let c = build_circuit(&p, &sample_receipt(), &sample_actions());
        assert_eq!(c.actions.len(), MAX_ACTIONS);
        assert_eq!(c.policy.allowed_targets.len(), MAX_POLICY_TARGETS);
        for slot in &c.policy.allowed_targets {
            assert!(p.permits_target(*slot), "padded slot {slot} is not allowed");
        }
    }
}

#[cfg(test)]
mod shape_tests {
    use super::*;

    #[test]
    fn measure_shape_reports_the_shipped_shape() {
        let policy = Policy::new(1_000, 300, 2_000, 1, vec![3, 7, 9]).unwrap();
        let receipt = Receipt {
            total_amount: 400,
            action_count: 2,
            completed_at: 1_500,
            chain_id: 1,
            execution_id: 1_001,
        };
        let actions = vec![
            Action {
                target: 3,
                amount: 250,
                trace_digest: 11,
            },
            Action {
                target: 7,
                amount: 150,
                trace_digest: 22,
            },
        ];
        let (constraints, public_inputs) = measure_shape(&policy, &receipt, &actions).unwrap();
        println!("measured: {constraints} constraints, {public_inputs} public inputs");
        assert_eq!(public_inputs, 15, "the arity the verifier expects");
        assert!(constraints > 0);
    }
}
