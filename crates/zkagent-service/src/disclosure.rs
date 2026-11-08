//! Selective disclosure: prove that one action's digest is inside the attested set,
//! without revealing the other seven.
//!
//! # Why this needs no new circuit
//!
//! The trace root is already a public input and the tree is already built over the padded
//! `trace_digest` leaves. Membership in that tree is therefore checkable by *anyone* who
//! has the leaf and its siblings: walk the path, compare with the root the proof already
//! published. The prover gains nothing by putting the path in the circuit — the verifier
//! would have to trust the same arithmetic either way — and the constraint count stays at
//! zero added.
//!
//! # What this does and does not prove
//!
//! It proves: **a leaf with digest `d` sits at slot `i` under the root in this receipt.**
//!
//! It does **not** prove the action's `target` or `amount`, because the leaf is the digest
//! alone. A disclosure can therefore say "one of the actions committed here has digest 11",
//! but not "the action that spent 250 on target 3 has digest 11". Binding those fields means
//! making the leaf `H(target, amount, digest)`, which costs eight permutations in the circuit
//! (2 640 constraints at 330 each) and a format bump. `docs/SELECTIVE-DISCLOSURE.md` prices
//! both designs; this module implements the cheap one and says so in every artifact.

use serde::{Deserialize, Serialize};

use zkagent_core::{Action, Receipt, MAX_ACTIONS};
use zkagent_proofs::merkle::{
    field_from_bytes, inclusion_path, leaves_from_digests, root_bytes_for_actions,
    verify_inclusion, Step, ROOT_BYTES, TREE_DEPTH,
};

/// Marker written into every disclosure, so a file cannot be mistaken for a receipt.
pub const KIND: &str = "zkagent/disclosure";

/// Disclosures are versioned separately from the circuit: the shape can change without
/// invalidating a proof, and a proof format change does not silently reinterpret one.
pub const VERSION: u32 = 1;

/// One sibling on the way to the root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PathStep {
    /// The other child at this level, hex-encoded little-endian.
    pub sibling: String,
    /// True when the node being proven is the parent's left child.
    pub left: bool,
}

/// The artifact a holder of the private actions publishes to reveal exactly one of them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Disclosure {
    /// Always [`KIND`].
    pub kind: String,
    /// Always [`VERSION`].
    pub version: u32,
    /// Which of the eight slots is being revealed.
    pub index: usize,
    /// The revealed trace digest.
    pub leaf_digest: u64,
    /// The root this path walks to, hex-encoded little-endian.
    pub root: String,
    /// Sibling hashes, leaf level first.
    pub path: Vec<PathStep>,
}

/// Builds a disclosure for one action.
///
/// # Errors
/// When the index is outside the actions supplied, when there are more actions than the
/// tree has slots, or when the receipt's root is not the root of these actions — the last
/// one matters because a disclosure that cannot verify against its own receipt is a
/// fabricated artifact, and it is better to fail here than at the verifier.
pub fn disclose(actions: &[Action], index: usize, receipt: &Receipt) -> Result<Disclosure, String> {
    if actions.is_empty() {
        return Err("disclose: no actions supplied".to_string());
    }
    if actions.len() > MAX_ACTIONS {
        return Err(format!(
            "disclose: {} actions supplied, the tree has {MAX_ACTIONS} slots",
            actions.len()
        ));
    }
    if index >= actions.len() {
        return Err(format!(
            "disclose: index {index} is outside the {} action(s) in this execution",
            actions.len()
        ));
    }

    let root = root_bytes_for_actions(actions);
    if root != receipt.trace_root {
        return Err(
            "disclose: the receipt's trace_root is not the root of these actions; this \
             execution and this action list do not match"
                .to_string(),
        );
    }

    let digests: Vec<u64> = actions.iter().map(|a| a.trace_digest).collect();
    let leaves = leaves_from_digests(&digests);
    let path = inclusion_path(&leaves, index);

    Ok(Disclosure {
        kind: KIND.to_string(),
        version: VERSION,
        index,
        leaf_digest: actions[index].trace_digest,
        root: hex::encode(root),
        path: path
            .iter()
            .map(|step| PathStep {
                sibling: hex::encode(zkagent_proofs::merkle::root_bytes(step.sibling)),
                left: step.node_is_left,
            })
            .collect(),
    })
}

/// Checks a disclosure against the receipt it claims to be about.
///
/// # Errors
/// Every refusal names the reason: a wrong kind or version, a malformed hex field, a root
/// that is not this receipt's, or a path that does not reach that root. The distinction
/// matters — "this is about a different execution" and "this leaf is not in the set" are
/// different failures, and collapsing them would make a bad artifact look like a lie.
pub fn check_disclosure(disclosure: &Disclosure, receipt: &Receipt) -> Result<(), String> {
    if disclosure.kind != KIND {
        return Err(format!(
            "not a zkagent disclosure: kind is {:?}, expected {KIND:?}",
            disclosure.kind
        ));
    }
    if disclosure.version != VERSION {
        return Err(format!(
            "disclosure version {} is not {VERSION}",
            disclosure.version
        ));
    }
    if disclosure.index >= MAX_ACTIONS {
        return Err(format!(
            "disclosure index {} is outside the {MAX_ACTIONS} tree slots",
            disclosure.index
        ));
    }
    if disclosure.path.len() != TREE_DEPTH {
        return Err(format!(
            "disclosure path has {} step(s), the tree is depth {TREE_DEPTH}",
            disclosure.path.len()
        ));
    }

    let root = parse_hex32(&disclosure.root, "root")?;
    if root != receipt.trace_root {
        return Err(
            "the disclosure's root is not this receipt's trace_root: it is about a different \
             execution"
                .to_string(),
        );
    }

    let mut steps = Vec::with_capacity(disclosure.path.len());
    for (level, step) in disclosure.path.iter().enumerate() {
        let sibling = parse_hex32(&step.sibling, &format!("path[{level}].sibling"))?;
        // The claimed slot must agree with the path's directions. Membership alone proves a
        // digest is somewhere in the set, not that it sits at `index`: without this check a
        // valid disclosure for one slot could be relabelled as any other slot and still
        // verify, while the artifact asserts a position it never had.
        let expected_left = (disclosure.index >> level) & 1 == 0;
        if step.left != expected_left {
            return Err(format!(
                "path[{level}] has left={} but slot {} requires left={expected_left}: the claimed \
                 index does not match this inclusion path",
                step.left, disclosure.index
            ));
        }
        steps.push(Step {
            sibling: field_from_bytes(&sibling),
            node_is_left: step.left,
        });
    }

    let leaf = leaves_from_digests(&[disclosure.leaf_digest])[0];
    if !verify_inclusion(leaf, &steps, field_from_bytes(&root)) {
        return Err(
            "the disclosed leaf is not in the set committed by the trace root: the digest or \
             the path was changed"
                .to_string(),
        );
    }
    Ok(())
}

fn parse_hex32(value: &str, field: &str) -> Result<[u8; ROOT_BYTES], String> {
    let bytes =
        hex::decode(value).map_err(|e| format!("disclosure {field} is not valid hex: {e}"))?;
    let bytes: [u8; ROOT_BYTES] = bytes.try_into().map_err(|_| {
        format!(
            "disclosure {field} must be {ROOT_BYTES} bytes, got {}",
            value.len() / 2
        )
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actions() -> Vec<Action> {
        vec![
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
            Action {
                target: 9,
                amount: 50,
                trace_digest: 33,
            },
        ]
    }

    fn receipt_for(actions: &[Action]) -> Receipt {
        Receipt {
            total_amount: actions.iter().map(|a| a.amount).sum(),
            action_count: actions.len() as u32,
            completed_at: 1_500,
            chain_id: 1,
            execution_id: 1_001,
            trace_root: root_bytes_for_actions(actions),
        }
    }

    #[test]
    fn a_disclosure_verifies_at_its_own_slot() {
        let actions = actions();
        let receipt = receipt_for(&actions);
        for index in 0..actions.len() {
            let disclosure = disclose(&actions, index, &receipt).expect("disclose");
            check_disclosure(&disclosure, &receipt).expect("must verify at its own slot");
        }
    }

    #[test]
    fn a_relabelled_index_is_rejected_even_though_the_leaf_is_still_in_the_set() {
        let actions = actions();
        let receipt = receipt_for(&actions);
        let mut disclosure = disclose(&actions, 0, &receipt).expect("disclose");
        check_disclosure(&disclosure, &receipt).expect("the unmodified disclosure verifies");
        // The leaf and its path are untouched, so this is a positional forgery, not a
        // membership forgery: it is exactly the case an index range check alone misses.
        disclosure.index = 2;
        let error = check_disclosure(&disclosure, &receipt).expect_err("relabelling must fail");
        assert!(
            error.contains("index"),
            "error must name the index mismatch: {error}"
        );
    }

    #[test]
    fn flipping_a_path_direction_is_rejected() {
        let actions = actions();
        let receipt = receipt_for(&actions);
        let mut disclosure = disclose(&actions, 1, &receipt).expect("disclose");
        disclosure.path[0].left = !disclosure.path[0].left;
        assert!(check_disclosure(&disclosure, &receipt).is_err());
    }
}
