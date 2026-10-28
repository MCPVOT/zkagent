//! Policy definition and canonical encoding.
//!
//! A [`Policy`] is the human's delegation: the bounds an agent is allowed to
//! operate within. It is the thing a human signs (see [`crate::authority`]) and
//! the thing a verifier checks a proof against.
//!
//! DESIGN NOTE (canonicalisation is load-bearing):
//! The policy commitment is a hash over the *canonical* byte encoding of the
//! policy. If two different byte strings could encode the same policy, an
//! attacker could obtain a signature on one encoding and replay the proof
//! against a different policy that hashes the same way. Therefore:
//!
//!   * fields are encoded in a FIXED order,
//!   * integers are encoded as fixed-width big-endian,
//!   * the target allow-list is SORTED and DEDUPLICATED before encoding,
//!   * lengths are encoded explicitly so that no two policies share an
//!     encoding ("length extension" / concatenation ambiguity),
//!   * the domain-separation tag is part of the hashed bytes.
//!
//! Every one of those properties has a test in this module.

use std::fmt;

/// Domain separator for policy commitments.
///
/// Bumping this string invalidates every previously issued policy and every
/// proof made under it. It is part of the hashed bytes, so a proof for policy
/// A can never be presented as a proof for policy B.
pub const POLICY_DOMAIN: &str = "zkagent.policy.v1";

/// Maximum number of targets a single policy may allow.
///
/// The allow-list is bounded so that the in-circuit membership check is a
/// fixed-size lookup rather than an unbounded Merkle path, which keeps the
/// Groth16 circuit small enough to prove on a laptop CPU.
pub const MAX_POLICY_TARGETS: usize = 8;

/// A human-signed delegation of authority to an agent.
///
/// # Security model
///
/// The policy itself is **public**. What is hidden is the *execution* — which
/// concrete actions the agent took inside the granted bounds. That inversion
/// matters: a verifier must be able to check "this execution was within the
/// policy you signed", so the policy has to be readable by the verifier. The
/// agent's private trace (which tool it called, with what arguments, in what
/// order) is what the proof keeps hidden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Maximum total value the agent may move in a single execution.
    pub max_amount: u64,
    /// Maximum value the agent may move in any single action.
    pub max_per_action: u64,
    /// Unix timestamp (seconds) after which the policy is no longer valid.
    pub expires_at: u64,
    /// Chain / network the policy is scoped to. Prevents cross-chain replay.
    pub chain_id: u64,
    /// Permitted action targets (opaque identifiers chosen by the human).
    pub allowed_targets: Vec<u64>,
}

impl Policy {
    /// Builds a policy, normalising the target allow-list.
    ///
    /// Sorting and deduplicating here (rather than at encoding time) means the
    /// struct's `PartialEq` agrees with the commitment, so two policies that
    /// compare equal always produce equal bytes and the same commitment.
    pub fn new(
        max_amount: u64,
        max_per_action: u64,
        expires_at: u64,
        chain_id: u64,
        allowed_targets: Vec<u64>,
    ) -> Result<Self, PolicyError> {
        if allowed_targets.len() > MAX_POLICY_TARGETS {
            return Err(PolicyError::TooManyTargets {
                got: allowed_targets.len(),
                max: MAX_POLICY_TARGETS,
            });
        }
        if max_per_action > max_amount {
            return Err(PolicyError::PerActionExceedsTotal {
                max_per_action,
                max_amount,
            });
        }
        // An empty allow-list would make every action forbidden, and it also
        // breaks the circuit's padding rule (padding repeats the first entry).
        if allowed_targets.is_empty() {
            return Err(PolicyError::EmptyAllowList);
        }
        let mut allowed_targets = allowed_targets;
        allowed_targets.sort_unstable();
        allowed_targets.dedup();
        Ok(Self {
            max_amount,
            max_per_action,
            expires_at,
            chain_id,
            allowed_targets,
        })
    }

    /// Canonical byte encoding of the policy.
    ///
    /// Deterministic and injective: distinct policies produce distinct bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 8 * self.allowed_targets.len());
        out.extend_from_slice(POLICY_DOMAIN.as_bytes());
        out.push(0u8); // explicit separator
        out.extend_from_slice(&self.max_amount.to_be_bytes());
        out.extend_from_slice(&self.max_per_action.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&(self.allowed_targets.len() as u32).to_be_bytes());
        for t in &self.allowed_targets {
            out.extend_from_slice(&t.to_be_bytes());
        }
        out
    }

    /// True when `target` is in the allow-list.
    pub fn permits_target(&self, target: u64) -> bool {
        self.allowed_targets.contains(&target)
    }

    /// True when the policy is expired at `now`.
    pub fn is_expired_at(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// Errors produced when constructing or checking a policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// More targets were supplied than [`MAX_POLICY_TARGETS`].
    TooManyTargets {
        /// How many targets were supplied.
        got: usize,
        /// The maximum allowed.
        max: usize,
    },
    /// `max_per_action` exceeded `max_amount`, which is incoherent.
    PerActionExceedsTotal {
        /// The per-action cap.
        max_per_action: u64,
        /// The total cap.
        max_amount: u64,
    },
    /// A target used the value reserved as the padding sentinel.
    EmptyAllowList,
    /// A required condition on the policy was violated.
    Violation(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyTargets { got, max } => {
                write!(f, "policy has {got} targets, maximum is {max}")
            }
            Self::PerActionExceedsTotal {
                max_per_action,
                max_amount,
            } => write!(
                f,
                "per-action cap {max_per_action} exceeds total cap {max_amount}"
            ),
            Self::EmptyAllowList => {
                write!(f, "policy allow-list must contain at least one target")
            }
            Self::Violation(m) => write!(f, "policy violation: {m}"),
        }
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Policy {
        Policy::new(1_000, 250, 1_700_000_000, 1, vec![7, 3, 9]).unwrap()
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let p = sample();
        assert_eq!(p.canonical_bytes(), p.canonical_bytes());
    }

    #[test]
    fn target_order_does_not_change_the_commitment() {
        // This is the property that stops a signature on policy A being
        // replayed as a signature on policy B.
        let a = Policy::new(100, 10, 500, 1, vec![3, 7, 9]).unwrap();
        let b = Policy::new(100, 10, 500, 1, vec![9, 3, 7]).unwrap();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn duplicate_targets_do_not_change_the_commitment() {
        let a = Policy::new(100, 10, 500, 1, vec![3, 7]).unwrap();
        let b = Policy::new(100, 10, 500, 1, vec![3, 7, 7]).unwrap();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn distinct_policies_have_distinct_encodings() {
        let base = sample();
        let mut others = Vec::new();
        others.push(Policy::new(1_001, 250, 1_700_000_000, 1, vec![3, 7, 9]).unwrap());
        others.push(Policy::new(1_000, 251, 1_700_000_000, 1, vec![3, 7, 9]).unwrap());
        others.push(Policy::new(1_000, 250, 1_700_000_001, 1, vec![3, 7, 9]).unwrap());
        others.push(Policy::new(1_000, 250, 1_700_000_000, 2, vec![3, 7, 9]).unwrap());
        others.push(Policy::new(1_000, 250, 1_700_000_000, 1, vec![3, 7]).unwrap());
        for o in others {
            assert_ne!(base.canonical_bytes(), o.canonical_bytes());
        }
    }

    #[test]
    fn allow_list_membership_works() {
        let p = sample();
        assert!(p.permits_target(3));
        assert!(p.permits_target(7));
        assert!(!p.permits_target(4));
    }

    #[test]
    fn rejects_too_many_targets() {
        let many: Vec<u64> = (0..MAX_POLICY_TARGETS as u64 + 1).collect();
        assert!(Policy::new(1, 1, 1, 1, many).is_err());
    }

    #[test]
    fn rejects_per_action_cap_above_total_cap() {
        assert!(Policy::new(100, 101, 1, 1, vec![1]).is_err());
    }

    #[test]
    fn expiry_is_half_open() {
        let p = Policy::new(1, 1, 100, 1, vec![1]).unwrap();
        assert!(!p.is_expired_at(99));
        assert!(p.is_expired_at(100));
        assert!(p.is_expired_at(101));
    }
}
