//! Execution receipt: the public statement of what an agent did.
//!
//! A [`Receipt`] is what the agent publishes after executing. It is PUBLIC and
//! contains only what a verifier needs to check the execution against the
//! policy. The agent's private trace is *not* here; it lives in the proof's
//! witness.

use crate::policy::Policy;

/// Domain separator for execution receipts.
pub const RECEIPT_DOMAIN: &str = "zkagent.receipt.v1";

/// A single action taken by the agent.
///
/// Actions are part of the *private* witness: the proof demonstrates that
/// every action respected the policy without disclosing which actions were
/// taken. Only the aggregate [`Receipt`] is public.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    /// The target the action touched (must be in the policy allow-list).
    pub target: u64,
    /// The value moved by this action.
    pub amount: u64,
    /// Free-form per-action commitment; the agent may use it to bind a
    /// transcript hash without revealing the transcript.
    pub trace_digest: u64,
}

/// The public result of an agent execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Total value moved across all actions.
    pub total_amount: u64,
    /// Number of actions performed.
    pub action_count: u32,
    /// Unix timestamp at which the execution completed.
    pub completed_at: u64,
    /// Chain / network the execution happened on.
    pub chain_id: u64,
}

impl Receipt {
    /// Canonical byte encoding of the receipt.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(RECEIPT_DOMAIN.as_bytes());
        out.push(0u8);
        out.extend_from_slice(&self.total_amount.to_be_bytes());
        out.extend_from_slice(&self.action_count.to_be_bytes());
        out.extend_from_slice(&self.completed_at.to_be_bytes());
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out
    }

    /// Checks the receipt against a policy, returning every violation found.
    ///
    /// This is the *plain* check — the same conditions the circuit enforces.
    /// It is used by the prover to fail fast, and by tests as the reference
    /// semantics that the ZK proof must agree with.
    pub fn check_against(&self, policy: &Policy) -> Result<(), Vec<ReceiptViolation>> {
        let mut violations = Vec::new();

        if self.chain_id != policy.chain_id {
            violations.push(ReceiptViolation::ChainMismatch {
                receipt: self.chain_id,
                policy: policy.chain_id,
            });
        }
        if self.total_amount > policy.max_amount {
            violations.push(ReceiptViolation::TotalExceedsPolicy {
                total: self.total_amount,
                max: policy.max_amount,
            });
        }
        if policy.is_expired_at(self.completed_at) {
            violations.push(ReceiptViolation::Expired {
                completed_at: self.completed_at,
                expires_at: policy.expires_at,
            });
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// A concrete reason a receipt fails its policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptViolation {
    /// The receipt was produced on a different chain than the policy covers.
    ChainMismatch {
        /// Chain id carried by the receipt.
        receipt: u64,
        /// Chain id in the policy.
        policy: u64,
    },
    /// The total moved exceeds the policy's total cap.
    TotalExceedsPolicy {
        /// Total moved.
        total: u64,
        /// Policy cap.
        max: u64,
    },
    /// The execution completed at or after the policy expiry.
    Expired {
        /// Completion timestamp.
        completed_at: u64,
        /// Policy expiry.
        expires_at: u64,
    },
}

impl std::fmt::Display for ReceiptViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainMismatch { receipt, policy } => {
                write!(f, "chain mismatch: receipt on {receipt}, policy for {policy}")
            }
            Self::TotalExceedsPolicy { total, max } => {
                write!(f, "total {total} exceeds policy cap {max}")
            }
            Self::Expired {
                completed_at,
                expires_at,
            } => write!(f, "receipt at {completed_at} is past policy expiry {expires_at}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::new(1_000, 250, 1_000, 1, vec![3, 7]).unwrap()
    }

    #[test]
    fn compliant_receipt_passes() {
        let r = Receipt {
            total_amount: 100,
            action_count: 2,
            completed_at: 500,
            chain_id: 1,
        };
        assert!(r.check_against(&policy()).is_ok());
    }

    #[test]
    fn over_cap_receipt_fails() {
        let r = Receipt {
            total_amount: 1_001,
            action_count: 2,
            completed_at: 500,
            chain_id: 1,
        };
        let v = r.check_against(&policy()).unwrap_err();
        assert!(v.contains(&ReceiptViolation::TotalExceedsPolicy {
            total: 1_001,
            max: 1_000
        }));
    }

    #[test]
    fn wrong_chain_receipt_fails() {
        let r = Receipt {
            total_amount: 10,
            action_count: 1,
            completed_at: 500,
            chain_id: 999,
        };
        let v = r.check_against(&policy()).unwrap_err();
        assert!(v.contains(&ReceiptViolation::ChainMismatch {
            receipt: 999,
            policy: 1
        }));
    }

    #[test]
    fn expired_receipt_fails() {
        let r = Receipt {
            total_amount: 10,
            action_count: 1,
            completed_at: 1_000,
            chain_id: 1,
        };
        let v = r.check_against(&policy()).unwrap_err();
        assert!(v.contains(&ReceiptViolation::Expired {
            completed_at: 1_000,
            expires_at: 1_000
        }));
    }
}
