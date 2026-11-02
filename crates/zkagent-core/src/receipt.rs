//! Execution receipt: the public statement of what an agent did.
//!
//! A [`Receipt`] is what the agent publishes after executing. It is PUBLIC and
//! contains only what a verifier needs to check the execution against the
//! policy. The agent's private trace is *not* here; it lives in the proof's
//! witness.

use serde::{Deserialize, Serialize};

use crate::policy::Policy;

/// Domain separator for execution receipts.
pub const RECEIPT_DOMAIN: &str = "zkagent.receipt.v1";

/// Bytes in a trace root: one BN254 scalar, little-endian.
///
/// Not truncated to 64 bits on purpose. A 64-bit root gives roughly 2^32
/// collision work, which is well inside a determined attacker's budget; the full
/// field element is what makes "these are the actions behind the proof" worth
/// anything.
pub const TRACE_ROOT_BYTES: usize = 32;

/// Serde for a trace root: a 64-character lowercase hex string.
///
/// The bytes are the field element's canonical little-endian encoding, matching
/// `CircuitField::from_le_bytes_mod_order` on the verifier's side. Parsing is
/// strict — wrong length or non-hex is an error, never a panic — because this
/// field arrives from untrusted JSON.
pub mod trace_root_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::TRACE_ROOT_BYTES;

    /// Writes the root as lowercase hex.
    ///
    /// # Errors
    /// Propagates the serializer's own error.
    pub fn serialize<S: Serializer>(
        root: &[u8; TRACE_ROOT_BYTES],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(root))
    }

    /// Reads a root from a 64-character hex string.
    ///
    /// # Errors
    /// Returns a deserialisation error when the value is not a string, is not
    /// hex, or does not decode to exactly [`TRACE_ROOT_BYTES`] bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; TRACE_ROOT_BYTES], D::Error> {
        let text = String::deserialize(d)?;
        let bytes = hex::decode(text.trim()).map_err(serde::de::Error::custom)?;
        <[u8; TRACE_ROOT_BYTES]>::try_from(bytes.as_slice()).map_err(|_| {
            serde::de::Error::custom(format!(
                "trace_root must be {TRACE_ROOT_BYTES} bytes ({} hex characters), got {} bytes",
                TRACE_ROOT_BYTES * 2,
                bytes.len()
            ))
        })
    }
}

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Total value moved across all actions.
    pub total_amount: u64,
    /// Number of actions performed.
    pub action_count: u32,
    /// Unix timestamp at which the execution completed.
    pub completed_at: u64,
    /// Chain / network the execution happened on.
    pub chain_id: u64,
    /// Unique identifier for this execution, chosen by the agent.
    ///
    /// This is the anti-replay measure. Without it, two identical executions
    /// produce identical public inputs, so a proof produced once could be
    /// re-presented forever and a verifier could not tell a fresh execution
    /// from a replayed proof. The verifier must reject an id it has already
    /// seen (see `Receipt::is_replay`) and must refuse `0`, which is reserved
    /// as "unset".
    pub execution_id: u64,
    /// Merkle root over the padded per-action `trace_digest` leaves.
    ///
    /// This is the field that ties the proof to *this* execution rather than to
    /// some execution with the same totals: the circuit rebuilds the tree from
    /// the private digests and constrains the result to equal this public root.
    /// The bytes are the BN254 scalar's little-endian encoding; see
    /// [`trace_root_hex`] for the JSON form.
    #[serde(with = "trace_root_hex")]
    pub trace_root: [u8; TRACE_ROOT_BYTES],
}

impl Receipt {
    /// Canonical byte encoding of the receipt.
    ///
    /// The trace root is included: two executions with identical totals but
    /// different private digests are different executions, and an encoding that
    /// hid that would be lying about which one it describes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48 + TRACE_ROOT_BYTES);
        out.extend_from_slice(RECEIPT_DOMAIN.as_bytes());
        out.push(0u8);
        out.extend_from_slice(&self.total_amount.to_be_bytes());
        out.extend_from_slice(&self.action_count.to_be_bytes());
        out.extend_from_slice(&self.completed_at.to_be_bytes());
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.execution_id.to_be_bytes());
        out.extend_from_slice(&self.trace_root);
        out
    }

    /// True when this receipt reuses an execution id the verifier has already
    /// accepted.
    ///
    /// The proof system cannot enforce this on its own — freshness is stateful,
    /// and a circuit is stateless — so a verifier that must accept each receipt
    /// at most once keeps a set of seen ids (`seen.contains(&receipt.execution_id)`).
    /// This helper exists so every caller answers the question the same way.
    pub fn is_replay(&self, seen: &[u64]) -> bool {
        seen.contains(&self.execution_id)
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
        if self.execution_id == 0 {
            // 0 is reserved as "unset": a receipt without an id cannot be
            // checked for replay, so accepting one silently disables the
            // anti-replay measure.
            violations.push(ReceiptViolation::MissingExecutionId);
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
    /// The receipt carries no execution id, so replay cannot be detected.
    MissingExecutionId,
}

impl std::fmt::Display for ReceiptViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainMismatch { receipt, policy } => {
                write!(
                    f,
                    "chain mismatch: receipt on {receipt}, policy for {policy}"
                )
            }
            Self::TotalExceedsPolicy { total, max } => {
                write!(f, "total {total} exceeds policy cap {max}")
            }
            Self::Expired {
                completed_at,
                expires_at,
            } => write!(
                f,
                "receipt at {completed_at} is past policy expiry {expires_at}"
            ),
            Self::MissingExecutionId => write!(
                f,
                "receipt has no execution id (0), so replay cannot be detected"
            ),
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
            execution_id: 1,
            trace_root: [0u8; 32],
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
            execution_id: 1,
            trace_root: [0u8; 32],
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
            execution_id: 1,
            trace_root: [0u8; 32],
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
            execution_id: 1,
            trace_root: [0u8; 32],
        };
        let v = r.check_against(&policy()).unwrap_err();
        assert!(v.contains(&ReceiptViolation::Expired {
            completed_at: 1_000,
            expires_at: 1_000
        }));
    }

    #[test]
    fn zero_execution_id_fails() {
        // A receipt with no id silently disables anti-replay, so it is a
        // violation rather than a defaulted field.
        let r = Receipt {
            total_amount: 10,
            action_count: 1,
            completed_at: 500,
            chain_id: 1,
            execution_id: 0,
            trace_root: [0u8; 32],
        };
        let v = r.check_against(&policy()).unwrap_err();
        assert!(v.contains(&ReceiptViolation::MissingExecutionId));
    }

    fn receipt_with_root() -> Receipt {
        let mut r = Receipt {
            total_amount: 10,
            action_count: 1,
            completed_at: 500,
            chain_id: 1,
            execution_id: 7,
            trace_root: [0u8; TRACE_ROOT_BYTES],
        };
        r.trace_root[0] = 0xab;
        r.trace_root[TRACE_ROOT_BYTES - 1] = 0x01;
        r
    }

    #[test]
    fn the_trace_root_is_hex_and_round_trips() {
        let r = receipt_with_root();
        let json = serde_json::to_string(&r).expect("serialise");
        let expected = format!("\"trace_root\":\"{}\"", hex::encode(r.trace_root));
        assert!(json.contains(&expected), "json was {json}");
        let hex_field = json
            .split("\"trace_root\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("trace_root field");
        assert_eq!(hex_field.len(), TRACE_ROOT_BYTES * 2);
        assert_eq!(hex_field, hex_field.to_lowercase());
        let back: Receipt = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(r, back);
    }

    #[test]
    fn a_malformed_trace_root_is_rejected_without_panicking() {
        // The field arrives from untrusted JSON: non-hex, wrong length and a
        // non-string must all be errors, never a panic and never a silent zero.
        for bad in ["\"zz\"", "\"00ff\"", "12", "\"\""] {
            let json = format!(
                "{{\"total_amount\":10,\"action_count\":1,\"completed_at\":500,\"chain_id\":1,\
                 \"execution_id\":7,\"trace_root\":{}}}",
                bad
            );
            assert!(
                serde_json::from_str::<Receipt>(&json).is_err(),
                "trace_root {bad} must be rejected"
            );
        }
    }

    #[test]
    fn replay_is_detected_from_a_seen_id() {
        let r = Receipt {
            total_amount: 10,
            action_count: 1,
            completed_at: 500,
            chain_id: 1,
            execution_id: 7,
            trace_root: [0u8; 32],
        };
        assert!(!r.is_replay(&[1, 2, 3]));
        assert!(r.is_replay(&[1, 7, 9]));
    }
}
