//! The on-disk artifact formats.
//!
//! These types are the *file* representation of the protocol, kept in one place
//! so every shell (CLI, MCP server, Tauri plugin, a future WASM host) reads and
//! writes exactly the same bytes. A shell that re-declares them drifts; a shell
//! that imports them cannot.

use serde::{Deserialize, Serialize};

use zkagent_core::{Action, Policy, Receipt, SignatureBytes};

/// A signed policy file.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedPolicyFile {
    /// The policy fields.
    pub policy: PolicyJson,
    /// Hex-encoded compressed Ed25519 authority public key.
    pub authority_pubkey: String,
    /// Hex-encoded Ed25519 signature over the policy commitment.
    pub signature: String,
}

/// The policy fields as they appear on disk.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PolicyJson {
    /// Total cap over the whole execution.
    pub max_amount: u64,
    /// Cap over any single action.
    pub max_per_action: u64,
    /// Expiry, unix seconds, exclusive.
    pub expires_at: u64,
    /// Chain id the execution must belong to.
    pub chain_id: u64,
    /// Allowed target ids.
    pub allowed_targets: Vec<u64>,
}

impl From<&Policy> for PolicyJson {
    fn from(p: &Policy) -> Self {
        Self {
            max_amount: p.max_amount,
            max_per_action: p.max_per_action,
            expires_at: p.expires_at,
            chain_id: p.chain_id,
            allowed_targets: p.allowed_targets.clone(),
        }
    }
}

impl PolicyJson {
    /// Rebuild the validated policy.
    ///
    /// # Errors
    /// Returns the policy's own validation error when the fields do not form a
    /// legal policy (empty allow-list, zero caps, too many targets).
    pub fn to_policy(&self) -> Result<Policy, String> {
        Policy::new(
            self.max_amount,
            self.max_per_action,
            self.expires_at,
            self.chain_id,
            self.allowed_targets.clone(),
        )
        .map_err(|e| e.to_string())
    }
}

/// A receipt file.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceiptJson {
    /// Sum of all action amounts.
    pub total_amount: u64,
    /// Number of actions claimed.
    pub action_count: u32,
    /// When the execution completed, unix seconds.
    pub completed_at: u64,
    /// Chain the execution ran on.
    pub chain_id: u64,
    /// Unique id of this execution; must be non-zero.
    pub execution_id: u64,
}

impl From<&Receipt> for ReceiptJson {
    fn from(r: &Receipt) -> Self {
        Self {
            total_amount: r.total_amount,
            action_count: r.action_count,
            completed_at: r.completed_at,
            chain_id: r.chain_id,
            execution_id: r.execution_id,
        }
    }
}

impl From<&ReceiptJson> for Receipt {
    fn from(r: &ReceiptJson) -> Self {
        Self {
            total_amount: r.total_amount,
            action_count: r.action_count,
            completed_at: r.completed_at,
            chain_id: r.chain_id,
            execution_id: r.execution_id,
        }
    }
}

/// One private action in the witness.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ActionJson {
    /// Which target was acted on.
    pub target: u64,
    /// How much was spent.
    pub amount: u64,
    /// Digest of the transcript for this action.
    pub trace_digest: u64,
}

impl From<&Action> for ActionJson {
    fn from(a: &Action) -> Self {
        Self {
            target: a.target,
            amount: a.amount,
            trace_digest: a.trace_digest,
        }
    }
}

impl From<&ActionJson> for Action {
    fn from(a: &ActionJson) -> Self {
        Self {
            target: a.target,
            amount: a.amount,
            trace_digest: a.trace_digest,
        }
    }
}

/// A signed policy, in memory, with its decoded key material.
#[derive(Debug, Clone)]
pub struct AuthorizedPolicy {
    /// The policy itself.
    pub policy: Policy,
    /// The authority public key.
    pub authority_pubkey: Vec<u8>,
    /// The signature over the policy commitment.
    pub signature: SignatureBytes,
    /// Whether the signing key came from a reproducible demo seed.
    ///
    /// A shell should surface this: a demo key makes the policy forgeable.
    pub used_demo_key: bool,
    /// Whether a new key file was created during this call.
    pub created_key_file: bool,
    /// A warning the host should show the user, if any.
    pub warning: Option<String>,
}

impl AuthorizedPolicy {
    /// The file representation.
    #[must_use]
    pub fn to_file(&self) -> SignedPolicyFile {
        SignedPolicyFile {
            policy: PolicyJson::from(&self.policy),
            authority_pubkey: hex::encode(&self.authority_pubkey),
            signature: hex::encode(&self.signature.bytes),
        }
    }
}
