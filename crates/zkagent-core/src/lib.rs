//! `zkagent-core` — protocol data types for zero-knowledge agent attestation.
//!
//! This crate holds the *vocabulary* of the protocol: the policy a human
//! signs, the receipt an agent publishes, and the authority layer that binds
//! the two. It contains no proving logic; see `zkagent-proofs` for the
//! circuit and `zkagent-verifier` for the checking side.
//!
//! # The protocol in one paragraph
//!
//! A human defines a [`Policy`] (caps, expiry, chain, allow-list) and signs
//! it. An agent executes some private [`Action`](receipt::Action)s inside that
//! policy and publishes a public [`Receipt`] (total, count, time, chain) plus
//! a zero-knowledge proof. The proof demonstrates that *some* set of actions
//! existed that (a) totals the receipt amount, (b) never exceeded the
//! per-action cap, (c) only touched allowed targets, and (d) ran on the
//! policy's chain — without revealing which actions those were.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod authority;
pub mod policy;
pub mod receipt;

pub use authority::{
    policy_commitment, policy_signing_message, verify_policy_signature, Authority, SignatureBytes,
};
pub use policy::{Policy, PolicyError, MAX_POLICY_TARGETS, POLICY_DOMAIN};
pub use receipt::{Action, Receipt, ReceiptViolation, RECEIPT_DOMAIN};

/// Maximum number of actions an execution may contain.
///
/// Mirrors [`MAX_POLICY_TARGETS`] in purpose: both bound the circuit so that
/// proving stays cheap on a CPU. A receipt that claims more actions than this
/// cannot be proven.
pub const MAX_ACTIONS: usize = 8;
