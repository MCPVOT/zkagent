//! `zkagent-service` — the embeddable operations layer.
//!
//! This crate is the reason `zkagent` can live inside a Tauri app, a plugin
//! host, an MCP harness or a CLI without each of them re-implementing (and
//! getting subtly wrong) the same protocol steps.
//!
//! # Layering
//!
//! ```text
//!   zkagent-core      vocabulary: policy, receipt, authority, replay state
//!   zkagent-proofs    the Groth16 circuit and the prover
//!   zkagent-verifier  pure verification: a proof + inputs -> a verdict
//!   zkagent-service   <<< this crate: the four operations, over files
//!   zkagent-cli       a shell: arguments -> service -> human output
//!   zkagent-mcp       a shell: JSON-RPC -> service -> tool results
//! ```
//!
//! A shell adds presentation. It does not add protocol logic. If a shell needs
//! a rule that is not in this crate, the rule is missing from this crate, not
//! from the shell.
//!
//! # The four operations
//!
//! - [`ops::setup`] — run the trusted setup, write the key pair.
//! - [`ops::authorize`] — build a policy, sign it with the authority key, write it.
//! - [`ops::prove`] — produce the zero-knowledge proof for an execution.
//! - [`ops::verify`] — verify a proof and apply the replay gate.
//!
//! # Rules this crate guarantees to every host
//!
//! - **No printing.** Nothing here writes to stdout or stderr.
//! - **No global state.** Every input is a parameter.
//! - **No panics.** Every failure is a [`ServiceError`] carrying a path or value.
//! - **Fail closed on state.** An unreadable replay ledger is an error, never
//!   an empty set of accepted executions.
//!
//! See `docs/EMBEDDING.md` in the repository for worked examples (Tauri
//! command, MCP server, plain library use).

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod bundle;
pub mod disclosure;
pub mod error;
pub mod ops;
pub mod wire;

pub use bundle::{publish, verify_bundle, PublishedBundle};
pub use disclosure::{check_disclosure, disclose, Disclosure, PathStep};
pub use error::ServiceError;
pub use ops::{
    authorize, load_keys, prove, prove_with_keys, read_actions, read_json, read_receipt,
    read_signed_policy, resolve_authority, setup, verify, write_json, AuthorityKey, PolicySpec,
    ResolvedAuthority, SetupOutcome, VerifyOutcome,
};
// Re-exported so a host needs ONE dependency, not three, to read a verdict.
pub use zkagent_verifier::{RejectReason, Verdict};
// The artifact types and the block sources, re-exported for the same reason: a
// shell should name what it passes to these operations without adding three
// crates to do it. `zkagent-cli` and `zkagent-mcp` depend on this crate alone —
// see `docs/CODE-MAP.md`.
pub use wire::{ActionJson, AuthorizedPolicy, PolicyJson, ReceiptJson, SignedPolicyFile};
pub use zkagent_ipfs::{AttestationManifest, BlockSource, DirSource, MemorySource};
// `Keys` is re-exported for the same reason: a host that caches a parsed key
// names the type it is caching, and should not have to depend on the prover
// crate to do it.
pub use zkagent_proofs::prover::{Keys, ProvenExecution};
pub use zkagent_wire::{ProofBytes, FORMAT_VERSION};

/// The crate version, surfaced for hosts that want to report it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
