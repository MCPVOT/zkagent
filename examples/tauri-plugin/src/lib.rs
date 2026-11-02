//! Example: embedding `zkagent` in a Tauri v2 app.
//!
//! # The shape of the integration
//!
//! A Tauri command is a function that takes JSON-serialisable arguments and
//! returns a JSON-serialisable result. That is exactly the shape the service
//! layer already has, so the integration is thin on purpose:
//!
//! ```text
//!   frontend (JS/TS)  --invoke-->  #[tauri::command]  -->  zkagent-service
//! ```
//!
//! The command layer below does three things and nothing else:
//!
//! 1. takes path strings and plain numbers (what IPC can carry);
//! 2. calls one service function;
//! 3. turns a `ServiceError` into a string the UI can show.
//!
//! It does **not** re-implement policy validation, the replay gate, or the
//! fail-closed rule on unreadable state. Those live in `zkagent-service`, so a
//! Tauri app, the CLI and an MCP harness cannot disagree about what a proof
//! means.
//!
//! # Wiring it into an app
//!
//! With the `tauri` feature enabled, the crate provides `run_app()`, which
//! registers the three commands:
//!
//! ```ignore
//! fn main() {
//!     zkagent_tauri_example::run_app();
//! }
//! ```
//!
//! The command functions themselves are plain Rust and can be called directly
//! (they are what the `#[tauri::command]` wrappers expose):
//!
//! ```no_run
//! let verdict = zkagent_tauri_example::verify_execution(
//!     "/home/user/.zkagent/keys".to_string(),
//!     "/home/user/.zkagent/policy.json".to_string(),
//!     "/home/user/.zkagent/receipt.json".to_string(),
//!     "/home/user/.zkagent/proof.json".to_string(),
//!     Some("/home/user/.zkagent/seen.json".to_string()),
//!     Some(1_700_000_000),
//! );
//! // `verdict.ok` and `verdict.message` are what the UI shows.
//! ```
//!
//! And from the frontend:
//!
//! ```js
//! const verdict = await invoke("verify_execution", {
//!   keysDir: "/home/user/.zkagent/keys",
//!   policyPath: "/home/user/.zkagent/policy.json",
//!   receiptPath: "/home/user/.zkagent/receipt.json",
//!   proofPath: "/home/user/.zkagent/proof.json",
//!   seenPath: "/home/user/.zkagent/seen.json",
//!   now: Math.floor(Date.now() / 1000),
//! });
//! ```
//!
//! # Why the Tauri dependency is optional
//!
//! The `tauri` feature is off by default, so this crate builds and tests on a
//! headless CI runner without the Tauri/WebView dependency tree. Turn it on
//! with `cargo build --features tauri` in a real app.

#![deny(missing_docs)]
#![deny(unsafe_code)]

use std::path::PathBuf;

use zkagent_service::{AuthorityKey, PolicySpec, Verdict};

/// The result a command returns to the UI.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommandResult {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// A human-readable message (the verdict, or the error).
    pub message: String,
    /// Structured payload, for the UI to render.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl CommandResult {
    fn ok(message: impl Into<String>, data: Option<serde_json::Value>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            data,
        }
    }

    fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            data: None,
        }
    }
}

/// Create and sign a policy.
#[cfg_attr(feature = "tauri", tauri::command)]
pub fn authorize_policy(
    policy_path: String,
    authority_key_path: String,
    max_amount: u64,
    max_per_action: u64,
    expires_at: u64,
    chain_id: u64,
    targets: Vec<u64>,
) -> CommandResult {
    let spec = PolicySpec {
        max_amount,
        max_per_action,
        expires_at,
        chain_id,
        targets,
    };
    let key = AuthorityKey::File(PathBuf::from(authority_key_path));

    match zkagent_service::authorize(&PathBuf::from(policy_path), &spec, &key) {
        Ok(authorized) => {
            let warning = authorized
                .warning
                .map(|w| format!("warning: {w}"))
                .unwrap_or_default();
            CommandResult::ok(
                if warning.is_empty() {
                    "policy written".to_string()
                } else {
                    format!("policy written. {warning}")
                },
                Some(serde_json::json!({
                    "authority_pubkey": hex_encode(&authorized.authority_pubkey),
                    "created_key_file": authorized.created_key_file,
                })),
            )
        }
        Err(e) => CommandResult::err(e.to_string()),
    }
}

/// Produce the proof for an execution.
#[cfg_attr(feature = "tauri", tauri::command)]
pub fn prove_execution(
    keys_dir: String,
    policy_path: String,
    receipt_path: String,
    actions_path: String,
    proof_path: String,
) -> CommandResult {
    let receipt = match zkagent_service::read_receipt(&PathBuf::from(&receipt_path)) {
        Ok(r) => r,
        Err(e) => return CommandResult::err(e.to_string()),
    };
    let actions = match zkagent_service::read_actions(&PathBuf::from(actions_path)) {
        Ok(a) => a,
        Err(e) => return CommandResult::err(e.to_string()),
    };

    match zkagent_service::prove(
        &PathBuf::from(keys_dir),
        &PathBuf::from(&policy_path),
        &receipt,
        &actions,
    ) {
        Ok(proven) => {
            if let Err(e) = zkagent_service::write_json(&PathBuf::from(&proof_path), &proven.proof) {
                return CommandResult::err(e.to_string());
            }
            // The prover completes the receipt with the trace root over the
            // private digests; the proof's public inputs commit to it, so the
            // file on disk must carry it too.
            if let Err(e) = zkagent_service::write_json(
                &PathBuf::from(&receipt_path),
                &zkagent_service::ReceiptJson::from(&proven.receipt),
            ) {
                return CommandResult::err(e.to_string());
            }
            CommandResult::ok(
                "proof written".to_string(),
                Some(serde_json::json!({
                    "public_inputs": proven.proof.public_inputs,
                    "proof_bytes": proven.proof.proof.len(),
                    "trace_root": proven.receipt.trace_root.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                })),
            )
        }
        Err(e) => CommandResult::err(e.to_string()),
    }
}

/// Verify a proof, with the replay gate when a state path is given.
#[cfg_attr(feature = "tauri", tauri::command)]
pub fn verify_execution(
    keys_dir: String,
    policy_path: String,
    receipt_path: String,
    proof_path: String,
    seen_path: Option<String>,
    now: Option<u64>,
) -> CommandResult {
    let receipt = match zkagent_service::read_receipt(&PathBuf::from(receipt_path)) {
        Ok(r) => r,
        Err(e) => return CommandResult::err(e.to_string()),
    };
    let proof: zkagent_service::ProofBytes =
        match zkagent_service::read_json(&PathBuf::from(proof_path)) {
            Ok(p) => p,
            Err(e) => return CommandResult::err(e.to_string()),
        };

    let seen = seen_path.map(PathBuf::from);
    match zkagent_service::verify(
        &PathBuf::from(keys_dir),
        &PathBuf::from(policy_path),
        &receipt,
        &proof,
        now,
        seen.as_deref(),
    ) {
        Ok(outcome) => {
            let accepted = outcome.accepted();
            let message = match &outcome.verdict {
                Verdict::Accept => "ACCEPT".to_string(),
                Verdict::Reject(reason) => format!("REJECT: {reason}"),
            };
            CommandResult::ok(
                message,
                Some(serde_json::json!({
                    "accepted": accepted,
                    "recorded_execution_id": outcome.recorded,
                })),
            )
        }
        Err(e) => CommandResult::err(e.to_string()),
    }
}

/// Build and run the Tauri application with the zkagent commands registered.
///
/// Only available with the `tauri` feature. A real app would call this from
/// its own `main` after `tauri::Builder` configuration:
///
/// ```ignore
/// fn main() {
///     zkagent_tauri_example::run_app();
/// }
/// ```
#[cfg(feature = "tauri")]
pub fn run_app() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            authorize_policy,
            prove_execution,
            verify_execution,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_policy_is_reported_as_a_failure_not_a_panic() {
        let result = authorize_policy(
            "does-not-exist/policy.json".into(),
            "does-not-exist/authority.hex".into(),
            100,
            10,
            10,
            1,
            vec![3],
        );
        assert!(!result.ok);
        assert!(!result.message.is_empty());
    }

    #[test]
    fn verifying_a_missing_proof_is_reported_as_a_failure() {
        let result = verify_execution(
            "keys".into(),
            "policy.json".into(),
            "receipt.json".into(),
            "missing-proof.json".into(),
            None,
            None,
        );
        assert!(!result.ok);
    }
}
