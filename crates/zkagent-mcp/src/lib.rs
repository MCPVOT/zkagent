//! `zkagent-mcp` — the harness shell.
//!
//! An MCP (Model Context Protocol) server over stdio, so **any** agent harness
//! that speaks MCP can drive the primitives: Hermes, Claude Code, OpenCode,
//! Codex, or a host application that embeds the same JSON-RPC handler.
//!
//! # Why this exists
//!
//! The primitives are Rust libraries. A harness that cannot call Rust needs an
//! IPC surface. This is that surface — and it is a *thin* one: every tool
//! delegates to `zkagent-service`. There is no protocol logic in this crate,
//! so an MCP-driven harness and a Tauri-embedded host cannot disagree about
//! what a proof means.
//!
//! # Protocol
//!
//! JSON-RPC 2.0 over newline-delimited JSON on stdin/stdout:
//!
//! | Method | Behaviour |
//! |---|---|
//! | `initialize` | negotiates the protocol version, advertises the tools |
//! | `notifications/initialized` | acknowledged by silence (it is a notification) |
//! | `ping` | empty result |
//! | `tools/list` | the tool schemas |
//! | `tools/call` | runs one tool |
//! | `resources/list` | empty list (the tools are the interface) |
//!
//! **stdout carries JSON-RPC only.** Diagnostics go to stderr. A single stray
//! `println!` would corrupt the stream and break every harness at once, so
//! this crate prints nothing to stdout except responses.
//!
//! # Tools
//!
//! - `zkagent_setup` — run the trusted setup, write the key pair
//! - `zkagent_authorize` — build and sign a policy
//! - `zkagent_prove` — produce the proof for an execution
//! - `zkagent_verify` — verify a proof and apply the replay gate
//! - `zkagent_status` — report what is present on disk
//!
//! Every tool is path-based: the harness decides where the workspace lives,
//! and the service never assumes a working directory.

#![deny(missing_docs)]
#![deny(unsafe_code)]

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use zkagent_service::{AuthorityKey, PolicySpec};

/// The MCP protocol version this server implements.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Every protocol version this server can speak.
///
/// Only versions actually implemented and tested belong here. Claiming support
/// for a version we have not exercised is a small overclaim that costs a
/// confused client later.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[PROTOCOL_VERSION];

/// The server name reported in `initialize`.
pub const SERVER_NAME: &str = "zkagent";

/// Handle one JSON-RPC request.
///
/// Returns `None` for notifications (requests without an `id`), which by the
/// JSON-RPC spec must not be answered.
///
/// # Panics
/// Never. Every malformed request becomes a JSON-RPC error object.
#[must_use]
pub fn handle(request: &Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");

    // A notification has no id and must not be answered.
    let id = id?;

    let result = match method {
        "initialize" => Ok(initialize_result(request)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_schemas() })),
        "resources/list" => Ok(json!({ "resources": [] })),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or(json!({}));
            call_tool(&params)
        }
        other => Err(RpcError {
            code: -32601,
            message: format!("method not found: {other}"),
        }),
    };

    Some(match result {
        Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }),
        Err(err) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": err.code, "message": err.message }
        }),
    })
}

/// A JSON-RPC level error.
#[derive(Debug)]
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }
}

/// The `initialize` result.
///
/// Per the MCP handshake the server answers with the protocol version it will
/// use: the client's if we support it, otherwise our own. The client then
/// decides whether to continue.
fn initialize_result(request: &Value) -> Value {
    let requested = request
        .get("params")
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION);

    let version = SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .find(|v| **v == requested)
        .copied()
        .unwrap_or(PROTOCOL_VERSION);

    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": SERVER_NAME, "version": zkagent_service::VERSION }
    })
}

/// The tool schemas.
fn tool_schemas() -> Vec<Value> {
    vec![
        json!({
            "name": "zkagent_setup",
            "description": "Run the zkagent trusted setup and write the Groth16 key pair (vk.bin, pk.bin). \
        Single-party setup: fine for development, not a ceremony. Produces key material that can prove \
        and verify the zkagent attestation circuit.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "keys_dir": { "type": "string", "description": "Directory to write the key pair into." },
                    "seed": { "type": "integer", "description": "Setup RNG seed. Fixed seeds are for tests only." }
                },
                "required": ["keys_dir"]
            }
        }),
        json!({
            "name": "zkagent_authorize",
            "description": "Create a policy and sign it with the human authority key, so an agent can \
        prove it stayed inside it. Use authority_key_path for real use; seed is a reproducible DEMO key \
        that makes the policy forgeable by anyone.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "policy_path": { "type": "string", "description": "Where to write the signed policy." },
                    "max_amount": { "type": "integer", "description": "Total cap over the execution." },
                    "max_per_action": { "type": "integer", "description": "Cap over any single action." },
                    "expires_at": { "type": "integer", "description": "Expiry, unix seconds, exclusive." },
                    "chain_id": { "type": "integer", "description": "Chain the execution must belong to." },
                    "targets": { "type": "array", "items": { "type": "integer" },
                                 "description": "Allowed target ids." },
                    "authority_key_path": { "type": "string",
                        "description": "File holding 32 hex-encoded bytes of Ed25519 key material. \
        Created with the OS CSPRNG if missing (mode 0600). This is the production path." },
                    "seed": { "type": "integer", "description": "DEMO ONLY: 64-bit seed for the authority key." }
                },
                "required": ["policy_path", "max_amount", "max_per_action", "expires_at", "chain_id", "targets"]
            }
        }),
        json!({
            "name": "zkagent_prove",
            "description": "Produce a zero-knowledge proof that some set of private actions explains \
        the receipt while staying inside the signed policy. The actions are never revealed: only the \
        public receipt fields and the policy limits enter the proof.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "keys_dir": { "type": "string", "description": "Key directory produced by zkagent_setup." },
                    "policy_path": { "type": "string", "description": "Signed policy file." },
                    "receipt_path": { "type": "string", "description": "Public receipt file." },
                    "actions_path": { "type": "string", "description": "Private action list (the witness)." },
                    "proof_path": { "type": "string", "description": "Where to write the proof artifact." }
                },
                "required": ["keys_dir", "policy_path", "receipt_path", "actions_path"]
            }
        }),
        json!({
            "name": "zkagent_verify",
            "description": "Verify a zkagent proof: the policy signature, the public-input binding, \
        the Groth16 proof and the freshness checks. With seen_path the verifier keeps a persistent set \
        of accepted execution ids and refuses replays; an unreadable state file fails closed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "keys_dir": { "type": "string", "description": "Key directory produced by zkagent_setup." },
                    "policy_path": { "type": "string", "description": "Signed policy file." },
                    "receipt_path": { "type": "string", "description": "Public receipt file." },
                    "proof_path": { "type": "string", "description": "Proof artifact." },
                    "now": { "type": "integer", "description": "Verifier clock, unix seconds, for the future-dating check." },
                    "seen_path": { "type": "string", "description": "Persistent set of accepted execution ids." }
                },
                "required": ["keys_dir", "policy_path", "receipt_path", "proof_path"]
            }
        }),
        json!({
            "name": "zkagent_status",
            "description": "Report what zkagent material exists on disk: key pair, policies, proofs and \
        the replay state, with their sizes and timestamps.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "keys_dir": { "type": "string", "description": "Key directory to inspect." },
                    "policy_path": { "type": "string", "description": "Signed policy file to inspect." },
                    "seen_path": { "type": "string", "description": "Replay state file to inspect." }
                },
                "required": []
            }
        }),
    ]
}

/// Dispatch `tools/call`.
fn call_tool(params: &Value) -> Result<Value, RpcError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing tool name"))?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "zkagent_setup" => tool_setup(&args),
        "zkagent_authorize" => tool_authorize(&args),
        "zkagent_prove" => tool_prove(&args),
        "zkagent_verify" => tool_verify(&args),
        "zkagent_status" => tool_status(&args),
        other => Err(RpcError {
            code: -32602,
            message: format!("unknown tool: {other}"),
        }),
    }
}

fn tool_setup(args: &Value) -> Result<Value, RpcError> {
    let keys_dir = PathBuf::from(req_str(args, "keys_dir")?);
    let seed = opt_u64(args, "seed").unwrap_or(7);
    let outcome = zkagent_service::setup(&keys_dir, seed).map_err(|e| RpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    Ok(ok(json!({
        "keys_dir": outcome.keys_dir.display().to_string(),
        "verifying_key_bytes": outcome.verifying_key_bytes,
        "proving_key_bytes": outcome.proving_key_bytes,
        "note": "single-party trusted setup; not a ceremony"
    })))
}

fn tool_authorize(args: &Value) -> Result<Value, RpcError> {
    let policy_path = PathBuf::from(req_str(args, "policy_path")?);
    let spec = PolicySpec {
        max_amount: req_u64(args, "max_amount")?,
        max_per_action: req_u64(args, "max_per_action")?,
        expires_at: req_u64(args, "expires_at")?,
        chain_id: req_u64(args, "chain_id")?,
        targets: req_u64_list(args, "targets")?,
    };

    let key = match (opt_str(args, "authority_key_path"), opt_u64(args, "seed")) {
        (Some(path), _) => AuthorityKey::File(PathBuf::from(path)),
        (None, Some(seed)) => AuthorityKey::Seed(seed),
        (None, None) => return Err(RpcError::invalid_params(
            "authority_key_path is required (seed is a DEMO key and makes the policy forgeable)",
        )),
    };

    let authorized =
        zkagent_service::authorize(&policy_path, &spec, &key).map_err(|e| RpcError {
            code: -32000,
            message: e.to_string(),
        })?;

    Ok(ok(json!({
        "policy_path": policy_path.display().to_string(),
        "authority_pubkey": hex_encode(&authorized.authority_pubkey),
        "used_demo_key": authorized.used_demo_key,
        "created_key_file": authorized.created_key_file,
        "warning": authorized.warning
    })))
}

fn tool_prove(args: &Value) -> Result<Value, RpcError> {
    let keys_dir = PathBuf::from(req_str(args, "keys_dir")?);
    let policy_path = PathBuf::from(req_str(args, "policy_path")?);
    let receipt_path = PathBuf::from(req_str(args, "receipt_path")?);
    let actions_path = PathBuf::from(req_str(args, "actions_path")?);

    let receipt = zkagent_service::read_receipt(&receipt_path).map_err(|e| RpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    let actions = zkagent_service::read_actions(&actions_path).map_err(|e| RpcError {
        code: -32000,
        message: e.to_string(),
    })?;

    let proof =
        zkagent_service::prove(&keys_dir, &policy_path, &receipt, &actions).map_err(|e| {
            RpcError {
                code: -32000,
                message: e.to_string(),
            }
        })?;

    let proof_path = opt_str(args, "proof_path").map(PathBuf::from);
    if let Some(path) = &proof_path {
        zkagent_service::write_json(path, &proof).map_err(|e| RpcError {
            code: -32000,
            message: e.to_string(),
        })?;
    }

    Ok(ok(json!({
        "proof_path": proof_path.map(|p| p.display().to_string()),
        "format_version": proof.format_version,
        "public_inputs": proof.public_inputs,
        "proof_bytes": proof.proof.len()
    })))
}

fn tool_verify(args: &Value) -> Result<Value, RpcError> {
    let keys_dir = PathBuf::from(req_str(args, "keys_dir")?);
    let policy_path = PathBuf::from(req_str(args, "policy_path")?);
    let receipt_path = PathBuf::from(req_str(args, "receipt_path")?);
    let proof_path = PathBuf::from(req_str(args, "proof_path")?);

    let receipt = zkagent_service::read_receipt(&receipt_path).map_err(|e| RpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    let proof: zkagent_proofs::prover::ProofBytes = zkagent_service::read_json(&proof_path)
        .map_err(|e| RpcError {
            code: -32000,
            message: e.to_string(),
        })?;

    let seen_path = opt_str(args, "seen_path").map(PathBuf::from);
    let outcome = zkagent_service::verify(
        &keys_dir,
        &policy_path,
        &receipt,
        &proof,
        opt_u64(args, "now"),
        seen_path.as_deref(),
    )
    .map_err(|e| RpcError {
        code: -32000,
        message: e.to_string(),
    })?;

    let (accepted, reason) = match &outcome.verdict {
        zkagent_verifier::Verdict::Accept => (true, Value::Null),
        zkagent_verifier::Verdict::Reject(r) => (false, Value::String(r.to_string())),
    };

    Ok(ok(json!({
        "accepted": accepted,
        "reason": reason,
        "recorded_execution_id": outcome.recorded,
        "replay_state": seen_path.map(|p| p.display().to_string())
    })))
}

fn tool_status(args: &Value) -> Result<Value, RpcError> {
    let mut out = serde_json::Map::new();

    if let Some(dir) = opt_str(args, "keys_dir") {
        let dir = PathBuf::from(dir);
        out.insert("keys_dir".into(), json!(dir.display().to_string()));
        out.insert("vk.bin".into(), file_info(&dir.join("vk.bin")));
        out.insert("pk.bin".into(), file_info(&dir.join("pk.bin")));
    }
    if let Some(policy) = opt_str(args, "policy_path") {
        let path = PathBuf::from(policy);
        out.insert("policy_path".into(), json!(path.display().to_string()));
        out.insert("policy".into(), file_info(&path));
    }
    if let Some(seen) = opt_str(args, "seen_path") {
        let path = PathBuf::from(seen);
        out.insert("seen_path".into(), json!(path.display().to_string()));
        out.insert("seen".into(), file_info(&path));
    }

    Ok(ok(Value::Object(out)))
}

/// Wrap a payload as an MCP tool result: JSON text content plus the same
/// payload as structured content for harnesses that understand it.
fn ok(payload: Value) -> Value {
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": payload,
        "isError": false
    })
}

fn file_info(path: &Path) -> Value {
    match std::fs::metadata(path) {
        Ok(meta) => json!({
            "exists": true,
            "bytes": meta.len(),
            "modified_unix": meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
        }),
        Err(_) => json!({ "exists": false }),
    }
}

fn req_str(args: &Value, name: &str) -> Result<String, RpcError> {
    args.get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            RpcError::invalid_params(format!("missing required string argument: {name}"))
        })
}

fn opt_str(args: &Value, name: &str) -> Option<String> {
    args.get(name).and_then(Value::as_str).map(str::to_string)
}

fn req_u64(args: &Value, name: &str) -> Result<u64, RpcError> {
    args.get(name).and_then(Value::as_u64).ok_or_else(|| {
        RpcError::invalid_params(format!("missing required integer argument: {name}"))
    })
}

fn opt_u64(args: &Value, name: &str) -> Option<u64> {
    args.get(name).and_then(Value::as_u64)
}

fn req_u64_list(args: &Value, name: &str) -> Result<Vec<u64>, RpcError> {
    let arr = args.get(name).and_then(Value::as_array).ok_or_else(|| {
        RpcError::invalid_params(format!("missing required array argument: {name}"))
    })?;
    arr.iter()
        .map(|v| {
            v.as_u64().ok_or_else(|| {
                RpcError::invalid_params(format!("{name} must contain only integers"))
            })
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_reports_the_protocol_and_tools() {
        let response = handle(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": PROTOCOL_VERSION }
        }))
        .expect("initialize is answered");

        let result = &response["result"];
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn tools_list_advertises_every_tool() {
        let response = handle(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
            .expect("tools/list is answered");
        let tools = response["result"]["tools"].as_array().expect("tools array");
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(
            names,
            vec![
                "zkagent_setup",
                "zkagent_authorize",
                "zkagent_prove",
                "zkagent_verify",
                "zkagent_status"
            ]
        );
        // Every tool must carry a schema, or a harness cannot call it.
        for tool in tools {
            assert!(tool["inputSchema"].is_object(), "tool without a schema");
            assert!(tool["description"].as_str().is_some_and(|d| !d.is_empty()));
        }
    }

    #[test]
    fn notifications_are_not_answered() {
        assert!(
            handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).is_none()
        );
    }

    #[test]
    fn unknown_methods_return_a_json_rpc_error() {
        let response = handle(&json!({"jsonrpc": "2.0", "id": 3, "method": "nope"})).unwrap();
        assert_eq!(response["error"]["code"], -32601);
        assert!(response["result"].is_null());
    }

    #[test]
    fn unknown_tools_return_a_json_rpc_error() {
        let response = handle(&json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": "zkagent_nope", "arguments": {} }
        }))
        .unwrap();
        assert_eq!(response["error"]["code"], -32602);
    }

    #[test]
    fn missing_arguments_are_reported_precisely() {
        let response = handle(&json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": { "name": "zkagent_setup", "arguments": {} }
        }))
        .unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert!(response["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("keys_dir")));
    }

    #[test]
    fn authorizing_without_a_key_is_refused() {
        let response = handle(&json!({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {
                "name": "zkagent_authorize",
                "arguments": {
                    "policy_path": "p.json", "max_amount": 100, "max_per_action": 10,
                    "expires_at": 10, "chain_id": 1, "targets": [3]
                }
            }
        }))
        .unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert!(response["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("authority_key_path")));
    }
}
