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
//!
//! # One key load per keys directory, not per call
//!
//! This is the one piece of state the server keeps: the parsed proving key. An
//! MCP server is a long-lived process driven by many `tools/call`s, and parsing
//! `pk.bin` costs ~258 ms of the ~400 ms a prove call takes end to end (the
//! cache lives in this crate's private `keycache` module). A CLI pays it once and exits; a server would pay it on every
//! call. The cache is keyed by the canonical keys directory plus a fingerprint of
//! both key files, so a regenerated key is noticed and reloaded rather than
//! served stale. Tool arguments, tool results and the key validation are
//! unchanged.

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod keycache;

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use keycache::KeyCache;
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

/// Handle one JSON-RPC request with the process-wide server.
///
/// This is the convenience entry point: it keeps a server — and therefore its
/// proving-key cache — alive for the life of the process, so repeated
/// `tools/call`s reuse the parsed key. A host that wants to own that lifetime
/// explicitly (to drop the key, or to serve two independent workspaces with two
/// separate caches) should build a [`Server`] and call [`Server::handle`].
///
/// Returns `None` for notifications (requests without an `id`), which by the
/// JSON-RPC spec must not be answered.
///
/// # Panics
/// Never. Every malformed request becomes a JSON-RPC error object.
#[must_use]
pub fn handle(request: &Value) -> Option<Value> {
    default_server().handle(request)
}

/// The server behind [`handle`], created on first use.
fn default_server() -> &'static Server {
    static DEFAULT: OnceLock<Server> = OnceLock::new();
    DEFAULT.get_or_init(Server::new)
}

/// One MCP server: the protocol dispatch, plus the parsed key it is holding.
///
/// The only state is the key cache, and it is per-server on purpose — a host
/// that constructs two servers gets two independent caches instead of two
/// callers silently sharing one.
pub struct Server {
    keys: KeyCache,
}

impl Server {
    /// A server with an empty key cache. The first `zkagent_prove` loads the
    /// key; later ones reuse it until the key files change.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: KeyCache::new(),
        }
    }

    /// Handle one JSON-RPC request.
    ///
    /// Returns `None` for notifications (requests without an `id`), which by the
    /// JSON-RPC spec must not be answered.
    ///
    /// # Panics
    /// Never. Every malformed request becomes a JSON-RPC error object.
    #[must_use]
    pub fn handle(&self, request: &Value) -> Option<Value> {
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
                self.call_tool(&params)
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

    /// Dispatch `tools/call`.
    fn call_tool(&self, params: &Value) -> Result<Value, RpcError> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("missing tool name"))?;
        let args = params.get("arguments").cloned().unwrap_or(json!({}));

        match name {
            "zkagent_setup" => tool_setup(&args),
            "zkagent_authorize" => tool_authorize(&args),
            "zkagent_prove" => self.tool_prove(&args),
            "zkagent_verify" => tool_verify(&args),
            "zkagent_status" => tool_status(&args),
            other => Err(RpcError {
                code: -32602,
                message: format!("unknown tool: {other}"),
            }),
        }
    }

    fn tool_prove(&self, args: &Value) -> Result<Value, RpcError> {
        let keys_dir = PathBuf::from(req_str(args, "keys_dir")?);
        let policy_path = PathBuf::from(req_str(args, "policy_path")?);
        let receipt_path = PathBuf::from(req_str(args, "receipt_path")?);
        let actions_path = PathBuf::from(req_str(args, "actions_path")?);

        let receipt = zkagent_service::read_receipt(&receipt_path).map_err(service_error)?;
        let actions = zkagent_service::read_actions(&actions_path).map_err(service_error)?;

        // The one expensive thing this server keeps between calls: the parsed
        // key pair. A miss (first call, or the files changed) costs the same
        // ~258 ms decompress a one-shot CLI pays.
        let keys = self.keys.get(&keys_dir).map_err(service_error)?;
        let proven = zkagent_service::prove_with_keys(&keys, &policy_path, &receipt, &actions)
            .map_err(service_error)?;

        let proof_path = opt_str(args, "proof_path").map(PathBuf::from);
        if let Some(path) = &proof_path {
            zkagent_service::write_json(path, &proven.proof).map_err(service_error)?;
        }

        // The receipt is completed by the prover (the trace root is derived from
        // the private witness), so write it back. A caller that keeps the old
        // file would verify against a root the proof does not commit to.
        zkagent_service::write_json(
            &receipt_path,
            &zkagent_service::ReceiptJson::from(&proven.receipt),
        )
        .map_err(service_error)?;

        Ok(ok(json!({
            "proof_path": proof_path.map(|p| p.display().to_string()),
            "format_version": proven.proof.format_version,
            "public_inputs": proven.proof.public_inputs,
            "proof_bytes": proven.proof.proof.len(),
            "trace_root": hex_encode(&proven.receipt.trace_root)
        })))
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a service failure onto a JSON-RPC tool error.
fn service_error(e: zkagent_service::ServiceError) -> RpcError {
    RpcError {
        code: -32000,
        message: e.to_string(),
    }
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

fn tool_setup(args: &Value) -> Result<Value, RpcError> {
    let keys_dir = PathBuf::from(req_str(args, "keys_dir")?);
    // No default seed: a default of 7 made every default key pair publicly reproducible,
    // which hands the trapdoor to anyone who bothers to regenerate it. Callers who pass a
    // seed get the deterministic, test-only path and are told so in the outcome.
    let outcome = match opt_u64(args, "seed") {
        Some(seed) => zkagent_service::setup(&keys_dir, seed),
        None => zkagent_service::setup_random(&keys_dir),
    }
    .map_err(|e| RpcError {
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

fn tool_verify(args: &Value) -> Result<Value, RpcError> {
    let keys_dir = PathBuf::from(req_str(args, "keys_dir")?);
    let policy_path = PathBuf::from(req_str(args, "policy_path")?);
    let receipt_path = PathBuf::from(req_str(args, "receipt_path")?);
    let proof_path = PathBuf::from(req_str(args, "proof_path")?);

    let receipt = zkagent_service::read_receipt(&receipt_path).map_err(|e| RpcError {
        code: -32000,
        message: e.to_string(),
    })?;
    let proof: zkagent_service::ProofBytes =
        zkagent_service::read_json(&proof_path).map_err(|e| RpcError {
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

    let (accepted, reason_code, reason) = match &outcome.verdict {
        zkagent_service::Verdict::Accept => (true, Value::Null, Value::Null),
        zkagent_service::Verdict::Reject(r) => (
            false,
            Value::String(r.code().to_string()),
            Value::String(r.to_string()),
        ),
    };

    Ok(ok(json!({
        "accepted": accepted,
        "reason_code": reason_code,
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
    use std::fs;

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

    /// The whole point of the cache, through the tool surface a harness uses:
    /// two `tools/call zkagent_prove` requests in one server must parse the key
    /// once, produce the same artifact both times, and be verified by the same
    /// verifier (a cached key that changed the proof would fail here).
    #[test]
    fn two_prove_calls_in_one_server_load_the_key_once() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keys_dir = dir.path().join("keys");
        let policy_path = dir.path().join("policy.json");
        let receipt_path = dir.path().join("receipt.json");
        let actions_path = dir.path().join("actions.json");
        let proof_path = dir.path().join("proof.json");

        fs::write(
            &receipt_path,
            concat!(
                r#"{"total_amount":400,"action_count":2,"completed_at":1500,"chain_id":1,"#,
                r#""execution_id":1001,"#,
                r#""trace_root":"0000000000000000000000000000000000000000000000000000000000000000"}"#
            ),
        )
        .expect("write receipt");
        fs::write(
            &actions_path,
            r#"[{"target":3,"amount":250,"trace_digest":11},{"target":7,"amount":150,"trace_digest":22}]"#,
        )
        .expect("write actions");

        let server = Server::new();
        let tool = |name: &str, arguments: Value| -> Value {
            server
                .handle(&json!({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": { "name": name, "arguments": arguments }
                }))
                .expect("every request with an id is answered")
        };

        let setup = tool(
            "zkagent_setup",
            json!({ "keys_dir": keys_dir.display().to_string(), "seed": 7 }),
        );
        assert_eq!(setup["result"]["isError"], json!(false), "{setup}");
        let authorized = tool(
            "zkagent_authorize",
            json!({
                "policy_path": policy_path.display().to_string(),
                "max_amount": 1000, "max_per_action": 300, "expires_at": 2000,
                "chain_id": 1, "targets": [3, 7, 9], "seed": 7
            }),
        );
        assert_eq!(
            authorized["result"]["isError"],
            json!(false),
            "{authorized}"
        );

        let probe_args = json!({
            "keys_dir": keys_dir.display().to_string(),
            "policy_path": policy_path.display().to_string(),
            "receipt_path": receipt_path.display().to_string(),
            "actions_path": actions_path.display().to_string(),
            "proof_path": proof_path.display().to_string()
        });

        let first = tool("zkagent_prove", probe_args.clone());
        let first_proof = fs::read(&proof_path).expect("read proof");
        let second = tool("zkagent_prove", probe_args);
        let second_proof = fs::read(&proof_path).expect("read proof");

        assert_eq!(first["result"]["isError"], json!(false));
        assert_eq!(second["result"]["isError"], json!(false));
        // Fresh Groth16 blinding on every call: the two proofs must differ, and the identical
        // public inputs are what show the same cached proving key served both.
        assert_ne!(first_proof, second_proof);
        assert_eq!(
            first["result"]["structuredContent"]["public_inputs"],
            second["result"]["structuredContent"]["public_inputs"]
        );
        assert_eq!(server.keys.loads(), 1, "the second call reloaded the key");

        // And it verifies, so the cache did not smuggle in a different key.
        let verdict = tool(
            "zkagent_verify",
            json!({
                "keys_dir": keys_dir.display().to_string(),
                "policy_path": policy_path.display().to_string(),
                "receipt_path": receipt_path.display().to_string(),
                "proof_path": proof_path.display().to_string()
            }),
        );
        assert_eq!(
            verdict["result"]["structuredContent"]["accepted"],
            json!(true)
        );
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
