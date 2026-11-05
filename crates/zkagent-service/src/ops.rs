//! The operations a host application calls.
//!
//! # The shape of this layer, and why
//!
//! Every shell — the CLI, an MCP server, a Tauri command, a WASM host, a test —
//! performs the same four operations in the same order, over the same files,
//! with the same failure modes. If each shell implements them itself, they
//! drift, and the drift is always in the security-relevant direction: one shell
//! forgets the replay gate, another forgets that an unreadable state file must
//! fail closed, a third prints a warning the others do not.
//!
//! So the operations live here, once, and the shells are thin:
//!
//! | Shell | What it adds | What it must NOT re-implement |
//! |---|---|---|
//! | `zkagent-cli` | argument parsing, human output | policy validation, replay gate, key handling |
//! | `zkagent-mcp` | JSON-RPC, tool schemas | the same |
//! | a Tauri command | IPC plumbing | the same |
//!
//! Rules for this layer, which every shell inherits:
//!
//! - **No printing.** The library never writes to stdout or stderr. A host
//!   that owns the terminal decides what the user sees.
//! - **No global state.** Everything is a parameter. A host can hold two
//!   workspaces, two authorities, two chains at once.
//! - **No panics.** Every failure is a [`ServiceError`] with a path or a value
//!   attached.
//! - **Fail closed on state.** An unreadable replay ledger is an error, never
//!   an empty set.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use zkagent_core::{Action, Authority, Policy, Receipt, SeenExecutions, SECRET_KEY_BYTES};
use zkagent_proofs::prover::{
    prove as prove_circuit, setup as run_setup, Keys, ProofBytes, ProvenExecution,
};
use zkagent_verifier::{verify as verify_proof, RejectReason, Verdict};

use crate::error::ServiceError;
use crate::wire::{ActionJson, AuthorizedPolicy, ReceiptJson, SignedPolicyFile};

/// Where the authority key comes from.
#[derive(Debug, Clone)]
pub enum AuthorityKey {
    /// A reproducible 64-bit seed. **Demo only**: anyone who knows the seed can
    /// reproduce the key and forge policies.
    Seed(u64),
    /// A file holding 32 bytes of hex. Created with the OS CSPRNG when it does
    /// not exist. This is the production path.
    File(PathBuf),
    /// 32 bytes of key material supplied by the caller (a KMS, a secret store).
    Bytes([u8; SECRET_KEY_BYTES]),
}

/// An authority key, resolved and ready to sign.
#[derive(Debug, Clone)]
pub struct ResolvedAuthority {
    /// The key.
    pub authority: Authority,
    /// Whether it came from a reproducible demo seed (forgeable by anyone).
    pub used_demo_key: bool,
    /// Whether a key file was created during this call.
    pub created_key_file: bool,
    /// A warning the host should show the user, if any.
    ///
    /// The service never prints; it hands the message back so every shell can
    /// decide how to surface it.
    pub warning: Option<String>,
}

/// The fields that define a policy.
#[derive(Debug, Clone)]
pub struct PolicySpec {
    /// Total cap over the execution.
    pub max_amount: u64,
    /// Cap over any single action.
    pub max_per_action: u64,
    /// Expiry, unix seconds, exclusive.
    pub expires_at: u64,
    /// Chain id.
    pub chain_id: u64,
    /// Allowed target ids.
    pub targets: Vec<u64>,
}

/// What [`setup`] produced.
#[derive(Debug, Clone)]
pub struct SetupOutcome {
    /// Directory the key pair was written to.
    pub keys_dir: PathBuf,
    /// Size of the verifying key, bytes.
    pub verifying_key_bytes: usize,
    /// Size of the proving key, bytes.
    pub proving_key_bytes: usize,
}

/// What [`verify`] concluded.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    /// The verdict.
    pub verdict: Verdict,
    /// Whether the execution id was newly recorded in the replay state.
    ///
    /// `false` means the verdict was `Accept` but the id was already present
    /// (which is a replay and therefore a rejection), or that no replay state
    /// was in use.
    pub recorded: bool,
}

impl VerifyOutcome {
    /// Whether the verdict is an acceptance.
    #[must_use]
    pub fn accepted(&self) -> bool {
        matches!(self.verdict, Verdict::Accept)
    }
}

/// Run the circuit-specific setup and write the key pair.
///
/// # Errors
/// Returns [`ServiceError::Io`] if the directory or the key files cannot be
/// written.
pub fn setup(keys_dir: &Path, seed: u64) -> Result<SetupOutcome, ServiceError> {
    fs::create_dir_all(keys_dir).map_err(|e| ServiceError::io(keys_dir, e))?;
    let keys = run_setup(seed).map_err(|e| ServiceError::Verification(e.to_string()))?;

    let vk = keys
        .verifying_key_bytes()
        .map_err(|e| ServiceError::Verification(e.to_string()))?;
    let pk = keys
        .proving_key_bytes()
        .map_err(|e| ServiceError::Verification(e.to_string()))?;

    fs::write(keys_dir.join("vk.bin"), &vk).map_err(|e| ServiceError::io(keys_dir, e))?;
    fs::write(keys_dir.join("pk.bin"), &pk).map_err(|e| ServiceError::io(keys_dir, e))?;

    Ok(SetupOutcome {
        keys_dir: keys_dir.to_path_buf(),
        verifying_key_bytes: vk.len(),
        proving_key_bytes: pk.len(),
    })
}

/// Create a policy, sign it, and write the signed policy file.
///
/// The returned [`AuthorizedPolicy`] says whether the key was a demo seed and
/// whether a key file was created, so the shell can warn the user without
/// having to re-derive it.
///
/// # Errors
/// Returns [`ServiceError::InvalidPolicy`] for an illegal policy,
/// [`ServiceError::Authority`] when the key cannot be produced or read, and
/// [`ServiceError::Io`] when the file cannot be written.
pub fn authorize(
    policy_path: &Path,
    spec: &PolicySpec,
    key: &AuthorityKey,
) -> Result<AuthorizedPolicy, ServiceError> {
    let policy = Policy::new(
        spec.max_amount,
        spec.max_per_action,
        spec.expires_at,
        spec.chain_id,
        spec.targets.clone(),
    )
    .map_err(|e| ServiceError::InvalidPolicy(e.to_string()))?;

    let auth = resolve_authority(key)?;

    let authorized = AuthorizedPolicy {
        // The signature must cover exactly the policy that is written to disk.
        policy: policy.clone(),
        authority_pubkey: auth.authority.public_key().as_bytes().to_vec(),
        signature: auth.authority.sign_policy(&policy),
        used_demo_key: auth.used_demo_key,
        created_key_file: auth.created_key_file,
        warning: auth.warning,
    };

    write_json(policy_path, &authorized.to_file())?;
    Ok(authorized)
}

/// Read and parse the key pair from `keys_dir`.
///
/// Split out of [`prove`] so a long-lived host can pay for the key load once.
/// Decompressing `pk.bin` is ~258 ms of a ~600 ms one-shot prove on this laptop
/// (see `zkagent-proofs/src/keyfile.rs`), and a CLI pays it once per process
/// anyway — but an MCP server or a Tauri app pays it once per *call* unless it
/// keeps the parsed key. That is a host decision, so it is a host-visible
/// function rather than hidden global state: `zkagent-mcp` caches the result,
/// `zkagent-cli` calls [`prove`] and lets the process exit.
///
/// The key is still validated exactly as before: compressed points, on-curve and
/// in-subgroup checks (`Compress::Yes`, `Validate::Yes`) inside the parser.
///
/// # Errors
/// Returns [`ServiceError::Io`] when either file cannot be read, and
/// [`ServiceError::Verification`] when either file is not a valid key.
pub fn load_keys(keys_dir: &Path) -> Result<Keys, ServiceError> {
    let pk_path = keys_dir.join("pk.bin");
    let vk_path = keys_dir.join("vk.bin");
    let pk_bytes = fs::read(&pk_path).map_err(|e| ServiceError::io(&pk_path, e))?;
    let vk_bytes = fs::read(&vk_path).map_err(|e| ServiceError::io(&vk_path, e))?;

    let proving = zkagent_proofs::prover::proving_key_from_bytes(&pk_bytes)
        .map_err(|e| ServiceError::Verification(e.to_string()))?;
    let verifying = zkagent_proofs::prover::verifying_key_from_bytes(&vk_bytes)
        .map_err(|e| ServiceError::Verification(e.to_string()))?;

    Ok(Keys { proving, verifying })
}

/// Produce the Groth16 proof for an execution, with the key pair already loaded.
///
/// Same proof, same rules as [`prove`]; it just does not touch the key files.
/// A caller that holds a key from [`load_keys`] is responsible for noticing that
/// the files changed underneath it.
///
/// # Errors
/// Returns [`ServiceError::Io`] when the policy cannot be read,
/// [`ServiceError::Malformed`] when it cannot be parsed, and
/// [`ServiceError::Verification`] when the proof cannot be produced.
pub fn prove_with_keys(
    keys: &Keys,
    policy_path: &Path,
    receipt: &Receipt,
    actions: &[Action],
) -> Result<ProvenExecution, ServiceError> {
    let signed = read_signed_policy(policy_path)?;
    let policy = signed
        .policy
        .to_policy()
        .map_err(ServiceError::InvalidPolicy)?;

    prove_circuit(keys, &policy, receipt, actions)
        .map_err(|e| ServiceError::Verification(e.to_string()))
}

/// Produce the Groth16 proof for an execution.
///
/// Loads the key pair from `keys_dir` and proves with it — the right shape for a
/// one-shot process. A long-lived host should call [`load_keys`] once and
/// [`prove_with_keys`] per call instead.
///
/// The returned [`ProvenExecution`] carries the receipt with its `trace_root`
/// filled in from the private witness. A host MUST publish *that* receipt (or
/// write it back over the one it read), because the proof's public inputs commit
/// to it: the whole point of the root is that a verifier recomputes it from the
/// receipt it holds.
///
/// # Errors
/// Returns [`ServiceError::Io`] when a file cannot be read,
/// [`ServiceError::Malformed`] when an artifact cannot be parsed, and
/// [`ServiceError::Verification`] when the proof cannot be produced.
pub fn prove(
    keys_dir: &Path,
    policy_path: &Path,
    receipt: &Receipt,
    actions: &[Action],
) -> Result<ProvenExecution, ServiceError> {
    let keys = load_keys(keys_dir)?;
    prove_with_keys(&keys, policy_path, receipt, actions)
}

/// Verify a proof, with the replay gate applied when `seen` is given.
///
/// The order matters and is fixed here rather than in each shell:
///
/// 1. load the replay state — **failing closed** if it exists but cannot be read;
/// 2. refuse an execution id that was already accepted;
/// 3. verify the proof;
/// 4. record the id, and refuse the acceptance if it cannot be persisted.
///
/// # Errors
/// Returns [`ServiceError::Replay`] when the state cannot be loaded or saved,
/// [`ServiceError::Io`] when the policy or key files cannot be read, and
/// [`ServiceError::Malformed`] when an artifact cannot be parsed.
pub fn verify(
    keys_dir: &Path,
    policy_path: &Path,
    receipt: &Receipt,
    proof: &ProofBytes,
    now: Option<u64>,
    seen: Option<&Path>,
) -> Result<VerifyOutcome, ServiceError> {
    let signed = read_signed_policy(policy_path)?;
    let vk_bytes = fs::read(keys_dir.join("vk.bin"))
        .map_err(|e| ServiceError::io(keys_dir.join("vk.bin"), e))?;

    let mut state = match seen {
        Some(path) => {
            Some(SeenExecutions::load(path).map_err(|e| ServiceError::Replay(e.to_string()))?)
        }
        None => None,
    };

    verify_with_vk(&vk_bytes, &signed, receipt, proof, now, state.as_mut())
}

/// Verify with the verifying key supplied as bytes, and the policy already parsed.
///
/// This is the shared core: the path-based [`verify`] reads files and calls it, and
/// [`crate::bundle::verify_bundle`] fetches the same four artifacts by CID and calls
/// it. One implementation of the replay gate and the verification steps, so a
/// bundle-verified proof and a file-verified proof cannot diverge.
///
/// # Errors
/// Returns [`ServiceError::InvalidPolicy`] for a policy that does not validate,
/// [`ServiceError::Malformed`] for an undecodable key or signature, and
/// [`ServiceError::Replay`] when the ledger cannot be read or written.
pub fn verify_with_vk(
    vk_bytes: &[u8],
    signed: &SignedPolicyFile,
    receipt: &Receipt,
    proof: &ProofBytes,
    now: Option<u64>,
    mut state: Option<&mut SeenExecutions>,
) -> Result<VerifyOutcome, ServiceError> {
    let policy = signed
        .policy
        .to_policy()
        .map_err(ServiceError::InvalidPolicy)?;
    let pubkey = hex::decode(&signed.authority_pubkey)
        .map_err(|e| ServiceError::Authority(format!("authority_pubkey is not hex: {e}")))?;
    let sig = hex::decode(&signed.signature)
        .map_err(|e| ServiceError::Authority(format!("signature is not hex: {e}")))?;

    if let Some(s) = &state {
        if s.contains(receipt.execution_id) {
            return Ok(VerifyOutcome {
                verdict: Verdict::Reject(RejectReason::AlreadyAccepted(receipt.execution_id)),
                recorded: false,
            });
        }
    }

    let verdict = verify_proof(vk_bytes, &policy, receipt, proof, &pubkey, &sig, now);

    if let Verdict::Accept = verdict {
        if let Some(s) = state.as_mut() {
            match s.record(receipt.execution_id) {
                Ok(true) => {}
                Ok(false) => {
                    // Recorded between the check and now: treat it as the replay.
                    return Ok(VerifyOutcome {
                        verdict: Verdict::Reject(RejectReason::AlreadyAccepted(
                            receipt.execution_id,
                        )),
                        recorded: false,
                    });
                }
                Err(e) => {
                    // An acceptance the verifier cannot remember is a replay
                    // waiting to happen. Refuse it.
                    return Err(ServiceError::Replay(e.to_string()));
                }
            }
        }
    }

    let recorded = state
        .as_ref()
        .is_some_and(|s| s.contains(receipt.execution_id));
    Ok(VerifyOutcome { verdict, recorded })
}

/// Read a signed policy file.
///
/// # Errors
/// Returns [`ServiceError::Io`] or [`ServiceError::Malformed`] on failure.
pub fn read_signed_policy(path: &Path) -> Result<SignedPolicyFile, ServiceError> {
    read_json(path)
}

/// Read a receipt file.
///
/// # Errors
/// Returns [`ServiceError::Io`] or [`ServiceError::Malformed`] on failure.
pub fn read_receipt(path: &Path) -> Result<Receipt, ServiceError> {
    let json: ReceiptJson = read_json(path)?;
    Ok(Receipt::from(&json))
}

/// Read the private action list.
///
/// # Errors
/// Returns [`ServiceError::Io`] or [`ServiceError::Malformed`] on failure.
pub fn read_actions(path: &Path) -> Result<Vec<Action>, ServiceError> {
    let json: Vec<ActionJson> = read_json(path)?;
    Ok(json.iter().map(Action::from).collect())
}

/// Read any JSON artifact.
///
/// # Errors
/// Returns [`ServiceError::Io`] or [`ServiceError::Malformed`] on failure.
pub fn read_json<T: for<'de> serde::Deserialize<'de>>(path: &Path) -> Result<T, ServiceError> {
    let raw = fs::read_to_string(path).map_err(|e| ServiceError::io(path, format!("read: {e}")))?;
    serde_json::from_str(&raw).map_err(|e| ServiceError::malformed(path, e))
}

/// Write any JSON artifact, pretty-printed.
///
/// # Errors
/// Returns [`ServiceError::Io`] or [`ServiceError::Malformed`] on failure.
pub fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), ServiceError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| ServiceError::malformed(path, format!("serialise: {e}")))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| ServiceError::io(parent, e))?;
        }
    }
    fs::write(path, text).map_err(|e| ServiceError::io(path, format!("write: {e}")))
}

/// Resolve an [`AuthorityKey`] into a usable authority.
///
/// # Errors
/// Returns [`ServiceError::Authority`] when the key cannot be produced or read.
pub fn resolve_authority(key: &AuthorityKey) -> Result<ResolvedAuthority, ServiceError> {
    match key {
        AuthorityKey::Seed(seed) => Ok(ResolvedAuthority {
            authority: Authority::from_seed(*seed),
            used_demo_key: true,
            created_key_file: false,
            warning: Some(format!(
                "signing with DEMO seed {seed}: that key is reproducible from the seed alone, so \
                 this policy is forgeable by anyone. Use a key file for anything real."
            )),
        }),
        AuthorityKey::Bytes(bytes) => Ok(ResolvedAuthority {
            authority: Authority::from_secret_bytes(bytes),
            used_demo_key: false,
            created_key_file: false,
            warning: None,
        }),
        AuthorityKey::File(path) => match fs::read_to_string(path) {
            Ok(text) => {
                let bytes = hex::decode(text.trim()).map_err(|e| {
                    ServiceError::Authority(format!("{}: not hex: {e}", path.display()))
                })?;
                let secret = Authority::secret_from_slice(&bytes)
                    .map_err(|e| ServiceError::Authority(e.to_string()))?;
                Ok(ResolvedAuthority {
                    authority: Authority::from_secret_bytes(&secret),
                    used_demo_key: false,
                    created_key_file: false,
                    warning: permissions_warning(path),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let auth =
                    Authority::generate().map_err(|e| ServiceError::Authority(e.to_string()))?;
                write_secret_file(path, &auth.secret_bytes())?;
                Ok(ResolvedAuthority {
                    authority: auth,
                    used_demo_key: false,
                    created_key_file: true,
                    warning: None,
                })
            }
            Err(e) => Err(ServiceError::Authority(format!(
                "read {}: {e}",
                path.display()
            ))),
        },
    }
}

/// Warn when a key file is group- or world-readable.
///
/// Not fatal: an operator may have other protections. But silence here would
/// hide a real exposure, so the message is handed back to the host.
fn permissions_warning(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Some(format!(
                    "{} has mode {mode:o}; an authority key should be 0600 (group or world access \
                     lets another account forge policies)",
                    path.display()
                ));
            }
        }
        None
    }
    #[cfg(not(unix))]
    {
        // Windows ACLs are not expressible through std's permission bits; the
        // operator owns file protection there.
        let _ = path;
        None
    }
}

/// Write secret bytes as hex with restrictive permissions.
///
/// `create_new` so an existing key is never silently replaced: replacing it
/// would invalidate every policy already signed with it.
fn write_secret_file(path: &Path, secret: &[u8; SECRET_KEY_BYTES]) -> Result<(), ServiceError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 0600, applied at open time so the file is never briefly world-readable.
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| ServiceError::io(path, e))?;
    f.write_all(hex::encode(secret).as_bytes())
        .map_err(|e| ServiceError::io(path, e))?;
    f.sync_all().map_err(|e| ServiceError::io(path, e))
}
