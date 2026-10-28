//! `zkagent` CLI — setup, authorise a policy, prove an execution, verify it.
//!
//! ```text
//! zkagent setup   --seed 7 --out keys/
//! zkagent policy  --max-amount 1000 --max-per-action 300 --expires-at 2000 \
//!                 --chain-id 1 --targets 3,7,9 --seed 99 --out policy.json
//! zkagent prove   --keys keys/ --policy policy.json --receipt receipt.json \
//!                 --actions actions.json --out proof.json
//! zkagent verify  --keys keys/ --policy policy.json --receipt receipt.json \
//!                 --proof proof.json --now 1600 [--seen ids.json]
//! ```
//!
//! `--seen` keeps a persistent set of accepted execution ids and refuses a
//! receipt whose id is already present. Without it a verifier accepts the same
//! proof repeatedly: a Groth16 proof attests to an execution, not to freshness.
//!
//! Exit codes: `0` = accept / success, `1` = verification rejected, `2` = usage
//! or I/O error. A verifier in a pipeline can therefore branch on the status
//! without parsing text.

#![deny(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use zkagent_core::{Action, Authority, Policy, Receipt, SeenExecutions};
use zkagent_proofs::prover::{prove, setup, ProofBytes};
use zkagent_verifier::{verify, Verdict};

#[derive(Parser)]
#[command(
    name = "zkagent",
    about = "Zero-knowledge attestation of AI agent executions",
    long_about = "Prove that an AI agent's execution stayed inside a human-signed policy \
                  without revealing which actions it took."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the circuit-specific trusted setup and write the key pair.
    Setup {
        /// Seed for the setup RNG. Fixed seeds are for tests only.
        #[arg(long, default_value_t = 7)]
        seed: u64,
        /// Directory to write `vk.bin` and `pk.bin` into.
        #[arg(long)]
        out: PathBuf,
    },
    /// Create and sign a policy.
    Policy {
        /// Total cap.
        #[arg(long)]
        max_amount: u64,
        /// Per-action cap.
        #[arg(long)]
        max_per_action: u64,
        /// Expiry (unix seconds, exclusive).
        #[arg(long)]
        expires_at: u64,
        /// Chain id.
        #[arg(long)]
        chain_id: u64,
        /// Comma-separated allow-list of target ids.
        #[arg(long, value_delimiter = ',')]
        targets: Vec<u64>,
        /// Path to the 32-byte Ed25519 authority seed, hex-encoded.
        ///
        /// Created with the OS CSPRNG if it does not exist. This is the
        /// production path: the key authorises every policy, so it must live in
        /// a protected file (mode 0600 is set on creation) or a KMS.
        #[arg(long)]
        authority_key: Option<PathBuf>,
        /// DEMO ONLY: derive the authority key from a 64-bit seed.
        ///
        /// Reproducible by design, therefore forgeable by anyone who guesses the
        /// seed. Present so tests and the walkthrough in the README are
        /// deterministic; never use it for a policy that matters.
        #[arg(long, conflicts_with = "authority_key")]
        seed: Option<u64>,
        /// Output path for the signed policy.
        #[arg(long)]
        out: PathBuf,
    },
    /// Prove that a set of actions explains a receipt inside a policy.
    Prove {
        /// Key directory produced by `setup`.
        #[arg(long)]
        keys: PathBuf,
        /// Signed policy file.
        #[arg(long)]
        policy: PathBuf,
        /// Receipt file.
        #[arg(long)]
        receipt: PathBuf,
        /// Actions file (the private witness).
        #[arg(long)]
        actions: PathBuf,
        /// Output path for the proof artifact.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a proof artifact.
    Verify {
        /// Key directory produced by `setup`.
        #[arg(long)]
        keys: PathBuf,
        /// Signed policy file.
        #[arg(long)]
        policy: PathBuf,
        /// Receipt file.
        #[arg(long)]
        receipt: PathBuf,
        /// Proof artifact.
        #[arg(long)]
        proof: PathBuf,
        /// The verifier's current time, for the future-dating check.
        #[arg(long)]
        now: Option<u64>,
        /// Persistent set of accepted execution ids.
        ///
        /// With this flag a receipt whose execution id was already accepted is
        /// rejected as a replay, and a newly accepted id is recorded. Omit it to
        /// verify a proof statelessly (one-shot checks, tests).
        #[arg(long)]
        seen: Option<PathBuf>,
    },
}

/// On-disk signed policy.
#[derive(Serialize, Deserialize)]
struct SignedPolicyFile {
    policy: PolicyJson,
    /// Hex-encoded compressed authority public key.
    authority_pubkey: String,
    /// Hex-encoded compressed Schnorr signature.
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct PolicyJson {
    max_amount: u64,
    max_per_action: u64,
    expires_at: u64,
    chain_id: u64,
    allowed_targets: Vec<u64>,
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
    fn to_policy(&self) -> Result<Policy, String> {
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

#[derive(Serialize, Deserialize)]
struct ReceiptJson {
    total_amount: u64,
    action_count: u32,
    completed_at: u64,
    chain_id: u64,
    execution_id: u64,
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

#[derive(Serialize, Deserialize)]
struct ActionJson {
    target: u64,
    amount: u64,
    trace_digest: u64,
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| format!("serialise: {e}"))?;
    fs::write(path, text).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Load the authority key at `path`, or create it with the OS CSPRNG.
///
/// The key authorises every policy this operator signs, so it is created
/// `0600`, written with `create_new` (never silently overwriting an existing
/// key — that would invalidate every policy already signed), and synced.
fn load_or_create_authority(path: &Path) -> Result<Authority, String> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let bytes = hex::decode(text.trim())
                .map_err(|e| format!("authority key {}: not hex: {e}", path.display()))?;
            let secret = Authority::secret_from_slice(&bytes).map_err(|e| e.to_string())?;
            warn_if_readable_by_others(path);
            Ok(Authority::from_secret_bytes(&secret))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let auth = Authority::generate().map_err(|e| e.to_string())?;
            write_secret_file(path, &auth.secret_bytes())?;
            eprintln!(
                "authority key created: {} — keep it private, it authorises every policy \
                 signed with it",
                path.display()
            );
            Ok(auth)
        }
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

/// Write secret bytes as hex with restrictive permissions.
fn write_secret_file(path: &Path, secret: &[u8; 32]) -> Result<(), String> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 0600: owner read/write. Set at open time, so the file is never
        // world-readable even briefly.
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    f.write_all(hex::encode(secret).as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    f.sync_all()
        .map_err(|e| format!("sync {}: {e}", path.display()))
}

/// Warn when a key file is group- or world-readable. Not fatal: an operator may
/// legitimately have it on a volume with other protections, but silence here
/// would hide a real exposure.
fn warn_if_readable_by_others(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "warning: {} has mode {mode:o}; an authority key should be 0600 \
                     (group/world access lets another account forge policies)",
                    path.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Windows ACLs are not expressible through std's permission bits; the
        // operator owns file protection there.
        let _ = path;
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let cli = Cli::parse();
    match cli.command {
        Command::Setup { seed, out } => {
            fs::create_dir_all(&out).map_err(|e| format!("mkdir {}: {e}", out.display()))?;
            let keys = setup(seed).map_err(|e| e.to_string())?;
            fs::write(
                out.join("vk.bin"),
                keys.verifying_key_bytes().map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("write vk: {e}"))?;
            fs::write(
                out.join("pk.bin"),
                keys.proving_key_bytes().map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("write pk: {e}"))?;
            println!("setup complete: {}", out.display());
            Ok(ExitCode::SUCCESS)
        }

        Command::Policy {
            max_amount,
            max_per_action,
            expires_at,
            chain_id,
            targets,
            authority_key,
            seed,
            out,
        } => {
            let policy = Policy::new(max_amount, max_per_action, expires_at, chain_id, targets)
                .map_err(|e| e.to_string())?;

            // Refuse to invent an authorisation root. Previously the key came
            // from a default `--seed 99`, so every policy this tool produced was
            // signed by the same reproducible key and anyone could forge one.
            // Making the choice explicit is the whole point: a silent default
            // here is a silent vulnerability.
            let auth =
                match (authority_key, seed) {
                    (Some(path), _) => load_or_create_authority(&path)?,
                    (None, Some(s)) => {
                        eprintln!(
                        "warning: signing with DEMO seed {s}. That key is reproducible from the \
                         seed alone, so this policy is forgeable by anyone. Use \
                         --authority-key <path> for anything real."
                    );
                        Authority::from_seed(s)
                    }
                    (None, None) => return Err(
                        "policy: no authorisation key. Pass --authority-key <path> (created with \
                         the OS CSPRNG if missing) or --seed <n> for a reproducible demo key."
                            .to_string(),
                    ),
                };

            let sig = auth.sign_policy(&policy);

            let pubkey = auth.public_key().as_bytes().to_vec();

            let file = SignedPolicyFile {
                policy: PolicyJson::from(&policy),
                authority_pubkey: hex::encode(pubkey),
                signature: hex::encode(&sig.bytes),
            };
            write_json(&out, &file)?;
            println!("policy written: {}", out.display());
            Ok(ExitCode::SUCCESS)
        }

        Command::Prove {
            keys,
            policy,
            receipt,
            actions,
            out,
        } => {
            let signed: SignedPolicyFile = read_json(&policy)?;
            let policy = signed.policy.to_policy()?;
            let receipt_json: ReceiptJson = read_json(&receipt)?;
            let receipt = Receipt::from(&receipt_json);
            let actions: Vec<ActionJson> = read_json(&actions)?;
            let actions: Vec<Action> = actions
                .into_iter()
                .map(|a| Action {
                    target: a.target,
                    amount: a.amount,
                    trace_digest: a.trace_digest,
                })
                .collect();

            let pk_bytes =
                fs::read(keys.join("pk.bin")).map_err(|e| format!("read pk.bin: {e}"))?;
            let vk_bytes =
                fs::read(keys.join("vk.bin")).map_err(|e| format!("read vk.bin: {e}"))?;
            let proving = zkagent_proofs::prover::proving_key_from_bytes(&pk_bytes)
                .map_err(|e| e.to_string())?;
            let verifying = zkagent_proofs::prover::verifying_key_from_bytes(&vk_bytes)
                .map_err(|e| e.to_string())?;
            let keys = zkagent_proofs::prover::Keys { proving, verifying };

            let proof: ProofBytes =
                prove(&keys, &policy, &receipt, &actions).map_err(|e| e.to_string())?;
            write_json(&out, &proof)?;
            println!("proof written: {}", out.display());
            Ok(ExitCode::SUCCESS)
        }

        Command::Verify {
            keys,
            policy,
            receipt,
            proof,
            now,
            seen,
        } => {
            let signed: SignedPolicyFile = read_json(&policy)?;
            let policy = signed.policy.to_policy()?;
            let receipt_json: ReceiptJson = read_json(&receipt)?;
            let receipt = Receipt::from(&receipt_json);
            let proof: ProofBytes = read_json(&proof)?;
            let vk_bytes =
                fs::read(keys.join("vk.bin")).map_err(|e| format!("read vk.bin: {e}"))?;
            let pubkey =
                hex::decode(&signed.authority_pubkey).map_err(|e| format!("decode pubkey: {e}"))?;
            let sig = hex::decode(&signed.signature).map_err(|e| format!("decode sig: {e}"))?;

            // Replay gate. Loaded BEFORE verification so a corrupt state file is
            // a hard error rather than an unnoticed empty set — silently
            // starting fresh would make "truncate the file" a replay attack.
            let mut seen_set = match seen {
                Some(path) => Some(SeenExecutions::load(&path).map_err(|e| e.to_string())?),
                None => None,
            };

            if let Some(s) = &seen_set {
                if s.contains(receipt.execution_id) {
                    println!(
                        "REJECT: execution id {} was already accepted (replay)",
                        receipt.execution_id
                    );
                    return Ok(ExitCode::from(1));
                }
            }

            match verify(&vk_bytes, &policy, &receipt, &proof, &pubkey, &sig, now) {
                Verdict::Accept => {
                    // Record before announcing: an acceptance the verifier
                    // cannot remember is a replay waiting to happen, so a failed
                    // write must not be reported as ACCEPT.
                    if let Some(s) = seen_set.as_mut() {
                        match s.record(receipt.execution_id) {
                            Ok(true) => {}
                            Ok(false) => {
                                // Another writer recorded it between the check
                                // and the verdict: treat as the replay it is.
                                println!(
                                    "REJECT: execution id {} was already accepted (replay)",
                                    receipt.execution_id
                                );
                                return Ok(ExitCode::from(1));
                            }
                            Err(e) => {
                                return Err(format!(
                                    "verified, but could not record the execution id, so this \
                                     acceptance is refused: {e}"
                                ))
                            }
                        }
                    }
                    println!("ACCEPT");
                    Ok(ExitCode::SUCCESS)
                }
                Verdict::Reject(reason) => {
                    println!("REJECT: {reason}");
                    Ok(ExitCode::from(1))
                }
            }
        }
    }
}
