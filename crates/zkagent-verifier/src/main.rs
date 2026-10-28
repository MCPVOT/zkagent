//! `zkagent` CLI — setup, authorise a policy, prove an execution, verify it.
//!
//! ```text
//! zkagent setup   --seed 7 --out keys/
//! zkagent policy  --max-amount 1000 --max-per-action 300 --expires-at 2000 \
//!                 --chain-id 1 --targets 3,7,9 --seed 99 --out policy.json
//! zkagent prove   --keys keys/ --policy policy.json --receipt receipt.json \
//!                 --actions actions.json --out proof.json
//! zkagent verify  --keys keys/ --policy policy.json --receipt receipt.json \
//!                 --proof proof.json --now 1600
//! ```
//!
//! Exit codes: `0` = accept / success, `1` = verification rejected, `2` = usage
//! or I/O error. A verifier in a pipeline can therefore branch on the status
//! without parsing text.

#![deny(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use zkagent_core::{Action, Authority, Policy, Receipt};
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
        /// Demo authority key seed. Production must persist a CSPRNG key.
        #[arg(long, default_value_t = 99)]
        seed: u64,
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
}

impl From<&Receipt> for ReceiptJson {
    fn from(r: &Receipt) -> Self {
        Self {
            total_amount: r.total_amount,
            action_count: r.action_count,
            completed_at: r.completed_at,
            chain_id: r.chain_id,
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
            fs::write(out.join("vk.bin"), keys.verifying_key_bytes().map_err(|e| e.to_string())?)
                .map_err(|e| format!("write vk: {e}"))?;
            fs::write(out.join("pk.bin"), keys.proving_key_bytes().map_err(|e| e.to_string())?)
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
            seed,
            out,
        } => {
            let policy = Policy::new(max_amount, max_per_action, expires_at, chain_id, targets)
                .map_err(|e| e.to_string())?;
            let auth = Authority::from_seed(seed);
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

            let pk_bytes = fs::read(keys.join("pk.bin"))
                .map_err(|e| format!("read pk.bin: {e}"))?;
            let vk_bytes = fs::read(keys.join("vk.bin"))
                .map_err(|e| format!("read vk.bin: {e}"))?;
            let proving = zkagent_proofs::prover::proving_key_from_bytes(&pk_bytes)
                .map_err(|e| e.to_string())?;
            let verifying = zkagent_proofs::prover::verifying_key_from_bytes(&vk_bytes)
                .map_err(|e| e.to_string())?;
            let keys = zkagent_proofs::prover::Keys {
                proving,
                verifying,
            };

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
        } => {
            let signed: SignedPolicyFile = read_json(&policy)?;
            let policy = signed.policy.to_policy()?;
            let receipt_json: ReceiptJson = read_json(&receipt)?;
            let receipt = Receipt::from(&receipt_json);
            let proof: ProofBytes = read_json(&proof)?;
            let vk_bytes = fs::read(keys.join("vk.bin"))
                .map_err(|e| format!("read vk.bin: {e}"))?;
            let pubkey = hex::decode(&signed.authority_pubkey)
                .map_err(|e| format!("decode pubkey: {e}"))?;
            let sig = hex::decode(&signed.signature).map_err(|e| format!("decode sig: {e}"))?;

            match verify(&vk_bytes, &policy, &receipt, &proof, &pubkey, &sig, now) {
                Verdict::Accept => {
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
