//! `zkagent` CLI — a shell over the service layer.
//!
//! ```text
//! zkagent setup   --seed 7 --out keys/
//! zkagent policy  --max-amount 1000 --max-per-action 300 --expires-at 2000 \
//!                 --chain-id 1 --targets 3,7,9 --authority-key authority.hex --out policy.json
//! zkagent prove   --keys keys/ --policy policy.json --receipt receipt.json \
//!                 --actions actions.json --out proof.json
//! zkagent verify  --keys keys/ --policy policy.json --receipt receipt.json \
//!                 --proof proof.json --now 1600 [--seen ids.json]
//! ```
//!
//! Exit codes: `0` = accept / success, `1` = verification rejected, `2` = usage
//! or I/O error. A verifier in a pipeline can therefore branch on the status
//! without parsing text.
//!
//! # This crate contains no protocol logic
//!
//! Every rule — policy validation, the replay gate, fail-closed state, key
//! handling — lives in `zkagent-service`. This file parses arguments and
//! prints. That split is what lets the same behaviour be embedded in a Tauri
//! app or driven over MCP without a second implementation.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use zkagent_service::{AuthorityKey, PolicySpec, Verdict};

#[derive(Parser)]
#[command(
    name = "zkagent",
    version,
    about = "Zero-knowledge attestation of AI agent executions",
    long_about = "Prove that an AI agent's execution stayed inside a human-signed policy \
                  without revealing which actions it took."
)]
struct Cli {
    /// Emit a machine-readable JSON document instead of the human line.
    ///
    /// A verdict is a decision an agent acts on, so it must not require parsing
    /// English. Exit codes are unchanged: 0 accept, 1 reject, 2 could not verify.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the version, the artifact format and the commit this binary was built from.
    Version,
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
        /// Optional disclosure artifact to check against this receipt.
        ///
        /// The proof already establishes that some set of actions satisfies the
        /// policy. A disclosure adds a narrower claim: this particular digest is
        /// in that set. If the disclosure fails, the command exits 1 even when
        /// the proof itself is valid — a bundle can be honest and the extra
        /// claim false, and the verdict must not cover for the extra claim.
        #[arg(long)]
        disclosure: Option<PathBuf>,
    },
    /// Reveal one action's digest, plus the path proving it is in the attested set.
    ///
    /// The proof never reveals which actions ran. This publishes exactly one of
    /// them: the digest at `--index` and the three sibling hashes on its way to
    /// the root. The other seven stay hidden.
    Disclose {
        /// Private actions (only the disclosed digest is written out).
        #[arg(long)]
        actions: PathBuf,
        /// Which action slot to reveal (0-based, up to the number of actions).
        #[arg(long)]
        index: usize,
        /// Receipt whose trace_root the disclosure proves against.
        #[arg(long)]
        receipt: PathBuf,
        /// Where to write the disclosure artifact.
        #[arg(long)]
        out: PathBuf,
    },
    /// Publish a bundle to a content-addressed block store.
    ///
    /// Hashes the four artifacts into a manifest and files each block under its
    /// CID. Nothing is uploaded anywhere: point `--blocks` at a directory that a
    /// node serves (`ipfs add -r`), and the CIDs are portable to any IPFS node.
    Publish {
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
        /// Private actions (needed only to measure the circuit shape; never published).
        #[arg(long)]
        actions: PathBuf,
        /// Where to write the manifest.
        #[arg(long)]
        out: PathBuf,
        /// Directory to store the blocks in, one file per CID.
        #[arg(long)]
        blocks: PathBuf,
    },
    /// Verify a bundle by its manifest, fetching each artifact by CID.
    VerifyBundle {
        /// The manifest (attestation.json).
        #[arg(long)]
        manifest: PathBuf,
        /// Directory holding the blocks.
        #[arg(long)]
        blocks: PathBuf,
        /// The verifier's current time, for the future-dating check.
        #[arg(long)]
        now: Option<u64>,
        /// Persistent set of accepted execution ids.
        #[arg(long)]
        seen: Option<PathBuf>,
    },
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
    let json_out = cli.json;
    match cli.command {
        Command::Version => {
            // Three different things are called "version" in this project and mixing them
            // up is how a format mismatch becomes a mystery: the crate version (what code),
            // FORMAT_VERSION (what artifacts it can read) and the commit (which tree).
            let commit = option_env!("ZKAGENT_GIT_SHA").unwrap_or("unknown");
            let dirty = option_env!("ZKAGENT_GIT_DIRTY").unwrap_or("0") == "1";
            let format = zkagent_service::FORMAT_VERSION;
            if json_out {
                // Built, not formatted by hand: a hand-rolled JSON string is one unescaped
                // character away from a document a harness cannot parse.
                let doc = serde_json::json!({
                    "name": "zkagent",
                    "version": env!("CARGO_PKG_VERSION"),
                    "format": format,
                    "commit": commit,
                    "dirty": dirty,
                });
                println!("{doc}");
            } else {
                println!(
                    "zkagent {} (artifact format {}) commit {}{}",
                    env!("CARGO_PKG_VERSION"),
                    format,
                    commit,
                    if dirty { " (dirty)" } else { "" }
                );
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Setup { seed, out } => {
            let outcome = zkagent_service::setup(&out, seed).map_err(|e| e.to_string())?;
            println!(
                "setup complete: {} (vk {} B, pk {} B)",
                outcome.keys_dir.display(),
                outcome.verifying_key_bytes,
                outcome.proving_key_bytes
            );
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
            // Refuse to invent an authorisation root. A silent default here is
            // a silent vulnerability: a key derived from a fixed seed is
            // reproducible by anyone, which makes the policy forgeable.
            let key =
                match (authority_key, seed) {
                    (Some(path), _) => AuthorityKey::File(path),
                    (None, Some(s)) => AuthorityKey::Seed(s),
                    (None, None) => return Err(
                        "policy: no authorisation key. Pass --authority-key <path> (created with \
                         the OS CSPRNG if missing) or --seed <n> for a reproducible demo key."
                            .to_string(),
                    ),
                };

            let spec = PolicySpec {
                max_amount,
                max_per_action,
                expires_at,
                chain_id,
                targets,
            };

            let authorized =
                zkagent_service::authorize(&out, &spec, &key).map_err(|e| e.to_string())?;

            if authorized.created_key_file {
                eprintln!(
                    "authority key created — keep it private, it authorises every policy signed \
                     with it"
                );
            }
            if let Some(warning) = authorized.warning {
                eprintln!("warning: {warning}");
            }

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
            let receipt_path = receipt.clone();
            let receipt = zkagent_service::read_receipt(&receipt).map_err(|e| e.to_string())?;
            let actions = zkagent_service::read_actions(&actions).map_err(|e| e.to_string())?;
            let proven = zkagent_service::prove(&keys, &policy, &receipt, &actions)
                .map_err(|e| e.to_string())?;
            zkagent_service::write_json(&out, &proven.proof).map_err(|e| e.to_string())?;
            // The receipt is an output of proving, not only an input: the proof
            // commits to the trace root over the private digests, and a verifier
            // recomputes that commitment from the receipt it is given. Writing
            // the completed receipt back is what keeps an honest run
            // self-consistent without making the caller hash a witness it cannot
            // see.
            zkagent_service::write_json(
                &receipt_path,
                &zkagent_service::ReceiptJson::from(&proven.receipt),
            )
            .map_err(|e| e.to_string())?;
            println!("proof written: {}", out.display());
            println!("receipt:       {}", receipt_path.display());
            println!("trace root:    {}", hex::encode(proven.receipt.trace_root));
            Ok(ExitCode::SUCCESS)
        }

        Command::Publish {
            keys,
            policy,
            receipt,
            proof,
            actions,
            out,
            blocks,
        } => {
            let actions = zkagent_service::read_actions(&actions).map_err(|e| e.to_string())?;

            let published =
                zkagent_service::publish(&keys, &policy, &receipt, &proof, &actions, now_unix())
                    .map_err(|e| e.to_string())?;

            // File each block under its own CID. `put` recomputes the hash, so a
            // block cannot be stored under a name it does not match.
            let store = zkagent_service::DirSource::new(&blocks);
            for (cid, bytes) in &published.blocks {
                let stored = store.put(bytes).map_err(|e| e.to_string())?;
                if &stored != cid {
                    return Err(format!(
                        "internal: block {stored} does not match the manifest's {cid}"
                    ));
                }
            }

            zkagent_service::write_json(&out, &published.manifest).map_err(|e| e.to_string())?;

            println!("manifest:  {}", out.display());
            println!(
                "blocks:    {} blocks in {}",
                published.blocks.len(),
                blocks.display()
            );
            println!("vk:        {}", published.manifest.circuit.vk.cid);
            println!("policy:    {}", published.manifest.policy.cid);
            println!("receipt:   {}", published.manifest.receipt.cid);
            println!("proof:     {}", published.manifest.proof.cid);
            println!(
                "circuit:   {} constraints, {} public inputs, format v{}",
                published.manifest.circuit.constraints,
                published.manifest.circuit.public_inputs,
                published.manifest.circuit.format_version
            );
            Ok(ExitCode::SUCCESS)
        }

        Command::VerifyBundle {
            manifest,
            blocks,
            now,
            seen,
        } => {
            let manifest: zkagent_service::AttestationManifest =
                zkagent_service::read_json(&manifest).map_err(|e| e.to_string())?;
            let store = zkagent_service::DirSource::new(&blocks);

            let outcome = zkagent_service::verify_bundle(&manifest, &store, now, seen.as_deref())
                .map_err(|e| e.to_string())?;

            Ok(emit_verdict(json_out, &outcome.verdict, None))
        }

        Command::Verify {
            keys,
            policy,
            receipt,
            proof,
            now,
            seen,
            disclosure,
        } => {
            // Not an error: expiry is enforced inside the circuit, so this only
            // drops the future-dating check. But a verifier that forgets the flag
            // should be told, rather than silently running with one fewer check
            // than it believes it has.
            if now.is_none() {
                eprintln!(
                    "warning: --now not supplied, so the future-dating check is skipped \
                     (the circuit still enforces completed_at < expires_at)"
                );
            }

            let receipt = zkagent_service::read_receipt(&receipt).map_err(|e| e.to_string())?;
            let proof: zkagent_service::ProofBytes =
                zkagent_service::read_json(&proof).map_err(|e| e.to_string())?;

            let outcome =
                zkagent_service::verify(&keys, &policy, &receipt, &proof, now, seen.as_deref())
                    .map_err(|e| e.to_string())?;

            // The disclosure is a second, narrower claim. It is checked only when the proof
            // itself was accepted, and it can still fail: a bundle can be honest about its
            // totals and the extra claim about one action can be false. Refusing here, with a
            // separate line, keeps the two verdicts from being confused for each other.
            if let Some(path) = disclosure {
                let claim: zkagent_service::Disclosure =
                    zkagent_service::read_json(&path).map_err(|e| e.to_string())?;
                match zkagent_service::check_disclosure(&claim, &receipt) {
                    Ok(()) => eprintln!(
                        "disclosure ACCEPT: slot {} with digest {} is in the attested set",
                        claim.index, claim.leaf_digest
                    ),
                    Err(why) => {
                        eprintln!("disclosure REJECT: {why}");
                        return Ok(ExitCode::from(1));
                    }
                }
            }

            Ok(emit_verdict(
                json_out,
                &outcome.verdict,
                Some(receipt.execution_id),
            ))
        }

        Command::Disclose {
            actions,
            index,
            receipt,
            out,
        } => {
            let receipt = zkagent_service::read_receipt(&receipt).map_err(|e| e.to_string())?;
            let actions = zkagent_service::read_actions(&actions).map_err(|e| e.to_string())?;
            let disclosure = zkagent_service::disclose(&actions, index, &receipt)?;
            zkagent_service::write_json(&out, &disclosure).map_err(|e| e.to_string())?;
            println!(
                "disclosed: slot {} digest {} -> {}",
                disclosure.index,
                disclosure.leaf_digest,
                out.display()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Prints the verdict the caller asked for and returns the matching exit code.
///
/// The exit codes are the original contract — 0 accept, 1 reject — so a shell
/// script that predates `--json` keeps working. The JSON document adds the stable
/// `reason_code`, the execution it is about, and the artifact format, because a
/// harness must not have to parse English to decide what to do next.
fn emit_verdict(json_out: bool, verdict: &Verdict, execution_id: Option<u64>) -> ExitCode {
    let accepted = matches!(verdict, Verdict::Accept);
    match (json_out, verdict) {
        (true, Verdict::Accept) => println!(
            "{}",
            serde_json::json!({
                "verdict": "accept",
                "reason_code": serde_json::Value::Null,
                "reason": serde_json::Value::Null,
                "execution_id": execution_id,
                "format": zkagent_service::FORMAT_VERSION,
            })
        ),
        (true, Verdict::Reject(reason)) => println!(
            "{}",
            serde_json::json!({
                "verdict": "reject",
                "reason_code": reason.code(),
                "reason": reason.to_string(),
                "execution_id": execution_id,
                "format": zkagent_service::FORMAT_VERSION,
            })
        ),
        (false, Verdict::Accept) => println!("ACCEPT"),
        (false, Verdict::Reject(reason)) => println!("REJECT: {reason}"),
    }
    if accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
