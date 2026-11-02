//! The CLI must be usable by a program, not only by a person at a terminal.
//!
//! `verify` decides whether an agent's execution is accepted. Today that verdict
//! leaves the process as the string `ACCEPT` or `REJECT: <English>`, so a harness
//! has to parse prose to learn *why* it was refused. `--json` makes the verdict a
//! document: a stable `verdict`, a stable `reason_code`, and the prose kept for
//! humans.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn zkagent(args: &[&str], dir: &Path) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zkagent"));
    cmd.args(args).current_dir(dir);
    cmd.output().expect("run zkagent")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

/// Build one honest, verifiable execution in `dir` and return the artifact paths.
fn prepared(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let keys = dir.join("keys");
    let policy = dir.join("policy.json");
    let proof = dir.join("proof.json");

    let o = zkagent(
        &["setup", "--seed", "7", "--out", keys.to_str().unwrap()],
        dir,
    );
    assert_eq!(code(&o), 0, "setup failed: {}", stderr(&o));

    let o = zkagent(
        &[
            "policy",
            "--max-amount",
            "1000",
            "--max-per-action",
            "300",
            "--expires-at",
            "2000",
            "--chain-id",
            "1",
            "--targets",
            "3,7,9",
            "--seed",
            "99",
            "--out",
            policy.to_str().unwrap(),
        ],
        dir,
    );
    assert_eq!(code(&o), 0, "policy failed: {}", stderr(&o));

    let receipt = dir.join("receipt.json");
    std::fs::write(
        &receipt,
        r#"{"total_amount":400,"action_count":2,"completed_at":1500,"chain_id":1,"execution_id":1001}"#,
    )
    .unwrap();
    let actions = dir.join("actions.json");
    std::fs::write(
        &actions,
        r#"[{"target":3,"amount":250,"trace_digest":11},{"target":7,"amount":150,"trace_digest":22}]"#,
    )
    .unwrap();

    let o = zkagent(
        &[
            "prove",
            "--keys",
            keys.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--receipt",
            receipt.to_str().unwrap(),
            "--actions",
            actions.to_str().unwrap(),
            "--out",
            proof.to_str().unwrap(),
        ],
        dir,
    );
    assert_eq!(code(&o), 0, "prove failed: {}", stderr(&o));

    (keys, policy, receipt, proof)
}

fn verify_json(dir: &Path, keys: &Path, policy: &Path, receipt: &Path, proof: &Path) -> Output {
    zkagent(
        &[
            "verify",
            "--json",
            "--keys",
            keys.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--receipt",
            receipt.to_str().unwrap(),
            "--proof",
            proof.to_str().unwrap(),
            "--now",
            "1600",
        ],
        dir,
    )
}

#[test]
fn a_json_accept_is_a_document_and_still_exits_zero() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (keys, policy, receipt, proof) = prepared(dir.path());

    let out = verify_json(dir.path(), &keys, &policy, &receipt, &proof);
    let text = stdout(&out);

    assert_eq!(code(&out), 0, "stdout={text} stderr={}", stderr(&out));

    let doc: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {text}"));
    assert_eq!(doc["verdict"], "accept");
    assert_eq!(doc["reason_code"], serde_json::Value::Null);
    assert_eq!(
        doc["format"], 2,
        "the artifact format version must be named"
    );
    assert_eq!(
        doc["execution_id"], 1001,
        "the verdict must name the execution it is about"
    );
}

#[test]
fn a_json_reject_names_the_reason_as_a_code_not_a_sentence() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (keys, policy, receipt, proof) = prepared(dir.path());

    // An honest proof for an inflated total: the receipt no longer matches the
    // public inputs the circuit produced, which is the rejection the docs
    // describe for `total_amount: 999`.
    std::fs::write(
        &receipt,
        r#"{"total_amount":999,"action_count":2,"completed_at":1500,"chain_id":1,"execution_id":1001}"#,
    )
    .unwrap();

    let out = verify_json(dir.path(), &keys, &policy, &receipt, &proof);
    let text = stdout(&out);

    assert_eq!(code(&out), 1, "a rejection exits 1: stdout={text}");
    let doc: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {text}"));
    assert_eq!(doc["verdict"], "reject");
    assert_eq!(doc["reason_code"], "public_input_mismatch");
    assert!(
        doc["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "the prose reason must still be there for a human"
    );
}

#[test]
fn without_json_the_human_line_is_unchanged() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (keys, policy, receipt, proof) = prepared(dir.path());

    let out = zkagent(
        &[
            "verify",
            "--keys",
            keys.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--receipt",
            receipt.to_str().unwrap(),
            "--proof",
            proof.to_str().unwrap(),
            "--now",
            "1600",
        ],
        dir.path(),
    );

    assert_eq!(code(&out), 0);
    assert_eq!(stdout(&out).trim(), "ACCEPT");
}
