//! Selective disclosure must accept the honest artifact and refuse every mutation of it.
//!
//! The property: a disclosure is a claim about *one* leaf, and it is only true if that leaf
//! and its siblings walk to the root the receipt publishes. These tests drive the real
//! binary, because the CLI is where the claim is made and where a harness reads the answer.

use std::path::Path;
use std::process::{Command, Output};

fn zkagent(args: &[&str], dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zkagent"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("the binary under test should run")
}

fn ok(args: &[&str], dir: &Path) -> String {
    let out = zkagent(args, dir);
    assert!(
        out.status.success(),
        "expected success for {args:?}, got {:?}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// A complete execution: keys, policy, actions, a receipt whose root the prover filled in,
/// and a proof. Small enough to run in a test and real enough to be the shipped path.
fn execution(dir: &Path) {
    ok(&["setup", "--seed", "7", "--out", "keys"], dir);
    ok(
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
            "--authority-key",
            "authority.hex",
            "--out",
            "policy.json",
        ],
        dir,
    );
    std::fs::write(
        dir.join("receipt.json"),
        r#"{"total_amount":400,"action_count":2,"completed_at":1500,"chain_id":1,
            "execution_id":1001,
            "trace_root":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("actions.json"),
        r#"[{"target":3,"amount":250,"trace_digest":11},{"target":7,"amount":150,"trace_digest":22}]"#,
    )
    .unwrap();
    ok(
        &[
            "prove",
            "--keys",
            "keys",
            "--policy",
            "policy.json",
            "--receipt",
            "receipt.json",
            "--actions",
            "actions.json",
            "--out",
            "proof.json",
        ],
        dir,
    );
}

fn verify_args(disclosure: Option<&str>) -> Vec<&str> {
    let mut args = vec![
        "verify",
        "--keys",
        "keys",
        "--policy",
        "policy.json",
        "--receipt",
        "receipt.json",
        "--proof",
        "proof.json",
        "--now",
        "1600",
    ];
    if let Some(path) = disclosure {
        args.push("--disclosure");
        args.push(path);
    }
    args
}

#[test]
fn an_honest_disclosure_is_accepted_and_the_proof_still_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    execution(dir);

    let out = ok(
        &[
            "disclose",
            "--actions",
            "actions.json",
            "--index",
            "1",
            "--receipt",
            "receipt.json",
            "--out",
            "disclosure.json",
        ],
        dir,
    );
    assert!(out.contains("slot 1 digest 22"), "unexpected output: {out}");

    let out = zkagent(&verify_args(Some("disclosure.json")), dir);
    assert!(out.status.success(), "honest disclosure must be accepted");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("disclosure ACCEPT: slot 1 with digest 22"),
        "the disclosure verdict must be stated: {stderr}"
    );
}

#[test]
fn a_changed_digest_is_refused_even_though_the_proof_is_valid() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    execution(dir);
    ok(
        &[
            "disclose",
            "--actions",
            "actions.json",
            "--index",
            "0",
            "--receipt",
            "receipt.json",
            "--out",
            "disclosure.json",
        ],
        dir,
    );

    let path = dir.join("disclosure.json");
    let mut doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    doc["leaf_digest"] = serde_json::json!(12);
    std::fs::write(&path, doc.to_string()).unwrap();

    let out = zkagent(&verify_args(Some("disclosure.json")), dir);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a false disclosure must exit 1 even when the proof verifies"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("disclosure REJECT"),
        "the refusal must be attributed to the disclosure"
    );
}

#[test]
fn a_changed_sibling_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    execution(dir);
    ok(
        &[
            "disclose",
            "--actions",
            "actions.json",
            "--index",
            "0",
            "--receipt",
            "receipt.json",
            "--out",
            "disclosure.json",
        ],
        dir,
    );

    let path = dir.join("disclosure.json");
    let mut doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let sibling = doc["path"][2]["sibling"].as_str().unwrap().to_string();
    let flipped = if sibling.starts_with('0') { "1" } else { "0" }.to_string() + &sibling[1..];
    doc["path"][2]["sibling"] = serde_json::json!(flipped);
    std::fs::write(&path, doc.to_string()).unwrap();

    let out = zkagent(&verify_args(Some("disclosure.json")), dir);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_disclosure_for_another_execution_is_refused_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    execution(dir);
    ok(
        &[
            "disclose",
            "--actions",
            "actions.json",
            "--index",
            "0",
            "--receipt",
            "receipt.json",
            "--out",
            "disclosure.json",
        ],
        dir,
    );

    // A disclosure about one execution must not be accepted against another one, and the
    // refusal has to say which of the two failures it is.
    let path = dir.join("disclosure.json");
    let mut doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let root = doc["root"].as_str().unwrap().to_string();
    doc["root"] = serde_json::json!(format!("00{}", &root[2..]));
    std::fs::write(&path, doc.to_string()).unwrap();

    let out = zkagent(&verify_args(Some("disclosure.json")), dir);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not this receipt's trace_root"),
        "a wrong-root refusal must name the cause: {stderr}"
    );
}

#[test]
fn disclosing_an_index_outside_the_actions_is_an_error_not_a_panic() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    execution(dir);

    let out = zkagent(
        &[
            "disclose",
            "--actions",
            "actions.json",
            "--index",
            "7",
            "--receipt",
            "receipt.json",
            "--out",
            "disclosure.json",
        ],
        dir,
    );
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("outside the 2 action(s)"),
        "the message should say how many actions exist"
    );
}
