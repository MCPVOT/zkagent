//! Tests for the shared operations layer.
//!
//! These matter more than they look: the CLI, the MCP server and any embedded
//! host all call these four functions. If a rule lives only in a shell, the
//! shells drift — and the drift is in the security-relevant direction. So the
//! rules are tested here, once, against the real files on disk.

use std::fs;
use std::path::{Path, PathBuf};

use zkagent_core::{Action, Receipt};
use zkagent_service::{
    authorize, prove, read_actions, read_receipt, setup, verify, AuthorityKey, PolicySpec,
    ServiceError, Verdict,
};

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

fn spec() -> PolicySpec {
    PolicySpec {
        max_amount: 1_000,
        max_per_action: 300,
        expires_at: 2_000,
        chain_id: 1,
        targets: vec![3, 7, 9],
    }
}

fn receipt() -> Receipt {
    Receipt {
        total_amount: 400,
        action_count: 2,
        completed_at: 1_500,
        chain_id: 1,
        execution_id: 1_001,
        trace_root: [0u8; 32],
    }
}

fn actions() -> Vec<Action> {
    vec![
        Action {
            target: 3,
            amount: 250,
            trace_digest: 11,
        },
        Action {
            target: 7,
            amount: 150,
            trace_digest: 22,
        },
    ]
}

/// Run the whole happy path and return the paths it produced.
fn full_flow(root: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let keys = root.join("keys");
    let policy_path = root.join("policy.json");
    let receipt_path = root.join("receipt.json");
    let proof_path = root.join("proof.json");

    setup(&keys, 7).expect("setup");
    authorize(
        &policy_path,
        &spec(),
        &AuthorityKey::File(root.join("authority.hex")),
    )
    .expect("authorize");

    fs::write(
        &receipt_path,
        r#"{"total_amount":400,"action_count":2,"completed_at":1500,"chain_id":1,"execution_id":1001,"trace_root":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
    )
    .expect("write receipt");

    let proven = prove(&keys, &policy_path, &receipt(), &actions()).expect("prove");
    zkagent_service::write_json(&proof_path, &proven.proof).expect("write proof");
    // The prover fills in the trace root; publish the receipt it returned so the
    // file on disk is the one the proof commits to.
    zkagent_service::write_json(
        &receipt_path,
        &zkagent_service::ReceiptJson::from(&proven.receipt),
    )
    .expect("write receipt");

    (keys, policy_path, receipt_path, proof_path)
}

#[test]
fn the_happy_path_accepts() {
    let dir = workspace();
    let (keys, policy_path, receipt_path, proof_path) = full_flow(dir.path());

    let receipt = read_receipt(&receipt_path).expect("receipt");
    let proof = zkagent_service::read_json(&proof_path).expect("proof");

    let outcome = verify(&keys, &policy_path, &receipt, &proof, Some(1_600), None).expect("verify");
    assert!(
        outcome.accepted(),
        "expected accept, got {:?}",
        outcome.verdict
    );
}

#[test]
fn a_replay_is_refused_when_state_is_used() {
    let dir = workspace();
    let (keys, policy_path, receipt_path, proof_path) = full_flow(dir.path());
    let seen = dir.path().join("seen.json");

    let receipt = read_receipt(&receipt_path).expect("receipt");
    let proof = zkagent_service::read_json(&proof_path).expect("proof");

    let first = verify(
        &keys,
        &policy_path,
        &receipt,
        &proof,
        Some(1_600),
        Some(&seen),
    )
    .expect("verify");
    assert!(first.accepted());
    assert!(first.recorded, "the accepted id must be recorded");

    let second = verify(
        &keys,
        &policy_path,
        &receipt,
        &proof,
        Some(1_600),
        Some(&seen),
    )
    .expect("verify");
    assert!(
        !second.accepted(),
        "the same proof must not be accepted twice"
    );
    assert!(matches!(
        second.verdict,
        Verdict::Reject(zkagent_service::RejectReason::AlreadyAccepted(1001))
    ));
}

#[test]
fn an_unreadable_state_file_fails_closed() {
    let dir = workspace();
    let (keys, policy_path, receipt_path, proof_path) = full_flow(dir.path());
    let seen = dir.path().join("seen.json");
    fs::write(&seen, b"{\"execution_ids\": [1,").expect("write corrupt state");

    let receipt = read_receipt(&receipt_path).expect("receipt");
    let proof = zkagent_service::read_json(&proof_path).expect("proof");

    let result = verify(
        &keys,
        &policy_path,
        &receipt,
        &proof,
        Some(1_600),
        Some(&seen),
    );
    match result {
        Err(ServiceError::Replay(_)) => {}
        other => panic!("a corrupt state file must fail closed, got {other:?}"),
    }
}

#[test]
fn a_tampered_policy_is_refused_as_unauthorised() {
    let dir = workspace();
    let (keys, policy_path, receipt_path, proof_path) = full_flow(dir.path());

    // Raise the cap without touching the signature.
    let signed = zkagent_service::read_json::<zkagent_service::SignedPolicyFile>(&policy_path)
        .expect("policy");
    let mut tampered = signed;
    tampered.policy.max_amount = 999_999;
    let tampered_path = dir.path().join("tampered.json");
    zkagent_service::write_json(&tampered_path, &tampered).expect("write tampered");

    let receipt = read_receipt(&receipt_path).expect("receipt");
    let proof = zkagent_service::read_json(&proof_path).expect("proof");

    let outcome =
        verify(&keys, &tampered_path, &receipt, &proof, Some(1_600), None).expect("verify");
    assert!(matches!(
        outcome.verdict,
        Verdict::Reject(zkagent_service::RejectReason::UnauthorisedPolicy)
    ));
}

#[test]
fn a_key_file_is_created_once_and_then_reused() {
    let dir = workspace();
    let key_path = dir.path().join("authority.hex");

    let first = authorize(
        &dir.path().join("p1.json"),
        &spec(),
        &AuthorityKey::File(key_path.clone()),
    )
    .expect("authorize");
    assert!(first.created_key_file, "the first call creates the key");
    assert!(key_path.exists());

    let second = authorize(
        &dir.path().join("p2.json"),
        &spec(),
        &AuthorityKey::File(key_path.clone()),
    )
    .expect("authorize");
    assert!(!second.created_key_file, "the second call reuses it");
    assert_eq!(
        first.authority_pubkey, second.authority_pubkey,
        "the same key file must produce the same public key"
    );
}

#[test]
fn a_demo_seed_is_flagged_as_forgeable() {
    let dir = workspace();
    let authorized =
        authorize(&dir.path().join("p.json"), &spec(), &AuthorityKey::Seed(99)).expect("authorize");

    assert!(authorized.used_demo_key);
    assert!(
        authorized.warning.is_some(),
        "a demo key must carry a warning the host can surface"
    );
}

#[test]
fn an_illegal_policy_is_refused_before_anything_is_written() {
    let dir = workspace();
    let policy_path = dir.path().join("p.json");
    let bad = PolicySpec {
        targets: vec![], // an empty allow-list would authorise nothing
        ..spec()
    };

    let result = authorize(&policy_path, &bad, &AuthorityKey::Seed(1));
    assert!(matches!(result, Err(ServiceError::InvalidPolicy(_))));
    assert!(
        !policy_path.exists(),
        "no file may be written for an invalid policy"
    );
}

#[test]
fn proving_an_out_of_policy_action_is_refused() {
    let dir = workspace();
    let keys = dir.path().join("keys");
    let policy_path = dir.path().join("policy.json");
    setup(&keys, 7).expect("setup");
    authorize(
        &policy_path,
        &spec(),
        &AuthorityKey::File(dir.path().join("authority.hex")),
    )
    .expect("authorize");

    let over_cap = vec![Action {
        target: 3,
        amount: 999,
        trace_digest: 1,
    }];
    let result = prove(&keys, &policy_path, &receipt(), &over_cap);
    assert!(
        result.is_err(),
        "an action over the per-action cap must not produce a proof"
    );
}

#[test]
fn the_service_reads_the_same_artifacts_the_shells_write() {
    let dir = workspace();
    let (_, policy_path, receipt_path, _) = full_flow(dir.path());

    // The wire types are shared, so a shell and the service cannot disagree.
    let signed = zkagent_service::read_signed_policy(&policy_path).expect("policy");
    assert_eq!(signed.policy.max_amount, 1_000);
    assert_eq!(signed.policy.allowed_targets, vec![3, 7, 9]);

    let r = read_receipt(&receipt_path).expect("receipt");
    assert_eq!(r.execution_id, 1_001);

    let actions_path = dir.path().join("actions.json");
    fs::write(
        &actions_path,
        r#"[{"target":3,"amount":250,"trace_digest":11}]"#,
    )
    .expect("write actions");
    let parsed = read_actions(&actions_path).expect("actions");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].target, 3);
}
