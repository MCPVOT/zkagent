//! Tests for the content-addressed publish/verify path.
//!
//! The property under test is not "a bundle round-trips". It is: **a bundle that
//! was tampered with in storage is refused**, and it is refused *before* the proof
//! is given the chance to distract from it.

use std::fs;
use std::path::PathBuf;

use zkagent_core::{Action, Receipt};
use zkagent_ipfs::DirSource;
use zkagent_service::{
    publish, setup, verify_bundle, AuthorityKey, PolicySpec, ServiceError, Verdict,
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
        execution_id: 7_001,
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

struct Fixture {
    keys: PathBuf,
    policy: PathBuf,
    receipt: PathBuf,
    proof: PathBuf,
}

/// Build a complete, verifiable bundle on disk.
fn fixture(root: &std::path::Path) -> Fixture {
    let keys = root.join("keys");
    let policy = root.join("policy.json");
    let receipt_path = root.join("receipt.json");
    let actions_path = root.join("actions.json");
    let proof = root.join("proof.json");

    setup(&keys, 7).expect("setup");
    zkagent_service::authorize(
        &policy,
        &spec(),
        &AuthorityKey::File(root.join("authority.hex")),
    )
    .expect("authorize");

    fs::write(
        &receipt_path,
        r#"{"total_amount":400,"action_count":2,"completed_at":1500,"chain_id":1,"execution_id":7001}"#,
    )
    .expect("receipt");
    fs::write(
        &actions_path,
        r#"[{"target":3,"amount":250,"trace_digest":11},{"target":7,"amount":150,"trace_digest":22}]"#,
    )
    .expect("actions");

    let proof_bytes =
        zkagent_service::prove(&keys, &policy, &receipt(), &actions()).expect("prove");
    zkagent_service::write_json(&proof, &proof_bytes).expect("write proof");

    Fixture {
        keys,
        policy,
        receipt: receipt_path,
        proof,
    }
}

#[test]
fn a_published_bundle_verifies() {
    let dir = workspace();
    let f = fixture(dir.path());
    let blocks = DirSource::new(dir.path().join("blocks"));

    let published = publish(
        &f.keys,
        &f.policy,
        &f.receipt,
        &f.proof,
        &actions(),
        1_761_700_000,
    )
    .expect("publish");

    // The manifest names four artifacts, each with a CID and a hex digest.
    assert_eq!(published.manifest.kind, "zkagent/attestation");
    assert_eq!(published.blocks.len(), 4);
    for (cid, bytes) in &published.blocks {
        assert_eq!(
            &zkagent_ipfs::cid_string(bytes).expect("hash"),
            cid,
            "every block must hash to the CID it is filed under"
        );
        // Store it exactly as a block store would.
        blocks.put(bytes).expect("store block");
    }

    // The circuit identity is measured, not copied.
    assert_eq!(published.manifest.circuit.public_inputs, 15);
    assert_eq!(published.manifest.circuit.format_version, 2);

    let outcome = verify_bundle(&published.manifest, &blocks, Some(1_600), None).expect("verify");
    assert!(
        outcome.accepted(),
        "expected accept, got {:?}",
        outcome.verdict
    );
}

#[test]
fn a_bundle_whose_proof_was_swapped_in_storage_is_refused() {
    let dir = workspace();
    let f = fixture(dir.path());
    let blocks = DirSource::new(dir.path().join("blocks"));

    let published = publish(
        &f.keys,
        &f.policy,
        &f.receipt,
        &f.proof,
        &actions(),
        1_761_700_000,
    )
    .expect("publish");
    for (_, bytes) in &published.blocks {
        blocks.put(bytes).expect("store block");
    }

    // The attack: someone with write access to the store replaces the proof with
    // different bytes (here, another valid-looking JSON blob of the same length).
    let proof_cid = published.manifest.proof.cid.clone();
    let original = fs::read(blocks.path_for(&proof_cid)).expect("read proof block");
    let mut tampered = original.clone();
    let last = tampered.len() - 2;
    tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
    fs::write(blocks.path_for(&proof_cid), &tampered).expect("write tampered proof");

    match verify_bundle(&published.manifest, &blocks, Some(1_600), None) {
        Err(ServiceError::Verification(msg)) => {
            assert!(
                msg.contains("proof") || msg.contains("content does not match"),
                "the failure must name the artifact: {msg}"
            );
        }
        other => panic!("a substituted proof must be refused, got {other:?}"),
    }
}

#[test]
fn a_bundle_reports_a_missing_block_by_cid() {
    let dir = workspace();
    let f = fixture(dir.path());
    let blocks = DirSource::new(dir.path().join("blocks"));

    let published = publish(
        &f.keys,
        &f.policy,
        &f.receipt,
        &f.proof,
        &actions(),
        1_761_700_000,
    )
    .expect("publish");

    // Nothing is stored at all: the fetch must fail, and say which CID.
    match verify_bundle(&published.manifest, &blocks, Some(1_600), None) {
        Err(ServiceError::Verification(msg)) => {
            assert!(
                msg.contains("not found") || msg.contains("bafkrei"),
                "got: {msg}"
            );
        }
        other => panic!("expected a fetch failure, got {other:?}"),
    }
}

#[test]
fn a_replayed_bundle_is_refused_when_state_is_used() {
    let dir = workspace();
    let f = fixture(dir.path());
    let blocks = DirSource::new(dir.path().join("blocks"));
    let seen = dir.path().join("seen.json");

    let published = publish(
        &f.keys,
        &f.policy,
        &f.receipt,
        &f.proof,
        &actions(),
        1_761_700_000,
    )
    .expect("publish");
    for (_, bytes) in &published.blocks {
        blocks.put(bytes).expect("store block");
    }

    let first =
        verify_bundle(&published.manifest, &blocks, Some(1_600), Some(&seen)).expect("first");
    assert!(first.accepted());
    assert!(first.recorded);

    let second =
        verify_bundle(&published.manifest, &blocks, Some(1_600), Some(&seen)).expect("second");
    assert!(!second.accepted(), "the same bundle must not verify twice");
    assert!(matches!(
        second.verdict,
        Verdict::Reject(zkagent_service::RejectReason::AlreadyAccepted(7001))
    ));
}

#[test]
fn a_manifest_from_a_different_circuit_is_refused_before_verifying() {
    let dir = workspace();
    let f = fixture(dir.path());

    let mut published = publish(
        &f.keys,
        &f.policy,
        &f.receipt,
        &f.proof,
        &actions(),
        1_761_700_000,
    )
    .expect("publish");

    // Claim a different circuit than the proof belongs to.
    published.manifest.circuit.format_version = 99;

    let blocks = DirSource::new(dir.path().join("blocks2"));
    for (_, bytes) in &published.blocks {
        blocks.put(bytes).expect("store block");
    }

    match verify_bundle(&published.manifest, &blocks, Some(1_600), None) {
        Err(ServiceError::Verification(msg)) => {
            assert!(msg.contains("format"), "got: {msg}");
        }
        other => panic!("a circuit mismatch must be refused, got {other:?}"),
    }
}
