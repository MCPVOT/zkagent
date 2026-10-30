//! The untrusted-transport path, end to end: a real proof, fetched over real
//! HTTP from a server the verifier does not control.
//!
//! `bundle.rs` proves the join works when the bytes come from a directory the
//! caller owns. That is the easy half. The claim this file exists to test is the
//! hard half: **a gateway that lies is refused**, with a genuine Groth16 proof in
//! the bundle, so the failure cannot be blamed on a fake artifact.
//!
//! Feature-gated (`--features gateway`) because the default build carries no
//! HTTP client. CI runs `--all-features`, so this cannot rot unnoticed: a path
//! that no build compiles is a claim, not a mechanism.

#![cfg(feature = "gateway")]

use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use zkagent_core::{Action, Receipt};
use zkagent_ipfs::GatewaySource;
use zkagent_service::{
    publish, setup, verify_bundle, AuthorityKey, PolicySpec, PublishedBundle, ServiceError, Verdict,
};

/// A loopback HTTP gateway serving a fixed CID -> bytes table.
struct TestGateway {
    base: String,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TestGateway {
    fn start(routes: HashMap<String, Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().expect("local addr");

        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let hits_thread = Arc::clone(&hits);
        let stop_thread = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        serve_one(stream, &routes, &hits_thread);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base: format!("http://{addr}"),
            hits,
            stop,
            handle: Some(handle),
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for TestGateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve_one(mut stream: TcpStream, routes: &HashMap<String, Vec<u8>>, hits: &AtomicUsize) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == &b"\r\n\r\n"[..]) {
                    break;
                }
            }
            Err(_) => return,
        }
    }

    let request = String::from_utf8_lossy(&buf).into_owned();
    let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
    hits.fetch_add(1, Ordering::SeqCst);

    match routes.get(path.trim_start_matches('/')) {
        Some(body) => {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        }
        None => {
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    }
    let _ = stream.flush();
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
        execution_id: 8_001,
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

/// Build a complete, genuinely provable bundle on disk.
fn fixture(root: &Path) -> Fixture {
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
        r#"{"total_amount":400,"action_count":2,"completed_at":1500,"chain_id":1,"execution_id":8001}"#,
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

fn publish_fixture(f: &Fixture) -> PublishedBundle {
    publish(
        &f.keys,
        &f.policy,
        &f.receipt,
        &f.proof,
        &actions(),
        1_761_700_000,
    )
    .expect("publish")
}

fn routes_of(bundle: &PublishedBundle) -> HashMap<String, Vec<u8>> {
    bundle
        .blocks
        .iter()
        .cloned()
        .collect::<HashMap<String, Vec<u8>>>()
}

#[test]
fn a_real_bundle_verifies_when_fetched_over_http() {
    let dir = tempfile::tempdir().expect("temp dir");
    let f = fixture(dir.path());
    let published = publish_fixture(&f);

    let gateway = TestGateway::start(routes_of(&published));
    let source = GatewaySource::new(gateway.base.clone());

    let outcome =
        verify_bundle(&published.manifest, &source, Some(1_600), None).expect("verify over HTTP");

    assert!(
        outcome.accepted(),
        "a genuine bundle must verify over HTTP, got {:?}",
        outcome.verdict
    );
    assert_eq!(gateway.hits(), 4, "one fetch per artifact");
}

#[test]
fn a_bundle_with_a_substituted_proof_is_refused_over_http() {
    // The attack the crate exists to stop: the gateway serves valid JSON that
    // hashes to something else. Only the re-hash catches it, and the bundle must
    // be refused as an integrity failure — not accepted, and not a panic.
    let dir = tempfile::tempdir().expect("temp dir");
    let f = fixture(dir.path());
    let published = publish_fixture(&f);

    let mut routes = routes_of(&published);
    let proof_cid = published.manifest.proof.cid.clone();
    let original = routes.get(&proof_cid).expect("proof block").clone();
    let mut tampered = original.clone();
    let last = tampered.len() - 2;
    tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
    routes.insert(proof_cid, tampered);

    let gateway = TestGateway::start(routes);
    let source = GatewaySource::new(gateway.base.clone());

    match verify_bundle(&published.manifest, &source, Some(1_600), None) {
        Err(ServiceError::Verification(msg)) => assert!(
            msg.contains("proof") || msg.contains("content does not match"),
            "the failure must name the artifact: {msg}"
        ),
        other => panic!("a substituted proof must be refused, got {other:?}"),
    }
}

#[test]
fn a_bundle_with_a_substituted_verifying_key_is_refused_before_verifying() {
    // Integrity before verification: a swapped key must never be paired with a
    // real proof, or the verdict would be about a circuit nobody authorised.
    let dir = tempfile::tempdir().expect("temp dir");
    let f = fixture(dir.path());
    let published = publish_fixture(&f);

    let mut routes = routes_of(&published);
    let vk_cid = published.manifest.circuit.vk.cid.clone();
    let original = routes.get(&vk_cid).expect("vk block").clone();
    let mut tampered = original.clone();
    tampered[0] ^= 0xff;
    routes.insert(vk_cid, tampered);

    let gateway = TestGateway::start(routes);
    let source = GatewaySource::new(gateway.base.clone());

    match verify_bundle(&published.manifest, &source, Some(1_600), None) {
        Err(ServiceError::Verification(msg)) => assert!(
            msg.contains("verifying key"),
            "the failure must name the verifying key: {msg}"
        ),
        other => panic!("a substituted verifying key must be refused, got {other:?}"),
    }
}

#[test]
fn a_replayed_bundle_is_refused_over_http_when_state_is_used() {
    // The replay gate is verifier state, not a property of the proof, so it has
    // to hold on the transport path too.
    let dir = tempfile::tempdir().expect("temp dir");
    let f = fixture(dir.path());
    let published = publish_fixture(&f);
    let seen = dir.path().join("seen.json");

    let gateway = TestGateway::start(routes_of(&published));
    let source = GatewaySource::new(gateway.base.clone());

    let first = verify_bundle(&published.manifest, &source, Some(1_600), Some(&seen))
        .expect("first verify");
    assert!(first.accepted());
    assert!(first.recorded);

    let second = verify_bundle(&published.manifest, &source, Some(1_600), Some(&seen))
        .expect("second verify");
    assert!(!second.accepted(), "the same bundle must not verify twice");
    assert!(matches!(
        second.verdict,
        Verdict::Reject(zkagent_service::RejectReason::AlreadyAccepted(8001))
    ));
}

#[test]
fn a_missing_block_over_http_is_could_not_verify_rather_than_false() {
    // "Could not verify" is not "verified false". A 404 must not be reported as
    // a rejection, because the caller's reaction to each is different.
    let dir = tempfile::tempdir().expect("temp dir");
    let f = fixture(dir.path());
    let published = publish_fixture(&f);

    let mut routes = routes_of(&published);
    routes.remove(&published.manifest.receipt.cid);

    let gateway = TestGateway::start(routes);
    let source = GatewaySource::new(gateway.base.clone());

    match verify_bundle(&published.manifest, &source, Some(1_600), None) {
        Err(ServiceError::Verification(msg)) => assert!(
            msg.contains("not found") || msg.contains("bafkrei"),
            "got: {msg}"
        ),
        other => panic!("a missing block must be a fetch failure, got {other:?}"),
    }
}
