//! Integration tests for the untrusted-transport path.
//!
//! `GatewaySource` is the one block source in this crate that talks to something
//! the verifier does not control. The property under test is not "the fetch
//! works"; it is **a gateway that lies is refused**, and refused by naming the
//! artifact — before the proof is given a chance to distract from it.
//!
//! Every test runs against a real HTTP server on loopback. No network access,
//! and no mock of the transport itself: the thing being tested *is* the
//! transport, so replacing it would test nothing.
//!
//! These tests exist because the feature is off by default (so embedders that
//! carry no HTTP client do not pay for it). A feature-gated path that no CI
//! compiles is a claim, not a mechanism: `cargo test --features gateway` is
//! wired into CI for exactly that reason.

#![cfg(feature = "gateway")]

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use zkagent_ipfs::{
    cid_string, AttestationManifest, BlockSource, GatewaySource, ManifestError, SourceError,
};

/// A loopback HTTP server that answers `GET /<cid>` from a fixed route table.
///
/// It is deliberately dumb: one request at a time, `Content-Length`, then close.
/// Everything it can do wrong (return the wrong bytes, 404, 500) is something a
/// real gateway can do too, and each is exercised below.
struct TestGateway {
    base: String,
    hits: Arc<AtomicUsize>,
    paths: Arc<Mutex<Vec<String>>>,
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
        let paths = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let hits_thread = Arc::clone(&hits);
        let paths_thread = Arc::clone(&paths);
        let stop_thread = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Accepted from a nonblocking listener: make the stream
                        // blocking again so the read below is not a busy loop.
                        let _ = stream.set_nonblocking(false);
                        serve_one(stream, &routes, &hits_thread, &paths_thread);
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
            paths,
            stop,
            handle: Some(handle),
        }
    }

    /// How many requests reached the server.
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// The request paths the server saw, in order.
    fn paths(&self) -> Vec<String> {
        self.paths.lock().expect("paths lock").clone()
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

fn serve_one(
    mut stream: TcpStream,
    routes: &HashMap<String, Vec<u8>>,
    hits: &AtomicUsize,
    paths: &Mutex<Vec<String>>,
) {
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
    paths.lock().expect("paths lock").push(path.clone());

    // A CID is passed in the path with no leading slash.
    let cid = path.trim_start_matches('/');
    match routes.get(cid) {
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

/// The four artifacts a manifest names, as raw bytes.
fn artifacts() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        b"vk-bytes".to_vec(),
        b"policy-bytes".to_vec(),
        b"receipt-bytes".to_vec(),
        b"proof-bytes".to_vec(),
    )
}

fn manifest_for(vk: &[u8], policy: &[u8], receipt: &[u8], proof: &[u8]) -> AttestationManifest {
    let circuit = AttestationManifest::circuit_ref(vk, 3_333, 15, 2).expect("circuit ref");
    AttestationManifest::build(circuit, policy, receipt, proof, 1_761_700_000).expect("manifest")
}

/// Route every artifact the manifest names to its correct bytes.
fn honest_routes(
    manifest: &AttestationManifest,
    vk: &[u8],
    policy: &[u8],
    receipt: &[u8],
    proof: &[u8],
) -> HashMap<String, Vec<u8>> {
    let mut routes = HashMap::new();
    routes.insert(manifest.circuit.vk.cid.clone(), vk.to_vec());
    routes.insert(manifest.policy.cid.clone(), policy.to_vec());
    routes.insert(manifest.receipt.cid.clone(), receipt.to_vec());
    routes.insert(manifest.proof.cid.clone(), proof.to_vec());
    routes
}

#[test]
fn a_gateway_serves_the_blocks_a_manifest_names() {
    let (vk, policy, receipt, proof) = artifacts();
    let manifest = manifest_for(&vk, &policy, &receipt, &proof);
    let gateway = TestGateway::start(honest_routes(&manifest, &vk, &policy, &receipt, &proof));

    let source = GatewaySource::new(gateway.base.clone());
    let bundle = manifest.collect(&source).expect("collect over HTTP");

    assert_eq!(bundle.vk, vk);
    assert_eq!(bundle.policy, policy);
    assert_eq!(bundle.receipt, receipt);
    assert_eq!(bundle.proof, proof);
    assert_eq!(gateway.hits(), 4, "one fetch per artifact");
}

#[test]
fn the_gateway_is_asked_for_the_cid_and_nothing_else() {
    // The path is the contract with a real gateway, and it is also the guard
    // that keeps a hostile manifest from requesting an arbitrary URL.
    let (vk, policy, receipt, proof) = artifacts();
    let manifest = manifest_for(&vk, &policy, &receipt, &proof);
    let gateway = TestGateway::start(honest_routes(&manifest, &vk, &policy, &receipt, &proof));

    let source = GatewaySource::new(gateway.base.clone());
    manifest.collect(&source).expect("collect over HTTP");

    let seen = gateway.paths();
    assert_eq!(seen.len(), 4);
    for path in &seen {
        assert!(
            path.starts_with("/bafkrei"),
            "a raw-block CIDv1 path was expected, got {path}"
        );
        assert!(!path.contains(".."), "no traversal segment may be sent");
        assert!(!path.contains('?'), "no query string may be sent");
    }
}

#[test]
fn a_hostile_gateway_that_returns_other_bytes_is_refused_by_name() {
    // The attack the whole crate exists to stop: the gateway answers every
    // request with a 200 and the right length, but different content. Only the
    // re-hash can catch this, and the failure must name the artifact.
    let (vk, policy, receipt, proof) = artifacts();
    let manifest = manifest_for(&vk, &policy, &receipt, &proof);

    let mut routes = honest_routes(&manifest, &vk, &policy, &receipt, &proof);
    let mut poisoned = proof.clone();
    poisoned[0] ^= 0xff; // same length: the size check cannot help here
    routes.insert(manifest.proof.cid.clone(), poisoned);

    let gateway = TestGateway::start(routes);
    let source = GatewaySource::new(gateway.base.clone());

    match manifest.collect(&source) {
        Err(ManifestError::Integrity { artifact, .. }) => assert_eq!(artifact, "proof"),
        other => panic!("a lying gateway must be refused, got {other:?}"),
    }
}

#[test]
fn a_gateway_that_substitutes_the_verifying_key_is_refused_first() {
    // Integrity is checked before verification, so a substituted key must never
    // reach the point where it is paired with a real proof.
    let (vk, policy, receipt, proof) = artifacts();
    let manifest = manifest_for(&vk, &policy, &receipt, &proof);

    let mut routes = honest_routes(&manifest, &vk, &policy, &receipt, &proof);
    let mut substituted = vk.clone();
    substituted[0] ^= 0xff;
    routes.insert(manifest.circuit.vk.cid.clone(), substituted);

    let gateway = TestGateway::start(routes);
    let source = GatewaySource::new(gateway.base.clone());

    match manifest.collect(&source) {
        Err(ManifestError::Integrity { artifact, .. }) => assert_eq!(artifact, "verifying key"),
        other => panic!("a substituted verifying key must be refused, got {other:?}"),
    }
}

#[test]
fn a_truncated_block_is_refused_by_length_rather_than_hashed() {
    let (vk, policy, receipt, proof) = artifacts();
    let manifest = manifest_for(&vk, &policy, &receipt, &proof);

    let mut routes = honest_routes(&manifest, &vk, &policy, &receipt, &proof);
    routes.insert(manifest.proof.cid.clone(), b"short".to_vec());

    let gateway = TestGateway::start(routes);
    let source = GatewaySource::new(gateway.base.clone());

    match manifest.collect(&source) {
        Err(ManifestError::Size { artifact, .. }) => assert_eq!(artifact, "proof"),
        other => panic!("a truncated block must be refused, got {other:?}"),
    }
}

#[test]
fn a_missing_block_is_not_found_rather_than_an_empty_body() {
    let (vk, policy, receipt, proof) = artifacts();
    let manifest = manifest_for(&vk, &policy, &receipt, &proof);

    let mut routes = honest_routes(&manifest, &vk, &policy, &receipt, &proof);
    routes.remove(&manifest.receipt.cid);

    let gateway = TestGateway::start(routes);
    let source = GatewaySource::new(gateway.base.clone());

    match manifest.collect(&source) {
        Err(ManifestError::Source(SourceError::NotFound(cid))) => {
            assert_eq!(cid, manifest.receipt.cid, "the missing artifact is named");
        }
        other => panic!("a 404 must be NotFound, got {other:?}"),
    }
}

#[test]
fn a_path_like_cid_is_rejected_before_any_request_is_made() {
    // The guard that stops a hostile manifest from turning the verifier into an
    // SSRF primitive. It must fire locally, so the server is never contacted.
    let gateway = TestGateway::start(HashMap::new());
    let source = GatewaySource::new(gateway.base.clone());

    assert!(matches!(
        source.get("../../etc/passwd"),
        Err(SourceError::BadCid(_))
    ));
    assert!(matches!(
        source.get("https://evil.example/x"),
        Err(SourceError::BadCid(_))
    ));
    assert_eq!(
        gateway.hits(),
        0,
        "a rejected CID must not reach the network"
    );
}

#[test]
fn a_gateway_that_returns_an_oversized_block_is_refused_without_buffering_it() {
    // A hostile transport may answer with a body of any length. The manifest's
    // size check runs *after* the read, so without a cap the memory is already
    // gone by the time anything notices.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = vec![b'x'; 4096];
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });

    let source = GatewaySource::new(format!("http://{addr}")).with_max_block_bytes(1024);
    let cid = cid_string(b"anything").expect("hash");

    match source.get(&cid) {
        Err(SourceError::TooLarge { limit, .. }) => assert_eq!(limit, 1024),
        other => panic!("an oversized block must be refused, got {other:?}"),
    }
    let _ = server.join();
}

#[test]
fn a_gateway_that_answers_with_a_server_error_is_a_transport_failure() {
    // "Could not verify" is not "verified false". A 500 must surface as a
    // transport error, never as an integrity rejection and never as a panic.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            let _ = stream.flush();
        }
    });

    let source = GatewaySource::new(format!("http://{addr}"));
    let cid = cid_string(b"anything").expect("hash");

    match source.get(&cid) {
        Err(SourceError::Transport(_)) => {}
        other => panic!("a 500 must be a transport failure, got {other:?}"),
    }
    let _ = server.join();
}
