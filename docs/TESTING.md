# Testing

The tiers here replace the ones a C-to-Rust port would use. That project's tiers
exist to prove *drop-in replacement of C*; this project's hard problem is
**soundness under an adversarial witness**. So the tiers are different, and the
tests that may never be skipped are different.

## The tiers

### Tier 0 — pure unit tests

Encoding, canonicalisation, validation, field arithmetic helpers. Fast, no
proving. Example: `policy.rs` asserting that every field change alters the
commitment, and that an empty allow-list is refused.

### Tier 1 — circuit tests, including one negative per constraint

Every constraint `C1..C8` needs a test where a witness **violating that
constraint** fails to satisfy the system. A constraint with no negative test is
a constraint nobody has checked is load-bearing.

Also in this tier:

- `circuit_shape_is_data_independent` — the constraint system built at setup
  must equal the one built when proving. Groth16 is circuit-specific; if these
  differ, every honest proof fails with `InvalidProof`.
- `public_input_order_matches_the_allocation_order` — the circuit's public
  inputs are ordered by **allocation**, not by what reads naturally. When
  `public_inputs()` and the allocation order disagree, every individual input is
  correct and every honest proof is still rejected. This test has been verified
  to fail when the vector is deliberately permuted.
- `constraint_count_is_sane` — asserts the constraint count *and* the arity, so
  a gadget that silently allocates per-bit public inputs fails here rather than
  at proving time.

### Tier 2 — end-to-end through the service layer

`crates/zkagent-service/tests/` drives the four real operations over real files:
setup, authorise, prove, verify. This is where the rules that a shell could get
wrong are pinned: the replay gate, fail-closed state, key creation, and the
refusal to report an acceptance that cannot be recorded.

### Tier 3 — hostile artifacts

The verifier is fed things a hostile peer would send: a truncated proof, a
malformed verifying key, a permuted public-input vector, a wrong format version,
a tampered policy, a receipt dated in the future, an execution id of zero. It
must reject each one **by name** and never panic.

### Tier 3b — the hostile transport (feature `gateway`)

The block source is the one component the verifier does not control, so it gets
its own tier, and the tests drive it over a real loopback HTTP server rather than
a mock of the transport — the transport *is* the thing under test.
`crates/zkagent-ipfs/tests/gateway.rs` and `crates/zkagent-service/tests/gateway.rs`
assert that:

- a gateway that returns different bytes of the **same length** is refused as an
  integrity failure naming the artifact (a size check cannot catch this);
- a substituted **verifying key** is refused before any proof is verified;
- a 404 is `NotFound` and a 5xx is a transport failure — "could not verify" is
  never reported as "verified false";
- a path-like CID (`../etc/passwd`, an absolute URL) is rejected **before any
  request leaves the process**, so a hostile manifest cannot become an SSRF;
- a body larger than the block cap is refused without buffering it;
- a genuine bundle, with a real Groth16 proof, verifies over HTTP and still
  honours the replay gate.

Both guards are mutation-verified: disabling the re-hash, or the CID path check,
makes the corresponding tests fail. A test that cannot fail is documentation.

### Tier 4 — cross-verification (not implemented)

A second, independent verifier — ideally in another language — consuming the
same artifacts. Until it exists, the claim "this proof verifies" rests on one
implementation.

## Tests that may NEVER be skipped

These are the tests whose absence lets an unsound circuit ship green:

- any test asserting a **rejection** (violated constraint, tampered policy,
  expired receipt, replayed id, corrupt replay state);
- `public_input_order_matches_the_allocation_order`;
- `circuit_shape_is_data_independent`;
- the end-to-end accept path in `zkagent-service`.

If a change makes one of these inconvenient, the change is wrong, not the test.
Removing one requires a written justification in the PR and a reviewer who
explicitly agrees.

## Circuit identity

Any attestation, cached verifying key, or published measurement must record:

- the verifying-key bytes' hash,
- the constraint count,
- the public-input count,
- `FORMAT_VERSION`.

A proof is only meaningful relative to a circuit. An attestation that does not
bind circuit identity can "pass" against a different circuit — which is exactly
how a gate ends up proving nothing.

## Running everything

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --manifest-path examples/tauri-plugin/Cargo.toml
python tools/leaderboard/test_generate.py
```

**`--all-features` is not optional.** The `gateway` feature is off by default
(a host that already holds its blocks should not carry an HTTP client and a TLS
stack), and nothing in the workspace enables it. A plain `cargo test` therefore
compiles `GatewaySource` — the untrusted-transport path — to nothing, and its
tests silently vanish. CI runs `--all-features` for exactly that reason: a
security-relevant path that no build compiles is a claim, not a mechanism.

CI additionally runs the real binaries: the CLI exit-code contract, and a full
MCP JSON-RPC round trip (setup → authorise → prove → verify → replay).

## Evidence, not adjectives

A test result is evidence when it includes the command and its output. "It
should pass" and "tests look green" are not evidence, and neither is a green
badge on a commit that never ran the suite.
