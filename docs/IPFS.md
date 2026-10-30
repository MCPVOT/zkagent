# IPFS + zkagent: content-addressed attestations

Two halves of one guarantee. A proof gives you **soundness** and **privacy**; it
says nothing about whether the bytes you received are the bytes that were
attested. Content addressing gives you **integrity** and **availability**; it says
nothing about whether the content is true.

| | ZK alone | IPFS alone | both |
|---|---|---|---|
| the statement is true | yes | — | yes |
| the bytes are unmodified | — | yes | yes |
| the witness stays private | yes | — | yes |
| anyone can fetch the artifact | — | yes | yes |

## What ships

| Piece | Crate | What it does |
|---|---|---|
| CIDv1 (raw, sha2-256) over artifact bytes | `zkagent-ipfs` | names an artifact by its hash |
| the manifest | `zkagent-ipfs` | names all four artifacts + circuit identity by CID |
| block sources | `zkagent-ipfs` | `DirSource`, `MemorySource`, `GatewaySource` (feature `gateway`) |
| publish / verify-by-CID | `zkagent-service` | joins content addressing to the protocol |
| `zkagent publish`, `zkagent verify-bundle` | `zkagent-cli` | the two commands |

**What this is not:** a libp2p node. No DHT, no bitswap, no pinning, no IPNS. A
full node (`dariusc93/rust-ipfs`) builds in tens of minutes and pulls libp2p,
which a library embedding in a Tauri app or an MCP server cannot carry by
default. A verifier needs something narrower — *given a CID, get the bytes and
check the hash* — and that is what this does. Connecting it to a real node is one
`ipfs add`, below.

## The manifest

```json
{
  "kind": "zkagent/attestation",
  "version": 1,
  "circuit": {
    "vk": { "cid": "bafkreibjyua75…", "bytes": 712, "sha256": "…" },
    "constraints": 3333,
    "public_inputs": 15,
    "format_version": 2
  },
  "policy":  { "cid": "bafkreibtnwjhs…", "bytes": 421, "sha256": "…" },
  "receipt": { "cid": "bafkreifupy33cr…", "bytes": 118, "sha256": "…" },
  "proof":   { "cid": "bafkreidyu7hugs…", "bytes": 2170, "sha256": "…" },
  "created_at": 1761700000
}
```

Why the four are bound together: publishing them as loose files means four
chances to mix up a version, and a proof verified against the wrong verifying key
fails in a way that looks like a broken prover.

**Circuit identity is the verifying key's CID**, not a comment. `docs/TESTING.md`
requires every attestation to record which circuit it belongs to; here that record
*is* the bytes, so it cannot drift.

The `constraints` / `public_inputs` numbers are **measured at publish time** by
`zkagent_proofs::circuit::measure_shape` for the exact policy, receipt and
witness. They are not copied from a document.

## The rule: never trust the transport

Every fetch is re-hashed against the CID that was requested. A gateway, a mirror
or a peer can return any bytes it likes, and a mismatch is a hard error:

```
$ zkagent verify-bundle --manifest attestation.json --blocks blocks/ --now 1600
error: verification material: verifying key: content does not match its CID
       (expected bafkreibjyua75…, got bafkreihzpzcoz…)
```

Note what that demonstrates: the **verifying key** was tampered with, not the
proof. Integrity is checked before verification, so a substituted key cannot be
paired with a real proof.

## Usage

```bash
# 1. the normal flow
zkagent setup  --seed 7 --out keys/
zkagent policy --max-amount 1000 --max-per-action 300 --expires-at 2000 \
               --chain-id 1 --targets 3,7,9 --authority-key authority.hex --out policy.json
zkagent prove  --keys keys/ --policy policy.json --receipt receipt.json \
               --actions actions.json --out proof.json

# 2. publish: hash the four artifacts, file each block under its CID
zkagent publish --keys keys/ --policy policy.json --receipt receipt.json \
                --proof proof.json --actions actions.json \
                --out attestation.json --blocks blocks/

# 3. verify from the manifest alone (no keys directory, no policy path)
zkagent verify-bundle --manifest attestation.json --blocks blocks/ --now 1600 --seen seen.json
```

`publish` uploads nothing. It writes `blocks/<cid>.block`, one file per artifact.

## Putting the blocks on IPFS for real

The CIDs are standard CIDv1 raw sha2-256, so a normal node accepts them. To keep
the CIDs identical to the ones in the manifest, add with raw leaves and CIDv1:

```bash
ipfs add --raw-leaves --cid-version 1 -r blocks/    # should print the same CIDs
```

`--only-hash` prints the CID without adding, which is the right way to check
before publishing. A verifier with no node can then fetch through a gateway:

```rust
let source = zkagent_ipfs::GatewaySource::new("https://ipfs.io/ipfs");
zkagent_service::verify_bundle(&manifest, &source, Some(now), None)?;
```

`GatewaySource` requires the `gateway` feature and an HTTP client; the gateway is
not trusted, which is why the re-hash exists. The read is also **bounded**: 64 MiB
per block by default (`GatewaySource::with_max_block_bytes`), because an untrusted
gateway can otherwise answer with an unbounded body and exhaust the verifier
before the manifest's size check ever runs.

This path is covered by `crates/zkagent-ipfs/tests/gateway.rs` and
`crates/zkagent-service/tests/gateway.rs`, which drive a real HTTP server on
loopback (a real Groth16 proof included, and no mock of the transport — the
transport is the thing under test). CI builds and tests with `--all-features`,
because a feature-gated path that nothing compiles is a claim, not a mechanism.

## What is published, and what is not

| Artifact | Published | Why |
|---|---|---|
| verifying key | yes | it is the circuit identity |
| signed policy | yes | it is the authorisation, and it is public by design |
| receipt | yes | it is the public claim |
| proof | yes | it is the thing being checked |
| **actions (the witness)** | **no** | never written to the manifest, never hashed, never stored |

The private witness is used at publish time only to measure the circuit shape.
`publish` takes `--actions` for that reason and stores nothing from it.

## Threat model

| Attack | Outcome |
|---|---|
| a gateway returns different bytes | refused: re-hash mismatch, naming the artifact |
| a gateway returns an unbounded body | refused: block size cap (64 MiB default) |
| a block is truncated | refused: length mismatch, named by artifact |
| a manifest from another circuit | refused: `format_version` mismatch |
| a hostile manifest names a path (`../etc/passwd`) | refused: every CID is parsed before any fetch, so no request leaves the process |
| a valid bundle replayed | refused: `--seen` ledger (as with plain `verify`) |
| wrong verifying key paired with a real proof | refused: the vk's CID is part of the manifest |

Not covered: **availability**. If no node has the blocks, verification cannot
happen. That is a fetch failure (exit 2), not a rejection, and the distinction
matters: "could not verify" is not "verified false".

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ACCEPT |
| 1 | REJECT: the bundle was fetched, its hashes matched, and verification failed |
| 2 | could not verify: a block is missing, a hash does not match, or a file will not parse |
