# zkagent

**Zero-knowledge attestation of AI agent executions.**

An AI agent should be able to prove that what it did stayed inside the limits a
human gave it — **without publishing what it did**. `zkagent` is a Rust
implementation of that primitive:

* a **human** signs a *policy* (caps, expiry, chain, allow-list);
* an **agent** executes inside it and publishes a *receipt* (total, count, time,
  chain);
* the agent attaches a **Groth16 proof** that some set of actions exists which
  explains that receipt and respects that policy;
* a **verifier** checks the human's signature, the receipt binding, and the
  proof — and learns nothing about the individual actions.

```
human ──sign policy──▶ policy + signature ─────────────┐
                                                       ▼
agent ──executes──▶ private actions ──prove──▶ receipt + proof
                                                       │
verifier ◀─────────────────────────────────────────────┘
   "an execution inside this policy produced this receipt"
   (which actions? not disclosed)
```

## Why this is not another "AI guardrails" wrapper

Guardrails inspect an agent's traffic and trust the inspector. A ZK receipt
trusts nothing: the verifier does not need to see the traffic, the tool calls or
the payloads, and the agent cannot produce a receipt for an execution it did not
perform inside the policy.

## Status

**Private development.** Working end-to-end on BN254/Groth16: circuit, prover,
verifier, CLI, and a test suite that includes the negative cases (over-cap,
disallowed target, expired, tampered receipt, wrong key, wrong verifying key).
See `docs/ARCHITECTURE.md` for the design, the threat model, and what is
deliberately *not* claimed.

Not yet: an on-chain verifier, a multi-party trusted setup, agent-framework
integration.

## Quick start

```bash
cargo test                 # unit + end-to-end + negative controls

# 1. circuit-specific trusted setup (development only — see the warning below)
cargo run -- setup --seed 7 --out keys/

# 2. a human authorises a policy
cargo run -- policy \
  --max-amount 1000 --max-per-action 300 --expires-at 2000 \
  --chain-id 1 --targets 3,7,9 --authority-key authority.hex --out policy.json

# 3. the agent proves its execution (private witness lives here)
cat > receipt.json <<'JSON'
{"total_amount": 400, "action_count": 2, "completed_at": 1500, "chain_id": 1, "execution_id": 1001}
JSON
cat > actions.json <<'JSON'
[{"target": 3, "amount": 250, "trace_digest": 11},
 {"target": 7, "amount": 150, "trace_digest": 22}]
JSON
cargo run -- prove --keys keys/ --policy policy.json \
  --receipt receipt.json --actions actions.json --out proof.json

# 4. anyone can verify
cargo run -- verify --keys keys/ --policy policy.json \
  --receipt receipt.json --proof proof.json --now 1600
# -> ACCEPT   (exit 0; REJECT prints the reason and exits 1)
```

## ⚠ Trusted setup

Groth16 requires a circuit-specific trusted setup. `zkagent setup` performs one
**locally and single-party**, discarding the toxic waste. That is acceptable for
development and for an operator who is the only party who could exploit a bad
setup — it is **not** a public ceremony. Do not deploy a setup produced this way
to a public network. See `docs/ARCHITECTURE.md` §"Trusted setup".

## Layout

| Path | What it is |
|---|---|
| `crates/zkagent-core` | policy, receipt, canonical encoding, Ed25519 authority, replay state |
| `crates/zkagent-proofs` | the Groth16 circuit and the prover |
| `crates/zkagent-verifier` | pure verification: a proof and inputs become a verdict, no state |
| `crates/zkagent-service` | **the four operations over files** — the layer an embedder uses |
| `crates/zkagent-cli` | the `zkagent` command line (a thin shell over the service) |
| `crates/zkagent-mcp` | an MCP server, so any agent harness can drive the same operations |
| `examples/tauri-plugin` | embedding zkagent in a Tauri v2 app |
| `docs/ARCHITECTURE.md` | design, threat model, decisions, roadmap |
| `docs/EMBEDDING.md` | how to embed it: plain Rust, Tauri, MCP, CLI |
| `docs/research/` | the cited research corpus this was built from |
| `tools/loop.py` | the loop-learning ledger and its consumer |
| `docs/loop-ledger.jsonl` | append-only record of what was tried and what happened |

## Design decisions worth knowing before you read the code

1. **The policy is public; the execution is private.** An earlier draft hid the
   policy inside the commitment, which forces an in-circuit hash. Hiding the
   *execution* is the property that matters, and it needs no hash at all.
2. **Every compared integer is a 64-bit `UInt`.** Without the bit
   decomposition, a prover can supply `p − k` and pass a "sums to zero" check
   while real value moved.
3. **Allow-list padding repeats a real target.** A sentinel value would be a
   value an action could match directly, which silently widens the allowed set.
4. **arkworks 0.5.x, not 0.6.x.** 0.6.0 moved `AllocVar`/`UInt`/`Boolean` into
   a new `ark-r1cs-std` and removed `ark_relations::r1cs`; see
   `docs/ARCHITECTURE.md` §"Substrate".
5. **The public-input order has exactly one definition** (`public_inputs()`), and
   it is the circuit's **allocation** order — not the semantically tidy one.
   `execution_id` is allocated after the allow-list for that reason; putting it
   next to the other receipt scalars permutes the vector and every honest proof
   fails with `InvalidProof`. A test compares the constraint system's
   `instance_assignment` to `public_inputs()` element by element.
6. **Every receipt carries a non-zero `execution_id`**, and it is a public
   input. Without it two identical executions produce identical public inputs,
   so a proof could be re-presented forever. The circuit refuses `0`, and
   `zkagent verify --seen ids.json` keeps the set of ids it has already
   accepted, so a replay is refused rather than re-accepted. A state file that
   cannot be parsed fails **closed**: an unreadable ledger must never be read as
   "nothing seen yet".
7. **The authority key is real key material, not a seed.** `policy
   --authority-key <file>` generates a 32-byte Ed25519 secret with the OS CSPRNG
   on first use (mode 0600, `create_new`) and reuses it afterwards; `--seed` is
   the demo path and warns loudly. With neither flag the command refuses: an
   authorisation root must never come from a silent default. The signature is
   checked **before** the public-input binding, so a tampered policy is reported
   as `policy signature is not valid for this policy` rather than as a generic
   mismatch that hides the forgery.

## Embedding it

`zkagent` is a library first. The CLI is one shell; the MCP server is another;
a Tauri app is a third. They all call the same four operations in
`zkagent-service`, so they cannot disagree about what a proof means.

```rust
// one dependency
let outcome = zkagent_service::verify(&keys, &policy, &receipt, &proof, Some(now), Some(&seen))?;
assert!(outcome.accepted());
```

See `docs/EMBEDDING.md` for the plain-Rust, Tauri, MCP and CLI paths, and for
the rules a host inherits (no printing, no global state, no panics, fail-closed
on unreadable state).

## Contributing and governance

| File | What it is |
|---|---|
| `CONTRIBUTING.md` | the loop: one unit, claim, RED then GREEN, what "done" means |
| `GOVERNANCE.md` | soundness outranks everything; judged by the work; credit is by work |
| `SECURITY.md` | private disclosure, and what never enters the repo |
| `docs/TESTING.md` | the tiers, and the tests that may never be skipped |
| `.github/pull_request_template.md` | the RED/GREEN + soundness statement a PR must carry |
| `tools/leaderboard/` | the contributor board, ranked by merged PRs |

The contributor leaderboard publishes to the `leaderboard` branch every four
hours. It credits the **originating** author even when a maintainer re-lands the
work (a `Co-Authored-By:` trailer in at least half the commits, or anywhere in
the PR body). Those attribution rules are unit-tested, because a rule that
silently reassigns credit is worse than no leaderboard at all.

## Licence

MIT — see `LICENSE`.
