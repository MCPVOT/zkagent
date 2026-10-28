# zkagent — Research Architecture

**Status:** private development, v0 working end-to-end on BN254/Groth16.
**Written:** 2026-10-27.
**Scope:** this document is the *architecture*, not a summary. It records what was
researched, what was decided, what was built, what was measured, what is
deliberately excluded, and what would make each claim wrong.

Companion research corpus (all cited, per-claim URLs):

| File | Covers |
|---|---|
| `docs/research/01-proving-stack-landscape.md` | Rust proving systems: what is alive, what is abandoned, which substrate to pick |
| `docs/research/02-agent-human-security-primitive.md` | The problem space, prior art, EVM standards, five candidate designs |
| `docs/research/03-ecosystem-intel.md` | Dated ecosystem timeline, podcast digest, 2026 papers, who to watch |
| `docs/research/04-rust-repo-audit.md` | Reuse audit of the concrete repos and licences |
| `docs/research/05-rust-implementation-design.md` | API-level design spec, measured probe numbers |

---

## 1. The one-sentence thesis

**An agent's compliance with a human's instructions can be made a cryptographic
fact rather than a promise — and the interesting thing to hide is the execution,
not the policy.**

Every design decision below follows from that inversion. Most "AI guardrail"
products prove the *policy* is enforced by watching traffic; that moves trust to
the watcher. A ZK receipt moves trust to arithmetic: the verifier needs nothing
but the policy, the receipt, and 128 bytes of proof.

---

## 2. What the research actually established

### 2.1 The market is forming around exactly this primitive

* **zkGolf** (Zero Knowledge podcast, 2026-10-21) is a competition "challenging
  humans **and AI agents** to build the most efficient, formally verified ZK
  circuits", built on zkSecurity's **Clean** framework for writing and formally
  verifying circuits in Lean. The framing — AI agents as *ZK circuit authors* —
  is the same bet this project makes from the other side (AI agents as *ZK
  circuit users*).
* **ICME Labs' "PreFlight"** is marketed as "Verifiable AI Agent Controls"
  (icme.io). This is the closest commercial neighbour: it validates the problem
  and confirms nobody has published the primitive as an open Rust crate.
* **ZKP2P → Peer** (podcast, 2026-09-09) built ZK email proofs to connect Venmo
  payments to on-chain state. Proof-of-payment-without-disclosure is the same
  shape as proof-of-execution-without-disclosure.
* The **zkMesh/EF zk-API** line of work (and our own `MCPVOT/zkapi`, Rust,
  blind Schnorr credential auth with a Pedersen state-anchor chain) shows the
  "unlinkable credential for metered API usage" pattern is already being built
  with the Ethereum Foundation. `zkagent` deliberately does **not** duplicate
  that; it attests *execution*, not *authorisation to spend credits*.

### 2.2 The substrate answer is not "use the newest arkworks"

The single most consequential finding of the research pass, and the one most
likely to burn a week if missed:

**arkworks 0.6.0 is a breaking rewrite.** `ark-relations-0.6.0` no longer has an
`r1cs` module at all — it is `sr1cs` + `gr1cs` — and `AllocVar`, `Boolean`,
`UInt`, `ToBits` and the whole gadget vocabulary moved into a separate
`ark-r1cs-std` crate with changed semantics (`enforce_constraint` now takes a
predicate label; `enforce_r1cs_constraint` is the drop-in for the old call;
`create_random_proof` no longer exists; `generate_random_parameters_with_reduction`
returns only a `ProvingKey`). Every tutorial and most of the ecosystem's example
code targets the old shape, so an engineer following docs writes code that does
not compile against 0.6.

Decision: **pin arkworks 0.5.x** (`ark-groth16 0.5.0`, `ark-relations 0.5.1`,
`ark-r1cs-std 0.5.0`, `ark-bn254 0.5.0`, `ark-crypto-primitives 0.5.0`). It is
the mature line with the classic R1CS API, `CmpGadget`, `UInt`, and a
`r1cs` feature on groth16. This is a *deliberate downgrade* from latest, and it
is recorded here so a future session does not "helpfully" bump it.

Two further substrate facts that shaped the code:

* **`ark-bn254` needs the `curve` feature.** With `default-features = false`,
  `Bn254` and `Fr` simply do not exist, and the error is `no Bn254 in the root`.
* **`ark-snark` has no `std` feature**, so `features = ["std"]` fails to resolve
  at all — a resolution error, not a compile error, which reads like a broken
  registry.

### 2.3 Rejected substrates, with reasons

| Substrate | Why not (for v0) |
|---|---|
| **SP1 / RISC Zero** | A zkVM proves *arbitrary computation*, which sounds ideal until you price it: proving a general program on 2 vCPU / 3 GB is minutes-to-hours, and the statement here ("8 bounded actions, one sum, one membership") is small and fixed. **Measured constraint: no zkVM can prove on the droplet at all** — SP1 needs ~16 GB (64 GB for a PLONK wrap) and RISC Zero recommends 16 GB, against 3 GB total. A zkVM is the right answer when the thing proved is an interpreter; ours is not. Revisit for v2 if we must prove an actual model forward-pass. |
| **halo2** | Excellent for custom circuits with lookups and it has the only *audited, maintained* PLONKish EVM verifier path — but the ecosystem is fractured and half-dead: `privacy-scaling-explorations` renamed to `privacy-ethereum` and archived, taking halo2 (archived 2026-08-17), halo2curves and snark-verifier with it. The live fork is Axiom's, a 16-star dependency. That is a maintenance hazard for a protocol meant to outlive its authors. |
| **Plonky3** | Transparent setup (no ceremony) is a genuine advantage and it is the most active line — Plonky2 is archived with a deprecation notice pointing here. But `p3-*` is at `0.9.0-rc.2` (no stable API), there is no in-tree recursion, and the EVM verification story is weaker than Groth16's. **The strongest v2 candidate** if the trusted setup becomes the blocker. |
| **Noir / Circom** | A DSL would mean shipping a compiler toolchain and a proving backend; we would own the circuit but not the stack. Not worth it for eight constraints' worth of logic. |

Two further audit facts that bear on later phases, recorded so they are not
rediscovered:

* **`succinctlabs/sp1-contracts` — the actual on-chain SP1 verifier — has no
  LICENCE file at all.** That is a blocking question for any open-source
  protocol planning to depend on it, and it is one more reason the on-chain path
  here is "write a Groth16 verifier against our own vk" rather than "vendor
  someone else's verifier".
* **Proving is now a priced utility**: Boundless reports ~400T cycles/day at
  $0.04 per billion cycles (Jan 2026). Worth pricing against local proving
  before assuming a hosted prover is needed.

### 2.4 The eve-of-build consensus from the repo audit

The reuse audit (`04-rust-repo-audit.md`) found the useful, boring truth:
`arkworks-rs/*` is the only dependency set here that is (a) real source, (b)
permissively licensed (MIT/Apache-2.0), (c) buildable offline once vendored, and
(d) small enough to audit. Everything else was either a monorepo with a
toolchain vendored inside, or a binary distribution.

---

## 3. The gap this fills

Search the ecosystem for "agent execution attestation" and you find three
adjacent things, none of which is this:

1. **zkML / verifiable inference** — proves *what computed* (this output came
   from this model), not *what was permitted*. Useful and complementary; it does
   not answer "did the agent stay inside my limits".
2. **Agent identity / attestation** — proves *who* the agent is (TEE quote, DID,
   signed manifest). Says nothing about whether its actions conformed.
3. **Guardrail middleware** — inspects traffic and blocks. Trusts the inspector,
   logs everything, and cannot be checked by a third party after the fact.

The unoccupied square: **a receipt that a third party can verify, which proves
conformance to a human-signed policy, while disclosing neither the individual
actions nor the tool payloads.** That is what `zkagent` implements.

---

## 4. Protocol specification (v0)

### 4.1 Objects

```
Policy  { max_amount, max_per_action, expires_at, chain_id, allowed_targets[] }
Action  { target, amount, trace_digest }              // PRIVATE
Receipt { total_amount, action_count, completed_at, chain_id }   // public
Proof   { Groth16 proof over the public inputs }
```

### 4.2 Canonical encoding

`Policy::canonical_bytes()` is injective and deterministic:

```
"zkagent.policy.v1" ‖ 0x00
  ‖ max_amount:u64be ‖ max_per_action:u64be ‖ expires_at:u64be ‖ chain_id:u64be
  ‖ len(targets):u32be ‖ target_i:u64be …
```

with `allowed_targets` sorted and deduplicated **at construction**, so
`PartialEq` agrees with the encodings. Tests assert: order-independence,
dedup-invariance, and that changing any single field changes the bytes.

Why this matters: the human signs a hash of these bytes. If two encodings could
represent the same policy, a signature on one would authorise the other.

### 4.3 Public inputs, in order

```
0 max_amount      4 receipt_total
1 max_per_action  5 receipt_action_count
2 expires_at      6..13 allowed_targets[0..8]   (padded by repeating target[0])
3 completed_at    14   execution_id              (anti-replay; must be non-zero)
```

The order is fixed by **allocation order inside the circuit**, and
`public_inputs()` must reproduce it exactly. `execution_id` is allocated last,
after the allow-list, precisely because the vector is ordered by allocation
rather than by meaning — allocating it next to the other receipt scalars (the
natural place) permutes the vector and makes every honest proof fail with
`InvalidProof`. A test asserts the constraint system's `instance_assignment`
equals `public_inputs()` element by element, and it has been verified to fail
when the order is permuted.

`public_inputs(policy, receipt)` in `zkagent-proofs::circuit` is the **only**
definition of this order. A verifier that assembles the vector by hand can
reorder it, and a reordered vector either rejects a valid proof or accepts a
proof about different values.

### 4.4 The constraints the circuit enforces

| # | Constraint | Why it is there |
|---|---|---|
| C1 | `amount_i ≤ max_per_action` for every action slot | stops a single action exceeding its cap |
| C2 | `receipt_total ≤ max_amount` | stops the aggregate exceeding the total cap |
| C3 | `max_per_action ≤ max_amount` | rejects an incoherent policy rather than proving against nonsense |
| C4 | `∏_j (target_i − allowed_j) = 0` | allow-list membership, algebraically |
| C5 | `Σ amount_i = receipt_total` | the receipt is *explained* by the actions |
| C6 | `#(amount_i ≠ 0) = receipt_action_count` | the claimed count is the real count |
| C7 | `completed_at < expires_at` | the execution happened while the policy was live |
| C8 | `execution_id ≠ 0` | an id-0 receipt silently disables a verifier's anti-replay set |

C4 deserves a note: in a field, a product is zero exactly when one factor is
zero, so the product constraint is precisely "the target equals some allowed
slot". It needs no boolean disjunction gadget (this arkworks line only exposes
`or` on the allocated boolean variant) and it is cheaper and easier to audit.

### 4.5 Verification order (and why each step exists)

1. **Format version** — a proof from a different circuit must not be
   misinterpreted byte-for-byte.
2. **Public-input binding** — recompute the inputs from *our* policy and
   receipt and compare to the artifact's. Without this, a valid proof about
   different values replays.
3. **Authority signature** — Ed25519 over `SHA256(domain ‖ canonical policy)`.
   Without it, an agent mints its own generous policy and proves conformance to
   that.
4. **Chain + freshness** — receipt chain equals policy chain; the policy was not
   expired at completion; a receipt dated in the verifier's future is refused.
5. **Groth16 verification** — the part that carries the private execution.

Steps 2–4 are cheap and off-circuit, and they are *not* redundant with the
proof: the circuit cannot see the human's signing key and cannot express "this
specific policy is authorised".

---

## 5. Threat model

### 5.1 Assets

* The human's authority (nobody else may widen the caps).
* The agent's execution privacy (which tools, what payloads, what per-action
  amounts).
* The verifier's ability to reject a false conformance claim.

### 5.2 Adversaries considered

| Adversary | Capability | What stops it |
|---|---|---|
| **Malicious agent** | Owns the witness, wants a receipt for an out-of-policy execution | The circuit. There is no witness that satisfies C1–C7 for an execution that broke them, assuming the proof system is sound. |
| **Malicious agent (policy forgery)** | Mints its own policy with huge caps | Step 3: the verifier only accepts a policy signed by the human's key. |
| **Replay across executions** | Re-presents an old proof against a new receipt | Step 2 binds the public inputs; a different receipt changes `receipt_total`/`completed_at`, so the old proof no longer matches. |
| **Replay across policies** | Presents a proof about policy A as if for policy B | Step 2 again: the inputs include the policy fields. There is no nonce in v0 — see §5.4. |
| **Wrong verifying key** | Ships a proof under a key it controls | The verifier uses the key it trusts; a foreign key is rejected (tested). |
| **Curve-order / wraparound attack** | Supplies `amount = p − k` so a "sum" check passes | Every compared integer is a 64-bit `UInt` bit-decomposition, not a bare field element. |
| **Allow-list widening via padding** | Exploits unused slots | Padding repeats a real target instead of using a sentinel; a sentinel would be a value an action could match directly. |

### 5.3 What the proof does NOT establish

This section exists because a ZK system that overstates itself is worse than no
system.

* **It does not prove the actions actually happened.** It proves that *if* a set
  of actions existed with these properties, the receipt follows. Binding the
  proof to real-world side effects needs an oracle or a TEE that signs the trace
  — out of scope for v0.
* **It does not hide the receipt.** Total spend, action count, completion time
  and chain are public by design; a verifier needs them.
* **It does not prevent a *true-but-hostile* execution.** An agent may legally
  spend its whole cap on an allowed target. Policy design is the human's job;
  arithmetic only enforces what was written.
* **It does not survive a compromised human key.** Whoever holds the signing key
  can authorise any policy.
* **`trace_digest` is bound but unconstrained in v0.** It is a witness value
  that a v2 will bind to a Merkle root of the transcript. Today it proves
  nothing on its own — stated plainly rather than implied. PACE [2608.17220]
  calls exactly this a *field provenance* defect, and CVA [2607.21325] names
  execution binding as the open problem in the field. Two independent research
  slices flagged it in the same review, which is why it is stated twice.

### 5.4 Known gaps to close before "public"

1. **~~No nonce / execution id.~~ CLOSED.** `Receipt` now carries an
   `execution_id`, it is a public input, and the circuit refuses the reserved
   value `0`. Two identical executions no longer produce identical public
   inputs, so a proof cannot be re-presented as a new execution. Freshness is
   stateful, so it is the verifier's job, and it is now **mechanism rather than
   prose**: `zkagent_core::SeenExecutions` is a persistent, sorted, atomically
   written set of accepted ids, and `zkagent verify --seen ids.json` refuses an
   id it has already accepted. It **fails closed** — a state file that exists but
   cannot be parsed is an error, never an empty set, because otherwise
   "truncate the file" would be the replay attack. Limits, stated: the set only
   grows (no pruning/expiry) and it assumes a single writer.
2. **No revocation.** An expired policy stops new receipts, but there is no
   "revoke now" path. Needs a revocation commitment the verifier checks. The
   implementable shape identified in `docs/research/09`: an epoch-rooted sparse
   Merkle non-membership proof plus a public status epoch (ShadowPath
   [2608.19937]) with a reliance-time freshness rule (ChainIT [2610.22899]). The
   epoch counter itself is free as a public input; the tree is the cost.
3. **Single-party trusted setup.** See §6.
4. **No on-chain verifier.** Groth16 on BN254 is EVM-verifiable in principle;
   the Solidity verifier is not written yet (and arkworks 0.5 does not emit one,
   so this is a real piece of work — see §10).
5. **Ed25519 signature is not checked on-chain** without a precompile. Off-chain
   verification is the v0 model.
6. **~~Authority key material.~~ CLOSED in v0.** See §5.5.

### 5.5 Authority key handling

`Authority` previously had exactly one constructor, `from_seed(u64)`, and the CLI
defaulted to `--seed 99`. Every policy the tool produced was therefore signed by
the *same 64-bit-derived key*, and anyone could reproduce it — so anyone could
forge a policy for any operator who used the default. The docs said production
"loads key material from a KMS or an encrypted, permission-tight file", but no
code path existed to do that: the safe option was documentation.

The shipped model:

| Path | Constructor | Use |
|---|---|---|
| `policy --authority-key <file>` | `Authority::generate()` on first run, then `from_secret_bytes` | **production** |
| `policy --seed <n>` | `from_seed` | tests and the demo walkthrough only — prints a warning |

- The key file is created with `create_new` (never silently overwriting a key
  that has already signed policies) and `0600` on Unix, set at open time so it
  is never briefly world-readable.
- A key file that is group- or world-readable produces a warning rather than a
  hard failure: an operator may have other protections, but silence would hide a
  real exposure.
- `policy` with **neither** flag is refused (exit 2) rather than defaulting. A
  silent default here is a silent vulnerability, and an authorisation root is
  exactly the wrong place to be helpful.
- `Authority::generate` returns a `Result`. It never falls back to a predictable
  seed when the OS CSPRNG fails — that failure is precisely when nobody is
  watching.

---

## 5.6 What the literature says about these gaps

Four independent research slices (`docs/research/06..09`) converged on the same
three gaps. That convergence is why they are stated as structural rather than as
a to-do list.

1. **Execution binding.** A proof binds the statement that was written, not the
   behaviour that occurred. Every agent-domain paper in `06` proves one action
   is compliant; PACE [2608.17220] shows the field provenance defect; CVA
   [2607.21325] names execution binding as the open problem. Our unconstrained
   `trace_digest` is an instance of it.
2. **Completeness.** Omission is the attack that survives single-action proofs.
   Our receipt's `count` + `total` is an *arithmetic* completeness argument
   relative to the receipt — not completeness relative to reality, because the
   receipt's own provenance is trusted. zkLedger (NSDI'18) is the framing worth
   borrowing; the scoping caveat is ours to keep.
3. **Revocation.** No A2A-family specification defines it (`revok` appears once
   in the A2A spec, about keys). The implementable path is in §5.4 item 2.

What this corpus does **not** establish: that the design is novel, that a
protocol will adopt a ZK binding, or that any borrowed benchmark transfers to
this tree. `docs/research/README.md` records the provenance of every number and
the three caveats above.

---

## 6. Trusted setup, stated honestly

Groth16 is circuit-specific: someone must run a setup, and whoever keeps the
toxic waste can forge proofs. `zkagent::prover::setup` runs a **single-party**
setup and drops the randomness at the end of the function. Consequences:

* Fine for development, tests, and a single-operator deployment where the
  operator is the only party who could exploit a bad setup.
* **Not** fine for a public deployment where an anonymous prover must be
  prevented from forging receipts. That needs a multi-party ceremony, a
  universal-setup system (Plonky3/Marlin), or a transparent proof system.

The README and the binary both say this; the point of saying it twice is that a
quiet single-party Groth16 setup is the most common way a "ZK" product is
unsound in practice.

---

## 7. Measured behaviour

Measured on this implementation, not estimated:

| Metric | Value | How |
|---|---|---|
| constraints | **3333** | `constraint_count_is_sane` test (`--nocapture`) |
| public inputs | **15** | asserted by the same test (`num_instance_variables == 16`, incl. the constant-one slot) |
| proof | **128 B** (2 170 B JSON artifact) | `proof.json` |
| verifying key | **712 B** | `keys/vk.bin` |
| proving key | **649 KB** | `keys/pk.bin` |
| binary | 2.1 MB | release build |
| end-to-end | **ACCEPT** | real CLI run: setup → policy → prove → verify |
| setup (release, parallel) | 0.19 s | wall clock |
| prove (release, parallel) | **0.43–0.64 s** | 5 runs |
| prove (release, serial) | 1.02–1.16 s | 3 runs, `parallel` feature off |
| verify (release) | **0.048–0.091 s** | 5 runs, incl. ~40 ms process startup |

Rayon (`ark-groth16/parallel`) is worth ~2× on proving and nothing on
verification, so it is enabled — with the note that a memory-constrained box can
build serial instead. Raw runs and the stale-binary trap that produced a 28 936 B
vk once: `docs/MEASUREMENTS.md`.

An independent implementation probe of the same statement shape
(`05-rust-implementation-design.md`) measured a smaller circuit (2162
constraints — it predates the `pub_u64` range-binding, which is what makes this
one 3265) and its release-profile timings are the useful reference for what
release optimisations buy:

| Metric | Laptop (release) | Droplet 2 vCPU (release) |
|---|---|---|
| setup | 107 ms | 396 ms |
| prove | 161 ms | 382 ms |
| verify | 2.09 ms | 3.48 ms |
| peak RSS | — | 29 MB |

**The argument for Groth16 over a zkVM here:** a receipt costs a fraction of a
second to produce on a $12/month droplet and a couple of milliseconds to check,
with a 128-byte proof and a sub-megabyte key. A zkVM proof of a general program
is minutes and hundreds of megabytes for the same statement.

Constraint count is guarded by a test with an explicit expected band, so a change
that quietly allocates per-bit public inputs (which happened — see §12 and the
`MalformedVerifyingKey` failure) fails CI instead of producing a mystery.

---

## 8. Implementation map

```
crates/zkagent-core        policy.rs   canonical encoding, invariants, tests
                           receipt.rs  violations, reference semantics
                           authority.rs Ed25519 policy signature
                           replay.rs   persistent set of accepted execution ids
crates/zkagent-proofs      circuit.rs  C1–C8, public-input order
                           prover.rs   setup, prove, artifact format
crates/zkagent-verifier    lib.rs      pure verification: steps, verdicts
crates/zkagent-service     ops.rs      the four operations over files
                           wire.rs     the on-disk artifact formats
                           error.rs    ServiceError: every failure carries a path
crates/zkagent-cli         main.rs     the `zkagent` CLI (a thin shell)
crates/zkagent-mcp         lib.rs      MCP JSON-RPC handler + tool schemas
                           main.rs     the stdio loop
examples/tauri-plugin      lib.rs      embedding in a Tauri v2 app
tools/loop.py              the learning ledger + its only consumer
```

Deliberate structural choices:

* **core has no groth16 dependency.** A verifier-only deployment, or the JSON
  tooling, does not need to link the prover.
* **the verifier is a separate crate from the prover.** Same reason.
* **the service layer is the ONLY place the operations live.** The CLI, the MCP
  server and an embedded host all call it. A rule that lives in two shells is a
  rule that will drift, and the drift is always in the security-relevant
  direction: one shell forgets the replay gate, another forgets that an
  unreadable state file must fail closed.
* **the verifier stays stateless.** Freshness is a property of the verifier's
  memory, so the pure verifier has none and the service layer owns the
  seen-set. That split keeps `verify()` usable inside a host that manages its
  own state, and keeps it impossible to forget the fail-closed rule.
* **`public_inputs()` is the single source of the input order.**
* **`ProofBytes` carries `format_version`.** A mismatch is a loud rejection, not
  a byte-level reinterpretation.

### Test inventory (the part that makes this a protocol and not a demo)

Happy path: policy canonicalisation, signature round-trip, circuit satisfaction,
end-to-end prove→verify.

Negative controls, each asserted to **fail**:

| Test | Must fail because |
|---|---|
| `per_action_overrun_fails` | amount 301 > cap 300 |
| `total_over_cap_fails` | three compliant 300s exceed a 1000 total |
| `disallowed_target_fails` | target 4 is not in {3,7,9} |
| `expired_execution_fails` | `completed_at == expires_at` (half-open) |
| `action_count_mismatch_fails` | claims 3 actions, supplied 2 |
| `sum_mismatch_fails` | receipt 401 ≠ 250+150 |
| `tampered_receipt_is_rejected` | public-input binding |
| `wrong_authority_key_is_rejected` | signature under another key |
| `wrong_vk_is_rejected` | proof under a key the verifier does not trust |
| `format_version_mismatch_is_rejected` | artifact from another circuit |
| `a_flipped_signature_bit_is_rejected` | one-bit signature mutation |
| `malformed_key_or_signature_is_a_rejection_not_a_panic` | hostile input must not crash a verifier |
| `future_receipt_is_rejected` | receipt dated after the verifier's clock |

A protocol whose only test is the happy path is a demo. The negative half is the
specification.

---

## 9. The operator protocol — a tool for agents *and* humans

The protocol is only useful if both parties can actually drive it. v0 ships as a
CLI with machine-readable artifacts, which is the lowest-friction integration
surface for an agent:

```bash
zkagent setup   --seed N --out keys/          # operator, once
zkagent policy  --max-amount … --out policy.json   # human
zkagent prove   --keys … --policy … --receipt … --actions … --out proof.json   # agent
zkagent verify  --keys … --policy … --receipt … --proof … --now T  # anyone
```

Exit codes are part of the contract: `0` accept, `1` reject, `2` usage/IO. A
calling agent branches on the status instead of parsing prose.

The human-facing side is deliberately a *file plus a signature*: `policy.json`
contains the policy, the authority public key, and the signature. That is
inspectable, diffable, and can be committed to a repo or attached to an email —
no service to trust and no dashboard to log into.

**Natural next integration (not built):** expose `prove` as a Hermes/MCP tool so
an agent can emit a receipt as part of its own tool-use loop, and `verify` as a
tool a supervising agent calls on a subordinate's receipt. That turns "I did it"
into "here is a proof I did it inside your limits", inside the same agent
runtime that performed the work.

---

## 10. Fleet analysis — what we can build with what we actually have

Measured on 2026-10-27, not assumed.

### 10.1 The droplet (`hoodbot@100.111.194.19`, hostname `hoodbot-brain`)

| Fact | Value | Consequence |
|---|---|---|
| CPU / RAM | 2 vCPU / ~3 GB | proving must stay single-threaded and < ~1 GB peak |
| Disk | 20 GB free | a 479 KB proving key is fine; a zkVM's multi-GB artifacts are not |
| Rust | 1.98.1 | newer than the laptop's 1.97.1; same code builds on both |
| cargo registry cache | 444 MB | vendorable; offline builds are already the norm there |
| Firecrawl | CLI 1.26.3, working (scraped zk podcast live) | research passes are cheap and real |
| Hermes profiles | 7 (hoodbot, bounty, solana, storemoat, sentinel, mcpvot, jevprune-test) | a verification service can live in its own profile |
| cron | 15 jobs under `hoodbot`, 2 under `bounty`, 1 each under sentinel/storemoat | the scheduling substrate already exists |
| gateway | `hermes-brain.service` + multiplexed `hermes-gateway-host.service` | two gateways already contend for profiles — do not add a third |

**What this means:** the droplet can *prove and verify* this protocol today. It
cannot host a zkVM prover for a general program, and it should not host another
gateway. The realistic deployment shape is: `zkagent verify` as a tiny CLI called
by an existing cron job or HTTP handler in an existing profile — not a new
service with its own gateway.

### 10.2 The Hermes profiles (laptop, read-only survey)

| Profile | Model | Skills | MCP servers | Notes relevant to ZK work |
|---|---|---|---|---|
| `mcpvot` | deepseek-v4.1-flash (OpenRouter) | 42 | 106 | this work; largest tool surface |
| `ofcrm` | deepseek-v4.1-flash | 29 | 29 | separate ecosystem — not a ZK target |
| `organix` | minimax-m3.1-flash-free | 23 | 19 | separate ecosystem |
| `polloriko` | deepseek-v4.1-flash | 15 | 10 | separate ecosystem |
| `vot` | deepseek-v4.1-flash (openrouter-vot) | 21 | 43 | separate ecosystem |
| `jevprune-test` | deepseek-v4.1-flash | 12 | 108 | throwaway; do not build on it |

**Honest reading:** none of the other profiles are ZK workstreams and must not be
mixed into this one. The only cross-profile fact that matters is capability
inventory — and it says the same thing as the droplet: the estate has plenty of
*agent runtime* and no *proof infrastructure*. `zkagent` is that missing layer,
and it is deliberately a standalone Rust workspace so it does not entangle any
of the client ecosystems.

### 10.3 Why a separate repo rather than a folder in an existing one

The three client ecosystems are hard-isolated by standing rule, and the ZK work
is a fourth thing that will be **published**. A separate private repo
(`MCPVOT/zkagent`) means: no secret can leak from a client project into a repo
that later becomes public, and the public history starts clean. A pointer note
in `mcpvot-app/docs/research/zk/` keeps it discoverable from the main research
tree without copying any content.

---

## 11. Roadmap

### v0 — now (private) ✅
* circuit C1–C7, prover, verifier, CLI, negative test suite
* loop-learning ledger with a real consumer
* research corpus with per-claim citations

### v0.5 — harden (still private)
* **nonce / execution id** in policy + receipt (kills the replay gap in §5.4)
* **revocation commitment** checked by the verifier
* `trace_digest` bound to a Merkle root of the transcript (makes it mean
  something)
* fuzz the artifact parser (hostile JSON must be a rejection, never a panic)
* CI: build + test on Linux and Windows, `cargo deny` for licences, secrets scan

### v1 — public
* multi-party trusted setup *or* migration to a transparent system
* prebuilt binaries + crates.io publication
* a Solidity Groth16 verifier + a Foundry test that verifies a real receipt
  on-chain (arkworks 0.5 does not emit one; write it against the exported vk)
* an MCP/Hermes tool so agents emit and check receipts in-loop
* docs site with the threat model front and centre

### v2 — research
* **hidden policy**: move the policy into the witness with an in-circuit
  Poseidon commitment (this is where the soundness danger is — see §12)
* **zkVM path** for statements that need an interpreter (e.g. "this exact tool
  call sequence ran")
* **TEE/ZK hybrid**: TEE attests the trace happened, ZK attests it was in-policy

---

## 12. The soundness trap this project already fell into once

Recording this because it is the most transferable lesson in the repo.

The first circuit draft hid the policy inside the commitment, which requires
hashing the policy **in-circuit**. The draft's SHA-256 gadget computed its
rotations by reading `field.value()` and returning a constant:

```rust
fn rotr(x: &FpVar<F>, n: usize) -> FpVar<F> {
    let word = u32::from(v.value()?);      // <-- the prover's value
    FpVar::constant(word.rotate_right(n))  // <-- a constant, no constraint
}
```

For an honest prover it produces the right digest; for a dishonest one it
constrains **nothing**. The test suite would have passed, the proof would have
verified, and the protocol would have been worthless. It looks like a hash
gadget and it is a comment.

**The fix was a design change, not a better hash:** make the policy public and
the execution private. That removes the in-circuit hash entirely and, with it, a
whole class of bugs.

Transferable rules:

1. **A gadget that reads a witness value to compute a constant is not a
   constraint.** Any `value()?` inside circuit construction is a soundness
   question: is the result constrained, or merely computed?
2. **Prefer removing a primitive to implementing it.** Every hash gadget you do
   not write is a soundness bug you cannot have.
3. **A test that only checks the honest path cannot detect this class at all.**
   The negative tests are not decoration; they are the only thing that would have
   caught the *next* version of this mistake.

---

## 13. Loop learning — how this project learns without a report nobody reads

`tools/loop.py` is an append-only ledger (`docs/loop-ledger.jsonl`) plus
**exactly one consumer**, `loop.py next`, which derives the next actions from the
aggregate.

```bash
python tools/loop.py record --phase circuit --action "…" --result fail --note "…"
python tools/loop.py status     # counts per phase, fail streak
python tools/loop.py next       # the consumer: evidence-backed next actions
```

Design rules, each learned from a failure in this estate:

1. **A producer with no consumer is a report, not a loop.** `next` reads the
   ledger; if you add a field, add the branch that consumes it.
2. **A corrupt ledger must fail loudly** (exit 1), never skip rows — silently
   skipping is how a loop reports a healthy history it does not have. Tested with
   a deliberately corrupt file.
3. **A failure streak changes the recommendation.** Three consecutive failures in
   one phase produce "stop and re-read the soundness checklist", not "try again".
4. **The consumer must be able to disagree with the operator.** On first real
   run it correctly said *"Circuit passes but the verifier has no rows: a circuit
   proven to satisfy its own witness is not a protocol that verifies"* — which was
   true, and was the next thing done.

The skill `zk-agent-attestation` wraps this: it instructs a session to run
`loop.py next` **first** and record **after every experiment**, so the loop is
closed by the workflow rather than by good intentions.

---

## 14. Open questions

1. **Where does the trace oracle live?** Without binding to real side effects,
   the receipt proves a *consistent story*, not that the story happened. TEE
   signing, a trusted executor, or on-chain event correlation are the options;
   each has a different trust story.
2. **Is the policy really public?** v0 says yes. If a deployment needs the caps
   hidden from the verifier, that forces the in-circuit commitment (§12) and the
   soundness risk that comes with it.
3. **What is the right nonce scope?** Per (policy, agent, execution) vs per
   policy. Affects whether a receipt is a bearer token.
4. **Does the on-chain verifier pay for itself?** Groth16 verification is ~200k
   gas on EVM. Worth it only if a contract must act on the receipt.
5. **Which agent runtimes can emit a receipt honestly?** An agent that controls
   its own witness can always lie about *what it did*; the guarantee is only
   that a lying receipt cannot be produced for an out-of-policy execution. Making
   the honest path the easy path (a tool wrapper that records as it executes) is
   the actual adoption problem.

---

## 15. Sources

Primary sources are cited inline throughout `docs/research/`. The load-bearing
ones for the decisions in this document:

* arkworks 0.6.0 breaking changes — `ark-relations-0.6.0/src/lib.rs`,
  `src/gr1cs/*`, `ark-groth16-0.6.0/src/{prover,verifier,generator}.rs` (read
  from the vendored crate sources, not from docs).
* arkworks 0.5.x API used by this crate — `ark-r1cs-std-0.5.0/src/{alloc,cmp}.rs`,
  `ark-relations-0.5.1/src/r1cs/*`, `ark-groth16-0.5.0/src/*`.
* Zero Knowledge podcast, episode 414 (2026-10-21), zkGolf — https://zeroknowledge.fm/podcast/414/
* Zero Knowledge podcast RSS (episode dates) — https://feeds.captivate.fm/zeroknowledge
* zkhack learning hub — https://zkhack.dev/
* ICME Labs "PreFlight — Verifiable AI Agent Controls" — https://icme.io/
* Full cited corpus: `docs/research/01`–`05`.
