# 09 — A2H: verifiable delegation, revocation, and accountability

> **Provenance.** The constraint costs below were measured with a probe on an
> **arkworks 0.6.0** tree, not this repo's pinned 0.5.x. Treat them as gadget
> costs to re-measure, not as project measurements. See
> `README.md#measurement-provenance`.

Status: research report + **measured** circuit costs. Every number labelled "measured" was produced by
the probe in Appendix A, compiled and executed on this machine against the same pinned arkworks 0.6.0
tree as `05-rust-implementation-design.md`. Numbers borrowed from papers are labelled with their arXiv
ID. Anything I could not confirm is marked **UNVERIFIED**.

Scope: what the literature actually offers for (1) delegation that can be verified, (2) revocation in a
zero-knowledge setting, (3) accountability when an autonomous agent acts for a human — restricted to
mechanisms that a Groth16 circuit over BN254 can carry.

---

## 0. The headline

Three findings that change what we should build:

1. **Revocation is cheap; revocation *freshness* is the hard part.** An epoch-rooted sparse-Merkle
   non-membership proof costs **243 constraints per tree level, measured** (§3.4). At depth 20 that is
   4 862 constraints on top of our current 2 162, i.e. 7 024 total — a ~16.7 ms/1 000-constraint
   proving-time slope puts that at roughly 205–215 ms per receipt, still interactive. What no circuit
   can do is stop a proof that was *already generated* from being submitted after the human revokes.
   Every serious design in this literature solves that with a **status epoch** the verifier checks for
   freshness, not with more algebra ([2610.22899](https://arxiv.org/abs/2610.22899),
   [2608.19937](https://arxiv.org/abs/2608.19937), [2509.11934](https://arxiv.org/abs/2509.11934),
   [2211.13041](https://arxiv.org/abs/2211.13041)).

2. **Delegation chains should be hash-chained inside one proof, not signed per hop.** The two 2026
   agent-delegation protocols that actually ship (HDP, AIP) both verify a chain of *signatures* on
   cleartext scopes ([2604.04522](https://arxiv.org/abs/2604.04522),
   [2603.24775](https://arxiv.org/abs/2603.24775)). That is verifiable but not private, and it puts the
   whole chain on the verifier's disk. A Groth16 circuit can instead enforce attenuation arithmetically:
   **1 021 constraints per hop, measured**, including four `u64` attenuation comparisons (§4.3).

3. **Our `trace_digest` gap is a known, named failure mode with a published fix.** PACE calls it *field
   provenance*: a digest that binds bytes proves the bytes, not that the semantic fields describe those
   bytes ([2608.17220](https://arxiv.org/abs/2608.17220) §4.6). The fix is to reconstruct the checked
   fields from the decoded execution, never from the agent's own report. Separately, CVA formalises why
   authorization evidence ≠ execution evidence and calls the missing link the central open problem of
   agentic security ([2607.21325](https://arxiv.org/abs/2607.21325) eq. 8, §6).

---

## 1. What "verifiable delegation" has to mean, precisely

CVA's decomposition is the cleanest statement of the problem and I adopt it as the vocabulary for the
rest of this document ([2607.21325](https://arxiv.org/abs/2607.21325) §1, eq. 8):

```
Identity evidence  ≠  Delegation evidence  ≠  Authorization evidence  ≠  Execution evidence  ≠  Audit evidence
```

with the accompanying non-implications, which are exactly the gaps we have:

- `AuthN(A_i) ⇏ AuthZ(A_i, α, res, c, P_j)` — authentication does not imply that *this request* is
  permitted ([2607.21325](https://arxiv.org/abs/2607.21325) eq. 1).
- `Delegate(U, A_i, κ) ⇏ AuthZ(q_i)` — a delegation does not imply that a concrete request inside it is
  permitted ([2607.21325](https://arxiv.org/abs/2607.21325) eq. 3).

CVA instantiates a Groth16 prototype over BN254 with `R_CVA = BindPrincipal_Poseidon ∧ BindPlan_SHA256 ∧
SatisfyPolicy_circuit`, and measured circuit growth from 429 to **531 constraints** when principal binding
moved from a one-input to a two-input Poseidon commitment ([2607.21325](https://arxiv.org/abs/2607.21325)
§5.2). Two design decisions there are worth copying:

- the **policy identifier** `pid_j = H(policy_code_j ‖ version_j)` travels as a public input so the proof
  is bound to a policy *version* without encoding the policy in the circuit
  ([2607.21325](https://arxiv.org/abs/2607.21325) §3.1);
- **replay and freshness are deliberately outside the circuit**, because "proof verification is stateless,
  whereas replay resistance requires mutable enforcement state"
  ([2607.21325](https://arxiv.org/abs/2607.21325) §5.2, eq. 54).

Our `replay.rs` already implements the second point; §3 below adds the revocation analogue.

### 1.1 The gap CVA names and does not solve

CVA is explicit that its prototype leaves **runtime execution binding** out of scope, and that the
time-of-check-to-time-of-use gap `c_{t_v} ≠ c_{t_e}` (verify at `t_v`, execute at `t_e > t_v`) is a
structural limitation of the abstraction, not an implementation detail
([2607.21325](https://arxiv.org/abs/2607.21325) §5.2, §6, eq. 57). It also states the point that should
govern how we talk about our own product: a valid proof says the *relation* holds, not that the *policy*
is right — "the correctness of a proof must not be confused with the normative correctness of the encoded
policy" ([2607.21325](https://arxiv.org/abs/2607.21325) §6).

---

## 2. Four families of authority model, and what each buys

| family | what is signed/verified | revocation hook | implementable in our Groth16 design? |
|---|---|---|---|
| **Capability-token chain** (IBCT/AIP, HDP, SentinelAgent) | per-hop signature over a scope, cleartext | token expiry, issuer status list | as a *hash chain* yes (§4.3); as signatures, no (see §4.2) |
| **Evidence-object / VDT** (Provable Authority) | append-only records per grant, per decision, per outcome | status epoch + revocation conditions in the grant | outside the circuit; this is the verifier's job (§3.5) |
| **Policy-as-circuit** (CVA, NiyamAI, Aegis) | the policy predicate itself, compiled to constraints | epoch/nonce in the circuit, revocation externally | yes — this is what we already do |
| **TEE-attested guardrail** (Proof-of-Guardrail, Agentic Witnessing) | hardware attestation of code execution | platform identity revocation | no — different trust root |

### 2.1 Capability chains

**AIP** introduces Invocation-Bound Capability Tokens: a signed token chain with *holder-side attenuation*,
in two wire formats — a compact signed JWT for single-hop, and a **Biscuit token with Datalog policies**
for multi-hop ([2603.24775](https://arxiv.org/abs/2603.24775)). Verification is 0.049 ms in Rust and
0.189 ms in Python, with 0.22 ms overhead in a real MCP-over-HTTP deployment
([2603.24775](https://arxiv.org/abs/2603.24775)). The relevant structural claim: services can validate
"that the delegation chain only involves scope attenuation" before acting
([2609.30824](https://arxiv.org/abs/2609.30824)).

**HDP** is the human-provenance counterpart: an Ed25519-signed token binds a human authorization event to
a session and records each agent's delegation as a signed hop in an append-only chain; verification is
fully offline with only the issuer's public key and current session id
([2604.04522](https://arxiv.org/abs/2604.04522)). HDP states its own non-goals plainly — no
confidentiality (tokens are signed, not encrypted) and no semantic correctness of actions relative to
declared scope ([2604.04522](https://arxiv.org/abs/2604.04522) §3). **This is the honest baseline for
"human → agent → agent" and it is strictly weaker than what a ZK design can do**: every hop's scope is
readable by every verifier.

**SentinelAgent** supplies the property list I would adopt verbatim for a delegation calculus: authority
narrowing, policy preservation, forensic reconstructibility, **cascade containment**, scope–action
conformance, output schema conformance (deterministic) and intent preservation (probabilistic)
([2604.02767](https://arxiv.org/abs/2604.02767)). Two caveats worth internalising: the deterministic
properties were model-checked in TLA+ across 2.7 M states with zero violations, but intent verification
degrades to 13% against sophisticated paraphrasing ([2604.02767](https://arxiv.org/abs/2604.02767)) —
"the agent intended what the human meant" is not a property you can prove.

**DelegateGuard** is the clearest statement of the delegation-specific revocation problem: capabilities
attenuate over purpose, labels, operations, sinks and **delegation depth**, and "revocation cascades
through the delegation graph", with explicit blocking of **revocation replay**
([2610.16005](https://arxiv.org/abs/2610.16005)).

### 2.2 The evidence-object model

**Provable Authority** (ChainIT) is the most operationally complete design I found, and most of it is
adoptable without any cryptography of ours ([2610.22899](https://arxiv.org/abs/2610.22899)):

- an **Authority Resolution Pactvera** — versioned record of who may act, in what role, for what purpose,
  within what limits, during what period, under what quorum, subject to what revocation
  ([2610.22899](https://arxiv.org/abs/2610.22899) §2.3, Definitions);
- an **Execution Authorization Credential**: "single-use, short-lived credential authorizing one exact
  transaction for one audience after reservation and approvals… bound to the session key, digest,
  reservation, status epoch, and expiration; consumed atomically"
  ([2610.22899](https://arxiv.org/abs/2610.22899) §2.7);
- **atomic capacity reservation** so aggregate limits hold under concurrency
  ([2610.22899](https://arxiv.org/abs/2610.22899) Abstract, §2.5) — this is the piece our
  `max_amount` check does **not** have: narrowing per action does not bound the *sum* across concurrent
  executions;
- the **autonomous band / step-up boundary**: inside the band no human is in the loop; beyond it a person
  with independent authority approves the exact digest ([2610.22899](https://arxiv.org/abs/2610.22899) §2.3,
  §4.1);
- present validity is resolved **at reliance time** "against current ARP status, revocation state, and the
  applicable freshness bound" ([2610.22899](https://arxiv.org/abs/2610.22899) §2.3).

Its canonical digest is a flat hash over an ordered field list
([2610.22899](https://arxiv.org/abs/2610.22899) §5.2) — the same construction as our policy commitment,
which is reassuring for interop but means it inherits the same "what you hash is what you get" limitation
(§6.2).

### 2.3 Policy-as-circuit

**NiyamAI** seals permitted tools and constraints into an *Intent Contract* under a SHA-256 commitment and
generates a zkSNARK per authorized action certifying correct policy evaluation before execution proceeds
([2608.07167](https://arxiv.org/abs/2608.07167)). Its motivation is the one to keep in mind: existing
guardrails run in the same environment as the agent, so "a compromised host produces no evidence of its own
failure" ([2608.07167](https://arxiv.org/abs/2608.07167)).

**Aegis** adds governance machinery — an Immutable Ethics Policy Layer bound at genesis, amendments
requiring quorum, autonomous shutdown on verified violation, and an Immutable Logging Kernel — with a
median proof-verification latency of 238 ms ([2603.16938](https://arxiv.org/abs/2603.16938)). I would not
copy the ontology, but the "policy layer sealed at genesis, amendments are a quorum event" rule is the
right shape for our policy-version governance.

### 2.4 What ZK does *not* buy, stated by the people selling it

**Proof-of-Guardrail** makes the honesty point better than any critic: it gives developers a TEE-signed
attestation that a specific open-source guardrail ran, and then says outright that this "ensures integrity
of guardrail execution… but we also highlight a risk of deception about safety, for example, when
malicious developers actively jailbreak the guardrail" ([2603.05786](https://arxiv.org/abs/2603.05786)).
A proof that a check ran is not a proof that the check is adequate. Our docs should say the same thing
about `SatisfyPolicy`.

---

## 3. Revocation in a zero-knowledge setting

### 3.1 The design space

The clearest taxonomy is Freitag's survey, which also names the four families I use below
([2211.13041](https://arxiv.org/abs/2211.13041)):

1. **List-based** — simple allow/block lists (X.509 CRLs); *hidden* lists managed by a trusted party;
   **compressed** lists (Bloom filter / bit array)
   ([2211.13041](https://arxiv.org/abs/2211.13041) §3.1). Cheapest to operate, worst privacy: the verifier
   learns which entry was queried.
2. **Cryptographic accumulators** — one-way set commitment with membership or non-membership witnesses;
   asymmetric (RSA, bilinear pairing, Merkle) vs symmetric (Bloom); *positive* vs *negative* (non-membership)
   vs *universal*; static / additive / subtractive / dynamic
   ([2211.13041](https://arxiv.org/abs/2211.13041) §3.2).
3. **Credential update** — short validity windows, re-issued on a schedule; validity is freshness
   ([2211.13041](https://arxiv.org/abs/2211.13041) §3.3).
4. **Linked Validity Verifiable Credentials (LVVC)** — a small fixed-size companion credential carrying
   only an issuance date, refreshed on demand; the verifier checks signature, linkage, and issuance-date
   freshness ([2211.13041](https://arxiv.org/abs/2211.13041) §4). The survey's own conclusion: *the
   perfect revocation method does not exist yet*.

For anonymous credentials specifically, the accumulator route is the classical answer: Camenisch–Kohlweiss–
Soriente's pairing-based accumulator for efficient revocation of anonymous credentials is the reference
([2211.13041](https://arxiv.org/abs/2211.13041) ref. 16, LNCS 5443), and a 2023 protocol supports anonymous
predicate proofs plus **revocation through accumulators** with CP-ABE
([2308.06797](https://arxiv.org/abs/2308.06797)).

### 3.2 The two mechanisms that are actually being built in 2026

**(a) Epoch-rooted sparse-Merkle non-membership — "ShadowPath".** The holder proves in zero knowledge that
the credential's registry slot is not revoked under a *verifier-selected epoch root* `R_e`; the verifier
learns the status result and no lookup metadata ([2608.19937](https://arxiv.org/abs/2608.19937) §I, §II.A).
Encoding: each credential maps to a private index `idx` and fingerprint `fp`; non-revoked positions are
empty; on revocation the issuer stores `fp` at that position; non-revocation is "an authenticated absent
entry or an authenticated fingerprint different from `fp`"
([2608.19937](https://arxiv.org/abs/2608.19937) §II, §VI). Measured, 30 desktop trials on an M2 Pro:
**371.6 ms median Groth16 proving and 3.70 ms verification with a depth-50 Poseidon sparse-Merkle path**;
the Verkle variant (k=1024, d=5) took **2.11 s / 7.55 ms**
([2608.19937](https://arxiv.org/abs/2608.19937) Abstract, Table III). The paper's own conclusion is the
useful engineering lesson: *shorter authenticated paths do not yield cheaper zero-knowledge proofs*
([2608.19937](https://arxiv.org/abs/2608.19937) Abstract).

**(b) Blacklist non-membership with holder-chosen verification windows — "zkToken".** A blacklist of tokens
for revoked credentials, with ZK proofs of **non-membership in the blacklist**, and the holder individually
configures the verification period after which the revocation status is provably untraceable
([2509.11934](https://arxiv.org/abs/2509.11934)). This is the mechanism to copy if we ever need
*unlinkability* between receipts; for A2H we do not, because our policies are already public.

### 3.3 What "revocation" means for a delegation, not a credential

Three distinct things get called revocation, and conflating them is how designs end up unrevocable:

| what is revoked | who must notice | mechanism |
|---|---|---|
| the **grant** (policy) | every future verifier of a receipt | status epoch / registry root (§3.4) |
| the **agent instance** (key compromise) | every verifier, immediately | key revocation list, same machinery, different key |
| a **sub-delegation** (child policy) | verifiers of child receipts | cascade containment: child commits to parent hash (§4.3) |

Provable Authority's EAC is the sharpest formulation of the per-execution case: single-use, bound to the
status epoch, consumed atomically ([2610.22899](https://arxiv.org/abs/2610.22899) §2.7). DelegateGuard
cascades revocation through the delegation graph and explicitly defends against **revocation replay** —
replaying an action authorized before the revoke took effect ([2610.16005](https://arxiv.org/abs/2610.16005)).
That attack is exactly what a freshness window exists to bound, and it cannot be removed by any circuit.

### 3.4 Measured cost of adding revocation to *our* circuit

Our current circuit is **2 162 constraints / 10 public inputs** (`05-rust-implementation-design.md` §4.6,
measured on this machine). The probe in Appendix A measures the marginal cost, BN254, arkworks 0.6.0,
Poseidon rate 2, 8 full / 57 partial rounds:

```
-- component constraint costs (measured, this machine) --
depth  1:    245 constraints   (245.0/level)
depth  8:   1946 constraints   (243.2/level)
depth 16:   3890 constraints   (243.1/level)
depth 20:   4862 constraints   (243.1/level)
depth 24:   5834 constraints   (243.1/level)
depth 32:   7778 constraints   (243.1/level)
depth 40:   9722 constraints   (243.1/level)
linear fit: per-level = 243.00 constraints, fixed overhead = 2
```

The relation is exactly `c(d) = 243·d + 2` (the 2 is the leaf-is-empty check plus the root equality). Per
component:

| component | constraints (measured) |
|---|---|
| Poseidon 2-to-1 (Merkle node) | **243** |
| one `u64 ≤` comparison | **195** |
| four `u64 ≤` comparisons | **780** |
| one delegation hop = Poseidon link + 4 attenuation comparisons | **1 021** |
| nullifier (`Poseidon(policy_id, exec_id)`) + in-circuit epoch equality + expiry gate | **565** (of which the Poseidon is 243) |

Groth16 end-to-end on the pure path circuits, same machine:

```
depth 20:  4862 constraints  setup 135.3 ms  prove 158.6 ms  verify 3.14 ms  ok=true
depth 32:  7778 constraints  setup 207.4 ms  prove 210.6 ms  verify 2.32 ms  ok=true
```

**Projected totals** (addition is exact for constraints; proving time is an interpolation between the two
measured points above, at ≈16.7 ms per 1 000 constraints, and is therefore an estimate, not a measurement):

| design | constraints | Δ vs today | est. prove | proof size | on-chain verify |
|---|---|---|---|---|---|
| today | 2 162 | — | 161.2 ms (measured, doc 05) | 128 B | unchanged |
| + SMT revocation, depth 12 (4 096 policies) | 5 080 | +135% | ~190 ms | 128 B | unchanged |
| + SMT revocation, depth 20 (1 048 576 policies) | **7 024** | **+225%** | **~205–215 ms** | 128 B | unchanged |
| + depth-20 SMT + 3-hop chain | 10 087 | +366% | ~250 ms | 128 B | unchanged |
| + depth-32 SMT (paranoid) | 9 940 | +360% | ~245 ms | 128 B | unchanged |

Two facts make this affordable in a way the constraint count does not suggest: Groth16 proofs are
**constant 128 bytes** regardless of circuit size, and on-chain verification cost is independent of circuit
size (the property CVA also relies on, [2607.21325](https://arxiv.org/abs/2607.21325) §5.5). Growing the
circuit costs prover time only. ShadowPath's 371.6 ms at depth 50 is consistent with our
`c(50) = 12 152` constraints ([2608.19937](https://arxiv.org/abs/2608.19937)).

### 3.5 The mechanism I recommend, precisely

**Epoch-rooted sparse-Merkle non-membership, plus a public-input status epoch, plus a nullifier.** It is
ShadowPath's construction ([2608.19937](https://arxiv.org/abs/2608.19937)) reduced to the parts we need,
with Provable Authority's reliance-time status resolution ([2610.22899](https://arxiv.org/abs/2610.22899)).

Registry (off-circuit, verifier-side state):

```
slot(policy_id) = first 20 bits of Poseidon(policy_id)        // verifier computes natively; 0 circuit cost
leaf = 0                      => policy live
leaf = Poseidon(policy_id, revoked_at_epoch, reason_code)     => policy revoked
R_e   = SMT root at epoch e   (published; monotone epoch counter)
```

Public inputs added: `revocation_root R_e` (1 field element), `epoch e` (as `u64`, 1 field element).

Witness added: `siblings[20]`, and the leaf preimage when revoked.

Circuit (additions to our existing `SatisfyPolicy`):

```rust
// 1. non-membership: the policy's slot is empty under the verifier-selected root
let mut cur = FpVar::new_witness(cs.clone(), || Ok(Fr::zero()))?;   // leaf must be 0
cur.enforce_equal(&FpVar::Constant(Fr::zero()))?;                    //   1 constraint (measured: included)
for i in 0..20 {
    let sib = FpVar::new_witness(cs.clone(), || Ok(self.siblings[i]))?;
    let b   = Boolean::new_witness(cs.clone(), || Ok(self.idx_bits[i]))?;   // public in practice: idx is derived from public policy_id
    let l   = FpVar::conditionally_select(&b, &sib, &cur)?;
    let r   = FpVar::conditionally_select(&b, &cur, &sib)?;
    let mut sp = PoseidonSpongeVar::<Fr>::new(cs.clone(), &params);
    sp.absorb(&vec![l, r])?;
    cur = sp.squeeze_field_elements(1)?[0].clone();                 // 243 per level (measured)
}
cur.enforce_equal(&root_public)?;                                   //   1 constraint
// 2. single-use: nullifier is public, verifier keeps the accepted set (replay.rs, unchanged)
```

Verifier changes:

1. reject if `R_e` is older than `max_staleness` (Provable Authority's "bounded-freshness status rules",
   [2610.22899](https://arxiv.org/abs/2610.22899) Abstract);
2. reject if the receipt's `epoch` ≠ the epoch `R_e` was published for;
3. keep the existing accepted-nullifier set — `Poseidon(policy_id, execution_id)`, **243 constraints
   measured**, replacing the current execution-id set so the id need not be transmitted in the clear;
4. on revoke: set the leaf, recompute the root, bump the epoch, publish `(e, R_e)`.

Cost: **+4 862 constraints at depth 20; +2 918 at depth 12** (both from the measured formula). Depth 12
supports 4 096 policies, which is more than enough for a first deployment and is the right default.
Depth should be a *parameter of the proving key*, so a depth-12 deployment and a depth-20 deployment are
different key pairs — version the verification key alongside the circuit (§7).

**Why not an accumulator.** RSA accumulators give O(1) witnesses and no root churn per epoch
([2211.13041](https://arxiv.org/abs/2211.13041) §3.2), but verifying an RSA-2048 witness inside a BN254
Groth16 circuit requires emulated big-integer exponentiation mod a 2 048-bit modulus. arkworks can do it
(`fields/emulated_fp`), and the cost is far above anything in this document; ShadowPath's Verkle
experiment is the empirical warning that a theoretically shorter authentication path can be **5× more
expensive** in-circuit (2.11 s vs 371.6 ms, [2608.19937](https://arxiv.org/abs/2608.19937)). I did not
measure an RSA accumulator in-circuit, so I will not quote a number — call it UNVERIFIED but certainly
worse than 243 constraints/level.

### 3.6 The zero-constraint tier (build this first)

There is a strictly cheaper intermediate that requires **no circuit change at all**, and it is worth
shipping in a day:

- add `policy_epoch: u64` to the receipt as a **public input** (a public input is just a variable; the
  verifier compares it to its own counter, and comparing two public values costs **zero** constraints
  because it happens outside the circuit);
- the verifier keeps `policy_id → (epoch, revoked_at)`;
- a revoke is a counter bump.

This is Provable Authority's *status epoch* reduced to its minimum
([2610.22899](https://arxiv.org/abs/2610.22899) §2.7), and it is the same idea as LVVC freshness
([2211.13041](https://arxiv.org/abs/2211.13041) §4) and zkToken's verification window
([2509.11934](https://arxiv.org/abs/2509.11934)). It gives **revoke-all with a freshness bound**, but not
per-policy revocation without a registry and not revocation without a freshness bound. The SMT in §3.5 is
what upgrades it to "one policy, one leaf, one root".

---

## 4. Delegation chains: human → agent → agent

### 4.1 The property to enforce: attenuation, not just linkage

All four 2026 delegation designs agree on the core rule, in different words: authority may only narrow.
AIP: "services can validate that the delegation chain only involves scope attenuation"
([2609.30824](https://arxiv.org/abs/2609.30824)). SentinelAgent: *authority narrowing* + *policy
preservation* ([2604.02767](https://arxiv.org/abs/2604.02767)). DelegateGuard: capabilities attenuate over
purpose, labels, operations, sinks and **delegation depth**
([2610.16005](https://arxiv.org/abs/2610.16005)). Portability paper: "delegation attenuation" as one of
eight requirements ([2605.11487](https://arxiv.org/abs/2605.11487)).

Attribution note: SentinelAgent publishes a single-author framework with TLA+-checked properties but its
intent-detection numbers rest on an NLI model, and its own abstraction claim (P2 ≤ 1.7% TPR before
fine-tuning) should temper any "we verify intent" claim we ever make
([2604.02767](https://arxiv.org/abs/2604.02767)).

### 4.2 Why per-hop signatures do not fit our circuit

Both shipping protocols verify **signatures** per hop: HDP uses Ed25519 with offline verification
([2604.04522](https://arxiv.org/abs/2604.04522)); AIP uses signed JWTs / Biscuit
([2603.24775](https://arxiv.org/abs/2603.24775)). Inside Groth16 this is expensive, and the reason is
specific to BN254 rather than to our code:

- `ark-crypto-primitives` 0.6.0 **does** ship a signature gadget module
  (`signature/constraints.rs`, traits `SigVerifyGadget` / `SigRandomizePkGadget`), and **`Schnorr`
  implements only `SigRandomizePkGadget`** — public-key re-randomisation — not verification (read from the
  pinned source: `signature/schnorr/constraints.rs` contains no `SigVerifyGadget` impl). So there is no
  drop-in in-circuit Schnorr verify in our dependency set.
- More fundamentally, curve gadgets in `ark-r1cs-std` are declared as
  `ProjectiveVar<P, F> where F: FieldVar<P::BaseField, BasePrimeField<P>>`. For BN254 G1 the coordinates
  live in `Fq` while our Groth16 constraint field is `Fr`, so BN254 G1 arithmetic inside a BN254 circuit is
  a **non-native** computation that must run through emulated field arithmetic
  (`ark-r1cs-std::fields::emulated_fp`). I did not measure an emulated BN254 scalar multiplication, so its
  cost is **UNVERIFIED** — but it is the same cost class as the RSA-accumulator objection in §3.5, i.e.
  orders of magnitude above 243 constraints, and two scalar mults are needed per signature.

The literature shows what it costs to avoid this: ShadowPath runs its Groth16 circuits over **BW6-761** with
**BLS12-377 pairings verified inside** the circuit, precisely so that the in-circuit curve operations are
native and no generic foreign-field emulation is required
([2608.19937](https://arxiv.org/abs/2608.19937) §VI, Table III: "Outer curve / field BW6-761 / Fr";
"Verkle implementation verifies BLS12-377 pairings inside BW6-761 Groth16"). Changing our curve to make
per-hop signatures native would mean re-deriving every measured number in doc 05 and losing BN254's cheap
on-chain verifier — not a trade worth making for delegation.

The purely in-circuit alternative is a **hash chain**: the human signs only the root grant; each hop is a
Poseidon link; attenuation is arithmetic. That is what I measured, and it is 1 021 constraints per hop.

### 4.3 Measured hop cost and the attenuation predicate

One hop, as measured: `Poseidon(parent_commit, child_commit)` (243) + four `u64 ≤` comparisons
(4 × 195 = 780) = **1 021 constraints**.

Full per-hop predicate (the four compared fields are the scalar policy fields we already have):

```
child.max_amount      ≤ parent.max_amount
child.max_per_action  ≤ parent.max_per_action
child.expires_at      ≤ parent.expires_at
child.chain_id        = parent.chain_id          // equality, not ≤
child.allowed_targets ⊆ parent.allowed_targets   // subset over ≤8 elements
depth                 <  max_depth               // hard bound on chain length
h_i = Poseidon(h_{i-1} ‖ H(child_policy_bytes))  // link; h_0 covered by the human's signature
```

The target-subset check is **not measured** — it needs an 8×8 membership/mux network per hop and I would
budget low hundreds of constraints per hop for it, but it must be measured before it goes in a design doc.
Everything else above is measured or exact.

Consequences worth stating in the design:

- `child.expires_at ≤ parent.expires_at` plus a hard `max_depth` is what SentinelAgent calls *cascade
  containment* ([2604.02767](https://arxiv.org/abs/2604.02767)) and what DelegateGuard implements as
  revocation cascading through the graph ([2610.16005](https://arxiv.org/abs/2610.16005)). With a hash
  chain you get containment **for free**: revoking the root changes the root's registry leaf, and every
  descendant receipt proves against the same root (§3.5).
- A 3-hop chain costs **+3 063 constraints** (3 × 1 021), taking the depth-20 design to 10 087 total.
- **Aggregate limits do not follow from narrowing.** If a parent grants 100 and two children each get 100,
  narrowing holds per child and the sum is 200. Provable Authority solves this with *atomic capacity
  reservation* ([2610.22899](https://arxiv.org/abs/2610.22899) §2.5); in our design the only real fix is
  verifier-side accounting per `(policy_id, epoch)`, which means the receipt total must be public (it
  already is) and the verifier must sum. Say this out loud in the protocol docs — it is the most likely
  place for a false sense of safety.

### 4.4 Retention of provenance without disclosure

HDP's offline verification is genuinely nice — no registry lookup ([2604.04522](https://arxiv.org/abs/2604.04522))
— and the contrast with an epoch-rooted design is the trade we are making:

| | HDP/AIP (signed chain) | hash-chained, epoch-rooted (this design) |
|---|---|---|
| verifier work | verify k signatures | 1 proof verification |
| scope disclosure | full chain, cleartext | only the receipt fields |
| revocation | needs a registry anyway | root + epoch, same object as §3.5 |
| offline | yes | no (needs current root) |
| circuit cost | 0 (outside circuit) | 1 021/hop + 243/level (measured) |

---

## 5. Accountability: what can actually be proven after the fact

### 5.1 Four mechanisms, in increasing strength

1. **Receipt/telemetry** — HMAC- or signature-authenticated records of what the agent did. Cheap
   (<15 ms per response in NabaOS, [2603.10060](https://arxiv.org/abs/2603.10060)) and detects
   fabrication of tool outputs, but only against a party that does not hold the signing key: the agent's
   own host could forge them.
2. **Intent-bound decision records** — PACE's Policy Decision Record binds intent, policy, simulation
   report, decision, hashes of intent/policy/calldata, and a timestamp; the smart account re-checks
   **nine** bindings (signer, chain id, account, target, value, `keccak256(data)`, nonce unused,
   validAfter, validUntil) with nonce consumed **before** the external call, at a measured **29 826–31 822
   gas** overhead ([2608.17220](https://arxiv.org/abs/2608.17220) §4.5, §5.6, Fig. 2).
3. **ZK proof of policy satisfaction** — what we do: hides the trace, proves the bounds held.
4. **Anchored trace commitment** — a Merkle root over per-action records, carried in the receipt and
   anchored into an append-only log or chain event, so history cannot be rewritten after the fact. This is
   the constructive answer to our unconstrained `trace_digest`.

### 5.2 The named failure mode we currently have

PACE §4.6, verbatim on the point that matters: "Pace's soundness requires that the semantic fields it
checks (approvals, spend, slippage, touched contracts) reflect the bytes that execute. The calldata-hash
binding guarantees the submitted bytes equal the approved bytes, but does not by itself guarantee that the
typed fields match those bytes. A sound deployment must therefore reconstruct these fields from decoded
calldata and the simulation trace using trusted code, never trusting the LLM-supplied fields"
([2608.17220](https://arxiv.org/abs/2608.17220) §4.6). It also notes the residual: "the contract does not
replay the simulation on-chain, so a transaction approved at state S may execute at S′ with different
reserves… Pace thus guarantees byte- and field-level fidelity, not that the realised outcome equals the
simulated one" ([2608.17220](https://arxiv.org/abs/2608.17220) §4.5).

That is exactly our `trace_digest`: bound into the witness, unconstrained in meaning. A proof can show
`Poseidon(trace_digest, ...)` consistency while the digest commits to nothing an auditor can check.

### 5.3 Making `trace_digest` mean something — the cheap version

Replace the opaque digest with a **Merkle root over action leaves**, where each leaf commits to the fields
an auditor will challenge:

```
leaf_i  = Poseidon(domain_trace, seq_i, tool_id, target_id, amount, args_hash_i)
root    = Merkle_root_poseidon(leaf_1..leaf_N)      // N a fixed small power of two, e.g. 8
```

Cost, from the measured formula: a binary tree over N leaves needs N−1 internal hashes, so **N=8 costs
1 701 constraints**, N=4 costs 729. Then:

- the receipt carries `root` as a **public input** (auditors can compare it across receipts);
- for an audit of action *i*, the agent discloses `leaf_i` and the 3 siblings — the auditor checks the path
  natively, at zero circuit cost, and learns one action's fields, nothing else;
- the root is anchored into an append-only log or an on-chain event, so the set cannot be rewritten.

This is the standard commit-and-prove shape, and it maps our existing "receipt total/count" public outputs
onto a per-action structure. It does **not** prove the actions happened in the world — that is §5.4.

### 5.4 What no circuit can give us

- **World truth.** A ZK proof constrains algebra, not reality; the only bridges are (i) a public chain
  event whose calldata is the commitment (PACE's approach, [2608.17220](https://arxiv.org/abs/2608.17220)),
  or (ii) a hardware attestation. Agentic Witnessing moves verification "from attested execution to
  *attested reasoning*" by isolating an LLM auditor in a TEE
  ([2604.24203](https://arxiv.org/abs/2604.24203)), and Proof-of-Guardrail does the same for guardrails
  ([2603.05786](https://arxiv.org/abs/2603.05786)) — both trade our trust assumption (a human verified the
  circuit) for a vendor's (the TEE is honest).
- **Responsibility allocation.** The Accountability Horizon proves that once autonomy exceeds a computable
  threshold, no allocation of responsibility satisfying Attributability, Foreseeability, Non-Vacuity and
  Completeness exists — "not as an engineering limitation but as a mathematical necessity"
  ([2604.07778](https://arxiv.org/abs/2604.07778)). Read together with CVA's warning about policy
  correctness ([2607.21325](https://arxiv.org/abs/2607.21325) §6), the honest product claim is: *we prove
  the agent stayed inside the bounds a human signed; we do not prove the human chose good bounds or that
  the human is responsible for the outcome.*
- **Semantic intent preservation.** 13% detection under paraphrase
  ([2604.02767](https://arxiv.org/abs/2604.02767)).

---

## 6. Recommended build order

| step | change | circuit Δ | cost basis |
|---|---|---|---|
| 1 | `policy_epoch` public input + verifier-side `policy_id → (epoch, revoked_at)` | **0** | public-vs-public check is off-circuit |
| 2 | nullifier `Poseidon(policy_id, exec_id)` replacing the raw execution-id set in `replay.rs` | **+243** | measured (component of the 565 gate) |
| 3 | trace Merkle root over 8 action leaves, public input; per-action selective disclosure to auditors | **+1 701** | measured formula `243·(N−1)` |
| 4 | depth-12 SMT non-membership (4 096 policies) + root freshness check | **+2 918** | measured formula |
| 5 | hash-chained delegation, depth ≤ 3, attenuation predicate | **+3 063** | measured, 1 021/hop (target-subset unmeasured) |
| 6 | depth-20 SMT (1 048 576 policies) | +4 862 (replaces step 4) | measured |

Steps 1–3 take us from 2 162 to ~4 106 constraints and close the two gaps that cost us the most
credibility: *revocable at all* and *trace means something*. Steps 4–5 are the delegation story.

Wire/API changes implied: `Policy` gains `delegation_depth: u8`, `max_depth: u8`, `parent_commitment:
Option<Fr>`; `Receipt` gains `policy_epoch: u64`, `revocation_root: Fr`, `trace_root: Fr`, `nullifier: Fr`.
All four must go into the canonical encoders (§3.2 of doc 05) *and* into the public-input ordering, which
is a breaking protocol change — bump `PROTOCOL_VERSION` and the domain tags together, since the domain tag
is the thing that prevents cross-object substitution (`05-rust-implementation-design.md` §3.1).

Verification-key governance becomes a first-class problem the moment the circuit holds the policy and the
registry: CVA states it directly — policy versioning, circuit governance and verification-key distribution
are security concerns orthogonal to the proof system
([2607.21325](https://arxiv.org/abs/2607.21325) §6). A depth-12 key and a depth-20 key are different
verification keys, and a verifier that accepts the wrong one accepts a proof about a registry it never
read.

---

## 7. Open problems (nothing in this literature solves them)

1. **Revocation race.** Between proof generation and verification, the human may revoke. Bounded only by
   `max_staleness`; Provable Authority's answer is bounded-freshness status rules at reliance time
   ([2610.22899](https://arxiv.org/abs/2610.22899)), not elimination. Nobody claims otherwise.
2. **Aggregate limits under concurrency.** Atomic reservation is a stateful protocol
   ([2610.22899](https://arxiv.org/abs/2610.22899) §2.5); no ZK construction I found enforces a sum across
   *parallel* agents without a shared ledger.
3. **Execution binding.** CVA names it the central open problem ([2607.21325](https://arxiv.org/abs/2607.21325)
   §6) and PACE bounds its claim to byte-level fidelity ([2608.17220](https://arxiv.org/abs/2608.17220) §8).
   Anyone who says "the proof shows what the agent did in the world" is overclaiming.
4. **Revocation without a freshness window** (true offline revocation) — incompatible with a stateless
   verifier, which is the same reason replay resistance lives outside the circuit
   ([2607.21325](https://arxiv.org/abs/2607.21325) eq. 54).
5. **Accountability below the horizon** ([2604.07778](https://arxiv.org/abs/2604.07778)).

---

## Appendix A — probe source (reproducible)

Standalone crate, offline build against the cached registry, arkworks 0.6.0, BN254. Two binaries.
Built and run on this machine (Windows 11, rustc 1.97.1, `--release`, `--offline`).

`probe/Cargo.toml`:

```toml
[package]
name = "revprobe"
version = "0.1.0"
edition = "2021"

[dependencies]
ark-bn254 = "0.6.0"
ark-ff = "0.6.0"
ark-ec = "0.6.0"
ark-relations = "0.6.0"
ark-r1cs-std = "0.6.0"
ark-crypto-primitives = { version = "0.6.0", features = ["sponge", "constraints"] }
ark-groth16 = "0.6.0"
ark-serialize = "0.6.0"
ark-std = "0.6.0"
ark-snark = "0.6.0"
```

`src/main.rs` — Merkle non-membership path, component table, Groth16 timings:

```rust
use ark_bn254::{Bn254, Fr};
use ark_ff::Zero;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge, find_poseidon_ark_and_mds};
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use std::time::Instant;

fn cfg() -> PoseidonConfig<Fr> {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(254, 2, 8, 57, 0);
    PoseidonConfig { full_rounds: 8, partial_rounds: 57, alpha: 5, ark, mds, rate: 2, capacity: 1 }
}

#[derive(Clone)]
struct Path { depth: usize, leaf: Fr, siblings: Vec<Fr>, idx_bits: Vec<bool>, root: Fr }

impl ConstraintSynthesizer<Fr> for Path {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::gr1cs::Result<()> {
        let p = cfg();
        let root_var = FpVar::new_input(cs.clone(), || Ok(self.root))?;
        let mut cur = FpVar::new_witness(cs.clone(), || Ok(self.leaf))?;
        cur.enforce_equal(&FpVar::Constant(Fr::zero()))?;          // slot must be empty => not revoked
        for i in 0..self.depth {
            let sib = FpVar::new_witness(cs.clone(), || Ok(self.siblings[i]))?;
            let b = Boolean::new_witness(cs.clone(), || Ok(self.idx_bits[i]))?;
            let left  = FpVar::conditionally_select(&b, &sib, &cur)?;
            let right = FpVar::conditionally_select(&b, &cur, &sib)?;
            let mut sp = PoseidonSpongeVar::<Fr>::new(cs.clone(), &p);
            sp.absorb(&vec![left, right])?;
            cur = sp.squeeze_field_elements(1)?[0].clone();
        }
        cur.enforce_equal(&root_var)?;
        Ok(())
    }
}
```

`src/bin/hop.rs` — per-component costs (`UInt64::is_le` / `is_ge` from `ark_r1cs_std::cmp::CmpGadget`;
`is_cmp` does **not** exist on `UInt` in 0.6.0, only `is_ge` is implemented and the trait derives the rest):

```rust
use ark_r1cs_std::uint64::UInt64;
use ark_r1cs_std::cmp::CmpGadget;
// one u64 <= comparison
a.is_le(&b)?.enforce_equal(&Boolean::TRUE)?;
// hop: Poseidon(parent, child) == root, after 4 attenuation comparisons
```

## Appendix B — raw probe output

```
-- native 2-to-1 Poseidon sanity --
poseidon2(1,2) = 7142104613055408817911962100316808866448378443474503659992478482890339429929

-- component constraint costs (BN254, arkworks 0.6.0, Poseidon rate=2, 8f/57p) --
depth  1:    245 constraints  (245.0/level)
depth  8:   1946 constraints  (243.2/level)
depth 16:   3890 constraints  (243.1/level)
depth 20:   4862 constraints  (243.1/level)
depth 24:   5834 constraints  (243.1/level)
depth 32:   7778 constraints  (243.1/level)
depth 40:   9722 constraints  (243.1/level)
linear fit: per-level = 243.00 constraints, fixed overhead = 2

-- leaf-only (no path) --
depth  0: 2 constraints

-- Groth16 end-to-end on the path circuit --
depth 20:  4862 constraints  setup 135.3071ms  prove 158.6268ms  verify 3.1419ms  ok=true
depth 32:  7778 constraints  setup 207.352ms  prove 210.5839ms  verify 2.3172ms  ok=true

-- per-component costs (BN254, arkworks 0.6.0) --
u64 <= comparison (1)                             195 constraints
4 x u64 <= comparisons                            780 constraints
delegation hop = Poseidon(parent,child) + 4 cmps  1021 constraints
nullifier + epoch equality + expiry gate          565 constraints
```

## Appendix C — bibliography

| arXiv | date | title | role in this report | citations (Semantic Scholar, 2026-10-28) |
|---|---|---|---|---|
| [2607.21325](https://arxiv.org/abs/2607.21325) | 2026-07-23 | Cryptographically verifiable authorization for autonomous AI agents (CVA) | formal vocabulary; Groth16 PoC; identity/authorization/execution separation | 1 |
| [2608.19937](https://arxiv.org/abs/2608.19937) | 2026-08-20 | ShadowPath: Lookup-Private Credential Status Verification | SMT/Verkle non-membership; 371.6 ms / 3.70 ms Groth16 at depth 50 | not indexed |
| [2610.22899](https://arxiv.org/abs/2610.22899) | 2026-10-16 | Provable Authority (ChainIT) | EAC, capacity reservation, status epoch, reliance-time resolution | not indexed |
| [2608.17220](https://arxiv.org/abs/2608.17220) | 2026-08-18 | PACE: Policy-Attested Contract Execution | PDR field list, 9 on-chain checks, 29 826–31 822 gas, field-provenance limit | not indexed |
| [2604.04522](https://arxiv.org/abs/2604.04522) | 2026-04-06 | HDP: Human Delegation Provenance | offline Ed25519 hop chain; explicit non-goals | 7 |
| [2604.02767](https://arxiv.org/abs/2604.02767) | 2026-04-03 | SentinelAgent: Intent-Verified Delegation Chains | 7-property delegation calculus; cascade containment; 13% paraphrase | not indexed |
| [2603.24775](https://arxiv.org/abs/2603.24775) | 2026-03-25 | AIP: Agent Identity Protocol (IBCT) | Biscuit/JWT capability chain; 0.049 ms verify | not indexed |
| [2610.16005](https://arxiv.org/abs/2610.16005) | 2026-10-12 | DelegateGuard | purpose-bound capabilities; revocation cascade + replay | not indexed |
| [2509.11934](https://arxiv.org/abs/2509.11934) | 2025-09-15 | zkToken | blacklist non-membership; holder-chosen verification window | not indexed |
| [2211.13041](https://arxiv.org/abs/2211.13041) | 2022-11-23 | Privacy-preserving revocation for SSI (survey + LVVC) | the taxonomy in §3.1 | not indexed |
| [2308.06797](https://arxiv.org/abs/2308.06797) | 2023-08-13 | Revocable Anonymous Credentials from ABE | accumulator-based revocation with predicate proofs | not indexed |
| [2603.10060](https://arxiv.org/abs/2603.10060) | 2026-03-09 | Tool Receipts, Not Zero-Knowledge Proofs | signed receipts as the cheap audit tier; zkLLM 180 s/query | not indexed |
| [2603.05786](https://arxiv.org/abs/2603.05786) | 2026-03-06 | Proof-of-Guardrail | TEE attestation of guardrail execution; deception risk | not indexed |
| [2604.24203](https://arxiv.org/abs/2604.24203) | 2026-04-27 | Agentic Witnessing | TEE-attested auditing as the non-ZK alternative | not indexed |
| [2604.07778](https://arxiv.org/abs/2604.07778) | 2026-04-09 | The Accountability Horizon | impossibility theorem bounding responsibility allocation | not indexed |
| [2609.30824](https://arxiv.org/abs/2609.30824) | 2026-09-25 | Crypto-bound identity-verified capability tokens | scope attenuation along a chain | not indexed |
| [2605.11487](https://arxiv.org/abs/2605.11487) | 2026-05-12 | Digital Identity for Agentic Systems | portable authorization; revocation as a first-class requirement | not indexed |
| [2608.07167](https://arxiv.org/abs/2608.07167) | 2026-08-07 | NiyamAI | intent-contract commitment + per-action zkSNARK | not indexed |
| [2603.16938](https://arxiv.org/abs/2603.16938) | 2026-03-15 | Aegis | sealed policy layer, quorum amendment, 238 ms verify | not indexed |
| [2606.20760](https://arxiv.org/abs/2606.20760) | 2026-06-18 | Privacy-Preserving Compliance on Public Ledgers (SDAS) | Grant/Verify/Revoke lifecycle; 14-constraint sender binding | not indexed |
| [2501.05626](https://arxiv.org/abs/2501.05626) | 2025-01-09 | Kite: How to Delegate Voting Power Privately | private delegate/revoke/re-delegate without the delegate learning | not indexed |
| [2603.15721](https://arxiv.org/abs/2603.15721) | 2026-03-16 | Grant, Verify, Revoke | user-governed authorization sessions, <200 ms client-side proof | 2 |
| [2505.19301](https://arxiv.org/abs/2505.19301) | 2025-05-25 | Zero-Trust Identity Framework for Agentic AI | fine-grained agent access control baseline | not indexed |

Citation counts were queried from the Semantic Scholar Graph API; most 2026 papers are not yet indexed
there, so "not indexed" means *no data*, not *zero citations*.
