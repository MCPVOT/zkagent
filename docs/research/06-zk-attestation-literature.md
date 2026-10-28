# 06 — Zero-Knowledge Attestation of AI-Agent Execution: What the Literature Actually Proves

**As of:** 2026-10-28.
**Slice owner:** academic literature on proving that an agent's actions stayed inside an authorisation, without revealing the actions.
**Out of scope:** proving systems (doc 01), protocol design (doc 02/05), ecosystem/funding (doc 03). This is the evidence layer under those documents.

**Method.** Discovery ran against `arxiv.org/search` (HTML endpoint) with 36 queries across two sweeps, yielding **360 unique candidate records**; the arXiv *API* was unusable from this host — it returned HTTP 429 on every attempt, matching the note in doc 03. 53 candidates were then fetched individually from `arxiv.org/abs/<id>` and their title, author list, submission date and abstract recorded, so **every paper cited below was fetched and read, not recalled**. Five were additionally read as full text (HTML or PDF): 2607.21325, 2608.17220, 2606.23768, 2608.07167, 2608.30083 — claims about what those five do *not* do are drawn from their bodies, not only their abstracts. Semantic Scholar citation data was almost entirely unavailable: of 14 requests, 2 returned counts and the rest returned HTTP 429 or `-1` (not indexed). **Citation counts are therefore not used as a ranking signal anywhere in this document**, and the absence of an index entry for a 2026 preprint is not evidence that it is uninfluential.

**One-line read.** There are now ~20 papers attempting exactly our claim, and **not one of them proves the set of actions is complete**. They prove that a *particular* action satisfied a *particular* predicate. The literature has independently discovered that the hard problem is not the proof — it is binding the proof to the thing that actually executed — and it has named that problem without solving it.

---

## 1. The object being proven, and the five axes that separate the papers

Everything in this corpus is a variation on: *a verifier accepts that some agent did some action inside some authority*. Papers differ on **which** of the following five links they actually close. This is the classification axis used throughout, because it predicts what each system does and does not prove far better than the paper's own framing does.

| # | Link | Question it closes | Typical mechanism |
|---|---|---|---|
| **L1** | **Subject** | *Which* agent/key is acting? | signature, DID, commitment to key |
| **L2** | **Authority** | Who authorised *this* agent, to what scope, until when? | signed mandate, macaroon/Biscuit chain, delegation token |
| **L3** | **Act** | Does *this specific* action fall inside that scope? | circuit predicate over private payload |
| **L4** | **Execution** | Is the proven action the one that actually ran / the value the one the system of record holds? | nonce + calldata binding, TEE attestation, hash-chained receipt |
| **L5** | **Set** | Are these *all* the actions, and do they explain the public aggregate? | sum/count consistency, columnar ledger, completeness proof |

A result that closes L1–L3 and calls itself "verifiable policy compliance" is making a much weaker statement than the phrase implies, because **L4 and L5 are where every deployed system in this corpus fails**. Our design closes L3 and L5 and *inherits* L4 — §8 makes that precise.

---

## 2. Group A — End-to-end "ZK guardrail" systems (the direct neighbours)

These are the papers that generate a zero-knowledge proof per agent action. They are the only true peers of our construction.

### A1. CVA — the closest formal object to our statement
**"Cryptographically verifiable authorization for autonomous AI agents: a falsifiable hypothesis and proof of concept"** — Llambí-Morillas & Fernández-Fernández, 23 Jul 2026, author version of a *Frontiers in Computer Science* 8:1966725 (2026) article. [arXiv:2607.21325](https://arxiv.org/abs/2607.21325)

Defines authorisation as a relation `R_CVA` binding agent principal, a concrete authorisation request, an execution context, and policy satisfaction, and instantiates a subset over **Groth16**. Measured on an AMD Ryzen 7 7700 via a **WASM prover backend, n=20**, single circuit of **531 constraints / 537 wires / 9 private inputs / 5 outputs**: witness generation **61.9 ± 1.1 ms**, proof generation **351.9 ± 26.6 ms**, verification **309.4 ± 22.6 ms**, proof size **805 bytes**. The authors flag that timings include Node.js process startup and are not library-level microbenchmarks. [arXiv:2607.21325](https://arxiv.org/abs/2607.21325)

**What it proves.** Principal binding via `Poseidon(sk_i, ρ_i) = id_i`; request binding via `SHA256(plan) = h_plan`; and that private attributes satisfy a predicate compiled into the circuit. It gives reduction sketches: principal-bind and request/policy-bind advantages bound by `Adv_Groth16_sound + Adv_CommitID_bind` / `Adv_H_coll`. [arXiv:2607.21325](https://arxiv.org/abs/2607.21325)

**What it does NOT prove — stated by the authors.** (i) *Replay resistance is not in the proof at all*: `Accept(x,π) = VerifyAuth(pp,x,π) ∧ Fresh(n,t,N)`, where `N` is a gateway-maintained nonce set — "proof verification is stateless, whereas replay resistance requires mutable enforcement state". (ii) *Policy expressiveness is frozen at circuit-generation time*: "the predicate `P_PoC` … captures only the policy logic explicitly encoded at circuit generation time". (iii) *Context commitment is unimplemented* — the sponge-based `h_c` construction over variable-length context is "proposed here as design directions rather than validated mechanisms". (iv) *No comparative benchmark* across proof systems ("No comparative empirical benchmark … has been conducted"). (v) **No aggregate claim**: there is one proof per request; nothing binds a *set* of requests. (vi) The paper's own framing concedes the L4 gap it does not close: separating identity binding, request binding and *runtime execution binding* is named "a central open problem". (vii) Trusted setup appears in the text only as background on proof-system trade-offs (STARKs "removed trusted-setup requirements"); no ceremony for its own parameters is described. [arXiv:2607.21325](https://arxiv.org/abs/2607.21325)

This is the paper to cite as prior art for our *statement shape*, and the one whose open-problem list we should answer line by line.

### A2. NiyamAI — per-action proof with a neural judge inside the circuit
**"NiyamAI — An Intent-Bound AI Agent with Cryptographically Verifiable Guardrails using Zero-Knowledge Proofs"** — Katkar et al., 7 Aug 2026. [arXiv:2608.07167](https://arxiv.org/abs/2608.07167)

Session start seals permitted tools and constraints into an "Intent Contract" under a SHA-256 commitment; every tool invocation passes a deterministic authority gate and a **dedicated neural Judge (11→8→2 feedforward network)**; a zkSNARK certifies correct policy evaluation and execution proceeds only after it verifies. Reported: **88.8% F1 at 1.0% FPR** on 2,000 AgentSafetyBench scenarios (5-fold stratified CV, out-of-fold scoring; bootstrap 95% CI [85.5%, 92.1]) against 66.8% (Llama Prompt Guard 2), 46.2% (GPT-OSS Safeguard) and 40.4% (NeMo Guardrails); McNemar p < 0.0001. Cost: **1.7 s proof generation per approved action, 51 ms verification, 18.6 KB proof**; 18 adversarial vectors tested, two implementation vulnerabilities found and remediated. [arXiv:2608.07167](https://arxiv.org/abs/2608.07167)

**What it proves.** That a specific invocation was scored by a specific 11→8→2 network against a committed contract, and that the gate admitted it. Note the honest framing of the threat model, which is the same as ours: host-local filters "offer no guarantee to an external observer", and "a compromised host produces no evidence of its own failure."

**What it does NOT prove.** (i) **Not that the action is safe** — the circuit attests the *Judge's arithmetic*, and the Judge is a 3-layer MLP; the proof transfers the classifier's 1.0%-FPR error rate, not a safety property. (ii) **Not that the contract is the one a principal authorised** — the abstract seals the contract "at session initialization" and names no principal signature over it; whether a human authorises that contract is *not established in the reviewed material* (**UNVERIFIED either way** — the PDF body was not fully retrievable, only the abstract and opening section). (iii) **No set-level claim**: proofs are per action, so an agent's 100 compliant actions say nothing about the 101st, and nothing aggregates to a total. (iv) No revocation, no cross-session replay statement, no trusted-setup discussion in the abstract. [arXiv:2608.07167](https://arxiv.org/abs/2608.07167)

Also worth recording: the arXiv listing title ("An Intent-Bound AI Agent…") differs from the PDF title ("Cryptographically Verifiable Guardrails for Autonomous LLM Agents") — two titles for one paper, so cite by ID, not title.

### A3. The ZK predicate gateway — and the naming of the source-integrity gap
**"Zero-Knowledge Predicate Proofs Between AI Agents: A Measured, Cross-Protocol Gateway and the Source-Integrity Gap"** — Gopalakrishna, 30 Aug 2026. [arXiv:2608.30083](https://arxiv.org/abs/2608.30083)

Agents exchange **Bulletproofs** of governance-defined predicates over private data instead of the data, carried in a new slot implemented on both MCP and A2A from one endpoint. Measured: a 32-bit threshold predicate **proves in 6.2 ms, verifies in 1.0 ms, 608-byte proof, one commodity vCPU**; 11 adversarial experiments and 19 protocol checks pass; deployed to Kubernetes with verified network isolation. Case study: proving a retail order is within its limit without revealing the amount. [arXiv:2608.30083](https://arxiv.org/abs/2608.30083)

**What it proves.** One predicate, one committed value — data minimisation as an enforced technical measure (they tie it to GDPR).

**What it does NOT prove — and this is the most useful sentence in the corpus for us.** The author states plainly that "a predicate proof binds a statement to a committed value, **never to the system of record**", and that no comparable work resolves this. Their mitigation is to fuse an enclave attestation with the proof in both directions so that one artifact certifies both the predicate and that the value was read by a specific measured binary — tested "against a mock authority", i.e. **a mock, not real hardware**. [arXiv:2608.30083](https://arxiv.org/abs/2608.30083)

This is the published form of our `trace_digest` weakness. It is also the strongest available citation for the claim that a proof over a witness says nothing about where the witness came from.

### A4. PACE — soundness explicitly without completeness, enforced on-chain by signatures
**"PACE: Policy-Attested Contract Execution for Safe AI Agents in Decentralized Finance"** — Karanjai et al., 18 Aug 2026. [arXiv:2608.17220](https://arxiv.org/abs/2608.17220)

Typed transaction intents, a deterministic policy verifier, and signed **Policy Decision Records (PDRs)** binding approved intent + policy + simulation report to the exact execution bytes, with replay and expiration protection; a Solidity smart account enforces PDR signatures on-chain at **29,826–31,822 gas**. Results: 0.00 unsafe-execution and 0.00 false-positive rate on benign tasks across 2,800 trials / 10 seeds, versus 0.80 unsafe for the unguarded baseline; ablations attribute +57.5 pp to permissive-policy settings and +12.5 pp to the touched-contract allowlist. [arXiv:2608.17220](https://arxiv.org/abs/2608.17220)

**What it proves.** That the *bytes broadcast* equal the bytes a verifier approved, under a policy the verifier applied — the L4 binding, done properly with hashes over intent/policy/calldata plus a timestamp.

**What it does NOT prove.** (i) **No zero-knowledge at all** — the PDR is an ECDSA-signed record, so the transaction, policy and simulation are visible to whoever holds it; this is *attested transparency*, not privacy. (ii) The authors are explicit: PACE "targets soundness … It makes **no completeness claim** — whether the policy captures every unsafe outcome is the author's responsibility". (iii) It does not address key compromise. (iv) Safety is claimed "as logic-level safety within a reproducible benchmark rather than deployment-ready DeFi security". (v) One transaction at a time — no aggregate over a session. [arXiv:2608.17220](https://arxiv.org/abs/2608.17220)

PACE is the cleanest statement in the corpus of the soundness/completeness split we must adopt verbatim.

### A5. Certificates of validity — the position paper with the best caveat
**"Cryptographic certificates of validity for trustworthy AI"**, 22 Jun 2026. [arXiv:2606.23768](https://arxiv.org/abs/2606.23768)

Proposes compiling a logical predicate to polynomial constraints and certifying it with a succinct (optionally zero-knowledge) proof, positioned between formal verification and cryptographic authentication. Read in full: it is a programme, not an implementation — no measurements, no system. Its value is the caveat, stated twice: "a certificate of validity for a formal specification **does not in and of itself prove that the formal specification is the right specification**", and it proves only "under the stated assumptions and to within appropriate soundness bounds of the underlying cryptographic back end". [arXiv:2606.23768](https://arxiv.org/abs/2606.23768)

### A6–A7. Audit frameworks, not systems
- **ZKMLOps** — "Show Me You Comply… Without Showing Me Anything": zero-knowledge software auditing for AI-enabled systems, 30 Oct 2025, submitted to IEEE TSE. A framework for generating compliance evidence on demand; argues the "audit-on-demand" regime is where full ZK is the right tool. Abstract reports no proof sizes or times. [arXiv:2510.26576](https://arxiv.org/abs/2510.26576)
- **Private, Verifiable, and Auditable AI Systems** — PhD thesis, 27 Aug 2025, synthesising ZK claims about AI systems, MPC/TEE deployment, and delegation/credential mechanisms for multi-agent systems. Useful as a map of the space; it is not a protocol and reports no measurements. [arXiv:2509.00085](https://arxiv.org/abs/2509.00085)

**Group A verdict.** Four independent groups built the same architecture — sealed policy commitment, per-action proof, gate-on-verify — and reached the same wall: **each proof covers one action, and none of them can tell you the set is complete or that the action executed is the action proven.** Circuit sizes range from 531 constraints (CVA) to a system whose proof is 18.6 KB (NiyamAI); proving cost ranges from 6.2 ms to 1.7 s depending on whether the statement is a range proof or a neural network.

---

## 3. Group B — Delegation and authority evidence (signed, not hidden)

These papers close **L1+L2**. They are the state of the art in practice, and they are what a reviewer will compare us to on latency.

| Paper | Mechanism | Measured | Proves | Does NOT prove |
|---|---|---|---|---|
| **AIP** — Agent Identity Protocol for verifiable delegation across MCP and A2A, 25 Mar 2026 [arXiv:2603.24775](https://arxiv.org/abs/2603.24775) | Invocation-Bound Capability Tokens: signed JWT (compact) or **Biscuit with Datalog policies** (chained), append-only | verify **0.049 ms** (Rust) / **0.189 ms** (Python); **0.22 ms** overhead over no-auth in real MCP-over-HTTP; **2.35 ms** added in a Gemini 2.5 Flash deployment (**0.086%** of end-to-end); **600 attacks, 100% rejection**; a scan of ~2,000 MCP servers found **all lacked authentication** | identity + attenuated authority per invocation, across hops | nothing is hidden — the token chain and its policy are readable by the verifier and any intermediary; no proof that the *action* matched the token beyond parameter checks; no aggregate |
| **HDP** — Human Delegation Provenance, 6 Apr 2026, IETF Internet-Draft [arXiv:2604.04522](https://arxiv.org/abs/2604.04522) | Ed25519-signed hops in an append-only chain; verify offline from issuer's public key + session id | no latency figures in abstract | a human authorisation event, the delegation chain, and the scope under which terminal actions occurred | reveals the chain to the verifier; records *that* a hop happened, not that the action was in scope; explicitly positioned against OAuth token exchange/JWT/UCAN as a provenance layer, not a privacy layer |
| **Mandato** — protocol-level enforcement of signed mandates on MCP, 14 Aug 2026 [arXiv:2608.14074](https://arxiv.org/abs/2608.14074) | MCP-transparent governance proxy; mandate = tools + parameter constraints + context + duration + principal; hash-chained audit log, qualified timestamps | **5 pages, no results** — the paper states a "quantitative evaluation plan" rather than measurements | enforcement at the protocol boundary, decision semantics, audit trail with evidentiary intent; maps to EU AI Act Art. 12/14, GDPR, NIS2, eIDAS 2 | no cryptographic proof, no privacy of parameters, no performance data — an architecture + legal mapping |
| **KYA** — framework-agnostic trust layer, 25 May 2026 (Apache-2.0, `veldt-kya`) [arXiv:2605.25376](https://arxiv.org/abs/2605.25376) | HMAC-chained evidence, "only-tighten" composition algebra, delegation attribution | **89%** of 1,200 adversarial probes detected; ~**1,800 ops/s** at 20 workers; sub-ms p99 scorer; 36/36 matrix cells pass | that an action was authorised and policy-conforming *according to the operator's own engine* | HMAC is symmetric: the party that verifies is the party that logs, so a third party cannot verify independently; no zero-knowledge |
| **aiAuthZ** — off-host identity-bound authorisation, 6 Jul 2026 [arXiv:2607.05518](https://arxiv.org/abs/2607.05518) | gateway with per-message **HMAC-SHA256** + single-use nonce + timestamp window; SHA-256 hash-chained audit log; HMAC QR receipt | 15 models, refusal **100% → 38%**; residual attack success **0%** with gateway at **≤0.03 ms** added; 94% receipt verification across 8 channels, 0 forgeries in 25 wrong-key trials; blocks all 7 attacker-directed calls on AgentDojo banking | that the decision was made outside the agent's context | same symmetry problem as KYA — an HMAC receipt proves nothing to a party that does not share the key; a compromised gateway forges everything |
| **Compositional authorisation** for delegation and scope, 2 Jun 2026 [arXiv:2606.03518](https://arxiv.org/abs/2606.03518) | relational definitions of delegation types + resource-scope attenuation, composed over existing IAM | theory only | a vocabulary and composition operator for recursive delegation | no implementation, no proof system |
| **SentinelAgent** — intent-verified delegation chains, 3 Apr 2026 [arXiv:2604.02767](https://arxiv.org/abs/2604.02767) | Delegation Chain Calculus, 7 properties (6 deterministic, 1 probabilistic); runtime IPDP | claims meta-theorems incl. the **"practical infeasibility of deterministic intent verification"** | authority narrowing, policy preservation, forensic reconstructibility | intent preservation is only *probabilistic* by their own proposition — a negative result we should cite, because it bounds what any "prove the agent intended the right thing" claim can mean |

**Group B verdict.** Fast (sub-millisecond) and deployed, but structurally **not third-party verifiable**: every sub-millisecond design in this group relies on a symmetric MAC whose verification requires the operator's key, or on a signature that reveals the whole authority graph. That is precisely the trade our design refuses — at a cost of three orders of magnitude in verification time (51 ms NiyamAI / 309 ms CVA-WASM vs 0.049 ms AIP). **Stating that trade explicitly is mandatory in any comparison table we publish.**

---

## 4. Group C — Approval↔execution binding: the substitution gap

This group does not use ZK and is the most important group for our threat model, because it establishes that **the action approved is routinely not the action executed** — which is exactly the claim our proof is supposed to close.

- **Approval Laundering** (30 Sep 2026) systematises six failure modes by which a harness silently substitutes action `A'` for approved `A`: **Scope, Argument, Temporal, Tool, Delegation, Semantic**. Studied across Claude Code, Codex CLI and Cursor. [arXiv:2609.38983](https://arxiv.org/abs/2609.38983)
- **"Approve What, Exactly?"** (15 Oct 2026) defines 12 attacks on the approval path (decoy recipients, amount cancellation, card padding, label spoofing, enrollment squatting, threshold splitting), tests them against AP2, a Microsoft action-bound approval design and MCP elicitation, and audits ten agent runtimes: **no third-party verifiable approval record**, no flood limits where measurable, and **post-approval argument changes in 4 of 8 runtimes with measurable binding**. [arXiv:2610.21063](https://arxiv.org/abs/2610.21063)
- **EBL-Core / "From Intent to Execution Grant"** (10 Sep 2026) specifies a conformance profile binding a materialised candidate action, root+operational policies, typed evidence obligations, context, time and a verifiable Decision Record — the closest thing to a *specification* of the object our circuit should prove. [arXiv:2609.11596](https://arxiv.org/abs/2609.11596)
- **ChainIT Authority Protocol / "Provable Authority"** (16 Oct 2026) targets "compact, independently verifiable evidence that the party presenting one exact transaction holds current organisational authority" — including the case where "a software agent can produce a valid signature while acting outside its delegated purpose … or on transaction details that differ from those a human approved". [arXiv:2610.22899](https://arxiv.org/abs/2610.22899)

**What this group proves.** That approval-execution substitution is *empirically common in shipped runtimes* (4/8), and that it is a distinct failure class from "the policy was wrong".
**What it does NOT prove.** Nothing cryptographic: four of these are taxonomies, audits or conformance profiles. None produces a proof, none hides anything, and none measures a verifier cost.

**Why it matters to us.** Our statement is only meaningful if the `trace_digest`/receipt is bound to the *dispatched* call, not to the model's *proposed* call. That is the same weakness 2608.30083 names, arriving from the systems side.

---

## 5. Group D — Aggregate, offline and post-hoc accountability

- **Offline-verifiable accountability for cross-org agent messaging** (28 Aug 2026) defines a policy-controlled *evidence bundle* — sender authentication, authenticated log commitment, witness-backed checkpoints, append-only continuity, delegation-aware authorisation evidence, receiver-signed receipts — verified **offline** by a third party. 300 complete workflows / 1200 valid preserved bundles; all corrupted or policy-insufficient bundles rejected, no false accepts. Explicitly: it "does not infer delivery or receipt from transport behavior or log inclusion alone". [arXiv:2608.28542](https://arxiv.org/abs/2608.28542)
- **Matoi** (15 Oct 2026) separates reusable *consequence evidence* from current authority and durable occurrence history; a 1,440-cell matched-wire study finds reuse reduces complete lifecycle cost by **3.49% (JS)** and **1.79% (Python)**, with combined representation/reuse reductions of **10.87%** and **16.53%** against full proof — and honestly reports that **5 of 12** family intervals cross 1. Evaluated on a frozen AgentDojo Banking mapping: 5/16 user plans, 7/9 attack plans. [arXiv:2610.21394](https://arxiv.org/abs/2610.21394)
- **Verifiable Agent Insurance** (13 Oct 2026) puts programmatic policies + a monetary escrow in a smart contract; a user who detects a violation prompts a verifier to review traces logged through the harness's shared tool-execution path. Deployed end-to-end on an Ethereum L2; detects violations in **42.2% of runs containing violations** across three benchmarks, two re-annotated for task-level policy compliance. The paper's own finding is the useful one: many agents "do not emit user authorizations and security-relevant information as explicit, structured data objects — rather, they embed the data … in natural language exchanges". [arXiv:2610.18230](https://arxiv.org/abs/2610.18230)
- **No Certificate, No Execution: Certified Traces** (23 May 2026) formalises Proposal→Certification→Execution: a generator `M_G` proposes traces, a permissibility machine `M_Π` certifies them under policy `Π`, and the executable language is `L_exec = L_G ∩ L_cert(M_Π)`. The key sentence for us: "generation is not permission: an action may be computable yet impermissible, and individually permissible actions may compose into an impermissible trace". No implementation. [arXiv:2605.24462](https://arxiv.org/abs/2605.24462)
- **Governing Actions, Not Agents** (24 Jun 2026) formalises institutional attestation: the agent keeps autonomy over planning but holds **no execution authority** over designated high-risk actions; execution requires preconditions each independently attested by a separate authoritative source, bound to declared intent, evaluated by a deterministic policy, recorded in a tamper-evident log. Proof-of-concept only. [arXiv:2606.26298](https://arxiv.org/abs/2606.26298)
- **MutMem** (3 Aug 2026) — authorised mutation of persistent agent memory: each weight change is an authorised transition binding a provenance node, signer epoch, quantised old/new weights, a no-fork predecessor and two domain-separated SHA-256 commitments; Ed25519 verified in both writer and a portable verifier; median **4.865 ms** per signed transition. Its closing sentence is a model of scope discipline: it "provides evidence of integrity, authorization, traceability, and historical continuity; **it does not establish content truth**". [arXiv:2608.02843](https://arxiv.org/abs/2608.02843)
- **From Agent Traces to Trust** (3 Jun 2026) — survey framing execution provenance as a typed graph of an agent run. The right citation for "provenance is the object, not the log". [arXiv:2606.04990](https://arxiv.org/abs/2606.04990)

**Group D verdict.** This is where the field actually solves L5-adjacent problems — zkLedger-style completeness and evidence sufficiency — but **it solves them for signed, revealed records, not for hidden actions**. Nobody in this group produces a zero-knowledge proof over an aggregate.

---

## 6. Group E — Lifecycle: revocation and freshness (our known gap, partly closed by others)

- **Heartbeat-Bound Hierarchical Credentials** (20 May 2026): credential validity bound to periodic parent liveness proofs, verifiable with only a cached public key and local clock. Freshness window `W_z ≤ W_max + Δ_h + ε`. Measured: **0.26 ms** full authentication in Rust, **18,000+ verifications/s**, stable latency 10→10,000 agents, **90× reduction in the zombie window** over OAuth 2.0, **0.71%** end-to-end overhead on tool calls, zero post-revocation tool calls under prompt injection, cascading revocation across a **49-agent, four-level hierarchy** within the bound. [arXiv:2605.20704](https://arxiv.org/abs/2605.20704)
- **Authorization Revocation for Long-Running AI Agents** (18 Sep 2026): defines *root-scoped authorisation quiescence* with certificates over every cut-relevant acceptance, antichains of minimal sufficient root sets, and proofs of post-cut issuer non-expansion, compositional soundness, merge-order independence and crash/replay stability; 17/17 registered outcomes in a provider-free late-effect suite. [arXiv:2609.21284](https://arxiv.org/abs/2609.21284)

**What these prove.** That authority *expires* and that late effects are accounted for — with a machine-checkable certificate in the second case.
**What they do NOT prove.** Nothing about the content of actions: HBHC proves a key was alive at time *t*; it does not prove what was done with it. Neither composes with a ZK policy proof — **the composition (a proof that is only valid while a heartbeat is alive, and that self-invalidates on revocation) is unoccupied in this corpus.**

---

## 7. Group F — The limits literature, including the counter-position we must answer

This is the group that decides whether the project is defensible. Ignoring it would make this report advocacy.

### F1. Post-Audit Mirage — offline/static verification cannot be sound
**"Post-Audit Mirage: Identifiability Limits of Offline Agent Verification"**, 22 Oct 2026, accepted at the NeurIPS 2026 workshop *Who Verifies the Agents?* [arXiv:2610.31130](https://arxiv.org/abs/2610.31130)

Constructs matched safe and harmful agent lifecycles that expose **identical verifier-visible evidence** while an isolated scorer records opposite deployment truth, and proves an error–abstention tradeoff at that boundary. Benchmark covers authorisation, scheduling and shared-capacity environments; a monitor recovers the distinction only in favourable settings and "may remain undecided for rare groups, small effects, or missing observations". Conclusion: verification "must test both calculation validity and whether the available evidence supports the deployment decision".

**What it proves.** That a sound *offline* check of an agent's compliance is impossible in general — the evidence is observationally equivalent.
**What it does NOT prove.** That a *runtime-bound* check is impossible. This is the paper that forces our architecture: the proof must bind to the live execution context (nonce, timestamp, receipt), not to a static audit of the agent. We should cite it as the formal justification for per-execution proofs rather than "certify the agent once".

### F2. Tool Receipts, Not Zero-Knowledge Proofs — the cost counter-argument
9 Mar 2026. Argues ZK "impose[s] minutes of proving time per query, making [it] impractical for interactive agents", and proposes HMAC-signed tool-execution receipts with epistemic-source classification instead. Reports 94.2% of fabricated tool references, 87.6% of count misstatements, 91.3% of false absence claims detected at **<15 ms** verification overhead, against zkLLM at **180 s/query**. [arXiv:2603.10060](https://arxiv.org/abs/2603.10060)

**What it proves.** That HMAC receipts beat ZK *on latency* for hallucination detection against a cooperative logger.
**What it does NOT prove.** Anything to a third party — an HMAC receipt is unforgeable only to those without the key, so the operator can mint arbitrary receipts. The paper's "180 s/query" baseline is **zkLLM-style inference proving**, not a small policy circuit; our statement is 3–5 orders of magnitude cheaper (CVA: 352 ms prove / 309 ms verify at 531 constraints; NiyamAI: 1.7 s / 51 ms). **The comparison is only fair against the same statement, and that distinction must be made explicitly in our writing** — this is the paper most likely to be quoted at us.

### F3. Sampling instead of proving
**"Towards Verifiable AI with Lightweight Cryptographic Proofs of Inference"**, 19 Mar 2026, accepted at IEEE SaTML 2026. Commits to an execution trace with Merkle-tree vector commitments and opens a few random paths, trading soundness for efficiency: "from the order of minutes to the order of milliseconds, with moderately larger proofs". Suited to auditing and repeated queries where detection probability compounds. [arXiv:2603.19025](https://arxiv.org/abs/2603.19025)

**What it proves.** With probability related to the number of sampled paths, that the committed trace explains the output.
**What it does NOT prove.** A worst-case guarantee, or anything about *authorisation*. It is a completeness check on a trace, not a policy check.

### F4. Where ZK legitimately loses to TEEs
**"Agentic Witnessing"** (27 Apr 2026) argues ZKPs are "typically limited to precise algebraic constraints and are ill-suited for verifying qualitative, unstructured properties, such as the logic within a codebase", and moves to *attested reasoning*: an LLM auditor inside a TEE, answering boolean questions, with a signed hash chain binding the reasoning trace to the dataset and the hardware root of trust; 21 peer-reviewed artefacts automated. [arXiv:2604.24203](https://arxiv.org/abs/2604.24203)

**What it proves.** That a specific measured binary inspected the data and produced this transcript — conditional on the hardware vendor.
**What it does NOT prove.** Any algebraic property, or anything if the TEE is broken; and the verifier still trusts a vendor root.

### F5. The inference-proving line (context, not competition)
Three 2026 papers route *around* full ZK for inference — TensorCommitments [arXiv:2602.12630](https://arxiv.org/abs/2602.12630), Jolt Atlas [arXiv:2602.17452](https://arxiv.org/abs/2602.17452), and NanoZK (constant-size sub-circuit proofs of **3.5–3.7 KB**, "about 83 KB total at L=12", against monolithic ZKML proofs of 101–126 KB) [arXiv:2603.18046](https://arxiv.org/abs/2603.18046) — while Repeated-Game Security for restaking-based verifiable inference shows one-round slashing conditions overstate security when inference is supplied repeatedly [arXiv:2608.09055](https://arxiv.org/abs/2608.09055). **Implication for us: do not attach our claim to inference provenance.** The statement we prove is small and algebraic; theirs is large and being actively routed around.

---

## 8. What *no* paper in this corpus proves — the six structural gaps

This is the section the report exists for. Each row is a claim a reader might assume is covered somewhere above and is not.

| Gap | Why it is unproven | Strongest evidence |
|---|---|---|
| **G1. Set completeness** — "these are all the actions" | Every per-action system (CVA, NiyamAI, ZK gateway, PACE) proves one action. Only zkLedger proves completeness, and it does so with a columnar ledger under a **permissioned** model with **no zero-knowledge for amounts** — Pedersen commitments + Schnorr-type NIZKs, no trusted setup, 100k transactions, auditor queries answered in **<10 ms**. [arXiv:2607.21325](https://arxiv.org/abs/2607.21325), [arXiv:2608.07167](https://arxiv.org/abs/2608.07167), [zkLedger, NSDI'18](https://www.usenix.org/conference/nsdi18/presentation/narula) | No agent-domain paper proves an aggregate over hidden actions |
| **G2. Source integrity** — the witness really came from the system of record | Named explicitly: a predicate proof "binds a statement to a committed value, never to the system of record"; mitigation tested "against a mock authority". [arXiv:2608.30083](https://arxiv.org/abs/2608.30083) | The single most damaging gap for any ZK-agent claim |
| **G3. Execution binding** — the proven action is the dispatched action | Post-approval argument changes in **4 of 8** runtimes; six laundering modes. ZK papers bind to a *committed plan*, not to calldata. [arXiv:2610.21063](https://arxiv.org/abs/2610.21063), [arXiv:2609.38983](https://arxiv.org/abs/2609.38983) | Only PACE binds to exact bytes, and it is not ZK. [arXiv:2608.17220](https://arxiv.org/abs/2608.17220) |
| **G4. Revocation inside the proof** | HBHC and quiescence certificates handle expiry/withdrawal, but neither composes with a ZK policy proof; ZK papers put freshness outside the circuit by design. [arXiv:2605.20704](https://arxiv.org/abs/2605.20704), [arXiv:2609.21284](https://arxiv.org/abs/2609.21284), [arXiv:2607.21325](https://arxiv.org/abs/2607.21325) | Unoccupied intersection |
| **G5. Spec correctness** — the policy encodes what the principal meant | Stated as a limit by the position paper itself, and conceded by PACE ("makes no completeness claim"). [arXiv:2606.23768](https://arxiv.org/abs/2606.23768), [arXiv:2608.17220](https://arxiv.org/abs/2608.17220) | Nobody claims it; several disclaim it |
| **G6. Third-party verifiability at practical cost** | The fast designs (0.049–0.26 ms) are symmetric-MAC or signature schemes that require operator trust; the ZK designs cost 51 ms–1.7 s per proof and none reports an independent third-party deployment. [arXiv:2603.24775](https://arxiv.org/abs/2603.24775), [arXiv:2605.20704](https://arxiv.org/abs/2605.20704), [arXiv:2608.07167](https://arxiv.org/abs/2608.07167) | The honest cost of privacy is stated nowhere in one place |

A seventh, methodological gap: **no paper in this corpus publishes a trusted-setup story for its own parameters.** CVA uses Groth16 and discusses trusted setup only as background [arXiv:2607.21325](https://arxiv.org/abs/2607.21325); NiyamAI's abstract is silent [arXiv:2608.07167](https://arxiv.org/abs/2608.07167); the position paper does not address it [arXiv:2606.23768](https://arxiv.org/abs/2606.23768). The mechanism exists — scalable MPC for zk-SNARK parameters in the random-beacon model [eprint 2017/1050](https://eprint.iacr.org/2017/1050) — and zkLedger's choice to avoid trusted setup entirely by using Schnorr-type NIZKs and Pedersen commitments is the design precedent worth studying [zkLedger, NSDI'18](https://www.usenix.org/conference/nsdi18/presentation/narula).

---

## 9. Where our project sits — the gaps we can actually occupy

Our statement already differs from every paper above in one respect: **it binds a public receipt (total, count, time, chain, execution id) to a hidden multiset of actions.** That is a weak form of L5 that no agent-domain paper attempts. Naming it correctly is the whole opportunity, and it comes with a precise limit.

1. **Arithmetic completeness, not eventual completeness.** Because the circuit constrains Σamounts = receipt.total and #actions = receipt.count, a prover cannot silently drop an action *from the set it proves* — omission breaks the sum. zkLedger calls the analogous property *completeness* and it is the reason their auditor can trust that nothing is hidden [zkLedger, NSDI'18](https://www.usenix.org/conference/nsdi18/presentation/narula). **But** our completeness is relative to a receipt that some execution path produced. If the harness that emits the receipt is compromised, the receipt is a lie and the proof faithfully proves a lie about a lie. That is exactly gap **G2** [arXiv:2608.30083](https://arxiv.org/abs/2608.30083), and we must state it in the same sentence as the claim, not in a limitations appendix.
2. **Per-action + aggregate in one artifact.** CVA and NiyamAI give one proof per action and no aggregate [arXiv:2607.21325](https://arxiv.org/abs/2607.21325), [arXiv:2608.07167](https://arxiv.org/abs/2608.07167); PACE gives an aggregate-free per-transaction record [arXiv:2608.17220](https://arxiv.org/abs/2608.17220); Matoi shows evidence reuse is where the cost savings are but only recovers 1.79–3.49% in its own measurements [arXiv:2610.21394](https://arxiv.org/abs/2610.21394). A single proof over the set, with the count and total as public inputs, is a distinct object.
3. **The negative space as a published artifact.** The best practice in this corpus is PACE's one-line concession ("targets soundness… makes no completeness claim") and MutMem's closing sentence ("does not establish content truth") [arXiv:2608.17220](https://arxiv.org/abs/2608.17220), [arXiv:2608.02843](https://arxiv.org/abs/2608.02843). Our §9.2 in doc 05 should be as short and as quotable as those.
4. **Runtime binding justified by a theorem, not a preference.** F1 proves static/offline verification is unsound in general [arXiv:2610.31130](https://arxiv.org/abs/2610.31130). That is the argument for per-execution proofs with a nonce and a freshness window — the same construction CVA places *outside* its circuit [arXiv:2607.21325](https://arxiv.org/abs/2607.21325) — and it should be cited as the reason our verifier is stateful.
5. **Revocation composed with the proof.** HBHC's liveness-bound credentials [arXiv:2605.20704](https://arxiv.org/abs/2605.20704) and quiescence certificates [arXiv:2609.21284](https://arxiv.org/abs/2609.21284) are both available and neither has been combined with a ZK policy proof. This is a real, citable, unoccupied gap — and it is the honest answer to "no revocation path" in our baseline.
6. **Third-party verifiability stated as the differentiator, with its cost.** Against AIP at 0.049 ms [arXiv:2603.24775](https://arxiv.org/abs/2603.24775) we lose by ~3 orders of magnitude; against NiyamAI at 51 ms verify / 1.7 s prove [arXiv:2608.07167](https://arxiv.org/abs/2608.07167) we are comparable or faster on verify. Our published comparison must show **both** columns.

### What we must stop claiming
- **"Proves policy compliance."** Unbounded — the predicate only covers logic compiled into the circuit [arXiv:2607.21325](https://arxiv.org/abs/2607.21325), and the certificate does not prove the spec is the right spec [arXiv:2606.23768](https://arxiv.org/abs/2606.23768). Say: *proves that a hidden action set satisfies these arithmetic constraints under this committed policy*.
- **"The agent stayed within its authorisation"** — as an unqualified sentence — because L4 is inherited, not closed [arXiv:2608.30083](https://arxiv.org/abs/2608.30083), [arXiv:2610.21063](https://arxiv.org/abs/2610.21063).
- **Any inference-provenance claim.** The three 2026 inference papers show the field is routing around full ZK there [arXiv:2602.12630](https://arxiv.org/abs/2602.12630), [arXiv:2602.17452](https://arxiv.org/abs/2602.17452), [arXiv:2603.18046](https://arxiv.org/abs/2603.18046).

---

## 10. Weaknesses in our own position, stated plainly

- **Our circuit is bigger than the closest competitor and our numbers are not yet reconciled.** CVA reports **531 constraints** and 805-byte proofs [arXiv:2607.21325](https://arxiv.org/abs/2607.21325); our own doc 05 §4.2 states **2,162 constraints and 9 public inputs**, while the project baseline states **3,333 constraints and 15 public inputs**. Those three cannot all be current. The literature's smallest credible per-action proof is NiyamAI's **18.6 KB** [arXiv:2608.07167](https://arxiv.org/abs/2608.07167) and its smallest overall is the **608-byte** Bulletproofs predicate [arXiv:2608.30083](https://arxiv.org/abs/2608.30083); our 128-byte Groth16 proof is competitive *because the statement is smaller*, and that is the claim to defend — not a constraint-count claim.
- **1.7 s per action is the realistic cost of proving a neural component** [arXiv:2608.07167](https://arxiv.org/abs/2608.07167). If our statement ever grows to include a classifier, we inherit that, and per-action proving becomes unusable for interactive agents — which is the grain of truth in F2 [arXiv:2603.10060](https://arxiv.org/abs/2603.10060).
- **We have no user study and no deployment numbers.** The papers with deployment evidence (AIP, aiAuthZ, HBHC, PACE) all achieve it by *not* being zero-knowledge [arXiv:2603.24775](https://arxiv.org/abs/2603.24775), [arXiv:2607.05518](https://arxiv.org/abs/2607.05518), [arXiv:2605.20704](https://arxiv.org/abs/2605.20704), [arXiv:2608.17220](https://arxiv.org/abs/2608.17220). Our credibility has to come from measurement discipline instead: publish prove/verify times per constraint count, proof bytes, and the exact machine.
- **Citation-weight is unavailable as validation.** This literature is months old; Semantic Scholar returned a count for only two of fourteen sampled papers (one of them 10, one 0). Popularity is not evidence here, in either direction.

---

## 11. Foundations (verified separately; not competing systems)

| Primitive | Source (verified) | Why it is load-bearing for us |
|---|---|---|
| **Groth16** | "On the Size of Pairing-based Non-interactive Arguments", [eprint 2016/260](https://eprint.iacr.org/2016/260) | 128-byte proofs, 3-pairing verification; the reason a per-execution proof is affordable at volume, and the source of our trusted-setup obligation |
| **Bulletproofs** | "Bulletproofs: Short Proofs for Confidential Transactions and More", [eprint 2017/1066](https://eprint.iacr.org/2017/1066) | The no-trusted-setup range-proof primitive behind the 608-byte predicate proofs in [arXiv:2608.30083](https://arxiv.org/abs/2608.30083); the alternative if the ceremony is unacceptable |
| **Powers-of-Tau MPC** | "Scalable Multi-party Computation for zk-SNARK Parameters in the Random Beacon Model", [eprint 2017/1050](https://eprint.iacr.org/2017/1050) | The concrete answer to "single-party trusted setup": a public ceremony is a known, implementable procedure |
| **zkLedger** | Narula, Vasquez, Virza, NSDI'18 — [usenix.org](https://www.usenix.org/conference/nsdi18/presentation/narula) | The only verified precedent for *completeness* in a private-audit setting: columnar ledger, Pedersen commitments + Schnorr-type NIZKs, no trusted setup, 100k transactions, auditor queries in **<10 ms** |

---

## 12. Open questions worth tracking

1. **Does anyone compose revocation with a ZK policy proof?** Nothing in 360 records does. If that changes, it is a direct competitor to our lifecycle story.
2. **Will the source-integrity fix (enclave attestation fused with proof) be validated on real hardware?** Currently tested "against a mock authority" [arXiv:2608.30083](https://arxiv.org/abs/2608.30083). If it works, it closes G2 without our receipt design.
3. **Does the NeurIPS 2026 workshop line of work (F1) produce a positive construction?** It currently only proves impossibility for offline verification [arXiv:2610.31130](https://arxiv.org/abs/2610.31130).
4. **Do AgentDojo-style benchmarks acquire policy-level labels?** VAI had to re-annotate two of three benchmarks for task-level compliance [arXiv:2610.18230](https://arxiv.org/abs/2610.18230) — until that exists, every "policy compliance" number in this literature is measured against an author-defined policy.
5. **Is 4-of-8 post-approval argument mutation [arXiv:2610.21063](https://arxiv.org/abs/2610.21063) fixed in the harnesses, or does it become a permanent threat model?** Our value proposition depends on the answer.

---

## Sources

Every source below was fetched on 2026-10-28 and its title/date confirmed against the live page.

**Agent-domain papers (arXiv)**
1. [arXiv:2607.21325](https://arxiv.org/abs/2607.21325) — Cryptographically verifiable authorization for autonomous AI agents: a falsifiable hypothesis and proof of concept. Llambí-Morillas & Fernández-Fernández. 23 Jul 2026. (Frontiers in Computer Science 8:1966725, 2026)
2. [arXiv:2608.07167](https://arxiv.org/abs/2608.07167) — NiyamAI — An Intent-Bound AI Agent with Cryptographically Verifiable Guardrails using Zero-Knowledge Proofs. Katkar et al. 7 Aug 2026.
3. [arXiv:2608.30083](https://arxiv.org/abs/2608.30083) — Zero-Knowledge Predicate Proofs Between AI Agents: A Measured, Cross-Protocol Gateway and the Source-Integrity Gap. Gopalakrishna. 30 Aug 2026.
4. [arXiv:2608.17220](https://arxiv.org/abs/2608.17220) — PACE: Policy-Attested Contract Execution for Safe AI Agents in Decentralized Finance. Karanjai et al. 18 Aug 2026.
5. [arXiv:2606.23768](https://arxiv.org/abs/2606.23768) — Cryptographic certificates of validity for trustworthy AI. 22 Jun 2026.
6. [arXiv:2510.26576](https://arxiv.org/abs/2510.26576) — "Show Me You Comply… Without Showing Me Anything": Zero-Knowledge Software Auditing for AI-Enabled Systems. Scaramuzza et al. 30 Oct 2025.
7. [arXiv:2509.00085](https://arxiv.org/abs/2509.00085) — Private, Verifiable, and Auditable AI Systems (PhD thesis). 27 Aug 2025.
8. [arXiv:2603.24775](https://arxiv.org/abs/2603.24775) — AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A. Prakash. 25 Mar 2026.
9. [arXiv:2604.04522](https://arxiv.org/abs/2604.04522) — HDP: A Lightweight Cryptographic Protocol for Human Delegation Provenance in Agentic AI Systems. Dalugoda. 6 Apr 2026.
10. [arXiv:2608.14074](https://arxiv.org/abs/2608.14074) — Mandato: Protocol-Level Enforcement of Digitally Signed Mandates on AI Agent Actions with Cryptographically Chained Audit Trails. Racioppi. 14 Aug 2026.
11. [arXiv:2605.25376](https://arxiv.org/abs/2605.25376) — KYA: A Framework-Agnostic Trust Layer for Autonomous Systems with Verifiable Provenance and Hierarchical Policy Composition. Quadri. 25 May 2026.
12. [arXiv:2607.05518](https://arxiv.org/abs/2607.05518) — aiAuthZ: Off-Host, Identity-Bound Authorization for AI Agents. 6 Jul 2026.
13. [arXiv:2606.03518](https://arxiv.org/abs/2606.03518) — Overlaying Governance: A Compositional Authorization Framework for Delegation and Scope in Agentic AI. 2 Jun 2026.
14. [arXiv:2604.02767](https://arxiv.org/abs/2604.02767) — SentinelAgent: Intent-Verified Delegation Chains for Securing Federal Multi-Agent AI Systems. 3 Apr 2026.
15. [arXiv:2609.38983](https://arxiv.org/abs/2609.38983) — Approval Laundering: Systematizing Approval–Execution Binding Failures in AI Coding-Agent Harnesses. 30 Sep 2026.
16. [arXiv:2610.21063](https://arxiv.org/abs/2610.21063) — Approve What, Exactly? Effect Binding and Trusted Rendering for Agent Step-Up Authorization. 15 Oct 2026.
17. [arXiv:2609.11596](https://arxiv.org/abs/2609.11596) — From Intent to Execution Grant: An Execution-Boundary Conformance Profile for High-Risk AI Actions. 10 Sep 2026.
18. [arXiv:2610.22899](https://arxiv.org/abs/2610.22899) — Provable Authority: A Protocol for Verifiable Authority Resolution and Control Across Human, Organizational, and Agentic Systems. 16 Oct 2026.
19. [arXiv:2608.28542](https://arxiv.org/abs/2608.28542) — Offline-Verifiable Accountability for Cross-Organization Agent Messaging: A Preserved Evidence-Bundle Approach. Alshammari & Bahsi. 28 Aug 2026.
20. [arXiv:2610.21394](https://arxiv.org/abs/2610.21394) — Matoi: Selective Revalidation of Consequence Evidence for Agent Authorization. 15 Oct 2026.
21. [arXiv:2610.18230](https://arxiv.org/abs/2610.18230) — Holding Agents Accountable with Verifiable Agent Insurance. 13 Oct 2026.
22. [arXiv:2605.24462](https://arxiv.org/abs/2605.24462) — No Certificate, No Execution: Certified Traces as a Foundation for Trustworthy AI Agents. 23 May 2026.
23. [arXiv:2606.26298](https://arxiv.org/abs/2606.26298) — Governing Actions, Not Agents: Institutional Attestation as a Governance Model for Autonomous AI Systems. Salfeld-Nebgen. 24 Jun 2026.
24. [arXiv:2608.02843](https://arxiv.org/abs/2608.02843) — MutMem: Cryptographically Authorized Mutation in Persistent Agent Memory. Saidi. 3 Aug 2026.
25. [arXiv:2606.04990](https://arxiv.org/abs/2606.04990) — From Agent Traces to Trust: A Survey of Evidence Tracing and Execution Provenance in LLM Agents. 3 Jun 2026.
26. [arXiv:2605.15228](https://arxiv.org/abs/2605.15228) — Verifiable Agentic Infrastructure: Proof-Derived Authorization for Sovereign AI Systems. He & Yu. 13 May 2026.
27. [arXiv:2605.20704](https://arxiv.org/abs/2605.20704) — Heartbeat-Bound Hierarchical Credentials: Cryptographic Revocation for AI Agent Swarms. 20 May 2026.
28. [arXiv:2609.21284](https://arxiv.org/abs/2609.21284) — Authorization Revocation for Long-Running AI Agents: Root-Scoped Quiescence under Delegation and Asynchronous Execution. 18 Sep 2026.
29. [arXiv:2610.31130](https://arxiv.org/abs/2610.31130) — Post-Audit Mirage: Identifiability Limits of Offline Agent Verification. 22 Oct 2026. (NeurIPS 2026 workshop)
30. [arXiv:2603.10060](https://arxiv.org/abs/2603.10060) — Tool Receipts, Not Zero-Knowledge Proofs: Practical Hallucination Detection for AI Agents. 9 Mar 2026.
31. [arXiv:2603.19025](https://arxiv.org/abs/2603.19025) — Towards Verifiable AI with Lightweight Cryptographic Proofs of Inference. 19 Mar 2026. (IEEE SaTML 2026)
32. [arXiv:2604.24203](https://arxiv.org/abs/2604.24203) — Agentic Witnessing: Pragmatic and Scalable TEE-Enabled Privacy-Preserving Auditing. 27 Apr 2026.
33. [arXiv:2602.12630](https://arxiv.org/abs/2602.12630) — TensorCommitments: A Lightweight Verifiable Inference for Large Language Models. 13 Feb 2026.
34. [arXiv:2602.17452](https://arxiv.org/abs/2602.17452) — Jolt Atlas: Verifiable Inference via Lookup Arguments in Zero Knowledge. 19 Feb 2026.
35. [arXiv:2603.18046](https://arxiv.org/abs/2603.18046) — NanoZK: Privacy-Preserving Verifiable Inference for Large Language Models via Layerwise Zero-Knowledge Proofs. 17 Mar 2026.
36. [arXiv:2608.09055](https://arxiv.org/abs/2608.09055) — Repeated-Game Security for Restaking-Based Verifiable Inference. 10 Aug 2026.

**Foundations (IACR eprint / conference)**
37. [eprint 2016/260](https://eprint.iacr.org/2016/260) — On the Size of Pairing-based Non-interactive Arguments (Groth16).
38. [eprint 2017/1066](https://eprint.iacr.org/2017/1066) — Bulletproofs: Short Proofs for Confidential Transactions and More.
39. [eprint 2017/1050](https://eprint.iacr.org/2017/1050) — Scalable Multi-party Computation for zk-SNARK Parameters in the Random Beacon Model.
40. [zkLedger, NSDI'18](https://www.usenix.org/conference/nsdi18/presentation/narula) — Narula, Vasquez, Virza. Privacy-Preserving Auditing for Distributed Ledgers.

**Correction log.** Two arXiv IDs initially assumed from memory (`1810.01110` for Zexe, `1708.03372` for Solidus) were fetched and found to be unrelated papers ("Link Prediction Adversarial Attack", "Optimal Prediction for Additive Function-on-Function Regression"). Both were dropped rather than cited. No paper in this document rests on an unverified ID.
