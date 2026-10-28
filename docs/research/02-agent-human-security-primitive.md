# 02 — The Agent/Human Security Primitive

**What ZK actually proves for an AI agent, who checks it, and what already exists**

Status: research slice 2 of the MCPVOT ZK-agent project. Scope fence: this document covers the *problem space and prior art* for agent/human security. It does not survey proving-system substrates (slice 01) and does not teach ZK math. Every claim carries an inline source URL. Claims I could not source are marked `[unverified]`. Systems are labelled `[SHIPPED-MAINNET]`, `[SHIPPED-OSS]`, `[PAPER]`, `[DRAFT-STANDARD]`, `[FINAL-STANDARD]`, `[VENDOR-CLAIM]` or `[SECONDARY]`.

---

## 1. The problem, stated precisely

### 1.1 The claim we want to make checkable

> *"This action was executed by an agent acting under a policy you signed, within the budget and scope you granted, and it did not touch the endpoints or bytes you forbade."*

Today that sentence is asserted by the same process that could have violated it. The agent runtime, the tool gateway, and the log writer are all inside the trust boundary of the party being audited. Three independent 2026 results show this is not a theoretical worry:

- **Traces are tamperable by the agent itself.** Every tested local agent harness except one allowed the agent to delete its own execution traces when asked, without tripping monitor guardrails; external attackers can induce the same deletion, and the behaviour emerges naturally when agents optimise reward ([arXiv:2609.30266](https://arxiv.org/abs/2609.30266)).
- **A predicate proof binds a value, not the system of record.** A built-and-deployed ZK proof gateway proves "this number is under the limit" perfectly, but the proof binds a *committed* value and never the database it was read from — the paper calls this the source-integrity gap and proposes fusing an enclave attestation with the proof to close it ([arXiv:2608.30083](https://arxiv.org/abs/2608.30083)).
- **Proof of correct inference is not proof of the claimed model.** A dishonest provider can keep the declared architecture and parameter count but embed "ghost weights" whose algebraic structure collapses the effective computation: the circuit is satisfied, the proof verifies, and the provider did the work of a much smaller model ([arXiv:2607.28884](https://arxiv.org/abs/2607.28884), IEEE S&P 2026).

So the primitive is not "prove the agent is good". It is: **prove a specific, bounded relation between a public commitment and a private execution, such that a verifier who trusts only the commitment and the verification key learns nothing else, and cannot be fooled into accepting an execution that did not happen.** Everything below follows from taking that sentence literally, including its limits.

### 1.2 Formal shape

A proof system here is a relation `R(x, w) ∈ {0,1}` with public instance `x` and private witness `w`. The prover is the agent runtime (or a co-operating host). The verifier is whoever the claim is addressed to.

| | Contents | Why it is on this side |
|---|---|---|
| **Hidden (`w`)** | Prompts and system instructions; tool call arguments and returned payloads; model weights and KV state; the human's identity, balance, and deposit link; per-action salts; the policy's private evaluation trace | These are the things whose disclosure is the harm. Leaking them via a proof is a failure, not a side effect. |
| **Public (`x`)** | `policy_id` + hash of the signed policy; agent identity commitment; action/session commitment `H(tool, args, result, salt)`; the asserted verdict bits (`allowed=1`, `within_budget=1`, `no_forbidden_endpoint=1`); budget-after commitment; `epoch`; `nullifier`; `chainid`; `verifyingContract`; verifier-chosen `nonce`; expiry | These are the only facts a verifier is allowed to act on, and each must be *bound* — a verdict bit floating free of a commitment is worthless. |

The verifier checks `V(vk, x, π) = 1` and then acts on `x` alone. Anything the verifier needs but cannot see must appear in `x` as a commitment, and anything in `x` must be safe to publish.

### 1.3 The twelve properties a proof must have

Ordered by how often they are quietly skipped.

1. **Knowledge soundness.** No polynomial-time prover can produce `π` for a false `x` except with negligible probability. *Stops:* "the agent says it was allowed". *Fails if:* the circuit under-constrains (see the public-input overflow class of bug, [EIP-7520 / Beosin](https://beosin.com/resources/erc-7520-proposal-zk-snark-public-inputs-overflow)).
2. **Zero-knowledge, including public-input hygiene.** A simulator can produce `x` and `π` without `w`. *Stops:* the audit becoming the leak. *Fails if:* the public instance commits to a low-entropy secret (a balance of 3 possibilities, a timestamp to the second) — the commitment is then brute-forceable and the "private" value is public. This is why zkAPI's own EF write-up is explicit that prompt contents can still re-link sessions even when payment is unlinkable ([EF blog, 2026-10-01](https://blog.ethereum.org/2026/10/01/introducing-zkapi)).
3. **Binding to a committed transcript.** `x` must contain a commitment to the exact action the verdict is about, opened in-circuit. *Stops:* verdict transplant — reusing a "policy compliant" proof from a harmless action on a harmful one. ERC-8262 solves this per proof type by making `submitter`, `merkle_root`, `tx_set_hash` and `settlement_root` explicit public inputs ([ERC-8262](https://eips.ethereum.org/EIPS/eip-8262)).
4. **Freshness / non-replay.** Verifier-chosen nonce or a narrow epoch, plus `chainid` and `verifyingContract` in the instance. *Stops:* replay of yesterday's proof against today's request, and cross-chain replay. ERC-8039's discussion thread names chainId/verifyingContract/nonce/expiry as the required domain-separation lanes ([Ethereum Magicians, ERC-8039](https://ethereum-magicians.org/t/erc-8039-unified-interface-for-on-chain-proof-verification/25612)).
5. **One-shot semantics via nullifiers.** A spend, a delegation use, a session, or a "first time this claim is made" event publishes a nullifier `N = H(secret, scope, epoch)`; the verifier rejects a duplicate. *Stops:* double-spend of a budget note and double-use of a one-time delegation. Semaphore's `validateProof` does exactly this — check the nullifier set before verifying, then store it ([Semaphore contracts](https://docs.semaphore.pse.dev/technical-reference/contracts)); zkAPI derives its nullifier chain from the note so that two notes with the same secret still have disjoint chains ([zkapi `docs/note-bound-commitments.md`](https://github.com/MCPVOT/zkapi)).
6. **Unlinkability across presentations.** Two proofs from the same human or agent must be indistinguishable from two proofs from two different ones, within the relevant anonymity set. *Stops:* the audit becoming a tracking device. This is Privacy Pass's core guarantee, decomposed into Origin–Client, Issuer–Client and Attester–Origin unlinkability ([RFC 9576 §3.3](https://www.rfc-editor.org/rfc/rfc9576)).
7. **Revocability without identification.** The verifier must learn "this delegation is no longer valid" without learning *whose* it was. Mechanisms: short expiry, epoch-scoped credentials whose roots rotate, accumulator non-membership, or a status list keyed by a blinded handle. *Stops:* a revoked agent continuing to spend, and a revocation check that de-anonymises everyone who checks. Note the tension with (6): a per-credential revocation check is a linking oracle, so revocation must be epoch-batched.
8. **Scope limitation.** Budget cap, tool allowlist, time window, egress allowlist, and model constraint are all in `x`, and the circuit enforces them against `w`. *Stops:* capability creep — the failure mode where a sub-agent silently acquires tools the human never granted ([arXiv:2603.14332](https://arxiv.org/abs/2603.14332) names this capability–context separation and derives "capability integrity" as requirement G1).
9. **Succinct, cheap verification.** `O(1)`-ish verifier work, ideally milliseconds off-chain or ~300k gas on-chain. *Stops:* the verifier skipping the check because it is expensive.
10. **Composability.** Proofs must aggregate: N per-action proofs into one session proof, and a session proof into a settlement proof. *Stops:* omission attacks and makes (9) achievable at session granularity. RISC Zero's recursion/continuations give constant proof size for unbounded computation ([RISC Zero recursion docs](https://dev.risczero.com/api/next/recursion)).
11. **Circuit transparency.** The verification key, circuit version, public-input schema and proof-system id must be discoverable, or the verifier cannot know what it just verified. ERC-8084 standardises exactly this metadata set ([ERC-8084](https://eips.ethereum.org/EIPS/eip-8084)).
12. **Non-transferability (optional but usually wanted).** Bind the proof to the verifier: a proof presented to gateway A should not be replayable at gateway B. Domain separation again — cheap to add, embarrassing to omit.

### 1.4 What a ZK proof structurally cannot do

This list is the discipline that keeps the protocol honest. Each item is a place where a competitor's marketing will overclaim.

- **It cannot prove the absence of an unlogged event.** If the tenth action was never written into the committed transcript, no circuit can prove it did not happen. This is precisely the trace-integrity failure measured in [arXiv:2609.30266](https://arxiv.org/abs/2609.30266) and the "no interoperability protocol can carry such a proof" framing of [arXiv:2608.30083](https://arxiv.org/abs/2608.30083).
- **It cannot prove intent, alignment, or the absence of a hidden goal.** Those are not statements about a computation; they are statements about a policy's adequacy.
- **It cannot prove that a committed model is the model that did the work.** Ghost weights satisfy the circuit ([arXiv:2607.28884](https://arxiv.org/abs/2607.28884)).
- **It cannot make a dishonest host produce a proof.** The security property only exists if the verifier *refuses* unproven actions — fail-closed at the enforcement point. A protocol that merely offers proofs is advisory.
- **It cannot hide metadata the transport exposes.** IP address, timing, and payload size remain; zkAPI's own launch post lists network anonymity and prompt-content linkage as unsolved by the payment-layer proof ([EF blog](https://blog.ethereum.org/2026/10/01/introducing-zkapi)).

### 1.5 Who verifies, and where

| Verifier | Latency budget | What it can afford | What it must not learn |
|---|---|---|---|
| **Counterparty service** (tool server, API provider, exchange) | 10–100 ms in-line | off-chain verify, cached vk, epoch cache | the customer's identity, the full request body |
| **Human delegator** (the person who signed the policy) | seconds, asynchronous | local verify, or a wallet/companion app | nothing beyond what they already own |
| **Third-party auditor / regulator** | hours, offline | batch verify, sample re-execution | the data underlying the compliance claim |
| **On-chain contract** (escrow, registry, settlement) | one block | Groth16/PLONK verify at ~270–300k gas | anything not already public on-chain |

**Default: off-chain.** On-chain should carry only (i) settlement of value, (ii) the anchor of a proof root that someone else may later challenge, and (iii) revocation/epoch roots. Putting per-action proofs on-chain costs ~300k gas each and publishes the public instance forever, which is an anti-privacy choice disguised as rigour.

---

## 2. Prior art and near-neighbours

Five clusters, ordered from "proves the model ran" to "proves the agent was allowed".

### 2.1 zkML / inference attestation — proves *what computed*, not *what was permitted*

| System | Status | What it proves | Cost evidence |
|---|---|---|---|
| **zkLLM** ([arXiv:2404.16109](https://arxiv.org/abs/2404.16109)) | `[PAPER]` CCS 2024 | correctness of an entire LLM inference with hidden weights; `tlookup` for non-arithmetic ops, `zkAttn` for attention | 13B-parameter model: full-inference proof in **under 15 minutes**, proof **<200 kB** |
| **Modulus Labs / Remainder** ([modulus.xyz](https://www.modulus.xyz/), [Cost of Intelligence, eprint 2026/1063](https://eprint.iacr.org/2026/1063)) | `[VENDOR-CLAIM]` | specialised GKR prover for ML, later decision forests; "Accountable Magic" positioning, 1000x claim on their own site | Remainder launch claimed **180x overhead reduction** ([Modulus, ch.13](https://medium.com/@CountableMagic/chapter-13-scaling-intelligence-637d4a374153)). A third-party benchmark states the team joined Tools for Humanity in late 2024 and the company no longer operates as an independent zkML vendor `[SECONDARY]` ([proofoftech](https://proofoftech.org/blog/which-zkml-ships)) |
| **EZKL** ([docs](https://docs.ezkl.xyz), [repo](https://github.com/zkonduit/ezkl)) | `[SHIPPED-OSS]` | ONNX graph → Halo2 circuit → SNARK of inference; the one zkML library that backs its production-readiness claim with a published third-party audit | Trail of Bits, Jan–Mar 2025, **11 engineer-weeks**, covering circuit soundness, quantisation backdoors, verifier security; it *confirmed* model backdoors can be activated by quantisation ([EZKL audit post](https://blog.ezkl.xyz/post/audit)). Operator reports **200k+ proofs/day at peak** ([State of EZKL 2025](https://blog.ezkl.xyz/post/state_of_ezkl)) |
| **RISC Zero zkVM** ([repo](https://github.com/risc0/risc0), [Ethereum integration](https://mintlify.wiki/risc0/risc0/blockchain/ethereum) (RISC Zero docs mirror)) | `[SHIPPED-MAINNET]` | not zkML-specific: proves execution of a RISC-V program, so it is the general fallback when the model or the logic is not circuit-friendly | Groth16-wrapped receipt **~280,000 gas**, proof **~200–300 bytes**; native STARK receipts are far larger, which is why recursion/compression exists and why L1 verification uses the wrapped form ([recursion docs](https://dev.risczero.com/api/next/recursion)) |
| **Giza / Orion, zkComposer** ([arXiv:2607.08095](https://arxiv.org/abs/2607.08095)) | `[PAPER]` | Cairo/STARK transpilation; zkComposer splits one proof into layer-wise sub-proofs linked by boundary-activation commitments | up to **3.25x** (CNN), **4.83x** (GPT-2 by layer), **6.84x** (GPT-2 by layer+sequence) prover-time reduction vs zkCNN/zkGPT |

Cross-framework benchmark worth knowing, but read the disclosure: EZKL's own benchmark reports itself **65.88x faster than RISC Zero** and **2.92x faster than Orion** on average across four model classes, and says so up front ([EZKL blog](https://blog.ezkl.xyz/post/benchmarks)). An independent 2026 benchmark on a 3.4M-parameter, 14-layer MLP (INT8) reports EZKL 8.2 s / 412k gas, Modulus Remainder 5.8 s / 504k gas, Giza 22 s / 2.4M gas, RISC Zero 41 s (succinct 1.4 kB) / 540k gas `[SECONDARY]` ([proofoftech](https://proofoftech.org/blog/which-zkml-ships)).

**Verdict for us:** zkML solves the *inference provenance* leg at seconds-to-minutes per forward pass. It does not solve the policy leg, and at frontier scale it is minutes per inference, which is incompatible with an in-line gateway. Treat it as an integrate-not-build dependency.

### 2.2 Agent execution and transcript proofs — the closest neighbours

This cluster appeared in 2026 and is the direct competition.

| Work | Status | Claim | Numbers |
|---|---|---|---|
| **zkAgent** ([eprint 2026/199](https://eprint.iacr.org/2026/199)) | `[PAPER]` | "first SNARK system for verifiable agent execution": proves the whole pipeline (embedding lookup → positional encoding → transformer → decoding) and binds each tool observation with a zkTLS or zkVM sub-proof, producing one end-to-end proof; one-shot transcript proving exploits the causal mask | GPT-2, 512-token transcript; the ePrint abstract renders the timing values as bare units (`s/token`, `s`), so no throughput number should be quoted from it |
| **NiyamAI** ([arXiv:2608.07167](https://arxiv.org/abs/2608.07167)) | `[PAPER]` | intent contract sealed at session start under a SHA-256 commitment; every tool call gated by a deterministic authority gate + an 11→8→2 neural judge; a zkSNARK certifies correct policy evaluation before execution | **1.7 s prove / 51 ms verify per approved action**, **18.6 kB** proof; 18 adversarial vectors, two implementation vulnerabilities found and fixed |
| **Prezta** ([arXiv:2607.11466](https://arxiv.org/abs/2607.11466)) | `[PAPER]` | evaluates XACML 3.0 policies inside a RISC Zero zkVM on the client so edge devices need no policy gateway | **83%** of the XACML 3.0 conformance suite; **tens of seconds** to prove on a desktop, **tens of milliseconds** to verify |
| **ZK predicate gateway** ([arXiv:2608.30083](https://arxiv.org/abs/2608.30083)) | `[PAPER + reference impl](https://github.com/45h0kg/zk-proof-gateway)` | agents exchange proofs of governance-defined predicates over private data instead of the data; adds a proof slot to both MCP and A2A | 32-bit threshold predicate: **6.2 ms prove / 1.0 ms verify**, **608-byte** Bulletproofs proof on one commodity vCPU; 11 adversarial experiments, 19 protocol checks; explicitly names the source-integrity gap |
| **Capability binding + reproducibility** ([arXiv:2603.14332](https://arxiv.org/abs/2603.14332)) | `[PAPER]` | derives three governance requirements (capability integrity, behavioural verifiability, interaction auditability) and proves a Chain Verifiability Theorem: one unverifiable interior agent breaks end-to-end verification for all downstream nodes | Basic Ed25519/SHA-256 instantiation **97 µs** verify; enhanced BBS+ selective disclosure + Groth16 DV-SNARK **13.8 ms**; 9 models / 7 providers show **5.8x** variance in inference determinism |
| **AIP / IBCT** ([arXiv:2603.24775](https://arxiv.org/abs/2603.24775)) | `[PAPER]` | invocation-bound capability tokens fusing identity, attenuated authorisation and provenance in an append-only chain; compact JWT mode and chained Biscuit mode | scan of **~2,000 MCP servers found all lacked authentication**; compact verify **0.049 ms** (Rust); **2.35 ms** overhead in a Gemini 2.5 Flash multi-agent deployment; 600 attack attempts, 100% rejection |
| **Proof of Execution** ([arXiv:2607.05397](https://arxiv.org/abs/2607.05397)) | `[PAPER]` | runtime-verifiable execution triple (contract, event stream, replay context) with five invariants and an Execution Attestation Certificate | ~2.7 ms overhead, 4.4% on concurrent batches; explicitly **does not replace TEEs or zkVMs** |
| **NabaOS / tool receipts** ([arXiv:2603.10060](https://arxiv.org/abs/2603.10060)) | `[PAPER]` | the useful counter-position: HMAC-signed tool receipts + epistemic classification, arguing ZK is too slow for interactive agents | 94.2% detection of fabricated tool references at **<15 ms**, versus zkLLM at **180 s/query** |

**What this tells us.** The field has converged on the same architecture from four directions: (i) a sealed policy/intent commitment, (ii) a per-action gate that emits a proof, (iii) a transcript commitment that binds the sequence, (iv) a verifier that refuses unproven actions. What nobody has done cleanly is the **combination of unlinkable human delegation with revocable, budget-bounded authority and per-action proofs that aggregate** — the agent-side work assumes a known principal, and the Privacy Pass side has no notion of tool calls.

### 2.3 Agent identity and attestation standards — proves *who*, not *what*

- **ERC-8004 Trustless Agents** `[DRAFT-STANDARD]` creates three per-chain singleton registries — Identity (ERC-721 + URIStorage), Reputation, Validation — and explicitly lists zkML proofs, TEE oracles and stake-secured re-execution as pluggable trust models ([ERC-8004](https://eips.ethereum.org/EIPS/eip-8004)). Secondary reporting says Identity and Reputation went live on Ethereum mainnet on 2026-01-29 `[SECONDARY]` ([rya-sge](https://rya-sge.github.io/access-denied/2026/07/06/erc-8004-trustless-agents)).
- **ERC-8126 AI Agent Verification** `[FINAL-STANDARD]` (created 2026-01-15) layers five verification types (ETV, MCV, SCV, WAV, WV) on ERC-8004 agent IDs, runs them **off-chain**, and uses "Private Data Verification" to generate ZKPs so detailed results are visible only to the agent's wallet holder, exposed as a 0–100 risk score and optionally posted to the ERC-8004 Validation Registry ([ERC-8126](https://eips.ethereum.org/EIPS/eip-8126)). Note what it verifies: contracts, media provenance, Solidity, endpoints, wallet history — i.e. *the agent's assets*, not its behaviour.
- **A2A v1.0** `[SHIPPED-OSS]` treats agents as opaque enterprises and defines an `AgentCardSignature` object; the v1.0 announcement describes agent cards as cryptographically signed and verified with JWS per RFC 7515 and JSON canonicalisation per RFC 8785 ([A2A spec](https://github.com/a2aproject/A2A/blob/main/docs/specification.md), [Google developer forum](https://discuss.google.dev/t/what-s-new-in-a2a-v1-0-a-python-dx-glow-up-and-a-fresh-new-look/381896)).
- **IETF draft-klrc-aiagent-auth-00** `[DRAFT-STANDARD, Informational]` models the agent as a workload and composes SPIRE/WIMSE identifiers, workload credentials, OAuth 2.0 and OpenID SSF into an "Agent Identity Management System", with agent attestation defined as the identity-proofing mechanism ([IETF draft](https://www.ietf.org/archive/id/draft-klrc-aiagent-auth-00.html)).
- **MCP authorization** `[SHIPPED-SPEC]` — the 2025-11-25 spec aligns remote MCP servers with OAuth 2.1 + PKCE, resource indicators (RFC 8707) and protected-resource metadata (RFC 9728) ([MCP spec](https://mcp.mintlify.app/specification/2025-11-25/basic/authorization)).

**Gap:** every one of these answers "which agent is this and what may it reach". None answers "prove what it did, under which signed constraint, without showing me the payload". ERC-8126 comes closest but its ZK is a confidentiality wrapper around a *provider's* verification report — trust in the provider remains, which is the thing a proof was supposed to remove.

### 2.4 TEEs versus ZK — different trust anchors, not competitors

The best framing is ACM Queue's "confidential computing proofs": a TEE-based proof is a proof whose validity rests on a hardware root, where the TEE guarantees contents are invisible to and unmodifiable by anything outside it, including the hypervisor ([ACM Queue](https://queue.acm.org/detail.cfm?id=3689949)).

| Axis | TEE attestation | ZK proof |
|---|---|---|
| Trust anchor | silicon vendor + firmware/microcode chain | mathematical assumption + circuit correctness |
| What it asserts | "this *measured code* ran on genuine hardware with this report data" ([Intel TDX remote attestation](https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-whitepaper-final9-17.pdf)) | "this relation holds between public `x` and some `w`" |
| Cost | near-native (single-digit % for GPU TEEs in published measurements `[SECONDARY]` ([zkAI survey](https://mimoo.github.io/awesome-zk-ai/papers/tee-confidential-llm.html))) | 10³–10⁶× the native computation |
| Freshness | nonce inside the quote | nonce/epoch inside the instance |
| Revocation | microcode, firmware, key revocation — slow, vendor-controlled | circuit version bump + vk rotation |
| Failure mode | side channels and physical attacks. Oct 2025 reporting describes a DDR5 interposer observing encrypted memory traffic on TDX and SEV-SNP hosts `[SECONDARY]` ([beigemedia](https://beigemedia.org/article/hybrid-tee-zkp-secure-computation)) | circuit bugs, trusted setup, public-input leakage |
| Best role for us | **an input to the proof**: an attested measurement that says "this gateway binary read the value" closes the source-integrity gap that a bare predicate proof leaves open | **the portable artefact**: verifiable by anyone, forever, with no vendor in the loop |

The hybrid is already shipping in adjacent stacks — Phala publishes TDX + NVIDIA GPU attestation and verifies TEE quotes on-chain with a RISC Zero zkVM ([Phala docs](https://docs.phala.com/phala-cloud/attestation/verify-your-application), [Phala post](https://phala.com/posts/verifying_tee_onchain_with_risczero_zkvm)). ERC-8262's motivation section is blunt about why it does not use TEEs for compliance: hardware trust "has been broken by side-channel attacks and key extraction" ([ERC-8262](https://eips.ethereum.org/EIPS/eip-8262)).

### 2.5 Blind signatures and Privacy Pass-style unlinkable delegation

This is the cluster our own prior art sits in, and the one the agent world has mostly ignored.

- **Privacy Pass** `[FINAL-STANDARD]` is the reference architecture for "authorise without identifying". RFC 9576 defines four roles (Client, Origin, Issuer, Attester) and three unlinkability goals, and requires issuance to satisfy **unconditional input secrecy** (blindness: nothing about the client's private input leaks to Attester or Issuer, regardless of hardness assumptions) and **one-more forgery security** ([RFC 9576](https://www.rfc-editor.org/rfc/rfc9576)). RFC 9578 specifies two issuance variants: privately verifiable VOPRF(P-384, SHA-384) and publicly verifiable Blind RSA (2048-bit) ([RFC 9578](https://www.rfc-editor.org/rfc/rfc9578)); RFC 9577 is the HTTP auth scheme ([RFC 9577](https://www.rfc-editor.org/rfc/rfc9577)).
- **Macaroons** `[PAPER]` introduced decentralised delegation via nested, chained HMAC caveats ([Google Research](https://research.google.com/pubs/pub41892.html)). **Biscuit** `[SHIPPED-OSS]` modernises it: an append-only list of blocks, offline attenuation by adding checks, Datalog-based authorisation, and third-party blocks signed by an external key so a block can be added without the root key ([Biscuit spec](https://github.com/eclipse-biscuit/biscuit/blob/master/SPECIFICATIONS.md)). Both are **bearer** tokens: cheap, composable, but linkable and not private. They are the right shape for scope and the wrong shape for unlinkability.
- **MCPVOT/zkapi** `[SHIPPED-MAINNET]` is our own prior art and the closest existing thing to "unlinkable budget delegation". A credential is a **blind Schnorr signature over the Stark curve** on `H(balance, serial)`; the serial doubles as the spend token and replay key; a charge is a *refund* — the server re-issues a fresh blind credential for `balance − charge` under a new serial, so variable-size refunds fall out for free ([`blind_schnorr.rs`, `blind_signature.rs`](https://github.com/MCPVOT/zkapi)). The production protocol goes further: note-bound Pedersen commitments `C = B·G + r·H + L·J` on Baby-JubJub, a note-bound nullifier chain `N(τ) = Poseidon(secret, note_id, τ)`, successor anchors, and Groth16/BN254 proofs verified off-chain by the server and on-chain by the vault at deposit, close and escape ([`state_anchor.rs`](https://github.com/MCPVOT/zkapi), [`docs/note-bound-commitments.md`](https://github.com/MCPVOT/zkapi)). The EF's launch post confirms it runs on Ethereum mainnet with a 32-level Poseidon Merkle tree and off-chain spend verification ([EF blog](https://blog.ethereum.org/2026/10/01/introducing-zkapi)).

**What transfers directly:** the issuance/presentation split (blind), the nullifier discipline, the refund-by-reissue trick for variable budgets, and the "server never sees content, provider never sees payment" two-path architecture. **What does not transfer:** zkapi proves *solvency of a note*, not *compliance of an action*. The agent primitive needs a second relation on top.

### 2.6 Proof-carrying code and verifiable computation

Necula's PCC is the conceptual ancestor of "the agent carries a proof of its own compliance": the code producer supplies a formal safety proof, the consumer runs a **simple, fast validator**, and almost all the burden sits with the producer ([Necula, PCC](http://cs.berkeley.edu/~necula/pcc.html)). The reported numbers are the ones that matter for design intuition: packet-filter safety proofs **smaller than 1 KB** validated in **under 2 ms**, and mobile-agent proofs about **6× the size of the code** for resource bounds, termination and bandwidth. PCC's other lesson is a warning: it proves *static* properties of code, not runtime behaviour, and it explicitly needs no cryptography or trusted third party — which is why it is the right mental model for "the proof is checked by a tiny verifier", and the wrong one for "the proof says what the agent did".

### 2.7 ZK-based authorisation and policy proofs

- **ERC-8262 Zero-Knowledge Compliance Oracle** `[DRAFT-STANDARD]` is the best worked example of a *policy* circuit spec published as a standard. It defines nine proof types with explicit public/private input tables, requires ≥128-bit security, binds `submitter == msg.sender`, enforces `chain_id == block.chainid` and `oracle_address == address(this)` for signed variants, puts a TTL on attestations, and specifies non-membership over sorted Merkle leaves with `high_index == low_index + 1` to stop an attacker skipping a real entry ([ERC-8262](https://eips.ethereum.org/EIPS/eip-8262)). Its "What this standard does NOT prove" section is a model for how we should write ours.
- **ERC-8039** `[DRAFT-STANDARD, PR open]` proposes the unified on-chain verification interface: an ERC-1271-style `verifyProof(bytes publicInputs, bytes proof)` returning magic value `0x534f5876`, proof-system-agnostic, one verifier per statement ([ERC-8039](https://eip.tools/eip/8039)).
- **Policy languages** — Cedar (formally verified, CNCF) and Oso — express the policy a human signs; they are not proof systems, but they are the natural front-end that must be compiled into a circuit or a zkVM guest ([Cedar](https://www.cncf.io/projects/cedar/), [Cedar paper](http://arxiv.org/pdf/2403.04651v2)).

### 2.8 What is genuinely missing

Nobody currently ships a primitive that simultaneously has: (a) unlinkable issuance to a human, (b) revocable epoch-scoped authority, (c) budget with variable-size decrements, (d) per-action policy proofs over private payloads, (e) aggregation into a session proof, (f) an honest statement of the source-integrity and trace-completeness limits. zkapi has a+b+c for payments. NiyamAI/Prezta have (d) with a known principal. zkAgent has (d)+(e) for the transcript but at LLM-proving cost. That intersection is the product.

---

## 3. The EVM standards angle: how an on-chain verifier works today

### 3.1 Premise correction — ERC-7572 is not a proof-verification hook

The brief for this slice refers to "ERC-7572-style proof-verification hooks". That is not what ERC-7572 is. **ERC-7572 standardises `contractURI()` returning contract-level metadata** (name, description, image, banner) plus a `ContractURIUpdated()` event, for dapps and indexers ([ERC-7572](https://eips.ethereum.org/EIPS/eip-7572)). It contains no verification surface.

The actual lineage of proof-verification interfaces is:

| Standard | Status | What it does |
|---|---|---|
| **ERC-1922** ([link](https://eips.ethereum.org/EIPS/eip-1922)) | `[STAGNANT]` since 2018 | `verify(uint256[] proof, uint256[] inputs, bytes32 verificationKeyId) → bool`, EY-originated, libsnark-shaped |
| **ERC-1923** ([link](https://ercs.ethereum.org/ERCS/erc-1923)) | `[STAGNANT]` | a *registry* of verification keys and verifier contracts, with attest/challenge |
| **ERC-8039** ([link](https://eip.tools/eip/8039), [discussion](https://ethereum-magicians.org/t/erc-8039-unified-interface-for-on-chain-proof-verification/25612)) | `[DRAFT, PR #1238 open]` | ERC-1271-style magic-value interface, `schema` + `bytes32[] publicInputs` + `bytes proof`, proof-system agnostic, explicit domain-separation lanes |
| **ERC-8084** ([link](https://eips.ethereum.org/EIPS/eip-8084)) | `[DRAFT]` | ZKMeta metadata: `circuitId`, `circuitVersion`, `publicInputsSchemaHash/URI`, `verificationKeyURI`, `proofSystem` with a registry (`0x0001` Groth16, `0x0002` Plonk, `0x0003` Halo2, `0x0004` zkSTARK, `0x0005` zkVM) |
| **ERC-8262** ([link](https://eips.ethereum.org/EIPS/eip-8262)) | `[DRAFT]` | an application-level ZK standard (compliance oracle) with per-proof-type circuit specs |

### 3.2 Groth16 in Solidity, today

A Rust prover (arkworks, RISC Zero, SP1, Halo2→Groth16 wrap) emits a BN254 Groth16 proof; the verifier contract performs three pairings through the BN254 precompiles at `0x06/0x07/0x08`, defined by EIP-196/197 precisely so that zkSNARK verification fits in a block ([EIP-197](https://eips.ethereum.org/EIPS/eip-197)).

Concrete, current costs:

- **SP1**: Groth16 proof **~260 bytes**, on-chain verification **~270k gas**; PLONK **~868 bytes**, **~300k gas**, and about **1 m 30 s** slower to generate. The Groth16 circuit keys use the Aztec Ignition ceremony plus Succinct entropy — if you do not accept that setup, use PLONK ([Succinct docs — proof types](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types)).
- **RISC Zero**: Groth16 receipt verification **~280k gas**, **~200–300 bytes**, with `verify(seal, imageId, journalDigest)` as the interface; the router pattern routes by zkVM version ([RISC Zero Ethereum integration](https://mintlify.wiki/risc0/risc0/blockchain/ethereum), mirror of [dev.risczero.com](https://dev.risczero.com/api/blockchain-integration/contracts/verifier)).
- **Semaphore**: an extended snarkjs-generated Groth16 verifier with per-depth verification keys, because the circuit is compiled for `MAX_DEPTH` 1..32 ([Semaphore contracts](https://docs.semaphore.pse.dev/technical-reference/contracts)).

Two deployment patterns are live on mainnet and should be copied rather than invented:

1. **Version-routed gateway.** SP1's `SP1VerifierGateway` at `0x397A5f7f3dBd538f23DE225B51f532c34448dA9B` on Ethereum mainnet (same address on Arbitrum, Base, OP; different addresses on BSC/HyperEVM/Hoodi/Monad/Plasma/Tempo), with `addRoute()` for new versions and `freezeRoute()` for a broken one, and separate gateways for Groth16 and PLONK ([contract addresses](https://docs.succinct.xyz/docs/sp1/verification/contract-addresses)).
2. **Router + image ID.** RISC Zero's `RiscZeroVerifierRouter` plus an immutable `imageId` constant per guest program, with the contract reconstructing the expected journal and checking `sha256(journal)` ([RISC Zero](https://mintlify.wiki/risc0/risc0/blockchain/ethereum)).

### 3.3 Data availability: what blobs are for, and what they are not

EIP-4844 blob-carrying transactions carry data **that cannot be accessed by EVM execution, but whose commitment can be accessed** ([EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)). That asymmetry defines the only sane use here:

- **Do** put the encrypted transcript / witness archive / per-action payload log in blobs, and put the blob commitment (versioned hash) into the proof's public instance. The verifier contract can then bind the proof to data it cannot read, and an auditor with the decryption key can later check the archive against the same commitment.
- **Do not** put anything the verifier must read into a blob. Blob data has a limited lifetime — around 18 days initially ([ethereum.org](https://ethereum.org/developers/docs/data-availability/)) — and is not retrievable from the EVM.
- **Watch calldata pricing.** EIP-7623 raises calldata from 4/16 to 10/40 gas per byte for data-heavy transactions, capping adversarial payloads at roughly 0.72 MB ([EIP-7623](https://eips.ethereum.org/EIPS/eip-7623)). Large proof bundles in calldata are therefore a decaying design.

### 3.4 Precompiles that change the design space

- **P-256 (`0x100`, EIP-7951, `[FINAL]`)** — secp256r1 ECDSA verification at **6,900 gas**, added because Apple Secure Enclave, Android Keystore and FIDO2/WebAuthn all sign on that curve; it supersedes RIP-7212 and fixes its security issues ([EIP-7951](https://eips.ethereum.org/EIPS/eip-7951)). It shipped with Fusaka, whose mainnet activation was 2025-12-03 ([EIP-7607](https://eips.ethereum.org/EIPS/eip-7607)). **Consequence:** a human delegation signed by a passkey can be verified on-chain for ~7k gas, with no custom verifier — this is the cheapest credible "hardware-rooted human consent" primitive we have.
- **BLS12-381 (`0x0b`–`0x11`, EIP-2537, `[FINAL, Pectra]`)** — G1/G2 add and MSM, pairing check at `0x0f`, map-to-curve, with published gas costs ([EIP-2537](https://eips.ethereum.org/EIPS/eip-2537); inclusion and status per [EIPs Insight](https://eipsinsight.com/eip/2537)). Relevant if we ever want BBS+ selective disclosure or a BLS-based verifier on-chain.
- **BN254 pairing (`0x08`, EIP-197)** — the workhorse; every Groth16 verifier depends on it ([EIP-197](https://eips.ethereum.org/EIPS/eip-197)).

### 3.5 The reference architecture for us

```
agent runtime (Rust)
  ├─ per-action witness ──► circuit / zkVM guest ──► Groth16 or PLONK proof
  │                                                   (off-chain verify: ms)
  ├─ transcript chunks ──► encrypted archive ──► EIP-4844 blob ──► versioned hash in x
  └─ session aggregate ──► recursive proof ──► ERC-8039-shaped adapter
                                                └─► ERC-8084 ZKMeta metadata
                                                └─► (optional) anchor in ERC-8004 Validation Registry
                                                └─► settlement / revocation root on L1
```

Current status to design against, as of 2026-10-27: Fusaka is live (2025-12-03) and brought PeerDAS plus the P-256 precompile ([EIP-7607](https://eips.ethereum.org/EIPS/eip-7607)); Glamsterdam is the next fork and its Hoodi activation has been postponed with no new date set ([EF blog](https://blog.ethereum.org)). Do not depend on precompiles that are only proposed for a future fork.

---

## 4. Five candidate protocol designs

Each design is stated as: hidden statement, public statement, circuit shape, proving-cost class, verification cost, and the concrete attack it stops. Costs are engineering estimates grounded in the cited numbers; they are classes, not benchmarks.

### D1 — Policy Receipt (per-action compliance proof)

**The primitive.** Every tool call the agent makes is gated by a proof that it satisfies the signed policy.

- **Hidden:** the prompt and system instructions; tool name and arguments; the tool's response; any retrieved document content; the salt.
- **Public:** `policy_id` and `policy_hash`; `agent_commitment`; `action_commitment = H(tool, args, response, salt)`; verdict bits (`allowed=1`, `within_budget=1`, `endpoint_allowed=1`); `budget_after` commitment; `epoch`; `nullifier = H(secret, action_id)`; `chainid`; `verifyingContract`; verifier `nonce`.
- **Circuit shape:** hash preimage openings (Poseidon or Keccak); integer comparisons (`amount ≤ cap`, `now − epoch_start ≤ window`); set membership for the tool allowlist (Merkle path over a committed list, or a lookup argument); in-circuit verification of the policy issuer's signature (Schnorr on a SNARK-friendly curve, or ECDSA/P-256 — the latter is expensive in-circuit and is why the delegation layer in D2 is blind Schnorr, not ECDSA); nullifier derivation; commitment re-opening for `budget_after`.
- **Proving cost:** ~10⁵–10⁶ constraints → **sub-second to a few seconds** on one core with Groth16; the 18.6 kB / 1.7 s datapoint from NiyamAI is the realistic ceiling for a policy circuit with a small neural judge ([arXiv:2608.07167](https://arxiv.org/abs/2608.07167)).
- **Verification cost:** **5–10 ms** off-chain; **~270–300k gas** if anchored on-chain ([Succinct](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types), [RISC Zero](https://mintlify.wiki/risc0/risc0/blockchain/ethereum)).
- **Attack stopped:** prompt injection that induces a tool call outside the signed scope, followed by the agent reporting success. The gateway cannot accept the call without a proof whose public instance names the same `action_commitment`, and it cannot manufacture that proof without the witness. It also stops the retroactive policy rewrite ("there was never a $50 cap") because `policy_hash` is in the instance.
- **What it does not stop:** a host that simply declines to prove and calls the tool out of band. Mitigation is architectural, not cryptographic: the tool server must refuse unproven calls (fail-closed), and D3/D4 make the refusal auditable.

### D2 — Blind Budget Delegation (human → agent, unlinkable and revocable)

**The primitive.** A human grants an agent bounded authority without revealing identity or balance, and can revoke it without learning which presentations were theirs.

- **Hidden:** the human's identity, deposit and balance; the link between issuance and any later presentation; the agent's spend history.
- **Public:** issuer verification key; `scope_hash` (tool allowlist, per-tx cap, total cap, time window); `expiry`; `nullifier`; `epoch`; revocation root; `agent_key_commitment`; and, per presentation, the proven predicate (`remaining ≥ amount`, `now < expiry`, `serial ∉ revoked`).
- **Circuit shape:** blind Schnorr signature verification over `H(balance, serial, scope)` on a SNARK-friendly curve (zkapi uses the Stark curve with a domain-separated Keccak challenge — [`blind_schnorr.rs`](https://github.com/MCPVOT/zkapi)); range proof on the post-charge balance; nullifier derivation; **non-membership** in the revocation accumulator; expiry comparison. The refund-by-reissue trick means "variable budget decrement" needs no new mechanism: the issuer signs a fresh credential for `balance − charge` under a new serial ([`blind_signature.rs`](https://github.com/MCPVOT/zkapi)).
- **Proving cost:** **sub-second** (a few hundred ms) — this is a small circuit, and zkapi already does it in-browser with packaged WASM proving keys ([zkapi architecture](https://github.com/MCPVOT/zkapi)).
- **Verification cost:** **1–3 ms** off-chain; **~250–350k gas** on-chain for the Groth16 variant. The blind-signature-only path (no SNARK) is microseconds and is what zkapi uses server-side ([`blind_signature.rs`](https://github.com/MCPVOT/zkapi)).
- **Attack stopped:** (i) the provider correlating a human's on-chain deposit with their agent's API usage — the blindness property, which RFC 9576 requires unconditionally ([RFC 9576 §3.5.1](https://www.rfc-editor.org/rfc/rfc9576)); (ii) double-spend of the same budget note — duplicate nullifier; (iii) a revoked delegation continuing to spend — epoch-scoped revocation root, checked as non-membership in-circuit, without naming the holder.
- **Honest limit:** unlinkability holds only within an anonymity set. A single-user deployment has an anonymity set of one. RFC 9576's own privacy-considerations section warns that issuance-configuration partitioning shrinks the set and recommends bounding active configurations and applying consistency checks ([RFC 9576 §6.2](https://www.rfc-editor.org/rfc/rfc9576)).

### D3 — Egress Non-Exfiltration Proof (the "I did not send these bytes" claim)

**The primitive.** Prove that no forbidden byte sequence appears in the agent's outbound traffic, without revealing the traffic or the secret set.

- **Hidden:** every outbound payload; the contents of the forbidden set; destination details beyond the allowlist proof; per-chunk salts.
- **Public:** `egress_root` (Merkle root over chunk digests of the outbound transcript); `forbidden_root` (commitment to the forbidden set — typically hashes of the customer list, private keys, or a DLP label set); the asserted predicate (`∀ chunk ∈ transcript : chunk_digest ∉ forbidden_set`, plus `|transcript| ≤ max_chunks`); `session_id`; `epoch`; `nullifier`; `chainid`.
- **Circuit shape:** commitment openings for each chunk; hash equality against the forbidden-set digests; Merkle path verification to `egress_root`; a counting/bound argument over the chunk sequence. Real substring search inside a circuit is prohibitive, so the practical construction is **windowed chunk digests** (fixed-size overlapping windows, hashed, committed) plus set non-membership — which detects exact and lightly-mutated leakage but not semantic paraphrase.
- **Proving cost:** dominated by in-circuit hashing — **seconds for hundreds of chunks, minutes for megabytes**. This is the most expensive of the five per byte, and the one most in need of recursive decomposition (the zkComposer result — up to 6.84x on GPT-2 by splitting along layers and sequence — is directly applicable to chunked hashing; [arXiv:2607.08095](https://arxiv.org/abs/2607.08095)).
- **Verification cost:** **~10 ms** off-chain; ~300k gas on-chain at the SP1/RISC Zero Groth16 rate ([Succinct](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types)).
- **Attack stopped:** the agent that exfiltrates a customer list or a private key through a "legitimate" tool call and reports success. The proof cannot be produced if the bytes are in the transcript, and the transcript root is what the verdict is bound to.
- **Honest limit — this is the important one:** the proof is only as good as the transcript's completeness. A compromised host logs nine chunks and sends ten, and the proof is still valid over the nine. Closing this requires the mediation point to be outside the agent's control (an independent interceptor, per the recommendation in [arXiv:2609.30266](https://arxiv.org/abs/2609.30266)) or an attested gateway (the enclave-plus-proof fusion proposed in [arXiv:2608.30083](https://arxiv.org/abs/2608.30083)). **We should ship this only alongside such a mediation story, and say so in the marketing.**

### D4 — Session Transcript Proof (aggregate)

**The primitive.** One proof per session, not per action, binding the count and the chain.

- **Hidden:** the full multi-turn transcript; all tool observations; optionally the model weights.
- **Public:** `session_root`; `action_count`; `policy_hash`; `model_commitment` (optional); `final_output_hash`; aggregate verdict bits; `started_at`/`ended_at` (bucketed); `nullifier`; `chainid`/`verifyingContract`.
- **Circuit shape:** recursive aggregation of D1 proofs plus a hash chain over the action sequence, with an explicit `action_count` constraint. If inference provenance is included, a nested zkML sub-proof (D5) is verified in-circuit and its output hash is chained into the transcript.
- **Proving cost:** **tens of seconds to minutes** — recursion dominates; Prezta's tens-of-seconds figure for a zkVM policy evaluation is the closest measured analogue ([arXiv:2607.11466](https://arxiv.org/abs/2607.11466)), and zkAgent's end-to-end agent execution is in the same class ([eprint 2026/199](https://eprint.iacr.org/2026/199)).
- **Verification cost:** **10–50 ms** off-chain; one on-chain verify (~300k gas) if anchored ([Succinct](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types)).
- **Attack stopped:** **selective disclosure by omission** — the agent shows nine compliant actions out of ten. The aggregate binds `action_count` and the hash chain, and the Chain Verifiability Theorem says one unverifiable interior agent breaks verification for everything downstream, which is exactly the property we want to be able to assert ([arXiv:2603.14332](https://arxiv.org/abs/2603.14332)).
- **Honest limit:** same as D3 — it cannot prove that the tenth action was logged at all.

### D5 — Model Checkpoint Attestation (inference provenance)

**The primitive.** "This output came from checkpoint X of model Y", without revealing the weights or the prompt.

- **Hidden:** weights; the prompt and any retrieved context; KV cache; sampling randomness.
- **Public:** `weights_commitment` (Merkle root over quantised tensor blocks); `architecture_hash`; `input_commitment`; `output_hash`; `sampling_params` (temperature/top-p as public constants); `tokenizer_hash`; `epoch`.
- **Circuit shape:** the quantised forward pass (EZKL's ONNX→Halo2 path for conventional models; GKR/`tlookup`-style arguments for transformer-scale work), plus argmax or verifiable sampling. EZKL's audited implementation is the sane starting point ([EZKL docs](https://docs.ezkl.xyz)); zkLLM is the research ceiling ([arXiv:2404.16109](https://arxiv.org/abs/2404.16109)).
- **Proving cost:** **seconds for a small MLP** (EZKL's own 8.2 s median on a 3.4M-parameter model per the independent benchmark `[SECONDARY]`), **minutes for a 13B model** (zkLLM: under 15 minutes). Not viable in-line for a chat agent; viable for batch/attested outputs, high-value decisions, and audit sampling.
- **Verification cost:** **~5 ms** off-chain; **~280k gas** on-chain for the Groth16 wrap ([RISC Zero](https://mintlify.wiki/risc0/risc0/blockchain/ethereum)).
- **Attack stopped:** model substitution — the provider quietly serving a cheaper or differently-tuned model than advertised. **Not stopped:** ghost weights, where the declared architecture and parameter count are preserved but the effective computation collapses ([arXiv:2607.28884](https://arxiv.org/abs/2607.28884)). The public statement must therefore bind *work*, not just shape: parameter count alone is insufficient, and the honest mitigations are compute-binding, sampling-based re-execution, or spot-checking with an independent prover.

### 4.6 Recommendation

| Design | Build now? | Why |
|---|---|---|
| **D2 blind budget delegation** | **Yes, first** | Smallest circuit, sub-second proving, and we already have the blind Schnorr + nullifier machinery in zkapi. It is the human-side primitive and the easiest thing to demo end-to-end. |
| **D1 policy receipt** | **Yes, second** | The core agent-side primitive; sub-second proving; composes with D2 (the policy hash in D1 is the one signed in D2). |
| **D4 session aggregate** | **Yes, third** | It is what turns a pile of receipts into an auditable claim, and it is the only defence against omission. |
| **D3 non-exfiltration** | **Research** | Highest differentiation, highest cost, and only honest when paired with an out-of-agent mediation point. Prototype against a gateway-signed log first. |
| **D5 checkpoint attestation** | **Integrate, don't build** | EZKL is audited and shipping; the cost curve is set by the model, not by us; and the hollow-weight failure mode means a bare proof oversells. |

**Composition:** `D2 grant → D1 per action → D4 session root → anchor`. D5 is an optional nested sub-proof for outputs whose provenance matters. D3 is an optional predicate over the D4 transcript root.

---

## 5. What we deliberately will not build

Each exclusion is a design commitment with a reason, not a backlog item.

1. **A new proving system or zkVM.** RISC Zero and SP1 are shipped, version-routed on mainnet, and cost ~270–300k gas to verify. Building a prover is a multi-year cryptography programme with no product differentiation for us ([SP1](https://docs.succinct.xyz/docs/sp1/verification/contract-addresses), [RISC Zero](https://mintlify.wiki/risc0/risc0/blockchain/ethereum)).
2. **A general zkML prover for frontier models.** 13B parameters costs under 15 minutes per inference ([zkLLM](https://arxiv.org/abs/2404.16109)); that is a batch primitive, not an agent primitive. We integrate EZKL and, where needed, a zkVM.
3. **A TEE-only trust anchor.** Hardware attestation is an *input* to a proof (it closes the source-integrity and trace-completeness gaps), never the root of trust. The TEE.fail class of physical attacks and ERC-8262's explicit rejection of hardware trust for compliance are sufficient reasons ([ACM Queue](https://queue.acm.org/detail.cfm?id=3689949), [ERC-8262](https://eips.ethereum.org/EIPS/eip-8262)).
4. **Any claim of "alignment", "safety", "honesty", or "no hidden goal".** These are not relations over a computation. A protocol that claims them is lying, and the lie is detectable — which makes it a liability, not marketing.
5. **A "proof the agent did nothing else" claim.** Without a complete, externally-mediated transcript, absence is unprovable. We will state the completeness assumption in the same sentence as the guarantee.
6. **On-chain-everything.** ~300k gas per action, permanent publication of the public instance, and a 12-second latency floor. The chain gets settlement, revocation roots, and optional anchors.
7. **A new agent identity registry or KYC layer.** ERC-8004 (identity/reputation/validation) and ERC-8126 (multi-layer verification) exist and are standards-track; we consume them and do not compete ([ERC-8004](https://eips.ethereum.org/EIPS/eip-8004), [ERC-8126](https://eips.ethereum.org/EIPS/eip-8126)).
8. **A jurisdiction-specific compliance oracle.** ERC-8262 already specifies nine proof types, threshold registries and jurisdiction policy; duplicating it would produce a worse standard and a legal surface we do not want ([ERC-8262](https://eips.ethereum.org/EIPS/eip-8262)).
9. **A token, a points system, or "proof of personhood".** None of these are required by the primitive, and each converts a security product into a speculation.
10. **Unbounded retention of agent transcripts.** The protocol stores commitments and encrypted archives with a stated lifetime (blob-scale, ~18 days by default), not plaintext logs. Retaining everything would invert the data-minimisation property the proof exists to provide ([ethereum.org DA](https://ethereum.org/developers/docs/data-availability/)).
11. **A network-anonymity claim.** Our own prior art is explicit that IP correlation and prompt-content linkage survive payment unlinkability ([EF blog](https://blog.ethereum.org/2026/10/01/introducing-zkapi)). Tor is a separate layer; we will say so.
12. **Trusted setup of our own.** Use existing ceremonies (Aztec Ignition for SP1 Groth16) or transparent/PLONK-style systems. Running a ceremony is a trust and communications liability with no product benefit ([Succinct](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types)).

---

## 6. Sources

Primary standards and specifications

- RFC 9576 — The Privacy Pass Architecture: https://www.rfc-editor.org/rfc/rfc9576
- RFC 9577 — The Privacy Pass HTTP Authentication Scheme: https://www.rfc-editor.org/rfc/rfc9577
- RFC 9578 — Privacy Pass Issuance Protocols: https://www.rfc-editor.org/rfc/rfc9578
- RFC 9807 — OPAQUE aPAKE: https://www.rfc-editor.org/info/rfc9807/
- ERC-7572 — Contract-level metadata via `contractURI()`: https://eips.ethereum.org/EIPS/eip-7572
- ERC-1922 — zk-SNARK Verifier Standard (stagnant): https://eips.ethereum.org/EIPS/eip-1922
- ERC-1923 — zk-SNARK Verifier Registry Standard (stagnant): https://ercs.ethereum.org/ERCS/erc-1923
- ERC-8004 — Trustless Agents (draft): https://eips.ethereum.org/EIPS/eip-8004
- ERC-8039 — ZK Proof Verification for Smart Accounts (draft, PR open): https://eip.tools/eip/8039 · https://ethereum-magicians.org/t/erc-8039-unified-interface-for-on-chain-proof-verification/25612
- ERC-8084 — Zero-knowledge proof metadata (draft): https://eips.ethereum.org/EIPS/eip-8084
- ERC-8126 — AI Agent Verification (final): https://eips.ethereum.org/EIPS/eip-8126
- ERC-8262 — Zero-Knowledge Compliance Oracle (draft): https://eips.ethereum.org/EIPS/eip-8262
- ERC-8229 — FHE Computation Verification (draft): https://ethereum-magicians.org/t/erc-8229-fhe-computation-verification/28217
- EIP-196 / EIP-197 — BN254 precompiles: https://eips.ethereum.org/EIPS/eip-197
- EIP-2537 — BLS12-381 precompiles (final, Pectra): https://eips.ethereum.org/EIPS/eip-2537
- EIP-4844 — Shard Blob Transactions: https://eips.ethereum.org/EIPS/eip-4844
- EIP-7002 — Execution layer triggerable withdrawals (checked; unrelated to pairing precompiles): https://eips.ethereum.org/EIPS/eip-7002
- EIP-7607 — Hardfork Meta Fusaka (activation table): https://eips.ethereum.org/EIPS/eip-7607
- EIP-7623 — Increase calldata cost: https://eips.ethereum.org/EIPS/eip-7623
- EIP-7951 — P-256 precompile (final): https://eips.ethereum.org/EIPS/eip-7951
- IETF draft-klrc-aiagent-auth-00 — AI Agent Authentication and Authorization: https://research.google/pubs/pub41892
- A2A Protocol Specification v1.0: https://github.com/a2aproject/A2A/blob/main/docs/specification.md
- MCP authorization spec (2025-11-25): https://mcp.mintlify.app/specification/2025-11-25/basic/authorization
- W3C Verifiable Credentials Data Model v2.0 (Recommendation, 2025-05-15): https://www.w3.org/TR/vc-data-model-2.0

Papers

- zkAgent: Verifiable LLM Agent Execution via One-Shot Transcript Proofs: https://eprint.iacr.org/2026/199
- NiyamAI — Intent-Bound AI Agent with Cryptographically Verifiable Guardrails: https://arxiv.org/abs/2608.07167
- Prezta: Provable Remote Execution of Zero-Trust Authorization using SNARKs: https://arxiv.org/abs/2607.11466
- Zero-Knowledge Predicate Proofs Between AI Agents (source-integrity gap): https://arxiv.org/abs/2608.30083
- AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A: https://arxiv.org/abs/2603.24775
- Governing Dynamic Capabilities: Cryptographic Binding and Reproducibility Verification: https://arxiv.org/abs/2603.14332
- Proof of Execution: Runtime Verification for Governed AI Agent Actions: https://arxiv.org/abs/2607.05397
- Tool Receipts, Not Zero-Knowledge Proofs: https://arxiv.org/abs/2603.10060
- LLM Agents Can Easily Tamper With Their Own Traces: https://arxiv.org/abs/2609.30266
- Hollow-LLM Attack: Computationally Trivial Weights in ZK Verification of LLM Inference: https://arxiv.org/abs/2607.28884
- zkLLM: Zero Knowledge Proofs for Large Language Models: https://arxiv.org/abs/2404.16109
- zkComposer: Decomposing Proof Construction to Scale zkML: https://arxiv.org/abs/2607.08095
- The Cost of Intelligence: Proving Machine Learning Inference with Zero-Knowledge (Modulus): https://eprint.iacr.org/2026/1063
- Scaling Intelligence: Verifiable Decision Forest Inference with Remainder: https://eprint.iacr.org/2026/1038
- Macaroons: Cookies with Contextual Caveats for Decentralized Authorization: https://research.google.com/pubs/pub41892.html
- Proof-Carrying Code (Necula): http://cs.berkeley.edu/~necula/pcc.html
- Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization: http:/...51v2

Shipped systems and implementation references

- EZKL docs: https://docs.ezkl.xyz · repo: https://github.com/zkonduit/ezkl · Trail of Bits audit announcement: https://blog.ezkl.xyz/post/audit · State of EZKL 2025: https://blog.ezkl.xyz/post/state_of_ezkl · framework benchmark: https://blog.ezkl.xyz/post/benchmarks
- RISC Zero repo: https://github.com/risc0/risc0 · Ethereum integration and gas: https://mintlify.wiki/risc0/risc0/blockchain/ethereum · recursion: https://dev.risczero.com/api/next/recursion
- SP1 proof types and gas: https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types · contract addresses: https://docs.succinct.xyz/docs/sp1/verification/contract-addresses · contracts repo: https://github.com/succinctlabs/sp1-contracts
- Semaphore contracts and nullifier handling: https://docs.semaphore.pse.dev/technical-reference/contracts
- Biscuit specification: https://github.com/eclipse-biscuit/biscuit/blob/master/SPECIFICATIONS.md
- Modulus Labs: https://www.modulus.xyz/ · Remainder launch post: https://medium.com/@CountableMagic/chapter-13-scaling-intelligence-637d4a374153
- Phala TEE attestation: https://docs.phala.com/phala-cloud/attestation/verify-your-application · TEE verified on-chain with RISC Zero: https://phala.com/posts/verifying_tee_onchain_with_risczero_zkvm
- MCPVOT/zkapi (our prior art): https://github.com/MCPVOT/zkapi — `crates/zkapi-auth/src/blind_schnorr.rs`, `blind_signature.rs`, `state_anchor.rs`, `docs/note-bound-commitments.md`, `docs/architecture.md`
- EF launch post for zkAPI: https://blog.ethereum.org/2026/10/01/introducing-zkapi
- Ethereum Foundation blog index (fork status, Oct 2026): https://blog.ethereum.org
- Ethereum data availability (blob retention): https://ethereum.org/developers/docs/data-availability/
- ACM Queue — Confidential Computing Proofs: https://queue.acm.org/detail.cfm?id=3689949
- Intel TDX remote attestation whitepaper: https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-whitepaper-final9-17.pdf

Secondary / vendor claims used with attribution

- proofoftech zkML benchmark (five libraries): https://proofoftech.org/blog/which-zkml-ships
- ERC-8004 mainnet launch reporting: https://rya-sge.github.io/access-denied/2026/07/06/erc-8004-trustless-agents
- TEE.fail DDR5 interposer reporting: https://beigemedia.org/article/hybrid-tee-zkp-secure-computation
- GPU-TEE overhead survey: https://mimoo.github.io/awesome-zk-ai/papers/tee-confidential-llm.html
- EIP-7520 public-input overflow analysis (Beosin): https://beosin.com/resources/erc-7520-proposal-zk-snark-public-inputs-overflow
- Cedar project page (CNCF): https://www.cncf.io/projects/cedar/
