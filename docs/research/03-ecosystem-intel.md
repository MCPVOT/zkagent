# 03 — Ecosystem & Community Intelligence: ZK for AI Agents

**As of:** 2026-10-27 (all "last activity" figures are GitHub push timestamps read that day via `gh api`).
**Slice owner:** ecosystem / people / projects / funding / papers. Proving-system survey and protocol design are out of scope here.
**Method:** RSS feed pull (427 items) for episode titles + dates; site scrape for the podcast index; arXiv HTML search (10 queries, filtered to 2026 submissions) then per-paper abstract fetch; `gh api` for repo/licence/push facts; Firecrawl (droplet) for Substack + the jobs board; press releases for funding. Anything I could not open is marked as such rather than filled in.

**One-line read:** the frontier has split in two. Proving got cheap and commoditised (400T cycles/day at $0.04 per billion cycles, [boundless.network](https://boundless.network/blog)), while the *agent* layer became the live research question — 2026 produced a dozen papers on verifiable authorization, intent-bound guardrails and agent attestation, and almost no shipped standard. The gap is authorisation and auditability of autonomous action, not proof generation.

---

## 1. Dated timeline — last ~12 months of ZK-for-agents / verifiable-compute milestones

| Date | Event | Why it matters for us | Source |
|---|---|---|---|
| 2026-01-11 | Boundless reports 400T cycles/day proving capacity, 99.9% uptime, median **$0.04 per billion cycles** | Proving is now a priced utility, not a research project. Any agent protocol can assume "prove it later, cheaply" | [boundless.network/blog](https://boundless.network/blog) |
| 2026-01-12 | Boundless for Rollups: ZK proofs replace 7-day challenge games, finality "seven days to hours" | Template for replacing challenge periods with proofs — the same trade an agent escrow would make | [boundless.network/blog](https://boundless.network/blog) |
| 2026-01-15 | RISC Zero tags `v5.0.0-rc.1` (then ships `v3.0.6` on 2026-07-17) | Major-version churn in the most-used zkVM; pin versions, expect breaking | `gh api repos/risc0/risc0/releases` |
| 2026-01-30 | Aztec Ignition Chain at 75k blocks, 30M AZTEC distributed via block rewards | First decentralised private L2 running long enough to be a real target | [aztec.network/blog](https://aztec.network/blog/aztec-ignition-chain-update) |
| 2026-02-10 | Boundless verifier live on Stellar (Boundless × Nethermind × RISC Zero) | Cross-ecosystem proof verification: verifiers are becoming a public good | [boundless.network/blog](https://boundless.network/blog) |
| 2026-02-13 / 02-19 | `TensorCommitments` (2602.12630) and `Jolt Atlas` (2602.17452) preprints | The verifiable-LLM-inference wave starts in earnest | [arXiv 2602.12630](https://arxiv.org/abs/2602.12630), [2602.17452](https://arxiv.org/abs/2602.17452) |
| 2026-03-09 | "Tool Receipts, Not Zero-Knowledge Proofs" (2603.10060) argues ZK costs "minutes of proving time per query" and is impractical for interactive agents | The strongest published counter-position to ZK-for-agents; must be answered, not ignored | [arXiv 2603.10060](https://arxiv.org/abs/2603.10060) |
| 2026-03-19 | "Towards Verifiable AI with Lightweight Cryptographic Proofs of Inference" (2603.19025) proposes sampling-based verification instead of full proofs | Signals demand for *cheap* assurance tiers below full ZK | [arXiv 2603.19025](https://arxiv.org/abs/2603.19025) |
| 2026-03 (reported) | Google Quantum AI publishes a lower-resource secp256k1 point-addition circuit | Starts the public autoresearch race that ECDSA.fail then beats | [eigenlabs.org](https://www.eigenlabs.org/blog/open-autoresearch-the-ecdsa-fail-story/) |
| 2026-04-13 | Boundless brings ZK privacy to XRP Ledger | Proof infrastructure is going multi-ledger, not Ethereum-only | [boundless.network/blog](https://boundless.network/blog) |
| 2026-04-22 | ZK Podcast #399 "Is ZK dead? Or has it just begun?" — ZK becomes "invisible infrastructure" | Frames the year: the tech stops being the headline, becomes a primitive | [zeroknowledge.fm/podcast/399](https://zeroknowledge.fm/podcast/399) |
| 2026-05-06 | ZK Podcast #400 discloses that Google's quantum-algorithm paper had its result **proven in zero knowledge** | Precedent for publishing a sensitive computational claim with a ZK proof instead of disclosure — a direct model for publishing agent-safety claims | [zeroknowledge.fm/podcast/400](https://zeroknowledge.fm/podcast/400) |
| 2026-05-07 | **zkSummit14**, Rome | The community's main in-person gathering for this cycle; next summit not yet listed | [zeroknowledge.fm/events](https://zeroknowledge.fm/events/) |
| 2026-05-23 | "No Certificate, No Execution: Certified Traces" (2605.24462) — Proposal→Certification→Execution | First clean formalisation of "generation is not permission" | [arXiv 2605.24462](https://arxiv.org/abs/2605.24462) |
| 2026-06-10 | ZK Podcast #403: ICME's `ICMEPreflight` — ZK guardrails for agentic commerce; Jolt Atlas | First shipped product framing ZK as an *agent* guardrail | [zeroknowledge.fm/podcast/403](https://zeroknowledge.fm/podcast/403) |
| 2026-06-17 | Pramaana Labs raises **$27M seed** led by Khosla Ventures (Accel, BoldCap, Nexus VP, Premji, Unbound) for formal verification of AI | Money is moving to "provably right" AI, adjacent to but not identical with ZK | [techcrunch.com](https://techcrunch.com/2026/06/17/pramaana-labs-raises-27-million-seed-round-from-khosla-ventures-to-bring-formal-verification-to-ai) |
| 2026-07-02 | **zk.golf** launched by zkSecurity: circuits written in Clean (Lean), scored by allocations+constraints, LLM-authored submissions allowed | Makes "AI writes the circuit, Lean checks it" a public competition | [blog.zksecurity.xyz](https://blog.zksecurity.xyz/posts/zkgolf), [zk.golf](https://zk.golf) |
| 2026-07-23 | "Cryptographically verifiable authorization for autonomous AI agents" (2607.21325) | Names the exact object we care about: relation `R_CVA` binding principal, agent, request, policy, context | [arXiv 2607.21325](https://arxiv.org/abs/2607.21325) |
| 2026-08-07 | NiyamAI (2608.07167): intent-bound ZK guardrails, argues host-local filters give an external observer no evidence | The "compromised host produces no evidence of its own failure" argument is the core threat model | [arXiv 2608.07167](https://arxiv.org/abs/2608.07167) |
| 2026-08-30 | ZK predicate proofs between AI agents; documents a **source-integrity gap** in deployed multi-agent platforms | Evidence that cross-agent ZK is being attempted in production and failing on input integrity | [arXiv 2608.30083](https://arxiv.org/abs/2608.30083) |
| 2026-09-10 | ECDSA.fail preprint: **>100 participants and their agents**, 1,151 logical qubits, 1.30M Toffoli, Q×T >50% below Google's March 2026 result | Proof that agent-swarm autoresearch beats solo researchers on a cryptographic target | [eigenlabs.org](https://www.eigenlabs.org/blog/open-autoresearch-the-ecdsa-fail-story/), [arXiv 2609.09582](https://arxiv.org/abs/2609.09582) |
| 2026-09-29 | Aztec relaunches **zk.money**; Project Eleven acquires Riva Labs (post-quantum) | Privacy UX returns; PQ consolidation begins | [coin360.com](https://coin360.com/news/aztec-zk-money-privacy-wallet-relaunch), [prnewswire.com](https://www.prnewswire.com/news-releases/project-eleven-acquires-riva-labs-to-expand-post-quantum-research-and-engineering-302892036.html) |
| 2026-10-01 | zkMesh Sept recap ships `sig.golf` (EF × Yukon), Jolt-QED (Lean-verified bytecode expansion), lattice-SNARK coverage | Second golf-style competition, now for post-quantum signatures | [zkmesh.substack.com](https://zkmesh.substack.com/p/zkmesh-sept-2026-recap) |
| 2026-10-13 | "Holding Agents Accountable with Verifiable Agent Insurance" (2610.18230) | Moves from prevention to *financial recovery* — an economic layer on top of proofs | [arXiv 2610.18230](https://arxiv.org/abs/2610.18230) |
| 2026-10-22 | **2026 ZK Industry Report** preview published (ZK Podcast × Succinct); full report "next week"; Aztec `v6.0.0` tagged | The sector's own state-of-the-market doc — read it before positioning | [zkmesh.substack.com](https://zkmesh.substack.com/p/a-first-look-at-the-2026-zk-industry), `gh api repos/AztecProtocol/aztec-packages/releases` |
| 2026-10-26 | Aztec v6 executes on mainnet at 08:00 UTC; "Post-Audit Mirage" (2610.31130) and "Proof-of-Agentness" (2610.35288) posted | Same day: private execution matures, and offline agent verification is formally shown to be insufficient | [announce.aztec.network](https://announce.aztec.network/a/2026-10-upgrade-the-v6-upgrade-executed-on), [2610.31130](https://arxiv.org/abs/2610.31130), [2610.35288](https://arxiv.org/abs/2610.35288) |
| 2026-10-27 | sig.golf leaderboard record: 5,195-byte signature / 7,007 cycles (36.4M byte·cycles), 313 promoted results, **50.88% leaner** than baseline; solver credited to "DeepSeek-V4" | Humans-with-agents are now setting cryptographic size records in public, weekly | [yukon.org/sig.golf](https://www.yukon.org/sig.golf) |

---

## 2. Zero Knowledge podcast digest — latest 12 episodes

Pulled from the RSS feed (`feeds.captivate.fm/zeroknowledge`, `lastBuildDate` 2026-10-21) so titles and dates are exact; the podcast index page also renders correctly. Host: Anna Rose, with co-hosts Kobi Gurkan, Nico Mohnblatt, Guillermo Angeris, Tarun Chitra.

**#414 — zkGolf: AI, Clean and Optimising ZK Circuits with zkSecurity — 2026-10-21** ([link](https://zeroknowledge.fm/podcast/414))
Thesis: LLMs can write and *prove* circuits in Clean/Lean; an AI-optimised SHA-256 experiment (Opus 4.7, "a couple of nights") became zkGolf because the kernel check, not the human, decides correctness. Implication: our protocol should ship machine-checkable specs of its own circuits — Lean-checked artefacts are becoming the trust anchor, and AI-generated proofs of soundness are now a normal input.

**#412 — JP Aumasson on Quantum Risk, AI Attacks and Too Much Crypto — 2026-09-30** ([link](https://zeroknowledge.fm/podcast/412))
Thesis: Q-day timelines are still speculative, but AI-driven cryptanalysis is already producing records and a China NGCC competition where AI finds weaknesses in candidate designs; Poseidon-class ZK-friendly hashes have taken real hits. Implication: do not hard-code a single ZK-friendly hash or a single hardness assumption into an agent credential format.

**#411 — Auto Research on Yukon with Soubhik Deb — 2026-09-23** ([link](https://zeroknowledge.fm/podcast/411))
Thesis: ECDSA.fail proved that researchers + their agents, iterating on shared verified submissions, beat solo work; Yukon generalises this to SNARK.fast, better.codes, mlx.fast, lighter.fast, arguing the bottleneck is *well-defined problems with verifiers*. Implication: an agent-security protocol whose claims are checkable by a verifier can be improved by this crowd; one that isn't, can't.

**#410 — Ron Rothblum on Fiat-Shamir Attacks, Flock and SNARK.fast — 2026-09-16** ([link](https://zeroknowledge.fm/podcast/410))
Thesis: a Fiat-Shamir attack broke practical GKR deployments and forced changes in shipped systems; new PCS/code work (Blaze, TensorSwitch, BOLT, Veil, Flock, Jagged PCS) is closing the gap to "proving at the speed of ordinary computation". Implication: Fiat-Shamir instantiation is a live deployment risk — transcript-binding choices belong in our threat model explicitly.

**#409 — The Evolution from ZKP2P to Peer with Richard Liang — 2026-09-09** ([link](https://zeroknowledge.fm/podcast/409))
Thesis: a team that started on ZK email, moved to ZK TLS, then **abandoned ZK for TEEs** to get UX and speed, calls the result "ephemeral privacy" — and is now building agentic payments. Implication: the honest competitive baseline for any ZK agent protocol is a TEE + attestation story; we must state why proofs beat attestation for *our* threat model, or lose on latency.

**#406 — Alex Ozdemir on where Theorem Provers and ZK meet — 2026-07-15** ([link](https://zeroknowledge.fm/podcast/406))
Thesis: zkPi is the first zkSNARK for Lean theorems; CirC unifies compiler infrastructure across SNARKs and SMT; the ZK DSL landscape has consolidated around zkVMs. Implication: "prove a policy theorem, then prove the execution satisfied it" is now a buildable pipeline, not a research wish.

**#405 — Sergey Gorbunov on TEEs and the Arc Privacy Sector — 2026-07-08** ([link](https://zeroknowledge.fm/podcast/405))
Thesis: Circle chose TEEs over ZK/FHE for Arc's on-chain privacy because composability and enterprise latency dominated. Implication: the market's revealed preference is attestation-first; ZK wins where the verifier must not trust the operator at all — which is exactly the agent case.

**#403 — Building ZK-Powered AI Guardrails with Wyatt Benno — 2026-06-10** ([link](https://zeroknowledge.fm/podcast/403))
Thesis: `ICMEPreflight` uses succinct verification so an agent's action can be checked against policy by a third party, claiming stronger guarantees than classifier-style guardrails; Jolt Atlas adapts Jolt lookups to ONNX for zkML. Implication: the closest shipped competitor to our thesis — study its trust boundary (who holds the policy, who verifies, what is proven) before designing ours.

**#401 — From Access Control to Encrypted Execution with Auryn Macmillan — 2026-05-20** ([link](https://zeroknowledge.fm/podcast/401))
Thesis: Zodiac's modular access control meets The Interfold (ex-Enclave), combining FHE+ZK+MPC so multiple parties compute over private data and get a verifiable output with no single coordinator. Implication: multi-party agent settings (agent A's data, agent B's policy, agent C's auditor) already have a design vocabulary; reuse it rather than invent one.

**#402 — The Quantum Question Panel, live from zkSummit14 — 2026-05-27** ([link](https://zeroknowledge.fm/podcast/402))
Thesis: recorded in Rome with Justin Drake, plus Daira-Emma Hopwood and Jens Groth from the audience; the disagreement is about migration timing, not about whether ECDSA breaks. Implication: agent identity keys need a hybrid/PQ migration path from day one, and sig.golf is already optimising that primitive.

**#400 — Quantum Advances, Hybrid Signatures and SNARKs to the Rescue with Dan Boneh — 2026-05-06** ([link](https://zeroknowledge.fm/podcast/400))
Thesis: unpacks Google's quantum-algorithm announcement — including that the paper's result was itself **proven in zero knowledge** — and argues for hybrid signatures, more attention to algebraic (not just hash-based) signatures in blockchains, and witness encryption for encrypted mempools. Implication: ZK is already being used to make *research claims* verifiable without disclosure, which is a template for how we should publish agent-safety claims; and agent credentials should be hybrid-signable rather than locked to a hash-based scheme.

**#399 — Is ZK dead? Or has it just begun? — 2026-04-22** ([link](https://zeroknowledge.fm/podcast/399))
Thesis: ZK has moved from research → narrative → invisible infrastructure; teams now use ZK as an implicit primitive rather than a headline. Implication: positioning an "open-source ZK protocol for agents" as a ZK project is a 2024 pitch; position it as the missing *authorisation and audit* layer that happens to use ZK.

*Not covered here:* #413 (quantum-photonics lasers, 2026-10-07) and #408 (Commonware consensus, 2026-08-05) are outside this slice's relevance; #407 (PIR, 2026-07-29) matters for private agent queries but is a primitive deep-dive better handled by the proving-systems slice.

---

## 3. 2026 arXiv papers — ZK for agents, attestation, verifiable inference

Search: arXiv full-text (10 quoted queries: "verifiable inference", "zkML", "zero-knowledge"+"AI agent", "verifiable agent", "zero-knowledge proof"+LLM, "proof of inference", "confidential inference", "agentic commerce" cryptography, etc.), filtered to 2026 submissions; 119 unique hits, 18 read in full abstract. The arXiv *API* was rate-limited (HTTP 429) from both this host and the droplet, so the HTML search endpoint was used instead — dates below are `citation_date` from each abstract page.

| arXiv ID | Title | One-line thesis | Why it matters to an agent-security protocol |
|---|---|---|---|
| [2610.35288](https://arxiv.org/abs/2610.35288) | Proof-of-Agentness: Towards Verifying Agents on the Web | Services need to distinguish legitimate LLM agents from scripts, and proposes verifiable claims of agent-ness instead of CAPTCHA | The identity problem is upstream of ours; if "agent" is unprovable, our authorisation proofs have no subject |
| [2610.31130](https://arxiv.org/abs/2610.31130) | Post-Audit Mirage: Identifiability Limits of Offline Agent Verification | Matched safe/harmful agent lifecycles expose identical verifier-visible evidence; a theorem gives an error–abstention tradeoff for offline audits | Proves that "audit the agent before deployment" cannot be sound — verification must bind to the live execution context |
| [2610.18230](https://arxiv.org/abs/2610.18230) | Holding Agents Accountable with Verifiable Agent Insurance | Provider commits to programmatic policies in a smart contract plus a monetary bond, enabling recovery after misbehaviour | Economic backstop design; a natural complement to cryptographic proof of policy compliance |
| [2608.30083](https://arxiv.org/abs/2608.30083) | Zero-Knowledge Predicate Proofs Between AI Agents | Builds a cross-protocol predicate-proof gateway and measures it; finds a **source-integrity gap** where the proven value's origin is unauthenticated | Direct evidence that predicate proofs alone don't secure agent-to-agent trust — provenance must be inside the statement |
| [2608.07167](https://arxiv.org/abs/2608.07167) | NiyamAI — Intent-Bound AI Agent with Cryptographically Verifiable Guardrails using ZKPs | Guardrails must produce evidence for an external observer, because a compromised host yields no evidence of its own failure | Articulates the exact threat model our protocol must assume: the enforcement environment is hostile |
| [2607.21325](https://arxiv.org/abs/2607.21325) | Cryptographically verifiable authorization for autonomous AI agents | Formalises authorisation as relation `R_CVA` binding principal, agent, request, policy and context, with a PoC | Closest existing formal object to "agent authorisation proof"; cite it and either extend or falsify it |
| [2605.24462](https://arxiv.org/abs/2605.24462) | No Certificate, No Execution: Certified Traces | Generation is not permission; an action may be computable yet impermissible, and permissible actions can compose into an impermissible trace | Gives us the trace-level (not call-level) granularity argument, which most ZK-agent pitches miss |
| [2605.06738](https://arxiv.org/abs/2605.06738) | Trust Without Trusting: A Recomputable Trust Protocol for Autonomous Agents | Signed, independently recomputable credentials suffice in an open agent economy; borders are drawn by platforms | Reports production scale (69k bots, 165M transactions, $50M volume on one marketplace) — sizing for the addressable problem |
| [2604.24203](https://arxiv.org/abs/2604.24203) | Agentic Witnessing: TEE-Enabled Privacy-Preserving Auditing | Moves from attested execution to "attested reasoning" because ZKPs are ill-suited to qualitative, unstructured properties like code logic | Defines where ZK legitimately loses to TEEs — scope our claims to algebraic predicates |
| [2603.10060](https://arxiv.org/abs/2603.10060) | Tool Receipts, Not Zero-Knowledge Proofs | ZK costs minutes per query, so use epistemic-source classification of claims plus tool receipts for hallucination detection | The main counter-paper; also a reminder that *receipts* (signed logs) are the minimum viable product |
| [2603.19025](https://arxiv.org/abs/2603.19025) | Towards Verifiable AI with Lightweight Cryptographic Proofs of Inference | Sampling-based verification grounded in statistics replaces full proofs, avoiding hundreds of seconds of prover overhead | Suggests a tiered assurance model: probabilistic spot-checks now, proofs where stakes justify |
| [2603.18046](https://arxiv.org/abs/2603.18046) | NanoZK: Layerwise ZK Proofs for LLM Inference | Decomposes transformer inference into per-layer proofs chained by SHA-256 commitments (~83KB total at L=12), parallelisable | Shows the practical shape of verifiable inference: commitment chain + parallel sub-proofs, not one monolithic circuit |
| [2602.17452](https://arxiv.org/abs/2602.17452) | Jolt Atlas: Verifiable Inference via Lookup Arguments in ZK | Applies Jolt's lookup-centric proving directly to ONNX ops, skipping CPU emulation | The zkML backend behind ICME's agent guardrails — the most productised zkML stack in this set |
| [2602.12630](https://arxiv.org/abs/2602.12630) | TensorCommitments: Lightweight Verifiable Inference for LLMs | Tensor-native proof-of-inference that avoids both slow cryptography and a trusted verifier GPU | Another data point that full ZK at LLM scale is being routed around, not solved |
| [2609.36437](https://arxiv.org/abs/2609.36437) | Bits Under ZK-LLM: ZK-Friendly Quantization for Verifiable Private LLM Inference | Quantization choices directly change constraint complexity and proving cost in ZK-LLM | If we ever prove model behaviour, numerics are a design parameter, not an implementation detail |
| [2609.10149](https://arxiv.org/abs/2609.10149) | Sound Debloating of Redundant Checks in ZKML Circuits | Redundant range/sign/bit checks can be removed only with global entailment proofs, else the circuit becomes forgeable | The "optimise the circuit" failure mode in one paper — directly relevant to zkGolf-style AI optimisation |
| [2606.03771](https://arxiv.org/abs/2606.03771) | πCreds: Privately Inferred Credentials | LLM inference over authenticated data mints legacy-compatible verifiable credentials, expanding what can be certified | Bridges agent reasoning and credentials — a plausible issuance path for agent-held attestations |
| [2608.09055](https://arxiv.org/abs/2608.09055) | Repeated-Game Security for Restaking-Based Verifiable Inference | One-round slashing conditions overstate security when inference is supplied repeatedly under the same stake | If we lean on cryptoeconomic assurance, the security argument must be a repeated game, not a single round |
| [2607.23752](https://arxiv.org/abs/2607.23752) | ZKP Security Tools and Verification: Coverage, Effectiveness, Adoption | Surveys the bug-detection/formal-verification toolchain for ZK systems and finds adoption lagging coverage | Our own circuits will need this toolchain; budget for verification, not just auditing |
| [2606.01722](https://arxiv.org/abs/2606.01722) | Post-Deterministic Distributed Systems | Classical distributed-systems theory assumes deterministic participants; stochastic LLM agents break that assumption | Theoretical opening: agreement/authorisation protocols must tolerate non-deterministic participants |

Counter-evidence read: three independent 2026 papers (2603.10060, 2603.19025, 2602.12630) route *around* full ZK for inference. Any claim that "agents will be secured by ZK inference proofs" is contradicted by the current literature; the defensible claim is about **authorisation and action provenance**, where the statement is small and algebraic.

---

## 4. WHO TO WATCH — verified orgs, licences, last activity

All licence/push data read 2026-10-27 via `gh api repos/<owner>/<repo>`.

| Org / project | Role | Licence | Last public activity | What they own |
|---|---|---|---|---|
| **RISC Zero** | General-purpose zkVM (RISC-V, zk-STARK) + Boundless prover market | Apache-2.0 | `risc0/risc0` pushed 2026-10-28, 2,207★; latest tag `v3.0.6` (2026-07-17) | The zkVM most production rollups use, plus the largest decentralised proving market (ZKC, PoVW) |
| **Succinct** | SP1 zkVM, Prover Network, `flock` | Apache-2.0 | `sp1` `v6.10.0` 2026-10-23 (three releases in six weeks); `succinctlabs/flock` pushed 2026-10-28 | SP1, op-succinct (OP Stack proving), and co-authorship of the 2026 ZK Industry Report |
| **Aztec** | Private L2 / private smart contracts | Apache-2.0 | `aztec-packages` `v6.0.0` 2026-10-22, executed on mainnet 2026-10-26; repo pushed 2026-10-27 | The only live decentralised private execution environment with a token and a wallet (zk.money) |
| **StarkWare** | Cairo language, Stwo (circle-STARK) prover, sequencer | Apache-2.0 | `starkware-libs/stwo` pushed 2026-10-28 (504★); `cairo` 2026-10-28 (1,914★) | Cairo as the dominant "provable program" language and a fast open prover |
| **Plonky3 (community org)** | PIOP/PCS toolkit used across the ecosystem | Apache-2.0 | `Plonky3/Plonky3` pushed 2026-10-27, 860★; Sept 2026 deadlock in ZK mode found and fixed ([PR #2368](https://github.com/Plonky3/Plonky3/pull/2368)) | The de-facto polynomial-IOP toolkit; note the ZK-mode bug class |
| **Polygon Zero** | Former Plonky2/Plonky3 home | Apache-2.0 | **Dormant**: `0xPolygonZero/plonky2` last push 2025-07-01; `0xPolygonZero/Plonky3` (1★) last push 2025-09-10 | Brand and legacy repos; the live Plonky3 work has moved to the community org |
| **PSE → `privacy-ethereum`** | EF-linked privacy R&D lab, renamed org ("Privacy Stewards of Ethereum") | halo2: NOASSERTION; semaphore: MIT | `privacy-ethereum/halo2` pushed 2026-07-01 (250★); `semaphore-protocol/semaphore` 2026-10-17 (1,094★) | halo2, Semaphore (anonymous membership proofs), and the EF privacy roadmap vocabulary |
| **zkSecurity + Verified-zkEVM** | Audits, Clean (Lean circuit DSL), zk.golf | Clean: MIT | `Verified-zkEVM/clean` pushed 2026-10-27 (207★); new `signature-security-lean` pushed 2026-10-28 | The formal-verification layer for circuits — and the competitions that feed it |
| **ICME Labs** | zkML + agent guardrails (`ICMEPreflight`), NovaNet | `ICME-Lab/jolt-atlas` NOASSERTION | pushed 2026-10-27 (79★) | The only shipped "ZK guardrail for agents" product I could verify; closest competitor |
| **Eigen Labs / Yukon** | Autoresearch platform; ECDSA.fail, SNARK.fast, sig.golf | n/a (platform) | ECDSA.fail preprint 2026-09-10; sig.golf leaderboard active 2026-10-27 | The crowd + verifier infrastructure that produces optimised circuits on demand |
| **Miden (0xMiden)** | STARK VM, private smart contracts | Apache-2.0 | `miden-vm` pushed 2026-10-27 (777★); testnet v0.16 billed "last stop before mainnet" | A private-execution alternative to Aztec with a different (client-side) proving model |
| **Nexus** | zkVM aiming at "internet scale" | NOASSERTION | `nexus-zkvm` last push **2026-01-06** (2,623★) | Strong mindshare, but no public code activity for ~10 months — treat as a watch item, not a dependency |
| **Delphinus zkWasm** | WASM zkVM | Apache-2.0 | `DelphinusLab/zkWasm` last push 2026-02-10 (545★) | WASM proving; relevant if agent sandboxes are WASM-based, but activity has slowed |
| **World / World ID** | Proof-of-human credentials | MIT | `worldcoin/world-id-protocol` pushed 2026-10-27 (42★) | The main "is this a human" credential that agent frameworks will have to interoperate with |
| **zk.email** | Email provenance proofs (DKIM → ZK) | MIT | `zkemail/zk-email-verify` pushed 2026-10-01 (435★) | Web2-identity provenance; the pattern Peer abandoned for TEEs, still the cheapest real-world attestation source |
| **ERC-8004 authors** (MetaMask, EF, Google, Coinbase) | Standards: Trustless Agents registries (Identity / Reputation / Validation) | CC0 | Draft created 2025-08-13, still DRAFT | The standards-layer claim on agent discovery + validation, with zkML/TEE/stake-re-execution as pluggable trust models |

*Deliberately excluded as unverifiable:* Modulus Labs (no public repo found; no dated 2026 activity found), Espresso Systems (`github.com/EspressoSys` shows **0 public repos**, so no code claim can be made — its 2026 presence is research + the Bünz podcast appearance), and any org whose licence I could not read directly.

---

## 5. Funding and job-market signals

**Funding / M&A (verified):**

| Date | Event | Amount | Source |
|---|---|---|---|
| 2026-03-23 | Origins Network — modular AI chain with verifiable compute | $8M | [thecosmicmeta.com](https://thecosmicmeta.com/origins-network-raises-8m-for-modular-ai-chain-with-verifiable-compute) *(single trade-press source)* |
| 2026-04-15 | OpenGradient — "compute layer for verifiable AI", a16z crypto-led | $9.5M total | [theaiinsider.tech](https://theaiinsider.tech/2026/04/15/opengradient-announces-9-5m-in-total-funding-to-build-the-compute-layer-for-verifiable-ai) *(press-release coverage; PRNewswire original timed out on fetch)* |
| 2026-06-17 | Pramaana Labs — formal verification for high-stakes AI; Khosla Ventures lead | $27M seed | [techcrunch.com](https://techcrunch.com/2026/06/17/pramaana-labs-raises-27-million-seed-round-from-khosla-ventures-to-bring-formal-verification-to-ai) |
| 2026-09-29 | Project Eleven acquires Riva Labs (post-quantum research/engineering) | undisclosed | [prnewswire.com](https://www.prnewswire.com/news-releases/project-eleven-acquires-riva-labs-to-expand-post-quantum-research-and-engineering-302892036.html) |
| 2026-09 | Citrea acquires Crest (Zcash-style privacy for Bitcoin) | undisclosed | [zkMesh Sept 2026](https://zkmesh.substack.com/p/zkmesh-sept-2026-recap) → [blog.citrea.xyz](https://www.blog.citrea.xyz/citrea-acquires-crest-to-bring-zcash-style-privacy-to-bitcoin/) |
| 2026-10-22 | ZK Podcast × Succinct publish the **2026 ZK Industry Report** preview (paid; full release "next week") | n/a | [zkmesh.substack.com](https://zkmesh.substack.com/p/a-first-look-at-the-2026-zk-industry) |

Pattern: capital in 2026 went to **verification of AI behaviour** (Pramaana, OpenGradient, Origins) far more than to proving infrastructure, which is already funded and price-competitive. The $27M seed for formal verification — not ZK — is the single most indicative number in this report.

**zkMesh+ newsletter signals (dated):**
- Paid tier now gates substantive material: bonus clips with Benedikt Bünz on AI-as-threat (2026-07-01), Wyatt Benno on vericoding + SMT (2026-06-18), Patrick O'Grady on where LLMs help (Aug 2026), plus an FHE addendum (2026-06-18) — all per the [archive](https://zkmesh.substack.com/archive?sort=new).
- Sept 2026 recap (published 2026-10-01) leads with lattice-based PCS work (Akita, Maltese, LaBinius), Fiat-Shamir instantiability, and threshold/PQ signatures — i.e. the research frontier is post-quantum and hash-based, matching Flock/sig.golf ([recap](https://zkmesh.substack.com/p/zkmesh-sept-2026-recap)).
- Same recap's "Project Updates" include SP1 integrating **NVIDIA cuPQC** and Miden's "last stop before mainnet" — GPU-accelerated proving is now a shipped feature, not a roadmap item ([recap](https://zkmesh.substack.com/p/zkmesh-sept-2026-recap)).

**Job market:** the canonical ZK jobs board is **gone**. `jobsboard.zeroknowledge.fm` renders as "Search 0 live jobs" via normal fetch ([jobsboard](https://jobsboard.zeroknowledge.fm/)) and as **"Job Board Is Unavailable — This job board website is either expired or its domain name is invalid"** via Firecrawl on 2026-10-27. Hiring signal therefore has to be read from release cadence instead: SP1 shipped three releases in the six weeks to 2026-10-23, Aztec shipped a mainnet-mandatory major, RISC Zero commits daily, and zkSecurity opened three new Lean repos in the last week. Teams are shipping; the job-board layer of the community did not survive.

---

## 6. What this tells us to build

1. **Scope the proofs to authorisation, not inference.** Three 2026 papers route around full ZK for inference ([2603.10060](https://arxiv.org/abs/2603.10060), [2603.19025](https://arxiv.org/abs/2603.19025), [2602.12630](https://arxiv.org/abs/2602.12630)), while the authorisation papers ([2607.21325](https://arxiv.org/abs/2607.21325), [2608.07167](https://arxiv.org/abs/2608.07167), [2605.24462](https://arxiv.org/abs/2605.24462)) are small, algebraic and unsolved. Build the authorisation relation (`R_CVA`-style: principal, agent, request, policy, context) and prove *that*; treat model behaviour as a signed receipt, not a circuit.

2. **Bind provenance inside the statement.** The measured source-integrity gap in [2608.30083](https://arxiv.org/abs/2608.30083) and the source rule in [2603.10060](https://arxiv.org/abs/2603.10060) both say the same thing: a proof about a value that doesn't authenticate where the value came from is theatre. Our credential format should make `(claim, source-attestation, policy-id, context)` one statement, with the source hash committed.

3. **Make the verifier the product, and make it a public good.** Yukon/ECDSA.fail ([eigenlabs.org](https://www.eigenlabs.org/blog/open-autoresearch-the-ecdsa-fail-story/)) and zk.golf/sig.golf ([zk.golf](https://zk.golf), [yukon.org/sig.golf](https://www.yukon.org/sig.golf)) show that well-specified problems plus open verifiers produce 50–99% improvements in weeks. Ship a machine-checkable spec of our own protocol (Lean/Clean-style, per [#414](https://zeroknowledge.fm/podcast/414)) and let agents optimise against it — but heed [2609.10149](https://arxiv.org/abs/2609.10149): unsound debloating is exactly how an agent will "optimise" our circuit into forgeability.

4. **Design for the TEE baseline, and win on the one axis TEEs can't cover.** Peer abandoned ZK for TEEs for latency ([#409](https://zeroknowledge.fm/podcast/409)); Circle chose TEEs for Arc ([#405](https://zeroknowledge.fm/podcast/405)). Our claim must be narrow and testable: a proof verifies even when *every* operator, host and marketplace is compromised ([2608.07167](https://arxiv.org/abs/2608.07167), [2610.31130](https://arxiv.org/abs/2610.31130)). Publish latency numbers against a TEE baseline from day one, or the comparison will be made for us.

5. **Interoperate with ERC-8004 and PQ-migrate from the start.** The standards-layer claim is already staked (Identity/Reputation/Validation registries, CC0, zkML and TEE as pluggable validators — [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004)), and post-quantum migration is being optimised in public ([sig.golf](https://www.yukon.org/sig.golf), [#400](https://zeroknowledge.fm/podcast/400)). Be the strongest *validation* provider inside that registry rather than a competing registry, and make credentials hybrid-signable and aggregatable so a PQ swap is a parameter change.

---

## 7. Sources

Podcast / community
- https://feeds.captivate.fm/zeroknowledge (RSS; 427 items; `lastBuildDate` 2026-10-21)
- https://zeroknowledge.fm/podcast/399 · /400 · /401 · /402 · /403 · /405 · /406 · /409 · /410 · /411 · /412 · /414
- https://zeroknowledge.fm/events/ (zkSummit14, Rome, 2026-05-07)
- https://jobsboard.zeroknowledge.fm/ (unavailable; verified 2026-10-27)
- https://zkmesh.substack.com/archive?sort=new
- https://zkmesh.substack.com/p/zkmesh-sept-2026-recap (2026-10-01)
- https://zkmesh.substack.com/p/a-first-look-at-the-2026-zk-industry (2026-10-22)
- https://blog.zksecurity.xyz/posts/zkgolf (2026-07-02) · https://zk.golf · https://www.yukon.org/sig.golf
- https://www.eigenlabs.org/blog/open-autoresearch-the-ecdsa-fail-story/ (2026-09-10)

Papers (arXiv, 2026)
- 2610.35288 · 2610.31130 · 2610.18230 · 2609.36437 · 2609.10149 · 2608.30083 · 2608.09055 · 2608.07167 · 2607.23752 · 2607.21325 · 2606.03771 · 2606.01722 · 2605.24462 · 2605.06738 · 2604.24203 · 2603.19025 · 2603.18046 · 2603.14283 · 2603.10060 · 2602.17452 · 2602.12630 · 2602.09434 · 2609.09582
- (all at https://arxiv.org/abs/<id>)

Code / licences (read 2026-10-27 via `gh api`)
- https://github.com/risc0/risc0 · https://github.com/succinctlabs/sp1 · https://github.com/succinctlabs/flock · https://github.com/AztecProtocol/aztec-packages · https://github.com/starkware-libs/stwo · https://github.com/starkware-libs/cairo · https://github.com/Plonky3/Plonky3 · https://github.com/0xPolygonZero/plonky2 · https://github.com/privacy-ethereum/halo2 · https://github.com/semaphore-protocol/semaphore · https://github.com/Verified-zkEVM/clean · https://github.com/ICME-Lab/jolt-atlas · https://github.com/0xMiden/miden-vm · https://github.com/nexus-xyz/nexus-zkvm · https://github.com/DelphinusLab/zkWasm · https://github.com/worldcoin/world-id-protocol · https://github.com/zkemail/zk-email-verify · https://github.com/boundless-xyz/boundless

Funding / industry
- https://techcrunch.com/2026/06/17/pramaana-labs-raises-27-million-seed-round-from-khosla-ventures-to-bring-formal-verification-to-ai
- https://theaiinsider.tech/2026/04/15/opengradient-announces-9-5m-in-total-funding-to-build-the-compute-layer-for-verifiable-ai
- https://thecosmicmeta.com/origins-network-raises-8m-for-modular-ai-chain-with-verifiable-compute
- https://www.prnewswire.com/news-releases/project-eleven-acquires-riva-labs-to-expand-post-quantum-research-and-engineering-302892036.html
- https://boundless.network/blog · https://announce.aztec.network/a/2026-10-upgrade-the-v6-upgrade-executed-on
- https://eips.ethereum.org/EIPS/eip-8004

**Coverage gaps, stated plainly:** the arXiv API was rate-limited (429) from both this host and the droplet, so paper discovery went through the HTML search endpoint — the 119-result set is deep but not exhaustive; a "zero-knowledge proof" sweep without an agent qualifier would surface more. The ZK jobs board is offline, so no live job-count trend exists. Substack paid-tier content (full Industry Report, bonus clips) was not read, only the public previews. No 2026 activity could be verified for Modulus Labs or for Espresso Systems' code.
