# ZK-ML and zkVM Systems for Proving Computation About ML and Agent Behaviour

> **Provenance.** Third-party and vendor figures, plus our own shipped-tree
> numbers where labelled "ours". See `README.md#measurement-provenance` before
> citing anything here as this project's measurement.

**Date.** 2026-10-28
**Purpose.** Decide whether `zkagent`'s v0 statement — *"an agent's execution stayed within a signed policy"* — belongs in a hand-written fixed-shape circuit (current path) or requires a general-purpose zkVM, and record what each family actually measures.
**Scope fence.** Proof systems and their measured cost. Not agent frameworks, not prompt security, not token economics.
**Method.** arXiv API (`export.arxiv.org/api/query`), IACR ePrint, and vendor documentation, read 2026-10-27/28. Every number below is traceable to the source named in the same row or sentence; the two exceptions are flagged inline. Numbers I could not confirm are marked `[unverified]`. Nothing is quoted from a vendor blog without being labelled a vendor claim.

**One methodological note that governs how the numbers must be read.** The best single source in this space is a 2026 IACR paper that re-benchmarked eight prover families under one contract-validated harness on one machine.[1] Its own authors bound their claims: "the campaign collected one successful run per case for the large majority of cases", "medians are across distinct *cases* … not repeated runs of one case", and "orderings within an order of magnitude are not claimed".[1] Everything I quote from it inherits that caveat. Cross-paper tables in the ZKML literature inherit a worse one: different models, different quantization, different hardware.

---

## 0. The claim under test

Restated as something falsifiable: *for a statement whose witness shape is fixed by a schema (≤8 allow-listed targets, ≤8 actions, u64 caps, an expiry, a chain id, an execution id), a hand-written R1CS circuit is 1–2 orders of magnitude cheaper than any general zkVM, and no zkML system in the literature beats it for this class of statement.*

That is a narrower claim than "ZK is fast". It says nothing about proving a forward pass of a neural network, which is a genuinely hard problem and where the numbers are much worse. The two must not be blurred — conflating them is the single most common error in ZK-agent pitches, including the ones I would like to be true.

---

## 1. Three architectures, and what each can actually express

The literature sorts into three families, and the boundary between them is *what the statement quantifies over*, not how fast the prover is.

| Family | Statement form | Shape | Representative systems |
|---|---|---|---|
| **Fixed-shape circuit** (R1CS/PLONKish) | ∃ w. C(x, w) = 1, where \|w\| is bounded by the schema | Fixed at circuit-design time | Groth16/arkworks, Halo2, Plonky3, `ezkl`, our v0 circuit |
| **Specialised sumcheck/GKR argument** | ∃ w. *this specific computation* (matmul, conv, attention, gradient step) was done correctly | Fixed per *operator*, variable per *tensor dimension* | zkCNN, Mystique, Kaizen, zkLLM, Jolt Atlas, `zkComposer` |
| **General zkVM** | ∃ w. *program P* halted with output y | Arbitrary; the ISA is the schema | SP1, RISC Zero, Jolt, Pico, Nexus, OpenVM, Miden, Cairo |

The middle column is where the interesting engineering has gone. A zkVM is the only family that can prove "the agent ran *this code* and did not deviate", because only a VM binds the instruction stream. A fixed circuit can prove "the numbers in this receipt satisfy this predicate" and nothing about the code that produced them. zkCNN's authors put the tradeoff plainly in 2021: their GKR-based system has a *larger* proof than the pairing-based vCNN/ZEN but "does not have a trusted setup and a common reference string of tens of GBs".[2]

---

## 2. Measured: general provers on one machine

From the contract-validated benchmark,[1] CPU=8 medians across distinct cases. Hardware: **AMD Ryzen 7 7800X3D (8 cores, SMT disabled), NVIDIA RTX 5070 Ti 16 GB, 32 GB DDR5, Ubuntu 24.04**. Table III of that paper, reproduced verbatim in structure:

| Scheme | Total ms | Proving ms | Verify ms | Peak MB | Claimed sec. bits | Proof bytes |
|---|---|---|---|---|---|---|
| **plonky3** | 18 | 10 | 5.2 | 11 | 116 | 443,250 |
| **winterfell** | 21 | 20 | 0.36 | 8.3 | 96 | 44,999 |
| **groth16** | 3,800 | 26 | 1.4 | 280 | 100 | **707** |
| **icicle** (GPU) | 4,200 | 200 | 1.6 | 160 | 100 | 723 |
| **halo2** | 9,200 | 1,300 | 35 | 140 | 126 | 2,304 |
| **nova** (folding) | 2,800 | 97 | 54 | 100 | 100 | 1,661,400 |
| **risc0-cuda** | 430 | 410 | 10 | 980 | 96 | 260,810 |
| **sp1** | 10,000 | 9,300 | **360** | **4,000** | 100 | 5,674,577 |
| **risc0** (CPU) | 31,000 | 31,000 | 14 | **3,300** | 96 | 260,810 |

What survives the single-run caveat, because the gaps are far larger than an order of magnitude:

- **Proof size**: Groth16 and ICICLE are sub-kilobyte; SP1's proof artifact is **5.67 MB, ~8,000× larger than Groth16's 707 B**.[1] That is consistent with SP1's documented default: core proofs are "a list of STARK proofs that in aggregate have size proportional to the size of the execution".[11] The paper's summary sentence is the one to quote in a design doc: "zkVM systems trade larger proofs and higher memory for programmability."[1]
- **Memory**: SP1 4.0 GB and RISC Zero 3.3 GB peak versus 11 MB for Plonky3 and 8.3 MB for Winterfell on the same workloads.[1]
- **Verification**: Winterfell 0.36 ms, Groth16 1.4 ms, **SP1 360 ms** — a 1,000× spread across the eight schemes (Groth16→SP1 alone is 257×), and the ordering does not follow proof size at all.[1]
- **Groth16's 280 MB peak is the setup/generator path, not per-proof.** The paper separates these: "setup time (total minus proving) is about 3.8 s for Groth16 … compared to 7.5 ms for Plonky3".[1] Reading that column as per-proof memory would be wrong.
- **CPU scaling 1→8 cores**: risc0 7.3×, plonky3 and groth16 5.7×, sp1 4.6×, nova 3.1×; GPU paths 1.0×.[1] A 2-vCPU droplet therefore sits at roughly *half* of every CPU-prover figure above, and cannot use the GPU column at all.

---

## 3. Measured: ZKML systems

These prove something much larger than a policy check — a forward pass. They are included because their *architecture* is the candidate alternative for agent behaviour, not because their cost is comparable.

| System | Statement | Model / dataset | Prover | Proof size | Verifier | Peak mem | Hardware |
|---|---|---|---|---|---|---|---|
| **vCNN** (as run by [2]) | CNN prediction | LeNet/MNIST | 5.49 s | 0.34 KB | 84 ms | — | same machine as zkCNN |
| **vCNN** (extrapolated) | VGG16 | CIFAR-10 | **31 h** (marked estimated)[2] | 0.34 KB | 20 s | — | — |
| **ZEN** (as run by [2]) | LeNet/CIFAR-10 | — | 119.5 s | 0.28 KB | 18.6 ms | — | same machine as zkCNN |
| **zkCNN**[2] | CNN prediction | LeNet/MNIST | 0.44 s | 71.3 KB | 5.8 ms | — | — |
| **zkCNN**[2] | CNN prediction | VGG16/CIFAR-10 | 88.3 s | 341 KB | 59.3 ms | **24 GB** | "reasonable for a personal computer" |
| **Mystique**[6] | ResNet-101 inference | CIFAR-10 | 28 min (private model) / 5 min (public) | — | — | — | interactive (VOLE), not a NIZK |
| **Kaizen**[3] (ePrint v.) | VGG-11 training step, 10M params, bs=16 | — | 22 min/iteration | 1.36 MB | 103 ms | — | — |
| **Kaizen**[3] (CCS'24 v.) | same | — | 15 min/iteration | 1.63 MB | 130 ms | — | — |
| **zkLLM**[4] | OPT-13B inference | C4, seq 2048 | 713 s | 160 KB | 3.71 s | 22.9 GB GPU | EPYC 7413 12c, A100 SXM4 40 GB, 124.5 GB host RAM |
| **zkLLM**[4] | OPT-125M | C4 | 73.9 s | 141 KB | 0.342 s | 1.88 GB GPU | same |
| **Jolt Atlas**[5] | nanoGPT 0.25M params | — | 14 s | UNVERIFIED (not stated in the paper) | 0.517 s | — | MacBook Pro M3, 16 GB |
| **Jolt Atlas**[5] | GPT-2 125M | — | ~38 s end-to-end | not stated | not stated | — | same |
| **ezkl** (as reported by [5]) | nanoGPT 0.25M | — | 237 s (+212 s keygen) | — | 0.34 s | — | ezkl's own published benchmark |
| **zkPoT**[7] | logistic regression, 262k×1024 | 4 GB dataset | <10 min (online) / ~1 h (data-dependent) | ~MB total | ~30 s | constant RAM (streaming) | — |

Three things this table says that the marketing does not:

1. **The Kaizen numbers disagree between its own two versions** — 22 min / 224× / 1.36 MB / 103 ms in the ePrint revision versus 15 min / 24× / 1.63 MB / 130 ms in the ACM CCS'24 version.[3] Same model, same claim, materially different figures. Cite the version you read or the number is unfalsifiable.
2. **zkLLM's headline "under 15 minutes for 13B" is 713 s on an A100 with 124.5 GB of host RAM** — and 11.9 minutes is not "under 15 minutes" by much.[4] The proof is 160 KB, i.e. 1,250× our 128 B proof, and it verifies in 3.71 s, ~40–50× our verification.
3. **Jolt Atlas is the only entry that is structurally a competitor to our statement**, because it drops the CPU/ISA emulation and applies lookups directly to ONNX tensor ops: "unlike zkVMs … which emulate CPU instruction execution, Jolt Atlas adapts Jolt's lookup-centric approach and applies it directly to ONNX tensor operations."[5] It also advertises "streaming" proving in memory-constrained environments, and its companion work names our exact use case — "guardrails in agentic commerce".[5]

**What "specialisation" buys, stated carefully.** The gains in this table come from replacing generic boolean/bit-decomposition encodings of non-arithmetic operations with something purpose-built. ezDPS — a pipeline of discrete wavelet transform, PCA and SVM — reports "one-to-three orders of magnitude" improvement over "the generic circuit-based approach in all metrics" by designing gadgets per operation.[18] Range-Arithmetic does the same for rounding and ReLU: it converts them into arithmetic steps checkable by sum-check plus concatenated range proofs, explicitly "avoid[ing] the complexity of Boolean encoding, high-degree polynomials, and large lookup tables".[19]

The transferable lesson for `zkagent` is not "use GKR". It is that **domain-shaped gadgets beat generic encodings by 1–3 orders of magnitude**, and that a policy check is already the smallest possible encoding of its own domain: eight ≤-comparisons, one sum, one expiry, one id. There is nothing left to specialise.

---

## 4. The zkVM proof-mode ladder, and the wrap cost nobody quotes

zkVM proof size is a *choice*, not a constant, and the ladder is where most comparisons cheat. Measured on a 36-megagas Reth block (RSP) by zkbenchmarks:[13]

| SP1 mode | Proof size | Prove time |
|---|---|---|
| Core | **824 MB** | 14 m 42 s |
| Compressed | **1.48 MB** | 14 m 32 s |
| Groth16 | **1.45 KB** | 15 m 16 s |

So the honest zkVM row is: you may have a 1.45 KB proof, and it costs you a **15-minute prove on a 36-megagas workload** plus the wrap. SP1's own docs put the wrap's memory floor at "roughly 14 GB of memory for Groth16 and 60 GB for PLONK", with 16 GB+ RAM and 16+ CPU cores for Core/Compress, and ≥24 GB VRAM recommended for GPU proving.[10] SP1's docs also state a ~260 B Groth16 proof verifiable for ~270k gas, and ~868 B for PLONK — vendor figures, not independently measured.[11] The independently measured SP1 Groth16 artifact in §4's table is 1.45 KB (different version and settings), so treat 260 B as a best case, not a budget.

RISC Zero's own docs recommend "at least 16 GB of RAM" to prove locally.[12] The 2026 benchmark measured 3.3 GB peak for *small* workloads and 3.3 GB–4 GB medians,[1] which is the honest floor if you strip the recommendation down to what a tiny guest actually needs.

**A zkVM is not a smaller Groth16. It is a Groth16 whose witness is an entire program execution.** Recursion compresses the *proof*, never the *work*. vApps measures the compression as high as 230× and precompiles as saving >95% of proof time,[15] but both operate on a trace that has already been generated.

The overhead is structural, not a compiler deficiency. A 2025 study of 64 LLVM passes across 58 benchmarks on RISC Zero and SP1 found that standard optimisation levels do improve zkVM performance "over 40%", but far less than on a CPU, "since their decisions rely on hardware features rather than proof constraints" — and that the single most harmful pass (`licm`) *increases* proving time by 8.4% on SP1 and 13.5% on RISC Zero.[14] You cannot optimise your way out of the trace; the trace is the cost.

---

## 5. The resource floor against the actual deployment target

Our target is a **2 vCPU / 3 GB RAM droplet**.[21] Against that budget:

| System | Documented or measured floor | vs 3 GB | Fits? |
|---|---|---|---|
| Our Groth16 circuit (3333 constraints) | 29 MB peak RSS, serial, measured on the droplet for the smaller probe circuit;[21] proving key 648,816 B | 0.01× | **Yes, with ~100× headroom** |
| Groth16 (benchmark median, setup included) | 280 MB peak[1] | 0.09× | Yes |
| Plonky3 | 11 MB peak[1] | 0.004× | Yes |
| Winterfell | 8.3 MB peak[1] | 0.003× | Yes |
| RISC Zero (measured, small workload) | 3.3 GB peak[1] | 1.1× | **No** — a single prove already exceeds the whole box |
| RISC Zero (documented) | 16 GB recommended[12] | 5.3× | No |
| SP1 (measured, small workload) | 4.0 GB peak[1] | 1.33× | No |
| SP1 Core/Compress (documented) | 16 GB+, 16+ cores[10] | 5.3× | No |
| SP1 Groth16 wrap (documented) | ~14 GB for the wrap step alone[10] | 4.7× | No |
| zkCNN VGG16 | 24 GB peak[2] | 8× | No |
| zkLLM OPT-13B | 22.9 GB GPU + 124.5 GB host[4] | — | No |

This is the decisive table, and it is decisive for a reason that has nothing to do with cryptography: **the 3 GB droplet cannot run a zkVM prover at all**, so an A2H protocol built on SP1 or RISC Zero would have to either raise the deployment floor by ~5× or push proving to a hosted prover network — which reintroduces exactly the trusted third party the protocol exists to remove. Note the asymmetry: verification is cheap for zkVMs (10–360 ms) and could run on the droplet; it is *proving* that does not fit. A design where the agent proves elsewhere and the verifier runs cheaply is coherent, but it means the *agent operator* needs a 16 GB box, not us.

---

## 6. Where the fixed-shape/arbitrary line actually falls for "agent stayed in policy"

This is the part I would get wrong if I only read the ZKML papers, because ZKML is about *model inference*, and our statement is not one.

**Our v0 statement is a bounded predicate, not a computation.** The circuit is 3,333 R1CS constraints, 15 public inputs, 128-byte proof, 0.43–0.64 s prove, 0.048–0.091 s verify on a laptop, proving key 648,816 B, verifying key 712 B.[21] A zkVM asked to prove the same predicate would (a) execute a Rust program, (b) generate a trace, (c) prove the trace, (d) wrap it — for a statement that is three orders of magnitude smaller than the machine needed to prove it. The measured gap on comparable tiny workloads is 26 ms (Groth16) versus 9.3 s (SP1) and 31 s (RISC Zero) — **18.6× and 62× slower to prove the same class of thing**.[1]

**But "agent behaviour" in the strong sense is a computation, and our circuit does not currently prove it.** Two distinct claims hide behind the phrase:

1. *Accounting claim* — "the receipt's totals, per-action amounts, targets, expiry and execution id satisfy the policy." Our circuit proves this completely, and it is what the 15 public inputs bind.
2. *Behaviour claim* — "the agent's actual execution is the one summarised in that receipt." Our circuit does **not** prove this. `Action::trace_digest` is documented as a "free-form per-action commitment",[21] is allocated as a `U64Var::new_witness` at `crates/zkagent-proofs/src/circuit.rs:174`, and is then destructured as `_` in every consuming loop (e.g. line 181: `for (_, amount, _) in &action_vars`). It is an **unconstrained witness**: 64 bits, no hash, no chain relation, no public binding. Whatever integrity the trace has today comes from the receipt's signature over the struct, not from the proof.

That gap is cheap to close and should be closed before the protocol claims behaviour rather than accounting: raise the digest to 256 bits, chain it (`dᵢ = H(dᵢ₋₁ ‖ actionᵢ)`), compute it in-circuit, and bind the terminal digest into the public inputs. That turns a ~3.3k-constraint circuit into roughly a 3.3k + 8×SHA-256 circuit, which is still nowhere near zkVM territory — the benchmark's hash workloads put SHA-256 inside every prover family tested, and Groth16's per-proof cost stayed at 26 ms.[1]

**The correct middle ground, and where the literature converges.** Every serious system refuses to prove the whole computation at once when it can commit to it instead:

- zkCNN commits to model parameters and proves the sumcheck relation over the commitment rather than publishing the weights.[2]
- `zkComposer` splits a monolithic zkML proof into independent sub-proofs over contiguous layer ranges, "cryptographically linked through shared commitments to the activations from the boundary layer", and reports up to 3.25× prover-time reduction over zkCNN on CNNs and 4.83× over zkGPT on GPT-2 — with "the same guarantees as the monolithic proof".[17]
- Kaizen composes per-iteration GKR proofs recursively so proof size and verifier time are independent of iteration count.[3]
- Jolt Atlas uses "prefix–suffix decomposition and streaming" so the prover never materialises the full table.[5]

Our architecture is the limiting case of this pattern: commit to the trace, prove the bounded aggregate predicate, keep the circuit fixed-shape. The design is right; the commitment is currently a placeholder.

**When a zkVM becomes the correct answer** — three concrete triggers, so the decision is not aesthetic:
1. The policy must constrain *code paths* (e.g. "the agent never called tool X", where X is discovered at runtime), not just totals.
2. The witness shape becomes genuinely unbounded (variable-length conversation transcripts with content-dependent branching), so a fixed circuit either pads wastefully or lies.
3. A third party must verify a program it did not write, which is exactly what SP1's and RISC Zero's audit trail and EVM verifiers are for.[1][15]

None of these is true for v0.

---

## 7. Counter-evidence and failure modes

A report that only lists favourable numbers is advocacy. These cut against the whole category, including our own design.

- **ZK inference verification does not bind effort.** The Hollow-LLM Attack (2026) shows a provider can keep the declared architecture and parameter count while embedding "ghost weights whose algebraic structure collapses effective computation", producing valid proofs while doing "computation commensurate with a much smaller model than the declared public architecture."[16] The general lesson transfers directly to agent attestation: **a proof binds the statement you wrote, and nothing about whether the statement was the one that mattered.** Our circuit binds "these 8 amounts were under cap", not "this agent did useful work".
- **Proving a model ran is not proving the model is good**, and proving a policy was satisfied is not proving the policy was well-chosen. `Verifiable evaluations of machine learning models using zkSNARKs`[9] is explicit that it attestations *stated performance or fairness metrics over public inputs* — a narrow, checkable claim, packaged honestly. That is the right template for our docs.
- **Benchmark fragility is real.** The one paper that re-benchmarked everything says its own campaign was mostly single-run and refuses confidence intervals.[1] Any table — including mine — that presents 3 significant figures from that source is over-claiming.
- **Trusted setup.** Groth16 needs a per-circuit ceremony; SP1's Groth16 wrap uses "the Aztec Ignition ceremony + entropy contributions from members of the Succinct team".[11] We inherit that class of assumption, and our setup is at least *ours* and reproducible from a seed — a smaller trust surface than a borrowed ceremony, but not zero.
- **The ZKML field's own bottleneck is not cryptographic.** The 2025–26 survey names "limited circuit expressiveness, high proving cost, and deployment complexity" as the three blockers, and the first is a *language* problem, not a prover problem.[8] This is the strongest argument for a zkVM in the long run and the weakest for v0.
- **Non-arithmetic operations are where all the cost lives.** A later framework's analysis puts "more than 90 percent of the total runtime" of Mystique in the non-linear layer proofs,[20] and Mystique is a VOLE-based *interactive* protocol, not a NIZK[6][20] — a different trust and round model from anything we would deploy. Do not put Mystique in the same table as Groth16 without that caveat.

---

## 8. Verdict

**For v0, fixed-shape Groth16 over arkworks BN254 is correct, and the literature strengthens rather than weakens that choice.** The measured grounds:

1. Nothing in the general-prover benchmark reaches our proof size (707 B median, 128 B ours) at our verification cost (1.4 ms median, ~70 ms ours including process startup) with our memory footprint (29 MB measured).[1][21]
2. Every zkVM that could express an arbitrary agent execution has a **proving** memory floor of 3.3–16 GB and a Groth16 wrap floor of ~14 GB,[1][10][12] against a 3 GB droplet. The floor is not a tuning problem; it is the trace.
3. The zkML systems that beat generic circuits do so by specialising to an *operator family* (conv, attention, matmul) and accepting either 100s of MB to 24 GB of prover memory[2][4] or an interactive protocol.[6] Neither is available for a statement that is 3,333 constraints.

**What would change the verdict**, in order of likelihood: (a) the policy must constrain runtime code paths → zkVM, and budget a 16 GB prover box; (b) trace digests become unbounded and content-dependent → move to a streaming sumcheck argument (Jolt Atlas-style) rather than a VM, since the statement stays a predicate over committed data; (c) a hosted prover network becomes acceptable operationally, at which point SP1's 260 B Groth16 wrap is genuinely competitive on bytes and only loses on latency.[11]

**Immediate work item this research surfaced, independent of the substrate choice:** `trace_digest` is an unconstrained `u64` witness at `circuit.rs:174` and is never used in a constraint. Until it is a chained 256-bit commitment bound into the public inputs, the protocol proves *accounting* compliance and should not be described as proving *behaviour*. See §6.

---

## Sources

1. Hulek, Peresini, Homoliak. *A Unified Framework for Contract-Validated Benchmarking of Zero-Knowledge Proving Systems.* IACR ePrint 2026/1729, approved 2026-08-21. https://eprint.iacr.org/2026/1729
2. Liu, Xie, Zhang. *zkCNN: Zero Knowledge Proofs for Convolutional Neural Network Predictions and Accuracy.* IACR ePrint 2021/673 / ACM CCS '21. https://eprint.iacr.org/2021/673
3. Abbaszadeh, Pappas, Katz, Papadopoulos. *Zero-Knowledge Proofs of Training for Deep Neural Networks* (Kaizen). IACR ePrint 2024/162; ACM CCS '24, doi:10.1145/3658644.3670316. https://eprint.iacr.org/2024/162
4. Sun, Li, Zhang. *zkLLM: Zero Knowledge Proofs for Large Language Models.* arXiv:2404.16109, 2024-04-24. https://arxiv.org/abs/2404.16109
5. Benno, Centelles, Douchet, Gibran (ICME Labs). *Jolt Atlas: Verifiable Inference via Lookup Arguments in Zero Knowledge.* arXiv:2602.17452, 2026-02-19. https://arxiv.org/abs/2602.17452
6. Weng, Yang, Xie, Katz, Wang. *Mystique: Efficient Conversions for Zero-Knowledge Proofs with Applications to Machine Learning.* IACR ePrint 2021/730 / USENIX Security '21. https://eprint.iacr.org/2021/730
7. Garg, Goel, Jha, Mahloujifar, Mahmoody, Policharla, Wang. *Experimenting with Zero-Knowledge Proofs of Training* (zkPoT). IACR ePrint 2023/1345. https://eprint.iacr.org/2023/1345
8. Peng, Zhao, Wang, Liao et al. *A Survey of Zero-Knowledge Proof Based Verifiable Machine Learning.* arXiv:2502.18535v2, rev. 2026-03-29. https://arxiv.org/abs/2502.18535
9. South, Camuto, Jain, Nguyen et al. *Verifiable evaluations of machine learning models using zkSNARKs.* arXiv:2402.02675v2. https://arxiv.org/abs/2402.02675
10. Succinct Labs. *SP1 — Hardware Requirements* (local proving table; Groth16 wrap ~14 GB, PLONK ~60 GB; 24 GB VRAM recommended). https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements
11. Succinct Labs. *SP1 — Proof Types* (Groth16 ~260 B / ~270k gas; PLONK ~868 B / ~300k gas; Aztec Ignition ceremony). https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types
12. RISC Zero. *zkVM Quickstart* — "To create a proof with the zkVM on your own machine, we recommend at least 16 GB of RAM." https://dev.risczero.com/api/zkvm/quickstart
13. *zkVM Benchmarks* (neutral cross-prover suite; RSP 36-megagas core/compressed/Groth16 sizes and times). https://zkbenchmarks.com/
14. Gassmann, Chaliasos, Sotiropoulos, Su. *Evaluating Compiler Optimization Impacts on zkVM Performance.* arXiv:2508.17518v2 / ASPLOS '26. https://arxiv.org/abs/2508.17518
15. Zhang, Kulkarni, Li, Wong. *vApps: Verifiable Applications at Internet Scale.* arXiv:2504.14809, 2025-04-21. https://arxiv.org/abs/2504.14809
16. Gong, Liu, Li. *Hollow-LLM Attack: Computationally Trivial Weights in Zero-Knowledge Verification of LLM Inference.* arXiv:2607.28884, 2026-07-30. https://arxiv.org/abs/2607.28884
17. Sanjaya, Giannoula, Oktavian, Saeedi. *zkComposer: Decomposing Proof Construction to Scale zkML.* arXiv:2607.08095, 2026-07-09. https://arxiv.org/abs/2607.08095
18. Wang, Hoang. *ezDPS: An Efficient and Zero-Knowledge Machine Learning Inference Pipeline.* arXiv:2212.05428. https://arxiv.org/abs/2212.05428
19. Rahimi, Khalaj, Maddah-Ali. *Range-Arithmetic: Verifiable Deep Learning Inference on an Untrusted Party.* arXiv:2505.17623. https://arxiv.org/abs/2505.17623
20. Lu, Wang, Qu, Wang et al. *An Efficient and Extensible Zero-knowledge Proof Framework for Neural Networks.* IACR ePrint 2024/703 (reports 41.4× speedup over Mystique on ResNet-101; GPT-2 117M in 287.1 s). https://eprint.iacr.org/2024/703
21. Project-internal measurements: `docs/MEASUREMENTS.md` (3333 constraints, 15 public inputs, 128 B proof, 0.43–0.64 s parallel prove, 0.048–0.091 s verify, pk 648,816 B, vk 712 B, 29 MB RSS serial) and `crates/zkagent-proofs/src/circuit.rs:174` (`trace_digest` witness allocation). Local repository, read 2026-10-28.

### Verification status of each number

| Claim | Status |
|---|---|
| Table in §2 (all rows) | Measured, one machine, single run per case — see the paper's own budget caveat[1] |
| zkCNN LeNet/VGG11/VGG16 rows | Measured on the authors' machine; hardware not stated numerically in the text[2] |
| vCNN / ZEN rows | Measured by the zkCNN authors running those systems' open-source code on the same machine[2]; VGG16 vCNN figure is *their* estimate, marked `*` in the original table |
| Kaizen, both rows | Author-reported benchmarks, and the two versions of the paper disagree — both reported[3] |
| zkLLM rows | Author-reported, full hardware disclosed (A100 40 GB, 124.5 GB host RAM)[4] |
| Jolt Atlas rows | Author-reported on a MacBook Pro M3 / 16 GB; **proof size is not stated in the paper** |
| ezkl row | Reported by Jolt Atlas's authors from ezkl's own published benchmark — second-hand[5] |
| SP1 mode ladder (§4) | Measured by zkbenchmarks on an RSP workload; version and settings not normalised against §2's SP1 row[13] |
| SP1 ~260 B / RISC Zero 16 GB | **Vendor claims**, not independently reproduced[11][12] |
| Our 3333 constraints / 128 B / timings | Measured in-repo, reproducible via `cargo test -p zkagent-proofs constraint_count_is_sane -- --nocapture`[21] |
| Peak RSS on the droplet for *this* circuit | **Not measured.** 29 MB is the smaller probe circuit, serial. Flagged as an open measurement in `MEASUREMENTS.md`[21] |
| Any statement about zkVM cost for *our exact policy statement* | **Not measured and not projected here.** No zkVM port of the policy circuit exists; the 18.6×/62× figures are for the benchmark's own small workloads, not ours[1] |
