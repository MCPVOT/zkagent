# Rust ZK Proving-System Landscape — October 2026

**Purpose.** Choose the proving substrate for a private-first, open-source zero-knowledge attestation protocol for AI agents and humans.
**Scope fence.** Proving-system / substrate layer only. No agent frameworks, no prompt security, no business models.
**Method.** Every repository figure below was read from the GitHub REST API (`gh api repos/<owner>/<repo>`, `.../commits`, `.../releases`, `.../contents`) on 2026-10-27/28. Download counts are from the crates.io API on the same date. Nothing in this document is quoted from a vendor blog unless labelled as such. Claims I could not source are marked `[unverified]`.

Two audit notes that shape everything below:

- **`privacy-scaling-explorations` was renamed to `privacy-ethereum` and the entire org was archived.** `privacy-scaling-explorations/halo2` now resolves to `privacy-ethereum/halo2` with `archived: true`, last commit `2025-07-07`, and its GitHub page states "This repository was archived by the owner on Aug 17, 2026."[8] The same archive sweep caught `halo2curves`, `snark-verifier` (PSE's copy), `halo2-solidity-verifier`, `chiquito` and `zkevm-circuits`. The org's public repo list is archived end to end.[8][32]
- **`0xPolygonZero/plonky2` is archived and carries a deprecation notice** pointing users to Plonky3.[13] Jolt, SP1 and Miden all still consume Plonky3-lineage code, not Plonky2.

---

## (a) Comparison table — Rust ZK stacks, audited 2026-10-27

Proving/verification model, recursion and EVM-verifier columns are read from repository contents (crate directories, `*.sol` file counts, README statements), not from marketing pages.

| Stack | Repo | License | Stars | Last commit (default branch) | Commits since 2026-07-29 | Proving / verification model | Recursion in-tree | EVM verifier in-tree | Stated status (source's own words) |
|---|---|---|---|---|---|---|---|---|---|
| **arkworks — algebra/curves** | https://github.com/arkworks-rs/algebra | Apache-2.0 (README: dual MIT/Apache)[1] | 893 | 2026-10-26 | 12 | Field, curve, MSM, FFT primitives over R1CS | n/a (library) | — | Active; the numeric foundation for most of the R1CS ecosystem[1] |
| **arkworks — Groth16** | https://github.com/arkworks-rs/groth16 | Apache-2.0 (dual)[2] | 354 | 2026-08-02 | 2 | R1CS → QAP → Groth16; 3-pairing verification, constant-size proof | **No** — `src/` is `constraints, data_structures, generator, lib, prover, r1cs_to_qap, verifier` only[2] | **No** in-tree; community `Tetration-Lab/arkworks-solidity-verifier` (11★, last push 2025-06-23)[33] | README: "academic proof-of-concept prototype… NOT ready for production use"[2] |
| **arkworks — snark traits** | https://github.com/arkworks-rs/snark | Apache-2.0 (dual)[3] | 917 | **2025-09-12** | **0** | `SNARK`/`RelaxedR1CSSNARK` traits | — | — | Same prototype warning[3] |
| **arkworks — Marlin** | https://github.com/arkworks-rs/marlin | Apache-2.0[4] | 328 | **2024-01-18** | 0 | Universal-setup preprocessing SNARK | No | No | **Stale** — 2.8 years without a commit[4] |
| **arkworks — circom-compat** | https://github.com/arkworks-rs/circom-compat | Apache-2.0[5] | 284 | **2025-08-26** | 0 | Circom R1CS + witness → arkworks Groth16 | No | Yes, indirectly (circom/snarkjs Solidity templates) | Maintained for interop only[5] |
| **halo2 (Zcash)** | https://github.com/zcash/halo2 | Dual Apache-2.0/MIT (API: `NOASSERTION`, both LICENSE files present)[7] | 929 | **2026-10-27** | **92** | Plonkish arithmetization + IPA/Pasta; `halo2_proofs` 0.4.1 | Design-level only — accumulation over a 2-cycle with deferred checks; no turnkey API[31] | **No** — IPA proofs are too large for on-chain verifier gas[7] | Active; MSRV 1.88[7] |
| **halo2 (PSE → privacy-ethereum)** | https://github.com/privacy-ethereum/halo2 | `NOASSERTION` (dual files)[8] | 250 | **2025-07-07** | 0 | halo2 + KZG fork | — | — | **ARCHIVED 2026-08-17**[8] |
| **halo2 (Axiom fork) + halo2-lib** | https://github.com/axiom-crypto/halo2 · https://github.com/axiom-crypto/halo2-lib | Dual Apache-2.0/MIT[9][10] | 16 / 314 | 2026-08-07 / 2026-08-10 | — / 1 | halo2 + KZG, `halo2-base` 0.5.5, `halo2-ecc` 0.5.5 | Via in-circuit halo2 verifier in `snark-verifier`[11] | **Yes** — `snark-verifier-sdk/src/evm.rs`[11] | Active successor to the PSE fork[9][10] |
| **snark-verifier** | https://github.com/axiom-crypto/snark-verifier | Dual Apache-2.0/MIT[11] | 106 | 2026-08-10 | — | (S)NARK verifier: native + EVM, halo2 system only | Yes (verifier-in-circuit) | **Yes**, EVM SDK[11] | README: "recommended for production use", Trail of Bits audited 2023[11] |
| **Plonky3** | https://github.com/Plonky3/Plonky3 | Apache-2.0[12] | 860 | **2026-10-26** | **100+** | Toolkit: FRI/STIR/WHIR PCS, `uni-stark`, `multi-stark`, `batch-stark`, BabyBear/KoalaBear/Mersenne31/Goldilocks/binary-tower fields | **No** — `batch-stark`/`multi-stark` batch, they do not recurse[12] | **No**[12] | Active; `p3-*` at `0.9.0-rc.2` (pre-release)[36] |
| **SP1 (Succinct)** | https://github.com/succinctlabs/sp1 | Apache-2.0 (dual files)[14] | **1755** | 2026-10-26 | 83 | RISC-V zkVM, Plonky3-powered STARK, `crates/recursion` | **Yes** — `crates/recursion`[14] | **Yes**, but in a separate repo[15] | README: audited by Veridise, Cantina, Zellic, KALOS; "recommended for production use"[14]; v6.10.0 (2026-10-23) |
| **SP1 contracts** | https://github.com/succinctlabs/sp1-contracts | **No license file in repo root** — API reports `none`[15] | 147 | 2026-08-04 | — | Solidity verifier + gateway | — | **Yes**[15] | **Licensing gap: the on-chain verifier is unlicensed**[15] |
| **RISC Zero** | https://github.com/risc0/risc0 | Apache-2.0[16] | **2207** | 2026-10-26 | 2 | RISC-V zkVM, zk-STARK + Groth16 wrap (`groth16_proof/`) | **Yes**, via Groth16 wrap[16] | **Yes** — `risc0-ethereum`, 32 `.sol` files[17] | Production platform; v3.0.6 stable (2026-07-17), v5.0.0-rc.1 pre-release[16] |
| **Binius64** | https://github.com/binius-zk/binius64 | MIT [18] (repo ships both Apache-2.0 and MIT files) | 206 | 2026-10-08 | **100+** | Binary-tower-field SNARK over 64-bit-word circuits | **Yes** — `crates/recursion`[18] | **No** — zero `.sol` files[18] | Successor to Binius, "focus on simplicity and CPU performance"[18] |
| **Jolt (a16z)** | https://github.com/a16z/jolt | Apache-2.0[22] | 1058 | **2026-10-28** | **100+** | RISC-V zkVM via lookup arguments (Lasso/Twist-and-Shout), `jolt-spartan-verifier` | Yes — `jolt-blindfold`[22] | **No** — zero `.sol` files[22] | Active; book "currently undergoing updates"[22][45] |
| **Miden VM** | https://github.com/0xMiden/miden-vm | Apache-2.0[23] | 777 | 2026-10-27 | **100+** | Lifted-STARK VM with Plonky3 components; `verifier/src/recursive` | **Yes**[23] | **No**[23] | Pre-1.0; `next` targets 1.0, `miden-vm` 1.0.0-rc.0 on crates.io[23][41] |
| **OpenVM** | https://github.com/openvm-org/openvm | Apache-2.0[24] | 397 | 2026-10-26 | 40 | Modular "no-CPU" zkVM, RV32IM + custom ISA extensions, `crates/recursion`, `crates/static-verifier` | **Yes**[24] | **Yes** — `OpenVmHalo2Verifier.sol` (halo2 wrap)[24] | "out-of-the-box support for… verification on Ethereum"[24] |
| **Nova (Microsoft)** | https://github.com/microsoft/Nova | MIT[20] | 867 | 2026-09-11 | 9 | Folding scheme + IVC, Spartan compression; Pallas/Vesta, BN254/Grumpkin, secp/secq | **Native** (IVC is the product)[20] | **No** — the `evm` cargo feature is *serialization* only[20] | Reference implementation of a paper[20] |
| **winterfell** | https://github.com/facebook/winterfell | MIT[21] | 908 | **2025-07-19** | **0** | STARK prover/verifier library over AIR | No | **No**[21] | **Stale** — 15 months without a commit[21] |
| **Plonky2** | https://github.com/0xPolygonZero/plonky2 | Apache-2.0[13] | 858 | **2025-07-01** | 0 | PLONK + FRI, AIR/Starky | Was yes | Community forks only | **ARCHIVED + deprecation notice → use Plonky3**[13] |
| **Binius (original)** | https://github.com/IrreducibleOSS/binius | Apache-2.0[19] | 140 | **2025-09-09** | 0 | Binary-tower SNARK | — | — | **ARCHIVED**, superseded by Binius64[19] |
| **bellman** | https://github.com/zkcrypto/bellman | `NOASSERTION`[26] | 1129 | 2026-09-26 | — | Groth16 over BLS12-381 | No | No | Legacy incumbent of the Zcash Sapling era[26] |
| **Zisk** | https://github.com/0xPolygonHermez/zisk | Apache-2.0[27] | 216 | 2026-10-27 | — | RISC-V zkVM; `zisk-contracts/PlonkVerifier.sol` | Yes (`recurser/`)[27] | **Yes**[27] | Active, young[27] |
| **Noir** | https://github.com/noir-lang/noir | Apache-2.0[25] | 1420 | 2026-10-27 | **100+** | Language + ACIR; backends pluggable (not itself a prover) | Backend-dependent | Backend-dependent | Active; **819 open issues**[25] |

### Adoption signal (crates.io, 2026-10-27)

Downloads are supply-chain evidence of how much code already sits on each API, which matters more than stars for a substrate choice.

| Crate | Version | All-time downloads |
|---|---|---|
| `ark-std` | 0.6.0 | 113,141,073[1] |
| `ark-bn254` | 0.6.0 | 32,610,351[1] |
| `ark-relations` | 0.6.0 | 15,270,899[3] |
| `ark-snark` | 0.6.0 | 8,427,184[3] |
| `ark-groth16` | 0.6.0 | 7,242,809[34] |
| `halo2_proofs` | 0.4.1 | 3,595,495[35] |
| `p3-dft` | 0.9.0-rc.2 | 3,146,623[36] |
| `p3-fri` | 0.9.0-rc.2 | 2,047,250[36] |
| `risc0-zkvm` | 5.0.0-rc.1 | 2,029,367[38] |
| `halo2curves` | 0.10.0 | 1,050,940[8] |
| `halo2-poseidon` | 0.2.0 | 947,142[7] |
| `sp1-verifier` | 6.10.0 | 863,980[37] |
| `halo2-axiom` | 0.5.3 | 392,607[9] |
| `halo2-base` | 0.5.5 | 339,145[43] |
| `snark-verifier` | 0.2.7 | 329,761[11] |
| `winterfell` | 0.13.1 | 296,179[42] |
| `midnight-proofs` | 0.8.3 | 205,031[39] |
| `nova-snark` | 0.76.0 | 152,352[40] |
| `miden-vm` | 1.0.0-rc.0 | 32,705[41] |
| `jolt-core` | 0.1.3 | 10,059[22] |
| `openvm` | 2.0.2 | 2,719[24] |

Two caveats on that table, both material:

- `halo2_proofs` at 3.59M downloads is the **Zcash/Pasta (IPA)** crate.[35] The KZG variants the EVM world uses are `halo2-axiom`, `halo2-base` and Midnight's fork — together ~0.94M.[43][39] They are different trust models sharing one frontend, and they are routinely conflated.
- **`jolt-core` on crates.io resolves to `github.com/rlch/jolt`, not `a16z/jolt`.**[22] The a16z Jolt repo publishes no matching crate under that name, so the 10k download figure says nothing about the a16z zkVM. Treat Jolt as source-dependency-only until it publishes under its own namespace.

---

## (b) What is alive vs abandoned in 2026 (with evidence)

### Genuinely alive — commit activity in the last 90 days, plus a release in 2026

| Stack | Evidence |
|---|---|
| **zcash/halo2** | 92 commits since 2026-07-29, last commit 2026-10-27, `halo2_proofs` 0.4.1 republished 2026-10-27, MSRV 1.88[7][35] |
| **Plonky3** | 100+ commits since 2026-07-29 (API page cap), last commit 2026-10-26, 29 open issues, `p3-*` 0.9.0-rc.2 published 2026-10-16, Least Authority audit report in `audits/`[12][36] |
| **SP1** | 83 commits, last commit 2026-10-26, v6.10.0 released 2026-10-23, 8 audit artifacts in `audits/` (Cantina, Code4rena, Zellic, Veridise, KALOS, rkm0959)[14] |
| **RISC Zero** | 100+ commits historically, 2 commits since 2026-07-29 on `main`, last commit 2026-10-26, v3.0.6 stable 2026-07-17; `risc0-ethereum` last push 2026-10-22[16][17] |
| **Binius64** | 100+ commits since 2026-07-29, last commit 2026-10-08, 11 open issues[18] |
| **Jolt** | 100+ commits, last commit 2026-10-28 (the most recent of any repo audited here)[22] |
| **Miden VM** | 100+ commits, last commit 2026-10-27, `miden-vm` 1.0.0-rc.0 published 2026-10-27[23][41] |
| **OpenVM** | 40 commits, last commit 2026-10-26, 12 open issues (lowest in the set)[24] |
| **arkworks/algebra** | 12 commits, last commit 2026-10-26[1] |
| **axiom-crypto/halo2-lib** | `halo2-base`/`halo2-ecc` 0.5.5 published 2026-08-14, last commit 2026-08-10[10][43] |

### Abandoned or effectively frozen

| Stack | Evidence of death |
|---|---|
| **PSE/`privacy-ethereum` halo2, halo2curves, snark-verifier, halo2-solidity-verifier, chiquito, zkevm-circuits** | Whole org archived. `halo2` page: "archived by the owner on Aug 17, 2026"; last commit 2025-07-07; 0 commits in 90 days.[8] `halo2-solidity-verifier` archived 2024-10-01, last push 2024-10-01.[8] `zkevm-circuits` archived 2024-07-05 with an explicit sunset note.[32] |
| **Plonky2** | `archived: true`, last commit 2025-07-01, 0 commits in 90 days, README deprecation notice redirecting to Plonky3.[13] Survives only as third-party forks (0xPARC for POD2, Pearl, polymerdao).[13] |
| **Original Binius** (`IrreducibleOSS/binius`) | `archived: true`, last commit 2025-09-09.[19] Work moved to `binius-zk/binius64` (206★, active).[18] |
| **winterfell** | 0 commits since 2026-07-29, last commit 2025-07-19, and the `winterfell` crate is still at 0.13.1 with a 2025-07-19 publish date.[21][42] No archive flag, but 15 months of silence is abandonment in practice. |
| **arkworks Marlin** | Last commit 2024-01-18.[4] Parked. |
| **arkworks Groth16 / snark traits** | `snark` last commit 2025-09-12 with 0 commits in 90 days; `groth16` 2 commits since July.[2][3] The 0.6.0 crates were published 2026-04-26[34] but the *default branch* has not moved meaningfully — treat as **maintenance mode, not development**. |
| **arkworks/curves** | `archived: true`, last commit 2023-12-18; folded into `arkworks-rs/algebra`.[1] |
| **Polygon Zero zkEVM line** (`0xPolygonZero/zk_evm`) | Last commit 2024-12-03, last push 2025-05-02, 0 commits in 90 days, 89 open issues.[13] Dead project, unarchived shell. |

**The structural read.** The 2024–2026 consolidation is: *folding and monolithic PLONK systems lost; modular STARK toolkits and zkVMs won.* The three survivors of the "write your own circuit" era are Zcash's halo2 (alive, but deliberately narrow), Axiom's halo2 fork (alive, small, dependency of bigger systems) and arkworks (alive at the arithmetic layer, frozen at the proof-system layer). Everything with momentum is a zkVM or a PIOP toolkit: SP1, RISC Zero, Plonky3, Jolt, Miden, OpenVM, Binius64.

---

## (c) The three best substrate candidates for a privacy-preserving AI-agent attestation protocol

Framing the workload, because it decides the answer: an agent attestation is a **small, fixed-shape statement** — "I hold the private key for agent ID X, my model/config hash is H, my policy engine ran and produced this decision, and I have not been revoked." The witness is small (a key, a hash preimage, a Merkle path, a handful of signed claims). The verifier is often cheap, sometimes on-chain, and must not learn the witness. Volume is high; proof bytes and verification cost dominate the bill.

### Candidate 1 — Groth16 over arkworks (BN254), for fixed-size statements

**Why it wins on this workload.** It is the only option here that produces a **constant-size proof verified with 3 pairings**, which is what makes per-attestation verification affordable at volume, on-chain or in a constrained verifier. The arithmetic stack underneath it is the most heavily used Rust cryptography on crates.io by download count: `ark-std` at 113.1M and `ark-bn254` at 32.6M.[1] `ark-groth16` itself sits at 7.2M downloads on version 0.6.0.[34] `arkworks-rs/algebra` is actively maintained (last commit 2026-10-26).[1]

**Why it wins specifically for an attestation protocol.** Attestations are exactly the shape Groth16 is good at: one circuit per statement type, fixed public inputs (agent ID commitment, model hash, policy ID, epoch), witness = the secrets. You get one circuit per attestation class, reuse it forever, and the verifier is a few milliseconds.

**The costs, stated plainly.**
- **Circuit-specific trusted setup.** This is inherent to Groth16 (the arkworks impl is the scheme of eprint 2016/260[2]), not a flaw in arkworks. For a *private-first open-source* protocol this is a real governance problem: a ceremony you cannot prove was honest is a backdoor into every attestation. Mitigation is a public multi-party ceremony per circuit, which is expensive to run per attestation class.
- **No recursion in-tree.** `src/` is `constraints, data_structures, generator, lib, prover, r1cs_to_qap, verifier` — there is no recursion module.[2] Aggregating N attestations into one proof is your problem to solve. The polynomial-commitment layer it would build on (`arkworks-rs/poly-commit`) is maintained, last commit 2026-09-28, but it ships KZG/IPA/Hyrax primitives, not a recursion framework.[6]
- **No official EVM verifier.** The best available is a community repo at 11 stars whose last push was 2025-06-23.[33] If on-chain verification matters, you are either writing the Solidity verifier yourself or routing through circom/snarkjs templates.
- **The maintainers call it a prototype.** "This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use."[2][3] That warning is on the repo, in 2026. Any team choosing this is accepting that *they* are the audit.

**Verdict.** Best substrate if and only if (i) statements are fixed and few, (ii) proof size / verification cost dominate, and (iii) you are prepared to own the ceremony and the audit. It is the wrong choice the moment one attestation needs "and also prove arbitrary policy code ran."

### Candidate 2 — halo2 (Axiom KZG fork + halo2-lib), for custom circuits with lookups and real EVM verification

**Why it wins.** It is the only mature, *maintained* PLONKish option that has all three of: a rich custom-gate/lookup language for hash-heavy statements, a **production-audited EVM verifier path**, and constant-size KZG proofs. That verifier path is `snark-verifier-sdk/src/evm.rs`, reviewed by Trail of Bits in 2023, and its README states it is "recommended for production use".[11] Arithmetization is the strongest fit for attestation witnesses that are mostly hashing and signature checks: the protocol is a five-stage Plonkish argument (commit, vanishing, evaluate, multipoint opening, PCS opening) so lookups and custom gates are first-class,[30] and keccak/secp256k1/ed25519 gadgets ship in `halo2-lib`/`halo2-ecc` 0.5.5.[10]

**Why the Axiom fork and not Zcash's.** Zcash's `zcash/halo2` is very much alive (92 commits in 90 days) but it is IPA over Pasta — proofs are too large for an on-chain verifier, and it has no EVM story at all.[7] Axiom's fork is halo2 + KZG, which is what gives you a constant-size proof with a Solidity verifier. Axiom also holds the maintained `snark-verifier` and the in-circuit halo2 verifier used for recursion.[9][11]

**The costs.**
- **Governance risk is the headline.** The upstream (PSE) is archived and the maintained fork is a **16-star repo** with a last commit on 2026-08-07, one commit in 90 days on `halo2-lib`.[8][9][10] You are betting on Axiom's continued interest. That is a materially thinner bet than betting on `zcash/halo2` or Plonky3.
- **No turnkey recursion.** Recursion exists as an in-circuit halo2 verifier inside `snark-verifier`, not as a supported product.[11] Proof aggregation is real work.
- **Universal trusted setup.** KZG needs a powers-of-tau; less onerous than per-circuit Groth16 (one setup serves all circuits), but still a ceremony you must source and justify.
- **Ram cost is non-trivial.** Plonkish provers are memory-hungry relative to the statement size `[unverified]` — I found no first-party number for halo2 specifically, so size your circuits before committing.

**Verdict.** Best substrate when attestations are hash/signature-heavy, need to be verified on an EVM chain, and you can live with a two-maintainer dependency. It is the pragmatic middle: flexible circuits, audited on-chain verifier, no giant zkVM in the trust base.

### Candidate 3 — Plonky3 as the toolkit (or SP1 on top of it) for general computation and transparent setup

**Why it wins.** **No trusted setup at all** — hash-based, transparent, and post-quantum-leaning. For an open-source privacy protocol, "there is no ceremony to subvert" is a genuine security argument, not a marketing one. It is the most actively developed proving toolkit audited here (100+ commits in 90 days, 29 open issues, Least Authority audit, `p3-*` 0.9.0-rc.2 published 2026-10-16) and the substrate under SP1, Miden and others.[12][36]

Take **Plonky3 directly** if you want to author your own AIR for a bespoke attestation statement — you get `uni-stark`, `multi-stark`, `batch-stark`, FRI/STIR/WHIR PCS, and a choice of 31-bit fields that SIMD well.[12] Take **SP1** instead if the requirement is "prove that this arbitrary Rust policy program ran on this agent's private inputs" — it is the highest-star, most-audited option (1755★, 83 commits in 90 days, v6.10.0, audits from Veridise/Cantina/Zellic/KALOS) with `crates/recursion` and a Solidity verifier in `sp1-contracts`.[14][15]

**The costs, and they are the reason this is third rather than first.**
- **No EVM verifier in Plonky3 itself.** Zero `.sol` files in the repo.[12] On-chain verification means going through SP1's contracts or writing your own verifier.
- **No recursion in the toolkit.** `batch-stark`/`multi-stark` batch — they do not recurse.[12] Recursion is a downstream feature (SP1's `crates/recursion`), so choosing bare Plonky3 means building it.
- **`0.9.0-rc.2` is a pre-release.** The whole `p3-*` family is on a release candidate.[36] API churn is a real cost.
- **Hardware floor is high, and this matters for us specifically.** SP1's own docs: Core/Compress needs 16 GB+ RAM, Groth16 wrapping 16 GB+, PLONK wrapping 64 GB+.[28] RISC Zero recommends at least 16 GB to prove locally.[29] Our droplet is 2 vCPU / 3 GB / no GPU — **no zkVM prover will run there**. See the hardware section below.
- **SP1's on-chain verifier repo has no license file.** `sp1-contracts` root contains no `LICENSE`; the API reports `none`.[15] For an open-source protocol that is a blocking legal question, not a footnote.

**Verdict.** Best substrate when the attestation statement needs to express *computation* rather than a fixed relation, and when "no trusted setup" outranks proof size. Do not pick bare Plonky3 unless you are ready to own recursion and the EVM verifier; pick SP1 if you want them already built.

### The shortlist, decided

| If the constraint is… | Choose | Because |
|---|---|---|
| Smallest proof, cheapest verification, fixed statements, you own the ceremony | **arkworks Groth16 (BN254)** | 3-pairing verification, constant size, deepest download base[2][34] |
| Custom hash/signature circuits **and** on-chain verification | **halo2 (Axiom KZG) + snark-verifier** | Only maintained PLONKish path with an audited EVM verifier[10][11] |
| Arbitrary computation, no trusted setup | **Plonky3, or SP1 for batteries-included** | Transparent, actively developed, audited; SP1 adds recursion + Solidity[12][14] |

---

## (d) What we did NOT choose, and why

| Rejected | Reason (evidence) |
|---|---|
| **Plonky2** | Archived, deprecation notice pointing at Plonky3, last commit 2025-07-01.[13] Choosing it in 2026 means adopting a fork maintained by a third party with its own agenda. |
| **PSE / `privacy-ethereum` halo2** | Archived 2026-08-17.[8] Same code lineage is available through Axiom's maintained fork, so there is no reason to depend on a read-only repo. |
| **PSE `halo2-solidity-verifier`** | Archived 2024-10-01, last push 2024-10-01.[8] Superseded by `snark-verifier`'s EVM path.[11] |
| **`0xPolygonZero/zk_evm`** | Last commit 2024-12-03, 89 open issues, 0 commits in 90 days.[13] Dead, and out of scope anyway (we are not proving EVM state transitions). |
| **winterfell** | 15 months without a commit; crate frozen at 0.13.1 since 2025-07-19.[21][42] A STARK library that nobody maintains is a liability, not a substrate. |
| **arkworks Marlin** | Last commit 2024-01-18.[4] If we want universal setup we will use Plonky3 or halo2, both of which are alive. |
| **Nova / folding (microsoft/Nova)** | Technically excellent but the **wrong shape**: IVC is for long sequential computations, and our attestations are one-shot. It has **no Solidity verifier** — the `evm` feature is EVM-friendly *serialization* only — and only 9 commits in 90 days.[20] Folding would be right for a continuous "agent ran for 10^6 steps" proof, which is not the product. |
| **Binius64** | Genuinely interesting (100+ commits, recursion crate, 64-bit-word circuits that suit hashing) but young: 206 stars, 11 open issues, **zero EVM verifier**, and the binary-field tooling ecosystem (debuggers, gadget libraries, auditors) is thin.[18] Its protocol documentation lives at the project site rather than in the repo,[44] which for a security substrate means reading a website to audit code. Revisit in 12 months. |
| **Jolt** | Fastest-moving repo here (last commit 2026-10-28) and a beautiful design, but: no `.sol` verifier, no crate published under its own namespace (`jolt-core` on crates.io points at `rlch/jolt`), and its own book says it is "currently undergoing updates".[22][45] Too much churn to build a protocol on today. |
| **Miden VM** | Strong tech (lifted-STARK, recursion, Plonky3 components) but it is **its own ISA and assembly language**, not a Rust-guest VM.[23] An attestation protocol written in Miden assembly is locked to Miden's toolchain and hiring pool. Also pre-1.0 with 194 open issues. |
| **OpenVM** | Real contender — recursion, static verifier, an EVM halo2 wrap, only 12 open issues.[24] Excluded on maturity, not merit: 397 stars, 40 commits/90d, and the EVM path routes through a halo2 wrap, which adds a second proving system to our trust base for no benefit over choosing halo2 directly. |
| **RISC Zero** | The most-starred option (2207) with a real Solidity verifier in `risc0-ethereum`.[16][17] Excluded because a zkVM in the trust base is enormous relative to a fixed attestation circuit, its local-proving floor is 16 GB,[29] and — decisively for us — **it cannot prove on our 3 GB droplet**. Keep it as the "prove arbitrary Rust" fallback alongside SP1, not as the base layer. |
| **bellman** | Legacy Groth16/BLS12-381 from the Sapling era, `NOASSERTION` license.[26] arkworks is the better-maintained Groth16 in Rust. |
| **Noir** | Not a prover — a language plus ACIR with pluggable backends.[25] Choosing Noir means choosing a backend anyway, plus a DSL and 819 open issues. Useful later as an authoring frontend; not a substrate decision. |
| **Zisk** | Young (216★) but already ships `PlonkVerifier.sol` and a `recurser`.[27] Worth a benchmark run; not worth being the foundation. |
| **Midnight's `midnight-proofs`** | 205k downloads and published 2026-10-01,[39] but it is a halo2-KZG fork whose repository could not be resolved via the GitHub API (`repo: null` on crates.io) — **we could not verify its maintenance status**, which by itself disqualifies it as a substrate. |

---

## Hardware reality check (applies to every zkVM candidate)

Verified baseline for our environment: droplet `hoodbot@100.111.194.19`, 2 vCPU / 3 GB RAM / 20 GB free disk, **no GPU**.

- SP1 local proving minimums: Mock/Network 8 GB+, Core/Compress **16 GB+**, Groth16 wrap ~14 GB, **PLONK wrap ~60 GB**, plus a 24 GB-VRAM NVIDIA GPU for acceleration.[28]
- RISC Zero: "we recommend at least 16 GB of RAM" to prove locally, and steers users to remote proving below that.[29]
- Boundless prover guidance: 16 threads, 32 GB RAM, at least one ≥8 GB-VRAM GPU, 10 GPUs to be competitive.[29]

**Consequence:** no zkVM (SP1, RISC Zero, Jolt, Miden, OpenVM, Zisk) can produce proofs on the droplet. Only fixed-circuit provers — Groth16 and halo2 — fit inside 3 GB for small circuits, and even those want care. Any architecture that assumes local proving must either (a) constrain itself to small fixed circuits, or (b) add a proving service / remote prover, which is a protocol design decision, not an implementation detail.

---

## Sources

[1] https://github.com/arkworks-rs/algebra — arkworks-rs/algebra
[2] https://github.com/arkworks-rs/groth16 — arkworks-rs/groth16
[3] https://github.com/arkworks-rs/snark — arkworks-rs/snark
[4] https://github.com/arkworks-rs/marlin — arkworks-rs/marlin
[5] https://github.com/arkworks-rs/circom-compat — arkworks-rs/circom-compat
[6] https://github.com/arkworks-rs/poly-commit — arkworks-rs/poly-commit
[7] https://github.com/zcash/halo2 — zcash/halo2
[8] https://github.com/privacy-ethereum/halo2 — privacy-ethereum/halo2 (ex-PSE), archived
[9] https://github.com/axiom-crypto/halo2 — axiom-crypto/halo2
[10] https://github.com/axiom-crypto/halo2-lib — axiom-crypto/halo2-lib
[11] https://github.com/axiom-crypto/snark-verifier — axiom-crypto/snark-verifier
[12] https://github.com/Plonky3/Plonky3 — Plonky3/Plonky3
[13] https://github.com/0xPolygonZero/plonky2 — 0xPolygonZero/plonky2, archived
[14] https://github.com/succinctlabs/sp1 — succinctlabs/sp1
[15] https://github.com/succinctlabs/sp1-contracts — succinctlabs/sp1-contracts
[16] https://github.com/risc0/risc0 — risc0/risc0
[17] https://github.com/risc0/risc0-ethereum — risc0/risc0-ethereum
[18] https://github.com/binius-zk/binius64 — binius-zk/binius64
[19] https://github.com/IrreducibleOSS/binius — IrreducibleOSS/binius, archived
[20] https://github.com/microsoft/Nova — microsoft/Nova
[21] https://github.com/facebook/winterfell — facebook/winterfell
[22] https://github.com/a16z/jolt — a16z/jolt
[23] https://github.com/0xMiden/miden-vm — 0xMiden/miden-vm
[24] https://github.com/openvm-org/openvm — openvm-org/openvm
[25] https://github.com/noir-lang/noir — noir-lang/noir
[26] https://github.com/zkcrypto/bellman — zkcrypto/bellman
[27] https://github.com/0xPolygonHermez/zisk — 0xPolygonHermez/zisk
[28] https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements — SP1 hardware requirements
[29] https://dev.risczero.com/api/zkvm/quickstart — RISC Zero quickstart (16 GB RAM note)
[30] https://zcash.github.io/halo2/design/proving-system.html — halo2 Book - proving system
[31] https://zcash.github.io/halo2/background/recursion.html — halo2 Book - recursion
[32] https://github.com/privacy-scaling-explorations/zkevm-circuits — PSE zkevm-circuits archived notice
[33] https://github.com/Tetration-Lab/arkworks-solidity-verifier — arkworks-solidity-verifier (community)
[34] https://crates.io/crates/ark-groth16 — crates.io ark-groth16
[35] https://crates.io/crates/halo2_proofs — crates.io halo2_proofs
[36] https://crates.io/crates/p3-fri — crates.io p3-fri (Plonky3)
[37] https://crates.io/crates/sp1-verifier — crates.io sp1-verifier
[38] https://crates.io/crates/risc0-zkvm — crates.io risc0-zkvm
[39] https://crates.io/crates/midnight-proofs — crates.io midnight-proofs
[40] https://crates.io/crates/nova-snark — crates.io nova-snark
[41] https://crates.io/crates/miden-vm — crates.io miden-vm
[42] https://crates.io/crates/winterfell — crates.io winterfell
[43] https://crates.io/crates/halo2-base — crates.io halo2-base
[44] https://www.binius.xyz — binius.xyz docs
[45] https://jolt.a16zcrypto.com — The Jolt Book
