# 04 — Rust / ZK library reuse audit (build-vs-buy)

**Audited:** 2026-10-28T04:09Z by `MCPVOT` via authenticated `gh api` (scopes incl. `repo`), plus live `cargo` / `crates.io` probes on Rust 1.97.1.
**Method:** every number below comes from `GET /repos/{owner}/{repo}`, `/languages`, `/releases`, `/commits?per_page=1` and `/git/trees/{branch}?recursive=1` (`truncated:false` on all 23 trees). File counts are **blob counts from the git tree**, not README claims. Dependency weights are real `cargo tree -e normal` package counts; build times are real clean `cargo build --release` runs on this laptop. Nothing is from memory; anything I could not verify is marked `[unverified]`.

**Headline:** the reusable substrate is *not* the zkVM monorepos. For a first private build, the shortest legal, offline-verifiable path is **`sp1-verifier` 6.10.0** (verify-only, 364 KB binary, 174 deps) plus **`ark-groth16` / `ark-bn254` 0.6.0** if we need our own circuit — and we must write the attestation envelope ourselves, because every "zk-attestation for agents" repo in the search results is unlicensed, non-commercial, or a 0–8★ stub.

## Repos that do not exist / were renamed (asked for, verified 404)

| Asked for | Result of `GET /repos/...` |
|---|---|
| `risc-0/risc0` | **404** — the real repo is [`risc0/risc0`](https://github.com/risc0/risc0) (org is `risc0`) |
| `ethereum/zk-evm` | **404**. Also 404: `ethereum/zkEVM`, `ethereum/zkEVM-spec`, `ethereum/evm-zkvm-spec`, `ethereum/zkvm-specs`. There is **no public EF zkEVM Rust repo** under those names; `search/repositories?q=zk+org:ethereum` returns only `ethereum/zkevm-website`, `ethereum/zkapi`, `ethereum/spartan-whir`, `ethereum/zkID` |
| `AztecProtocol/aztec-protocol` | **404** — renamed to [`AztecProtocol/aztec-packages`](https://github.com/AztecProtocol/aztec-packages) |
| `AztecProtocol/noir` | **404** — moved to [`noir-lang/noir`](https://github.com/noir-lang/noir) |
| `scroll-tech/zkevm-node` | **404** (deleted / retired). Surviving org repo is [`scroll-tech/scroll`](https://github.com/scroll-tech/scroll) (Go) |
| `arkworks-rs/arkworks` | **404** — no meta-repo; arkworks publishes per-crate repos (`arkworks-rs/algebra`, `/groth16`, `/snark`, …) |
| `arkworks-rs/crypto-bigint` | **404** — `crypto-bigint` lives at [`RustCrypto/crypto-bigint`](https://github.com/RustCrypto/crypto-bigint) |
| `0xPolygonZero/plonky3` | Redirects to [`Plonky3/Plonky3`](https://github.com/Plonky3/Plonky3) (org renamed) |
| `privacy-scaling-explorations/halo2` | Redirects to [`privacy-ethereum/halo2`](https://github.com/privacy-ethereum/halo2) — **archived** |
| `consensys/gnark` | Redirects to [`Consensys-Incorporated/gnark`](https://github.com/Consensys-Incorporated/gnark) — **Go** |
| `AztecProtocol/barretenberg` | Exists but is a **shell repo**: tree is `.github` + `README.md` only (191★). The code moved into `aztec-packages` |
| `aleph-zero-foundation/zk-attestation` | **404** |

---

## (a) Per-repo audit

| Repo | Lang (GitHub) | License (SPDX) | ★ | Forks | Open issues | Last push | Last release | Files (.rs) | Build system | Ships Solidity verifier? | Monorepo / dependency weight |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [`succinctlabs/sp1`](https://github.com/succinctlabs/sp1) | Rust | Apache-2.0 | 1,755 | 712 | 154 | 2026-10-26 | v6.10.0 (2026-10-23) | 2,179 (1,389) | cargo workspace | no - 0 .sol in repo; contracts live in `succinctlabs/sp1-contracts` (90 .sol, **no LICENSE file**) | yes - 262 Cargo.toml / 1,389 .rs |
| [`risc0/risc0`](https://github.com/risc0/risc0) | C++ | Apache-2.0 | 2,207 | 743 | 195 | 2026-10-28 | v3.0.6 (2026-07-17) | 2,137 (563) | cargo workspace + CMake / CUDA | yes - 1 .sol (`groth16_proof/groth16/verifier.sol`); full set in `risc0/risc0-ethereum` (32 .sol, Apache-2.0) | yes - 145 Cargo.toml, C++/CUDA heavy (38.9 MB C++ vs 25.5 MB Rust) |
| [`Plonky3/Plonky3`](https://github.com/Plonky3/Plonky3) | Rust | Apache-2.0 | 860 | 478 | 29 | 2026-10-27 | p3-word-backend-v0.9.0-rc.2 (2026-10-16) | 1,389 (1,223) | cargo workspace | no - 0 .sol; on-chain verifiers are third-party (`ethereum/sol-whir-p3`, 10 stars) | yes - 56 workspace crates |
| [`zcash/halo2`](https://github.com/zcash/halo2) | Rust | NOASSERTION | 929 | 615 | 271 | 2026-10-27 | - | 235 (111) | cargo workspace | no - 0 .sol; PSE `halo2-solidity-verifier` is a separate **archived** repo | moderate - 5 crates (halo2, halo2_proofs, halo2_gadgets, halo2_poseidon) |
| [`privacy-ethereum/halo2`](https://github.com/privacy-ethereum/halo2) | Rust | NOASSERTION | 250 | 140 | 8 | 2026-07-01 | v0.4.0 (2024-09-13) | 208 (117) | cargo workspace | no | moderate - 8 Cargo.toml (archived fork) |
| [`a16z/jolt`](https://github.com/a16z/jolt) | Rust | Apache-2.0 | 1,058 | 347 | 56 | 2026-10-28 | - | 2,408 (1,775) | cargo workspace | no - 0 .sol; `book/src/roadmap/on-chain-verifier.md` says on-chain verifier is future work | yes - 123 Cargo.toml / 1,775 .rs |
| [`microsoft/Nova`](https://github.com/microsoft/Nova) | Rust | MIT | 867 | 254 | 27 | 2026-09-18 | - | 113 (101) | cargo crate | no - 0 .sol | no - single crate, 101 .rs |
| [`starkware-libs/stwo`](https://github.com/starkware-libs/stwo) | Rust | Apache-2.0 | 504 | 182 | 48 | 2026-10-28 | v1.0.0 (2025-07-18) | 255 (196) | cargo workspace | no - 0 .sol; enforces a `no_std` Rust verifier via `ensure-verifier-no_std` | no - 8 crates / 196 .rs |
| [`noir-lang/noir`](https://github.com/noir-lang/noir) | Rust | Apache-2.0 | 1,420 | 414 | 819 | 2026-10-28 | v1.0.0-rc.5 (2026-10-15) | 7,502 (883) | cargo workspace | indirect - 0 .sol; `compiler/integration-tests/scripts/generate-solidity-verifiers.sh` delegates to Barretenberg | yes - 7,502 files / 41 Cargo.toml |
| [`AztecProtocol/aztec-packages`](https://github.com/AztecProtocol/aztec-packages) | C++ | Apache-2.0 | 457 | 627 | 1,139 | 2026-10-27 | v6.0.0 (2026-10-22) | 4,965 (57) | CMake / C++ + cargo workspace | yes - 460 .sol in-tree (incl. `barretenberg/acir_tests/sol-test/Verifier.sol`) | yes - 22.6 MB C++ dominant, only 57 .rs / 9 Cargo.toml |
| [`Consensys-Incorporated/gnark`](https://github.com/Consensys-Incorporated/gnark) | Go | Apache-2.0 | 1,744 | 555 | 85 | 2026-10-24 | v0.16.4 (2026-10-07) | 1,281 (0) | Go modules | yes - a Solidity **exporter** (`backend/solidity/`, 16 .sol fixtures) - best in class here | no - Go module, 0 Cargo.toml |
| [`scroll-tech/scroll`](https://github.com/scroll-tech/scroll) | Go | MIT | 742 | 634 | 20 | 2026-10-27 | - | 514 (22) | Go modules + cargo workspace | partial - 1 mock `.sol`; real verifier is a prebuilt `plonk_verifier_0.11.4.bin` blob | yes - Go node + Rust crates mixed |
| [`zcash/zcash`](https://github.com/zcash/zcash) | C++ | NOASSERTION | 5,498 | 2,226 | 1,132 | 2026-07-19 | v6.20.0 (2026-06-03) | 1,719 (40) | autotools / C++ (1 stray Cargo.toml) | no | no - **archived** C++ node |
| [`arkworks-rs/algebra`](https://github.com/arkworks-rs/algebra) | Rust | Apache-2.0 | 893 | 424 | 232 | 2026-10-26 | v0.3.0 (2021-06-06) | 755 (530) | cargo workspace | no | yes - 42 Cargo.toml / 530 .rs |
| [`arkworks-rs/groth16`](https://github.com/arkworks-rs/groth16) | Rust | Apache-2.0 | 354 | 160 | 18 | 2026-09-16 | v0.3.0 (2021-06-06) | 30 (10) | cargo crate | no - 0 .sol (10 .rs); pairs with stale `circom-compat` for R1CS input | no - tiny crate |
| [`arkworks-rs/snark`](https://github.com/arkworks-rs/snark) | Rust | Apache-2.0 | 917 | 252 | 42 | 2026-04-26 | v0.3.0 (2021-06-06) | 47 (26) | cargo workspace | no | no - 3 crates |
| [`arkworks-rs/circom-compat`](https://github.com/arkworks-rs/circom-compat) | Rust | Apache-2.0 | 284 | 135 | 24 | 2026-04-26 | - | 59 (16) | cargo crate | test-only - `tests/verifier.sol`; 0 generator code | no |
| [`RustCrypto/crypto-bigint`](https://github.com/RustCrypto/crypto-bigint) | Rust | Apache-2.0 | 314 | 98 | 42 | 2026-10-26 | - | 243 (218) | cargo workspace | no | moderate - 5 Cargo.toml / 218 .rs |
| [`RustCrypto/formats`](https://github.com/RustCrypto/formats) | Rust | none | 343 | 196 | 72 | 2026-10-25 | - | 902 (390) | cargo workspace | no | yes - 31 Cargo.toml / 390 .rs |
| [`automata-network/tdx-attestation-sdk`](https://github.com/automata-network/tdx-attestation-sdk) | Rust | Apache-2.0 | 35 | 26 | 0 | 2026-08-14 | v0.1.1 (2025-07-11) | 19 (8) | cargo workspace | no | no - 2 Cargo.toml / 8 .rs |
| [`automata-network/amd-sev-snp-attestation-sdk`](https://github.com/automata-network/amd-sev-snp-attestation-sdk) | Rust | Apache-2.0 | 20 | 19 | 2 | 2026-10-13 | - | 139 (51) | cargo workspace | yes - 17 .sol incl. `contracts/src/SEVAgentAttestation.sol` | yes - 13 Cargo.toml, Rust+Solidity+Go |
| [`ethereum/zkapi`](https://github.com/ethereum/zkapi) | Rust | none | 69 | 30 | 16 | 2026-10-24 | - | 862 (117) | cargo workspace | no - 98 .sol are app/test contracts, not a proof verifier | yes - 13 Cargo.toml + Foundry |
| [`zero-savvy/zk-remote-attestation`](https://github.com/zero-savvy/zk-remote-attestation) | Circom | NOASSERTION | 24 | 1 | 0 | 2025-06-27 | v1.0.2 (2023-11-20) | 162 (0) | Circom / snarkjs | yes - 13 .sol (Circom/snarkjs output) | no - Circom circuits (60) |

Reading notes:

- **`risc0/risc0` is registered as C++**, not Rust: `/languages` returns C++ 38.9 MB, Rust 25.5 MB, Cuda 8.2 MB. "It's a Rust zkVM" is true of the guest API, not of the build.
- **`AztecProtocol/aztec-packages`** is the same story at larger scale: 22.6 MB C++ (Barretenberg) against 57 Rust files total.
- **`arkworks-rs/*` GitHub release pages are stale** (latest tag v0.3.0, 2021-06-06) while the *crates* are current: `ark-groth16` 0.6.0 and `ark-bn254` 0.6.0 both published 2026-04-26. Judge arkworks by crates.io, not by tags.
- **`starkware-libs/stwo` version drift:** repo `crates/stwo/Cargo.toml` says `version = "0.5.1"`; crates.io `stwo` is 2.3.0 (2026-06-25). Pin by version, never by branch.
- `RustCrypto/formats`, `ethereum/zkapi`, `succinctlabs/sp1-contracts` have **no LICENSE file at root** (verified by tree scan and `/license` → 404).
- `succinctlabs/sp1-contracts` (147★, Solidity, 90 `.sol`, 177 files) is where the on-chain SP1 verifier actually lives — and it is **unlicensed**.

## (b) Verdict table

| Repo | Verdict | Evidence (one sentence) |
|---|---|---|
| [`succinctlabs/sp1`](https://github.com/succinctlabs/sp1) | **ADOPT (verifier crate)** | `sp1-verifier` 6.10.0 is MIT OR Apache-2.0, MSRV 1.91.1, 174 transitive crates, and a clean offline verify-only build in 344 s producing a 364 KB binary - the smallest credible prove-elsewhere/verify-on-agent path. |
| [`risc0/risc0`](https://github.com/risc0/risc0) | **WATCH** | 2,207 stars and a real 3.0.6 (2026-07-17) release, but primary language is C++ (38.9 MB) with CUDA, `risc0-zkvm` carries 44 normal + 23 optional deps, and 5.0.0-rc.1 is already published - a major-version churn window we do not want in a first build. |
| [`Plonky3/Plonky3`](https://github.com/Plonky3/Plonky3) | **BORROW-IDEAS** | Excellent, active toolkit (1,223 .rs across 56 crates, last push 2026-10-27) but the only published line is 0.9.0-rc.2 (max stable 0.8.0) and it ships no verifier we can put on-chain or into a 300 KB binary. |
| [`zcash/halo2`](https://github.com/zcash/halo2) | **WATCH** | Active upstream (last commit 2026-10-27, `halo2_proofs` 0.4.1 published same day, dual MIT/Apache) but 271 open issues and no in-tree Solidity verifier; the PSE verifier generator has been archived since 2024-10-01. |
| [`privacy-ethereum/halo2`](https://github.com/privacy-ethereum/halo2) | **AVOID** | `archived: true`, last push 2025-07-01, last release v0.4.0 (2024-09-13) - superseded by upstream `zcash/halo2`. |
| [`a16z/jolt`](https://github.com/a16z/jolt) | **WATCH** | 1,058 stars and 1,775 .rs of real source, but only pre-release tags (v0.3.0-alpha, 2025-10-01), the `jolt-core` crate on crates.io (0.1.3) points at an unrelated repo, and the on-chain verifier is still roadmap. |
| [`microsoft/Nova`](https://github.com/microsoft/Nova) | **BORROW-IDEAS** | Clean MIT single crate (101 .rs, 72 transitive deps) still shipping `nova-snark` 0.76.0 (2026-09-03) and last commit 2026-09-11 - good folding design to learn from, no verifier ecosystem and no GitHub releases. |
| [`starkware-libs/stwo`](https://github.com/starkware-libs/stwo) | **WATCH** | Real, compact STARK (`stwo` 2.3.0, 75 deps, 196 .rs, 8 crates) with a deliberately `no_std` verifier, but the repo manifest declares 0.5.1 while crates.io ships 2.3.0, and there is no Solidity path. |
| [`noir-lang/noir`](https://github.com/noir-lang/noir) | **WATCH** | Vibrant (1,420 stars, 883 .rs, v1.0.0-rc.5 on 2026-10-15) but 819 open issues, and the verifier you actually deploy comes from Barretenberg (C++/WASM) - a second toolchain and a second licence surface. |
| [`AztecProtocol/aztec-packages`](https://github.com/AztecProtocol/aztec-packages) | **AVOID (for reuse)** | 4,965 files but only 57 .rs / 9 Cargo.toml against 22.6 MB of C++ and 1,139 open issues - there is no Rust library here to depend on, only a monorepo to compile. |
| [`Consensys-Incorporated/gnark`](https://github.com/Consensys-Incorporated/gnark) | **AVOID (language) / BORROW-IDEAS (design)** | Best Solidity export in the field (`backend/solidity/`) but it is Go (4.17 MB, 0 Cargo.toml) - unusable as a Rust dependency; copy the export pattern, not the code. |
| [`scroll-tech/scroll`](https://github.com/scroll-tech/scroll) | **AVOID** | Go node (1.4 MB Go vs 116 KB Rust), only 22 .rs, and `scroll-tech/zkevm-node` (the repo we were asked about) now returns HTTP 404. |
| [`zcash/zcash`](https://github.com/zcash/zcash) | **AVOID** | `archived: true` (zcashd end-of-life), C++ node, 40 .rs, 1,132 open issues - nothing to reuse in Rust and the codebase is frozen. |
| [`arkworks-rs/algebra`](https://github.com/arkworks-rs/algebra) | **ADOPT (primitives)** | `ark-ff`/`ark-bn254` at 0.6.0 (2026-04-26) with 111.8 M and 32.6 M lifetime downloads, 530 .rs, MSRV 1.89 - the field/curve layer under any Groth16 attestation circuit we write. |
| [`arkworks-rs/groth16`](https://github.com/arkworks-rs/groth16) | **ADOPT (proving)** | 10 .rs but shipped as `ark-groth16` 0.6.0 (2026-04-26, 7.2 M downloads), 74 transitive deps with `ark-bn254`, 124 s release build - the smallest real SNARK proving stack in the set. |
| [`arkworks-rs/snark`](https://github.com/arkworks-rs/snark) | **ADOPT (trait glue)** | 98.7% Rust, 0.6.0 line, tiny surface; only useful as the trait layer under groth16. |
| [`arkworks-rs/circom-compat`](https://github.com/arkworks-rs/circom-compat) | **WATCH** | Useful R1CS interop but last commit 2025-08-26 and 16 .rs - stale relative to the 0.6.0 core it must track. |
| [`RustCrypto/crypto-bigint`](https://github.com/RustCrypto/crypto-bigint) | **ADOPT (bignum)** | Dual MIT/Apache, 218 .rs, only 7 transitive crates, 322 M downloads, pushed 2026-10-26 - the cheapest correct big-integer dependency we can vendor. |
| [`RustCrypto/formats`](https://github.com/RustCrypto/formats) | **WATCH** | 1,037 files but **no root LICENSE file** (individual crates carry MIT/Apache); we would take only `crypto-bigint`, not this monorepo. |
| [`automata-network/tdx-attestation-sdk`](https://github.com/automata-network/tdx-attestation-sdk) | **BORROW-IDEAS** | 8 .rs over 19 files (Apache-2.0, v0.1.1 2025-07-11) - a thin quote-parsing wrapper worth reading for hybrid TEE-to-ZK binding, too small to depend on for a protocol. |
| [`automata-network/amd-sev-snp-attestation-sdk`](https://github.com/automata-network/amd-sev-snp-attestation-sdk) | **WATCH** | 51 .rs + 17 .sol (incl. `SEVAgentAttestation.sol`), Apache-2.0, but 20 stars and last commit 2026-04-21 - proof that on-chain hardware attestation is a known pattern, not a stable base. |
| [`ethereum/zkapi`](https://github.com/ethereum/zkapi) | **AVOID (licence)** | Real Rust (117 .rs) and a genuinely relevant design (unlinkable paid API calls), but **no LICENSE file at all** - all rights reserved, so we may read the idea and must not copy code. |
| [`zero-savvy/zk-remote-attestation`](https://github.com/zero-savvy/zk-remote-attestation) | **BORROW-IDEAS (design only)** | Closest prior art to our thesis (60 Circom circuits, 24 stars) but licensed **CC BY-NC 4.0** (non-commercial) and dead since 2025-06-27 - a licence trap for a commercial open-source product. |

Tally (23 audited repos): **ADOPT 5** (`sp1-verifier`, `ark-groth16`, `ark-bn254`/`algebra`, `ark-snark`, `crypto-bigint`) · **BORROW-IDEAS 4** (`Plonky3`, `Nova`, `tdx-attestation-sdk`, `zk-remote-attestation`) · **WATCH 8** · **AVOID 6** (gnark is counted here — wrong language, design worth copying).

---

## (c) What we would actually depend on for a first private build

### Recommended dependency set

| Crate | Version (crates.io, verified) | Licence (`versions[0].license`) | MSRV | Transitive pkgs (`cargo tree -e normal`) | Clean `--release` build |
|---|---|---|---|---|---|
| `sp1-verifier` | **6.10.0** (2026-10-23) | `MIT OR Apache-2.0` | **1.91.1** | **174** | **344 s**, 364,032-byte binary |
| `ark-groth16` (+ `ark-bn254`, `ark-ff`, `ark-serialize`) | **0.6.0** (2026-04-26) | `MIT/Apache-2.0` | 1.89 (repo `rust-version`) | **74** | **124 s** |
| `crypto-bigint` | **0.7.10** (2026-10-26) | MIT/Apache-2.0 | — | **7** | n/a |
| `ed25519-dalek` + `sha2` + `serde`/`serde_json` + `num-bigint` + `curve25519-dalek` (signed attestation envelope, no ZK) | 3.0.0 / 0.11.1 / 1.x / 0.5.1 / 4.x | MIT/Apache-2.0 | — | **30** | **51 s**, 26 MB vendor |
| *comparison only* `halo2_proofs` | 0.4.1 | `MIT OR Apache-2.0` | 1.88 | 40 | 125 s |
| *comparison only* `stwo` | 2.3.0 | Apache-2.0 | [unverified] | 75 | 123 s |
| *comparison only* `nova-snark` | 0.76.0 | MIT | 1.88 (repo) | 72 | — |
| *rejected for direct use* `p3-baby-bear` | 0.9.0-rc.2 (max stable 0.8.0) | `MIT OR Apache-2.0` | [unverified] | 36 | — |

### Shape of the build

1. **Envelope + policy layer (ours):** `ed25519-dalek` 3.0.0, `sha2`, `serde`/`serde_json`, `num-bigint`, `curve25519-dalek` → 30 packages, 51 s, 26 MB vendored. Always available: signed, hash-chained attestations that work with zero proving infrastructure.
2. **Proof layer (bought):** `sp1-verifier` 6.10.0 with `default-features = false` is the verification half only; proving happens off-device (Succinct network, or `sp1-sdk` 6.10.0 locally). Verified today: `cargo fetch`, then a clean `rm -rf target` + `cargo build --release --offline` succeeds on Rust 1.97.1.
3. **Our own circuit (when the claim is not "some program ran"):** `ark-groth16` 0.6.0 + `ark-bn254` 0.6.0 — 74 packages, 124 s, and the only ADOPT stack small enough to embed in a CLI.

### MSRV

Floor is **1.91.1**, set by `sp1-verifier` (declared as `rust-version.workspace = true` in its `Cargo.toml`, exposed as `rust_version: "1.91.1"` in the crates.io version record). Next highest: arkworks 1.89, `halo2_proofs` 1.88, Nova 1.88.0. The laptop is on 1.97.1, so nothing blocks us; declare `rust-version = "1.91"` in our workspace to keep the door open to SP1.

### Dependency weight and offline feasibility (measured, not estimated)

- `sp1-verifier` pulls **174 unique packages**; `cargo vendor` of that graph is **218 MB across 205 directories**. Entirely vendorable, and `--offline` builds succeed, so air-gapped CI is feasible — but budget the vendor dir deliberately (fetch step or LFS, not committed to git).
- It also pulls **forked crates**: the build log shows `p3-baby-bear v0.4.3-succinct` and a dependency renamed from `substrate-bn-succinct-rs`. Those are Succinct's own patches of upstream Plonky3 — which is why `sp1-verifier` is *not* simply "P3 with extra steps", and why we must pin by lockfile and review `-succinct` forks before trusting the verifier inside a security protocol.
- **Practical consequence — two tiers.** Tier A (envelope: 30 pkgs / 26 MB vendor) must build anywhere. Tier B (`sp1-verifier`: 174 pkgs / 218 MB) sits behind a `zk-sp1` feature so a constrained agent install never needs 218 MB of vendored crypto to start.

---

## (d) Licence compatibility for shipping an open-source Rust project

Assume we ship **Apache-2.0 OR MIT (dual)** — the Rust norm, and the posture that lets downstream users pick.

| Licence found | Repos (verified by reading the licence file / `versions[0].license`) | Compatible with Apache-2.0/MIT shipping? | Obligations |
|---|---|---|---|
| **MIT OR Apache-2.0 (dual)** | [`succinctlabs/sp1`](https://github.com/succinctlabs/sp1) (`LICENSE-APACHE` + `LICENSE-MIT`; crates say `MIT OR Apache-2.0`), [`arkworks-rs/*`](https://github.com/arkworks-rs/algebra), [`Plonky3/Plonky3`](https://github.com/Plonky3/Plonky3), [`zcash/halo2`](https://github.com/zcash/halo2) (`COPYING.md` = "Licensed under either of", hence `NOASSERTION`), [`noir-lang/noir`](https://github.com/noir-lang/noir), [`RustCrypto/crypto-bigint`](https://github.com/RustCrypto/crypto-bigint), [`a16z/jolt`](https://github.com/a16z/jolt) | **Yes** | Keep copyright notices; taking the Apache arm means shipping `NOTICE` and honouring §4 (state changes). §5's patent grant is inbound to us. |
| **Apache-2.0 only** | [`risc0/risc0`](https://github.com/risc0/risc0), [`starkware-libs/stwo`](https://github.com/starkware-libs/stwo), [`AztecProtocol/aztec-packages`](https://github.com/AztecProtocol/aztec-packages), [`Consensys-Incorporated/gnark`](https://github.com/Consensys-Incorporated/gnark), [`risc0/risc0-ethereum`](https://github.com/risc0/risc0-ethereum) | **Yes** | Preserve `LICENSE` + any `NOTICE`; inbound patent grant is a benefit for a security product. |
| **MIT only** | [`microsoft/Nova`](https://github.com/microsoft/Nova), [`scroll-tech/scroll`](https://github.com/scroll-tech/scroll), [`privacy-ethereum/halo2-solidity-verifier`](https://github.com/privacy-ethereum/halo2-solidity-verifier), [`zcash/zcash`](https://github.com/zcash/zcash) (`COPYING`, MIT text) | **Yes** | Attribution only. |
| **NO LICENSE FILE → all rights reserved** | [`succinctlabs/sp1-contracts`](https://github.com/succinctlabs/sp1-contracts) (`/license` → 404, no `LICENSE*` in tree), [`ethereum/zkapi`](https://github.com/ethereum/zkapi) (same), [`RustCrypto/formats`](https://github.com/RustCrypto/formats) (no root licence; per-crate only) | **No — do not copy code** | Re-implement from docs or obtain written permission. **This bites us directly:** the on-chain SP1 verifier we would deploy lives in the unlicensed `sp1-contracts`. If we need an on-chain verifier today, use `risc0/risc0-ethereum` (Apache-2.0, 32 `.sol`) or write our own; SP1 stays off-chain-verify only, which carries no such problem. |
| **CC BY-NC 4.0 (non-commercial)** | [`zero-savvy/zk-remote-attestation`](https://github.com/zero-savvy/zk-remote-attestation) (`LICENSE.md` = Attribution-NonCommercial 4.0 International) | **No — incompatible** | NonCommercial forbids the commercial use an OSS security protocol implies, and CC licences are not designed for code. Read the design, not the circuits. |
| **GPL / AGPL** | **none found** in this candidate set (each repo's `LICENSE*`/`COPYING` was read, or `/license` returned MIT/Apache/404) | n/a | — |
| **BUSL / SSPL / "Sustainable Use"** | **none found** in this candidate set | n/a | — |

Licensing traps worth recording:

- `privacy-ethereum/halo2` and `zcash/halo2` report `NOASSERTION` but are genuinely dual MIT/Apache — GitHub failing to parse `COPYING.md`, not a red flag.
- `zero-savvy` shows `NOASSERTION` **and** is the real problem case (CC BY-NC). `NOASSERTION` alone is not a verdict; open the file. We did, for every repo.
- Dual licensing lets us take Apache-2.0 inbound for the whole tree, keeping our patent position clean: take the Apache arm of every dual-licensed dep.

---

## (e) Rejected candidates and why

| Candidate | What it is (verified) | Why rejected |
|---|---|---|
| `succinctlabs/sp1-contracts` | 177 files, 90 `.sol`, 147★, pushed 2026-08-04, last release v6.1.1 (2026-04-28) | **No licence.** The one thing we want (SP1's on-chain verifier) cannot legally be copied. Off-chain `sp1-verifier` is unaffected. |
| `ethereum/zkapi` | Real Rust, 117 `.rs`, 98 `.sol`, 69★, pushed 2026-10-24; "pay for AI APIs with unlinkable requests" | **No licence** (all rights reserved), and it is an application, not a library. Design idea is relevant; code is off-limits. |
| `zero-savvy/zk-remote-attestation` | 60 Circom circuits, 13 `.sol`, 24★, dead since 2025-06-27, v1.0.2 (2023-11-20) | **CC BY-NC 4.0** (non-commercial), Circom not Rust, unmaintained. |
| `wienerlabs/aperture` | 474 files: 177 `.ts`, 47 `.rs`, 2 `.circom`, MIT, 5★, pushed 2026-05-21; commits a prebuilt `services/prover-service/artifacts/payment.wasm` | Prebuilt unsigned binary artifact inside a "ZK compliance for AI agent payments" repo with 5 stars. **Drainer-pattern red flag: do not run the checked-in wasm/artifacts.** Nothing load-bearing for us. |
| `usercrypto000/emtum` | 101 `.sol`, 7 `.ts`, **0 `.rs`**, no licence, 1★ | No licence, single star, no Rust despite the "Noir zk scoped authorization for AI agents" pitch. |
| `anandkrshnn/zk-agent-attestation` | 32 files, Python, one `.circom`, 0★ | Hobby demo; Apache-2.0 but nothing to depend on. |
| `alphaparkinc/genpark-...-skill` | 9 files: `README.md`, `client.py`, `mcp_server.py`, `skill.json`, no licence, 8★ | A prompt "skill" wrapper around EZKL; no licence, no library. |
| `privacy-ethereum/halo2` | `archived: true`, 250★, v0.4.0 (2024-09-13) | Archived; PSE consolidated onto `zcash/halo2`. |
| `zcash/zcash` | `archived: true`, 5,498★, C++ 7.7 MB, 40 `.rs` | zcashd is end-of-life; nothing Rust and nothing current. |
| `scroll-tech/scroll` / `scroll-tech/zkevm-node` | Go 1.4 MB, 22 `.rs`; `zkevm-node` = 404 | Go node; verifier is a prebuilt `.bin` blob (`crates/libzkp/src/plonk_verifier_0.11.4.bin`) — not source we can audit. |
| `Consensys-Incorporated/gnark` | Go, 1,744★, v0.16.4 (2026-10-07), real Solidity exporter | Wrong language for a Rust project. Copy the *idea* of `backend/solidity/` when we design our own verifier export. |
| `RustCrypto/formats` | 1,037 files, 31 crates, no root licence | Wrong tool (DER/PKCS parsing) and no root licence; we take `crypto-bigint` individually from its own crate. |

---

## (f) Sources

**API endpoints actually called** (account `MCPVOT`, via `gh api`, 2026-10-28):

- `GET /repos/{owner}/{repo}` — stars, forks, `open_issues_count`, `pushed_at`, `license.spdx_id`, `archived`, `size`
- `GET /repos/{owner}/{repo}/languages` — byte counts by language (basis of the C++-vs-Rust verdicts)
- `GET /repos/{owner}/{repo}/releases/latest` and `GET /repos/{owner}/{repo}/releases?per_page=1` — tag + `published_at`
- `GET /repos/{owner}/{repo}/commits?per_page=1` — last commit date + SHA
- `GET /repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1` — file / `.rs` / `.sol` / `Cargo.toml` counts and licence-file inventory; `truncated:false` on every tree
- `GET /repos/{owner}/{repo}/license` — SPDX + licence path
- `GET /repos/{owner}/{repo}/contents/{path}` — `Cargo.toml`, `LICENSE*`, `COPYING*` bodies (MSRV `rust-version`, licence text)
- `GET /search/repositories?q=...` — discovery for `zk-attestation`, `agent attestation zk`, `groth16 rust`, `halo2 prover`, `plonky3`, `zkevm org:scroll-tech`, `zk org:ethereum`
- crates.io `GET /api/v1/crates/{name}`, `GET /api/v1/crates/{name}/{version}/dependencies` (browser User-Agent required — bare curl gets 403)
- local: `cargo tree -e normal`, `cargo build --release`, `cargo fetch` + clean `cargo build --release --offline`, `cargo vendor` — cargo 1.97.1 / rustc 1.97.1

**Repo URLs cited**

ZK systems: https://github.com/succinctlabs/sp1 · https://github.com/succinctlabs/sp1-contracts · https://github.com/risc0/risc0 · https://github.com/risc0/risc0-ethereum · https://github.com/Plonky3/Plonky3 · https://github.com/zcash/halo2 · https://github.com/privacy-ethereum/halo2 · https://github.com/privacy-ethereum/halo2-solidity-verifier · https://github.com/a16z/jolt · https://github.com/microsoft/Nova · https://github.com/starkware-libs/stwo · https://github.com/noir-lang/noir · https://github.com/AztecProtocol/aztec-packages · https://github.com/AztecProtocol/barretenberg · https://github.com/Consensys-Incorporated/gnark · https://github.com/scroll-tech/scroll · https://github.com/zcash/zcash

Primitives: https://github.com/arkworks-rs/algebra · https://github.com/arkworks-rs/groth16 · https://github.com/arkworks-rs/snark · https://github.com/arkworks-rs/circom-compat · https://github.com/RustCrypto/crypto-bigint · https://github.com/RustCrypto/formats

Attestation-adjacent: https://github.com/automata-network/tdx-attestation-sdk · https://github.com/automata-network/amd-sev-snp-attestation-sdk · https://github.com/ethereum/zkapi · https://github.com/zero-savvy/zk-remote-attestation · https://github.com/wienerlabs/aperture · https://github.com/usercrypto000/emtum · https://github.com/anandkrshnn/zk-agent-attestation · https://github.com/alphaparkinc/genpark-verifiable-ai-agent-zk-proof-attestation-skill

**Licence URLs:** https://github.com/succinctlabs/sp1/blob/main/LICENSE-APACHE · https://github.com/succinctlabs/sp1/blob/main/LICENSE-MIT · https://github.com/zcash/halo2/blob/main/COPYING.md · https://github.com/starkware-libs/stwo/blob/main/LICENSE · https://github.com/microsoft/Nova/blob/main/LICENSE · https://github.com/zero-savvy/zk-remote-attestation/blob/main/LICENSE.md · https://github.com/ethereum/zkapi (no LICENSE file) · https://github.com/succinctlabs/sp1-contracts (no LICENSE file)

**Unverified / gaps**

- MSRV for `Plonky3`, `stwo`, `jolt`, `risc0`: no `rust-version` in the root manifests I fetched (they use `edition = "2024"`), so the true floor is `[unverified]`.
- No transitive supply-chain audit beyond noticing the `-succinct` forks; a `cargo deny` / `cargo vet` pass over the `sp1-verifier` lockfile is a separate task.
- One transient `rustc` failure (`p3-baby-bear`) occurred while `cargo vendor` was running concurrently; an isolated rerun and a clean rebuild both succeeded (344 s), so it is recorded as an environment artifact, not a repo defect.
