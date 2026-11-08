# Changelog

## 0.4.1+2026-11-08

### Changed

- **no functional change.** The prover, the circuit and the artefact format are identical to 0.4.0.

### Fixed

- **the 0.4.0 tag pointed at a commit that master does not contain**, because master received a
  squash merge and the tag was created on the branch. `git describe --tags` therefore reported
  `v0.3.1` on a tree that already carried 0.4.0's code. 0.4.1 is tagged on the merge commit, and
  `tools/check_version.py` now fails when the newest tag is not an ancestor of HEAD.

### Added

- `CHANGELOG.md`, `VERSIONING.md`, and the version consistency gate in CI.
- a project mark: SVG, PNG 16 through 512, and an `.ico`.
- `.mailmap` and `AUTHORS`; one author is one identity again (45 commits, one row).
- `CONSTITUTION.md` and `AGENTS.md`; branch protection with four required checks and admins enforced.

All notable changes to this project. Format: `semver + date`, newest first. See
[VERSIONING.md](VERSIONING.md) for what each bump means. Entries before 0.4.0 were reconstructed
from git history.

## 0.4.0+2026-11-08

### Fixed

- **the prover sampled blinding from a fixed seed.** `StdRng::seed_from_u64(0xA6E7)` was used per
  proof, so the zero-knowledge argument did not hold: identical `r` and `s` across proofs. Now
  `OsRng`, sampled fresh for every proof.
- the release workflow never published: `macos-14` is retired in this runner group and `publish`
  depends on every build, so a green Linux and Windows pair never became a release.
- internal crate pins did not follow the workspace to 0.4.0, so the tag build failed on a caret
  requirement that cannot accept a new minor before 1.0.

### Added

- `SECURITY.md`, `CONTRIBUTING.md` completed with the threat model.

## 0.3.1+2026-11-05

### Changed

- the binary's version string matches the tag, so `zkagent --version` and the release agree.
- proving key cache across MCP calls (about 1.9x faster prove).

### Added

- selective disclosure: reveal one action with its Merkle path.
- session index: several receipts, one Merkle root, one total.

## 0.2.0+2026-11-02

### Added

- MCP server, wire types, IPFS bundle publishing.
- replay ledger keyed by execution id, failing closed on unreadable state.

## 0.1.0+2026-11-02

### Added

- first proof of the stack end to end: policy, receipt, Groth16 proof, verification.
