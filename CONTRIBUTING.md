# Contributing

This is a zero-knowledge attestation protocol. The thing being built is a
**claim**, and the code is what makes the claim checkable. So the rules here are
less about style and more about not quietly weakening the claim.

If you are an AI agent working in this repository, follow this document exactly
as written. It is the same loop a human follows; there is no shorter path.

## Before you write code

Read, in this order:

1. `docs/ARCHITECTURE.md` — what the protocol claims, and the gaps it admits;
2. `docs/EMBEDDING.md` — the layer boundaries;
3. `docs/TESTING.md` — the tiers and the tests that may never be skipped;
4. `SECURITY.md` — how a soundness bug is reported, and what never enters git.

## The loop: one unit, claim to green

1. **One issue, one change.** If an issue holds several units, say so and take one.
2. **Claim it**: comment `Claiming: <what> — <numbered plan>`. A claim with no
   progress comment expires after 24 hours. If you stop, comment
   `Releasing: <what>` so nobody waits on you.
3. **Branch from `master`**: `feat/<topic>`, `fix/<issue>-<topic>`,
   `test/<topic>`, `docs/<topic>`, `chore/<topic>`.
4. **RED first** — a commit that fails and says how. For a bug, a test that
   reproduces it. For a feature, a test of the property being added. For a
   soundness fix, a proof or verification that is wrongly **accepted** today.
5. **GREEN second** — the smallest change that makes RED pass.
6. **Run the gate locally** — the same commands CI runs:
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
   python3 tools/arch/test_check.py && python3 tools/arch/check.py
   python3 tools/test_loop.py
   python3 tools/leaderboard/test_generate.py
   ```
   A shortcut worth having: `cargo test` with a feature flag that is not
   enabled runs zero tests and still prints `ok`. Read the counts, not the
   green words.
7. **Open the PR** using the template, quoting the RED output and the GREEN result.
   `Fixes #N` only when it completes the issue; otherwise `Refs #N`.
8. **Stop at the PR.** Do not merge your own work, do not push to `master`, do not
   rewrite someone else's branch.

## Non-negotiables

- **Never weaken a test to make a change pass.** If a test is wrong, say why in
  the PR and fix the test in its own commit, with its own justification.
- **Never make a proof verify by loosening a constraint.** The circuit *is* the
  claim. A constraint removed to make an awkward case pass is a soundness bug
  with a green build.
- **Never remove a negative test.** The tests that assert a *rejection* are what
  catch an unsound circuit.
- **One protocol rule, one layer.** The replay gate, policy validation and the
  fail-closed state rule live in `zkagent-service`. Re-implementing one in a
  shell is a bug even when both copies agree today.
- **Never commit key material.** `authority.hex`, `keys/*.bin`, a real
  `seen.json` — none of them belong in git.
- **State the evidence.** "Tests pass" is not evidence; the command and its output
  are. "Should work" is not evidence.

## What "done" means for a security-relevant change

A change to the circuit, the verifier, the policy encoding or the authority
layer is not done until:

- every existing negative test still passes, **and** a new one covers your case;
- `cargo test` is green from a clean checkout;
- the PR body names the soundness property that changed and the test that proves it.

## Versioning and releases

Three numbers, three jobs: the **crate version** says which code you are running, **`FORMAT_VERSION`**
says which artifacts that binary can read, and the **git tag** says which day and which tree.

- **Bump in one place.** `[workspace.package] version` in the root `Cargo.toml`; the crates inherit it
  (`version.workspace = true`) and their `zkagent-*` path dependencies pin the same string.
  `tools/arch/check.py` fails on either half, so a bump cannot half-land.
- **A format change is a minor bump.** Circuit, public inputs or artifact encoding changed →
  `FORMAT_VERSION` and the crate version move together, and the verifier refuses old artifacts loudly
  instead of guessing.
- **Cut the release in the PR that changes the behaviour**: bump the version, write the
  `docs/RELEASES.md` entry with measured numbers, merge, then tag the merged commit.
  ```bash
  git tag -a "v0.2.0+2026-11-02" -m "one line: what is true now"
  git push origin "v0.2.0+2026-11-02"
  ```
- **Numbers come from a measurement on a named machine**, never from the previous release note.
  `docs/MEASUREMENTS.md` is where the method lives.
- **After installing a binary anywhere**, `zkagent version` must print the commit the tag names.
  If it prints a different one, you are verifying with a build of some other branch.

## Git shape

- `master` is the only long-lived branch; work happens on `feat/`, `fix/`, `docs/`, `chore/`, `test/`.
- **Squash only.** Merge commits and rebase merges are disabled at the repository level, so history is
  one commit per unit and the branch name never outlives the work.
- **Branches delete on merge.** A branch still sitting there is leftover, not history.
- The one exception is `leaderboard`, an orphan data branch the weekly workflow pushes to. It is not
  source and must never be merged.
- Commit subjects name the unit, not the person: `proofs: bind trace_digest to a public MiMC Merkle root`.

## Review

Two things are checked before anything merges, in this order:

1. **Does it weaken a claim?** A reviewer may reject a change that passes CI.
2. **Does it pass CI?** Formatting, clippy, tests, the end-to-end CLI and the MCP
   harness round trip.

## Credit

Contributions are credited by merged pull request on the automated leaderboard.
If a maintainer re-lands your work, a `Co-Authored-By:` trailer in at least half
the commits (or anywhere in the PR body) keeps the credit with you. That rule is
tested: `tools/leaderboard/test_generate.py`.

## Reporting a vulnerability

Do not open a public issue. See `SECURITY.md`.
