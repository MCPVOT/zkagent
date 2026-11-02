# Publish checklist

This is the checklist `tools/loop.py next` names when the ledger has no
`publish` row. It is the gate between "a private repo with good CI" and "a
public repo that other people can install, audit and report bugs to".

Run every item. An item you did not run is **not** done. When the list is
green, record the result in the ledger:

```bash
python tools/loop.py record --phase publish \
  --action "flip the repo public" --result pass \
  --metric "licence=MIT secrets=clean ci=green readme=current" \
  --note "publish checklist run in full; evidence in the PR"
```

Then flip visibility, then confirm:

```bash
gh repo view MCPVOT/zkagent --json visibility
```

## 1. Licence

- [ ] `LICENSE` exists at the repository root.
- [ ] Every published crate declares the same licence in its `Cargo.toml`
      (`license = "..."`), so `cargo publish` and `cargo install` agree with
      the root file.
- [ ] The `README.md` licence section names the same licence.
- [ ] The copyright holder line is a name or organisation, never a person.

```bash
head -3 LICENSE
grep -rn '^license' Cargo.toml crates/*/Cargo.toml
grep -n -A2 '^## Licence' README.md
```

## 2. Secrets scan

Nothing in `SECURITY.md` §"What never enters this repository" may be in the
tree, and nothing may have been in it at any point in the history. A secret
deleted in a later commit is still published in the earlier one.

- [ ] No authority secret, key file, replay state or env file is tracked.
- [ ] No tracked file looks like key material (`.hex`, `.bin`, `.pem`, `.key`,
      `id_rsa`, `seen.json`, `.env`).
- [ ] A history-wide scan finds no PEM block, API key, password or token.
- [ ] The working tree has no stray key material outside git either.

```bash
# tracked files, current tree
git ls-files | grep -iE '\.(hex|bin|pem|key)$|seen\.json|\.env$|id_rsa'

# every path ever tracked, every commit
git rev-list --all | while read c; do git ls-tree -r --name-only "$c"; done \
  | sort -u | grep -iE '\.(hex|bin|pem|key)$|seen\.json|\.env$|id_rsa'

# content scan across all history (expect only source-code false positives)
git grep -InE 'BEGIN (RSA|OPENSSH|PRIVATE) KEY|api[_-]?key[[:space:]]*=|secret[[:space:]]*=|password[[:space:]]*=|token[[:space:]]*=' \
  $(git rev-list --all)

# stray material in the worktree, untracked
ls -la authority.hex keys/ 2>&1
```

A hit that is code (`let secret = ...`) is not a finding. A hit that is a real
key is a stop-the-line finding: rotate it before anything else, because
publication makes it public.

## 3. CI green on the commit being published

- [ ] The `ci` workflow is green on the exact commit that will be published.
- [ ] It ran on both matrix legs (ubuntu, windows), not just one.
- [ ] The `leaderboard` workflow is green or deliberately not applicable.
- [ ] The local gate from `CONTRIBUTING.md` passes on a clean checkout.

```bash
gh run list --workflow ci --limit 10
gh run list --workflow leaderboard --limit 5

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --manifest-path examples/tauri-plugin/Cargo.toml
python tools/leaderboard/test_generate.py
```

On a 6-core laptop, cap the build: `CARGO_BUILD_JOBS=6 cargo check --all-targets`.

## 4. README and public description are current

A public reader has no other context. Anything marked as private development
is now a false statement.

- [ ] The status section no longer says the project is private development.
- [ ] The quick start commands actually run, in the order given, with no
      private-only paths or hand-holding that no longer applies.
- [ ] The deliberate exclusions (on-chain verifier, multi-party trusted setup,
      agent-framework integration) are still listed. They are stated
      exclusions, not oversights, and hiding them would overstate the claim.
- [ ] The repository description on GitHub does not say "private".
- [ ] The security reporting route in `SECURITY.md` is reachable by someone
      outside the team: GitHub private vulnerability reporting must be
      **enabled** for the repository.

```bash
grep -n 'Private development\|private later' README.md
gh repo view MCPVOT/zkagent --json description,visibility
gh api repos/MCPVOT/zkagent --jq '.security_and_analysis.private_vulnerability_reporting.status'
```

A `null` status means private vulnerability reporting is **not enabled**. The
"Security → Advisories → Report a vulnerability" link in `SECURITY.md` then
leads nowhere for an outside reporter, which is exactly the bug report you
wanted to receive.

## 5. Repository hygiene before it is permanent

- [ ] No compiled or generated artifact is tracked. A `.pyc` file in the tree
      carries the machine's Python minor version for no reason, and grows.
- [ ] `.gitignore` covers the class, not just the one file, so the artifact
      cannot come back.
- [ ] CI enforces it: the `no generated artifacts in the tree` step fails when
      `git ls-files` matches `__pycache__`, `*.pyc`, `target/` or `.DS_Store`. Ignore
      rules do not remove what is already tracked, so a guard beats a rule.
- [ ] The declared MSRV is tested by CI, or it is removed. `rust-version` is a
      promise to downstream consumers; CI that installs `stable` does not
      verify it.

```bash
git ls-files | grep -iE '__pycache__|\.pyc$'
grep -n 'rust-version' Cargo.toml crates/*/Cargo.toml
grep -n 'toolchain' .github/workflows/ci.yml
```

## 6. The ledger knows

- [ ] A `publish` row exists in `docs/loop-ledger.jsonl`.
- [ ] `python tools/loop.py next` no longer says "No 'publish' row".

```bash
python tools/loop.py next
```

## What this checklist does not cover

It says nothing about whether the protocol is **sound**. That is what
`references/soundness-checklist.md` and the test tiers in `docs/TESTING.md`
are for, and they are the stronger gate: a public repo with a false claim is
worse than a private one. Publication widens the blast radius of a bug; it
does not make the bug less likely.

It also does not cover the trust story. `zkagent setup` performs a **single
party** trusted setup and discards the toxic waste. That is acceptable for
development and for an operator who is the only party who could exploit a bad
setup. It is not a public ceremony. Do not deploy a setup produced that way to
a public network.
