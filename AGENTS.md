# Working in this repository

For a human or an agent making a change here. Architecture is in `docs/ARCHITECTURE.md`, the
non-negotiables are in `CONSTITUTION.md`, and the threat model is in `SECURITY.md`.

## Layout

```
crates/zkagent-core        vocabulary: policy, receipt, action, authority, replay state
crates/zkagent-proofs      circuit, prover, verifier, key files
crates/zkagent-verifier    verification of an artifact against a policy
crates/zkagent-service     the operations layer both the CLI and the MCP server call
crates/zkagent-cli         argument parsing, human output
crates/zkagent-mcp         MCP server
crates/zkagent-wire        wire types shared by host integrations
crates/zkagent-ipfs        bundle publishing
tools/leaderboard          contributor board: generator, attribution rules and their tests
examples/verify-it-yourself  a receipt anyone can check without this repo's code
```

The service layer is the only place that decides. The CLI and the MCP server parse and print; they
must not reimplement a verdict, a replay check or a cap check.

## Branches and merging

`master` is protected: required pull request, four required checks, admins enforced, no force push.
Direct pushes are refused at receive time with `GH006`. So:

```bash
git checkout -b <type>/<slug>
# ... change ...
git add -A && git commit -m "<type>: <what changed and why>"
git push -u origin <branch>
gh pr create --base master --fill
gh pr checks --watch
gh pr merge --squash
```

`strict` is on, so rebase if master moved while the PR was open.

## Gates before a PR

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
python3 tools/leaderboard/test_generate.py
```

CI also cross-verifies a proof against an independent implementation and compiles the declared MSRV.
Those two catch interface drift that unit tests cannot.

## When adding a tool or a command

1. Put the decision in `zkagent-service`, not in the CLI.
2. Emit a verdict document shaped like the rest: `verdict`, `reason`, `reason_code`, `execution_id`,
   `format`. Exit codes stay `0` accept, `1` reject, `2` could not verify.
3. Refusals get a stable `reason_code` string, because callers branch on it and humans quote it.
4. Add a guard test that forces the failure: the happy path was never the risk.

## Things not to do

- Do not read secrets, `.env` files or keyrings. The proving key is public; the authority key is not.
- Do not shell out. The one subprocess this project needs is itself.
- Do not write outside the paths the host hands you.
- Do not edit `Cargo.lock` by hand, and do not bump the artifact format without a release.
- Do not merge with a red check, even as the administrator: the branch protection exists because
  that merge is easy to rationalise.

## Attribution

`.mailmap` merges git identities so one person is one author. `.git-blame-ignore-revs` keeps a
formatting commit from owning every line. If you add a mechanical reformat, add its commit hash to
that file in the same PR.
