<!--
  The RED/GREEN discipline is the point of this template. Fill both in.
-->

## What this changes

<!-- One paragraph. What is true after this PR that was not true before? -->

## RED — the failing state

<!-- Required for any behaviour change.

     Paste the command and its output, or the constraint that a violating
     witness previously satisfied. "N/A" is only acceptable for docs-only PRs. -->

```text
$ ...
```

## GREEN — the passing state

```text
$ ...
```

## Soundness

<!-- Required if this touches the circuit, the verifier, the policy encoding or
     the authority layer. -->

- Which claim does it change?
  <!-- e.g. "C5: sum(actions) == receipt.total_amount" -->
- Which test proves it?
- Does any existing **negative** test change? If yes, why is the old expectation wrong?

## Layer

<!-- Tick one. A rule implemented in a shell instead of the service is a bug. -->

- [ ] `zkagent-core` (vocabulary)
- [ ] `zkagent-proofs` (circuit / prover)
- [ ] `zkagent-verifier` (pure verification)
- [ ] `zkagent-service` (the four operations — where rules belong)
- [ ] a shell (`zkagent-cli`, `zkagent-mcp`, `examples/tauri-plugin`)
- [ ] docs / tooling only

## Checklist

- [ ] `cargo fmt --all -- --check` is clean
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] `cargo test` passes, including every existing negative test
- [ ] no key material, `.env`, or real `seen.json` is included
- [ ] the public-input order and arity are unchanged, or the change is explained above
- [ ] docs updated if a documented behaviour changed

Fixes #
