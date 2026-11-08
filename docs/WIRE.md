# The wire contract

Everything a second program must agree on. If a field here changes, a consumer breaks — usually
silently, because a verifier that cannot parse an artifact reports *could not verify*, not *your
format moved*.

## What is versioned

```rust
pub const FORMAT_VERSION: u32 = 3;   // zkagent-wire
pub const MAX_ACTIONS: usize = 8;    // zkagent-core
```

| knob | current | a change to it means |
| --- | --- | --- |
| `FORMAT_VERSION` | `3` | the proof or public-input encoding changed; old artifacts cannot verify |
| `MAX_ACTIONS` | `8` | the circuit shape changed, so the proving key changed |
| public inputs | `16` (8 policy + 8 receipt) | every verifier must be rebuilt |
| `TRACE_ROOT_BYTES` | fixed | the session index root width changed |

These are one contract, not four settings. Moving any of them is a format bump: new
`FORMAT_VERSION`, new release, new proving key, and a note in `CHANGELOG.md` under **Changed**.

## What a consumer sees

An artifact carries its own format stamp:

```json
{"format_version": 3, "public_inputs": ["…16 strings…"], "proof": "…bytes…"}
```

Read `format_version` before anything else. A verifier that ignores it and fails later reports
`could not verify`, which is indistinguishable from a corrupt proof — and that ambiguity is worse
than a refusal.

The session index stores a `trace_root` per receipt. A format change that renamed it produced
exactly this signature in the wild:

```
missing field `trace_root`
```

Not a verdict. That error means the artifact and the reader disagree about the format, so the fix is
a matching binary, never a re-proof.

## Compatibility

| reader | can read | notes |
| --- | --- | --- |
| `zkagent` 0.4.x | format 3 | verifies format-3 proofs only |
| `zkagent` 0.3.x | format 3 | same format, older prover: fixed blinding, do not use |
| `hermes-zkagent` 0.5.x | format 3 via the binary | never parses proofs itself |
| Omarchy widget | the verdict document | no format knowledge by design |

The widget is the example worth copying: it reads `verdict`, `reason_code`, `execution_id` and
`checked_at` from `zkagent verify --json`, and knows nothing about circuits. A consumer that needs
only a decision should take the decision, not the proof.

## Adding a field

1. Is it public? If yes it enters `public_inputs`, which changes the circuit and the key: format bump.
2. Is it private convenience for the prover? Keep it out of the artifact; put it in the witness file.
3. Is it metadata a human reads? Put it beside the verdict document, not inside the proof.
4. Regenerate `docs/SCHEMAS.md` (`python3 tools/gen_schemas.py`) so the field list and the code agree.

## What is deliberately not in the contract

The ledger, the action witness, the cost table and the plugin's `state.json`. They are local
implementation, and pinning them would freeze decisions that should stay cheap to change.
