# Code map — what each crate owns, and what it may depend on

`docs/ARCHITECTURE.md` describes the protocol. This file describes the **code**:
which crate owns which idea, which dependency edges are intended, and which ones
are debt. `tools/arch/check.py` enforces the first list and reports the second, so
neither lives in someone's memory.

## Roles

| Crate | Owns | LOC |
|---|---|---:|
| `zkagent-core` | vocabulary: `Policy`, `Receipt`, `Action`, canonical encoding, Ed25519 authority, replay set | 1 212 |
| `zkagent-wire` | the statement and the artifact: public-input order, `ProofBytes`, `FORMAT_VERSION`, verifying-key parsing. No circuit, no r1cs | 271 |
| `zkagent-ipfs` | content addressing only: CIDv1, the manifest, block sources (no node) | 1 379 |
| `zkagent-proofs` | the circuit and the prover | 1 099 |
| `zkagent-verifier` | pure verification: policy + receipt + proof → verdict, no state | 561 |
| `zkagent-service` | **the four operations over files** — the layer an embedder uses | 1 867 |
| `zkagent-cli` | a shell over the service | 613 |
| `zkagent-mcp` | a JSON-RPC surface over the service | 643 |

## Invariants (CI fails if broken)

```
zkagent-core       -> nothing            # the vocabulary depends on nothing
zkagent-ipfs       -> nothing            # content addressing is standalone
zkagent-verifier   -> not zkagent-service  # the verifier has no host state
zkagent-verifier   -> not zkagent-proofs   # and it does not carry the prover
zkagent-service    -> not a shell        # the service must not own an interface
```

The first two are about purity, the second two about direction: state and
interfaces point inward, never the other way.

## Targets (debt, reported every run)

**None right now.** Both debts the first version of this map named have been paid:
the verifier stopped carrying the prover (see below), and the shells now import
from `zkagent-service` alone.

```text
$ python tools/arch/check.py
OK: invariants hold        # no NOTE lines
```

The shell rule is worth stating plainly because the crate count barely moved:
`zkagent-cli` 311 → 308, `zkagent-mcp` 309 → 307, since the service legitimately
needs the prover for `prove`. The win is that a format detail now has **one import
site** instead of three, and the edge is enforced rather than remembered.

## Paid off: the verifier no longer carries the prover

`zkagent-verifier` is documented as *"a proof and inputs become a verdict, no
state"*. It used to compile **261 crates**, including `ark-r1cs-std`,
`ark-relations`, `ark-poly` and `ark-crypto-primitives` — the constraint-system and
polynomial machinery only a prover needs — because `ProofBytes`, `FORMAT_VERSION`,
`verifying_key_from_bytes` and `public_inputs()` all lived inside
`zkagent-proofs::{prover, circuit}`.

`zkagent-wire` now owns the statement and the wire format, and both the prover and
the verifier depend on it. Measured after the move:

| | before | after |
|---|---:|---:|
| `cargo tree -p zkagent-verifier -e normal \| wc -l` | 261 | **221** |
| `… \| grep -c ark-r1cs-std` | 1 | **0** |
| `… \| grep -c ark-poly` | 2 | 2 |

Forty crates lighter, and the constraint system is gone from the verifier entirely.

**What still remains, and why it is not a regression.** `ark-poly` still appears
because `ark-ec` (the pairing arithmetic) depends on it; `ark-crypto-primitives`
still appears because `ark-groth16` uses it for `process_vk`. Both are part of
performing a pairing check, not of building a circuit. The avoidable dependency was
`ark-r1cs-std`, and it is now zero.

The remaining shell target is smaller but real: once `zkagent-service` re-exports
the artifact types, `zkagent-cli` and `zkagent-mcp` can import them from one place
instead of reaching into `proofs`/`ipfs`/`verifier` directly.

## Why the shells reaching past the service is a real problem

The service exists so that "the layers cannot disagree about what a proof means"
(`README.md`). Today `zkagent-cli` imports `zkagent_proofs::prover` and
`zkagent_ipfs` directly, and `zkagent-mcp` imports `zkagent_verifier` and
`zkagent_proofs`. Both still route the *operations* through the service — so no
rule is duplicated yet — but each new format detail becomes three import sites
instead of one, which is how a layering rule quietly stops holding.

## Checking it

```bash
python tools/arch/check.py            # exit 1 on an invariant violation
python tools/arch/check.py --json     # the graph + rules, machine-readable
python tools/arch/test_check.py       # 10 unit tests, synthetic graphs
```

CI runs the check on both matrix legs. Moving a rule from `TARGETS` to
`INVARIANTS` belongs in the commit that pays it off — that is how the debt gets
smaller instead of being re-discovered.

## What this map does not cover

It does not score the design. A clean dependency graph says nothing about whether
the protocol is sound (`docs/ARCHITECTURE.md` §5) or whether the tests can fail
(`docs/TESTING.md`). It only stops the structure from drifting while those
questions are worked.
