# Code map — what each crate owns, and what it may depend on

`docs/ARCHITECTURE.md` describes the protocol. This file describes the **code**:
which crate owns which idea, which dependency edges are intended, and which ones
are debt. `tools/arch/check.py` enforces the first list and reports the second, so
neither lives in someone's memory.

## Roles

| Crate | Owns | LOC |
|---|---|---:|
| `zkagent-core` | vocabulary: `Policy`, `Receipt`, `Action`, canonical encoding, Ed25519 authority, replay set | 1 212 |
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
zkagent-service    -> not a shell        # the service must not own an interface
```

The first two are about purity, the second two about direction: state and
interfaces point inward, never the other way.

## Targets (debt, reported every run)

```
zkagent-verifier -> not zkagent-proofs
shell            -> zkagent-service only
```

Measured today:

```
$ cargo tree -p zkagent-verifier -e normal | wc -l
261
$ cargo tree -p zkagent-verifier -e normal | grep -cE 'ark-r1cs-std|rayon'
11
```

The verifier — *"a proof and inputs become a verdict, no state"* — compiles 261
crates, including `ark-r1cs-std`, `ark-relations`, `ark-poly` and
`ark-crypto-primitives`: the constraint-system and polynomial machinery that only
a **prover** needs at build time. A light verifier (a phone build, an on-chain
sidecar, a host that only checks receipts) pays for the whole proving stack.

**Why it happens.** The artifact types are trapped in the proving crate:
`ProofBytes`, `FORMAT_VERSION`, `verifying_key_from_bytes` and `public_inputs()`
all live under `zkagent-proofs::{prover, circuit}`. Verification needs the wire
format and the public-input order; it does not need the circuit.

**The fix, when it is taken.** Extract `zkagent-wire` (or `zkagent-artifact`):
`ProofBytes`, `FORMAT_VERSION`, key/proof (de)serialisation, and the canonical
`public_inputs()` + arity. Then `zkagent-proofs` keeps only the circuit and the
prover, and depends on `zkagent-wire`; `zkagent-verifier` depends on
`zkagent-wire` too. That single move is what turns the first target green, and it
is most of the second: once the shells can import their types from the service's
re-exports, they stop reaching into three crates to do one job.

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
