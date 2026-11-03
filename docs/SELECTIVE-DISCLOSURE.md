# Selective disclosure: reveal one action, keep the rest

## The gap this closes

A zkagent proof says "some set of at most eight actions satisfies this policy and commits to
this trace root". It says nothing about *which*. A verifier who needs to know that one
specific action happened — the one that paid invoice A, the one that touched wallet B — had no
way to ask.

## What was built

`zkagent disclose` publishes one leaf and its Merkle path:

```bash
zkagent disclose --actions actions.json --index 0 --receipt receipt.json --out disclosure.json
```

```json
{
  "kind": "zkagent/disclosure",
  "version": 1,
  "index": 0,
  "leaf_digest": 11,
  "root": "3d6b91a011b7ac280964f9f87e6c33bb5cd81f76e10d81738074035e1ad2d504",
  "path": [{"sibling": "1600…", "left": true}, {"sibling": "e5b9…", "left": true}, {"sibling": "…", "left": true}]
}
```

and any verifier checks it against the receipt it already trusts:

```bash
zkagent verify --keys keys/ --policy policy.json --receipt receipt.json --proof proof.json \
               --now 1600 --disclosure disclosure.json
# disclosure ACCEPT: slot 0 with digest 11 is in the attested set
# ACCEPT
```

A failed disclosure exits 1 even when the proof is valid, because the two are different claims:
the bundle can be honest about its totals while the extra claim about one action is false.

## Cost — measured, not estimated

| what | before | with disclosure |
|---|---|---|
| circuit constraints | 7 442 | **7 442** (unchanged) |
| artifact format | 3 | 3 (no bump) |
| verify time | 0.008–0.009 s | 0.008–0.009 s |
| prove time | 0.680–0.694 s | unchanged |
| disclosure artifact | — | ~700 bytes of JSON |

**Zero added constraints.** The trace root is already a public input and the tree is already
built over the padded digests, so membership is arithmetic any verifier can do: six MiMC
permutations, lost in the noise of one pairing check. Putting the path in the circuit would
add constraints and prove nothing extra, because the verifier would still be trusting the same
hash function.

## The honest limitation

The leaf is the **trace digest alone**. So a disclosure proves:

> a leaf with digest `d` sits at slot `i` under the root of this receipt.

It does **not** prove:

> the action that spent 250 on target 3 has digest `d`.

`target` and `amount` are not bound to the leaf. The artifact therefore carries no claim about
them, and the module says so in its header. Anyone who tries to attach "and this was the
payment to X" is making a claim the proof does not support.

## The sound version, priced

Make the leaf `H(target, amount, trace_digest)`:

| delta | value |
|---|---|
| leaves hashed in circuit | 8 |
| cost per leaf | 1 permutation = 3 constraints × 110 rounds = **330** |
| total added | **2 640 constraints** (7 442 → 10 082, +35.6%) |
| prove time, projected by constraint ratio | 0.69 s → ≈ 0.93 s (estimate, not measured) |
| artifact format | 4 (the circuit and therefore the vk change) |
| migration | vk changes, so old proofs are refused rather than reinterpreted |

That is the version where a disclosure can say *this* action, not merely *this digest*. It is a
format bump and a re-setup, which is why it is a separate unit and not part of this one.

## What this does not leak

The three sibling hashes reveal the shape of the tree (eight slots) and nothing about the other
leaves, beyond what a hash of a 64-bit digest can be brute-forced to. Eight leaf digests are a
small enough space that a determined verifier who holds two disclosures can start intersecting
siblings. The design is "one action revealed", not "k-anonymous among many"; for stronger
privacy the leaf space must grow (a 128-bit digest, or a commitment with a blinding factor),
which is a format change for the same reason as above.

## Where it lives

- `crates/zkagent-proofs/src/merkle.rs` — `inclusion_path`, `verify_inclusion`, `Step`
- `crates/zkagent-service/src/disclosure.rs` — the artifact, `disclose`, `check_disclosure`
- `crates/zkagent-cli` — `disclose` subcommand, `verify --disclosure`
- tests: 6 in `merkle.rs` (every slot, tampered sibling, flipped side, padded slot, short path),
  5 in `crates/zkagent-cli/tests/disclosure.rs`
