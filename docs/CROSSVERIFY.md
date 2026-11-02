# Tier 4 — a second implementation verifies our proofs

`references/soundness-checklist.md` states the gap plainly: *"Until a second,
independent verifier consumes the same artifacts, the claim 'this proof verifies'
rests on one implementation."* This document records closing that gap, what it
takes, and what it still does not prove.

## Result

**`snarkjs` — an independent JavaScript implementation of Groth16 — verifies a
proof produced by this repository, and refuses every tampered variant of it.**

Measured on a Linux laptop (rustc 1.99.1, node from `npx snarkjs@latest`),
2026-11-01, on the shipped artifacts for the demo execution documented in
`docs/MEASUREMENTS.md`:

| Case | `snarkjs groth16 verify` | Exit |
|---|---|---|
| honest artifacts | `[INFO] snarkJS: OK!` | 0 |
| public input `+1` | `[ERROR] snarkJS: Invalid proof` | 1 |
| proof `pi_a.y +1` | `[ERROR] snarkJS: Proof commitments are not valid.` | 1 |
| verifying key `IC[1].x +1` | `[ERROR] snarkJS: Invalid proof` | 1 |
| public input set to `0` | `[ERROR] snarkJS: Invalid proof` | 1 |

The fixture: 15 public inputs, 16 `IC` entries, our own verifier `ACCEPT` before
the cross-check runs — so the experiment measures agreement between two
implementations, not a broken fixture.

## Why it works, and what the actual work is

Groth16 over **BN254 (alt_bn128)** is a standard: same curve, same pairing, same
`r`, same verification equation. The arkworks encoding is *not* the wire format,
and that difference is the whole cost:

- field elements are canonical big-endian integers here, and decimal strings there
  (`hex -> int -> decimal`, one line of Python per artefact);
- G1 points are `[x, y]` in the library and `[x, y, "1"]` on the wire;
- G2 points are `[[x.c0, x.c1], [y.c0, y.c1]]` plus `["1", "0"]` — the `c0, c1`
  order matches snarkjs' `F2`, which is why no coordinate swapping is needed;
- `vk_alphabeta_12` is required by the schema but not read by the verifier, so it
  is written as a zeroed `Fq12` rather than computed from a pairing;
- `nPublic` is `gamma_abc_g1.len() - 1`, and the public inputs keep **circuit
  order** — the same rule `public_inputs()` follows in `zkagent-proofs`.

That is the entire converter: `examples/crossverify/src/main.rs` (reads `vk.bin`
and `proof.json`, emits hex) plus `tools/crossverify/run.py` (hex to decimal,
builds the three JSON documents, drives `snarkjs`). No re-proving, no trusted
setup re-run, no circuit change.

**So the honest answer to "how big is Tier 4?"** — a day, not a month. The
expensive part was never the curve; it was believing the encoding was portable.

## What this establishes, and what it does not

Establishes:

- our proofs are **standard Groth16/BN254**, verifiable outside arkworks;
- the encoding layer is understood well enough to reproduce it elsewhere, which is
  what Tier 4 asked for;
- tampering is caught by the independent implementation, not only by ours.

Does **not** establish:

- that `snarkjs` is correct — two implementations agreeing is not a proof of
  either one, it is one fewer reason to doubt us;
- anything about the **trusted setup**. This is a single-party dev setup
  (`ARCHITECTURE.md` §6); a second verifier cannot make that sound;
- execution binding, revocation or completeness — the three structural gaps stand
  exactly as `ARCHITECTURE.md` §5.3-5.4 describes them.

## Running it

```bash
cargo build -p zkagent-cli --bin zkagent
cargo build --manifest-path examples/crossverify/Cargo.toml
python tools/crossverify/run.py            # add --build to do both above
```

Exit code 0 means: honest accepted, and all four mutations refused. CI runs this
on `ubuntu-latest` only, because it needs node and the check is
implementation-independent rather than platform-independent.

`tools/crossverify/test_run.py` unit-tests the conversion (shape, ordering,
`nPublic` vs `IC` length) without needing node, cargo or ten seconds.

## What would make this a strong claim rather than a good one

1. **A second language, not just a second library.** `gnark` (Go) is the natural
   third implementation; two independent verifiers disagreeing would be
   interesting, and two agreeing is much stronger than one plus its port.
2. **Committed conformance vectors** — the four artifacts plus the expected
   verdicts, so anybody can check any implementation without running our code.
   Deliberately not done yet: the demo keys are reproducible but they are still
   key material, and `CONTRIBUTING.md` forbids committing it.
3. **On-chain verification** — an EVM verifier is the same Groth16 equation with
   BN254 precompiles; the conversion above is the template for it.
