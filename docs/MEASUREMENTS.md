# Measurements — raw method and output

Anything quoted in ARCHITECTURE.md §7 or the skill's `substrate-notes.md` should
trace back to a command here. Re-run and replace, never copy from memory.

## Measurement provenance

Numbers in this repository come from three different apparatuses, and only the
first is a claim about the shipped code.

| Kind | Apparatus | Cite it for |
|---|---|---|
| **project-measured** | the release binary in this repo, on the machine below | claims about this code |
| **research-probe** | a separate probe program on an **arkworks 0.6.0** tree | order-of-magnitude reasoning |
| **borrowed** | a paper or vendor benchmark | context only |

| Number | Value | Provenance |
|---|---|---|
| circuit size | 3 333 constraints, 15 public inputs | project-measured (`constraint_count_is_sane`) |
| probe circuit (research doc 05 §4.2) | 2 162 constraints, 9 public inputs | research probe on 0.6.0, earlier circuit shape |
| SMT non-membership gadget | `c(d) = 243·d + 2` | research probe on 0.6.0 — re-measure before budgeting |
| delegation hop | 1 021 constraints | research probe on 0.6.0 |
| zkVM proving floor | 3.3–16 GB RAM | borrowed benchmark |

The 2 162 figure and the 3 333 figure are both real; they measure different
circuits. Conflating them is the error, so neither is deleted. See
`docs/research/README.md#measurement-provenance`.

## Circuit size and public-input arity

```bash
cargo test -p zkagent-proofs constraint_count_is_sane -- --nocapture
```
```
constraints = 3333, instance variables = 16
test result: ok. 1 passed
```
16 instance variables = 15 public inputs + the constant-one slot. The test
asserts both numbers, so a regression fails rather than shifting silently.

A second test, `public_input_order_matches_the_allocation_order`, compares the
constraint system's `instance_assignment` to `public_inputs()` element by
element. It was verified to FAIL when the vector is deliberately permuted — the
defect class it exists for is a permuted vector, where every individual input is
correct and the proof still does not verify.

## Test suite

```bash
cargo test --workspace
```

Re-measured **2026-11-01 on Linux** (Omarchy, rustc 1.99.1, `CARGO_BUILD_JOBS=4`):

```
running 31 tests  ... test result: ok. 31 passed   (zkagent-core)
running 21 tests  ... test result: ok. 21 passed   (zkagent-ipfs)
running  7 tests  ... test result: ok.  7 passed   (zkagent-mcp)
running 18 tests  ... test result: ok. 18 passed   (zkagent-proofs)
running 11 tests  ... test result: ok. 11 passed   (zkagent-verifier)
running  9 tests  ... test result: ok.  9 passed   (zkagent-service, tests/service.rs)
running  5 tests  ... test result: ok.  5 passed   (zkagent-service, tests/bundle.rs)
TOTAL passed: 102  failed: 0
```

Two things the earlier `28 / 17 / 10` counts got wrong, both worth knowing:

- **The counts are stale.** The repository grew; `cargo test` alone also builds
  each crate's harness separately, so the per-crate lines are what to compare,
  not a remembered total.
- **Feature-gated test binaries report `running 0 tests` and `ok`.** The
  `tests/gateway.rs` binaries need `--all-features`; a zero-count `ok` is not a
  passing suite. Check the counts, not the colour.

The timings elsewhere in this file remain the **Windows** measurements; they have
not been re-taken on Linux, and per the provenance rule they must be labelled as
such until they are.

## End-to-end CLI, including negative controls

```bash
Z=target/debug/zkagent.exe
$Z setup  --seed 7 --out keys/
$Z policy --max-amount 1000 --max-per-action 300 --expires-at 2000 \
          --chain-id 1 --targets 3,7,9 --authority-key authority.hex --out policy.json
echo '{"total_amount":400,"action_count":2,"completed_at":1500,"chain_id":1,"execution_id":1001}' > receipt.json
echo '[{"target":3,"amount":250,"trace_digest":11},{"target":7,"amount":150,"trace_digest":22}]' > actions.json
$Z prove  --keys keys/ --policy policy.json --receipt receipt.json --actions actions.json --out proof.json
$Z verify --keys keys/ --policy policy.json --receipt receipt.json --proof proof.json --now 1600
```
```
ACCEPT
inputs: 14 | format: 1 | proof bytes: 128
pk.bin 648816   vk.bin 712   proof.json 2170
```
Release, with `parallel`: prove 0.43–0.64 s, verify 0.048–0.091 s (see the
timings table below for the serial comparison).

Negative controls, all exercised through the real binary:

| Command | Output | Exit |
|---|---|---|
| verify with `total_amount: 999` | `REJECT: public inputs do not match the supplied policy/receipt` | 1 |
| verify with a bumped `execution_id` (replay) | `REJECT: public inputs do not match the supplied policy/receipt` | 1 |
| verify the same proof again with `--seen ids.json` | `REJECT: execution id 1001 was already accepted (replay)` | 1 |
| verify with a corrupt `ids.json` | `error: replay state ids.json is unreadable (...); refusing to verify against an unknown set of accepted executions` | 2 |
| verify a policy with `max_amount` edited to 999999 | `REJECT: policy signature is not valid for this policy` | 1 |
| `policy` with no `--authority-key` and no `--seed` | `error: policy: no authorisation key. Pass --authority-key <path> ...` | 2 |
| `policy --seed 99` (demo path) | `warning: signing with DEMO seed 99. That key is reproducible ... forgeable by anyone` on stderr, policy still written | 0 |
| `policy --seed 5 --authority-key auth.hex` | `error: the argument '--seed <SEED>' cannot be used with '--authority-key <AUTHORITY_KEY>'` | 2 |
| verify without `--now` | `warning: --now not supplied, so the future-dating check is skipped` on stderr, then `ACCEPT` | 0 |
| verify with `execution_id: 0` | `REJECT: receipt has no execution id (0), so replay cannot be detected` | 1 |
| verify an expired receipt | `REJECT: policy was expired at the receipt's completion time` | 1 |
| prove with amount 400 (cap 300) | `error: policy rejected: action amount 400 exceeds per-action cap 300` | 2 |
| prove with target 4 (not in {3,7,9}) | `error: policy rejected: target 4 is not in the allow-list` | 2 |
| prove with 9 actions (max 8) | `error: policy rejected: 9 actions supplied, maximum is 8` | 2 |

The semantic checks run **before** the public-input binding. Otherwise every
specific defect is reported as the same generic "inputs do not match", because a
mismatched receipt fails binding for whatever reason it mismatched. Ordering the
cheap refusals first is what lets those messages name the real cause.

## Timings, serial vs parallel

`ark-groth16`'s `parallel` feature (rayon) is enabled in
`crates/zkagent-proofs/Cargo.toml`. Same artifacts, same machine:

| Run | Serial prove | Parallel prove |
|---|---|---|
| 1 | 1.024 s | 0.672 s |
| 2 | 1.017 s | 0.430 s |
| 3 | 1.164 s | 0.471 s |
| 4 | — | 0.599 s |
| 5 | — | 0.638 s |

Proving: **1.02–1.16 s serial → 0.43–0.64 s parallel** (~2×). Verification is one
pairing check and is unaffected: **0.048–0.091 s** including ~40 ms of process
startup. Setup with the parallel build: **0.187 s** (0.565 s on the earlier
serial build; both are dominated by the same NTT work).

Keeping `parallel` on is a deliberate trade: rayon in the dependency tree and a
little peak memory for ~2× proving. A memory-constrained box can build serial —
on the droplet, memory is the constraint (3 GB total), not CPU.

## The one measurement this project got wrong first

`keys/vk.bin` was **28 936 B** and every CLI `verify` said
`MalformedVerifyingKey`, while the unit test passed. Two causes stacked:

1. **The binary under test was stale.** `cargo test` builds test harnesses, not
   necessarily the standalone `zkagent.exe`, so the test passed against the new
   circuit while the CLI still ran the old one. When a test and the CLI disagree,
   check the binary — do not start doubting the test.
2. **The old circuit allocated public inputs with `UInt::new_input`,** which
   allocates **one public input per bit**: 896 of them. `verify_proof` then
   expected a 896-element vector and got the 14 the verifier actually has.

A vk's size is a fingerprint of its public-input count: **712 B = 15 inputs**,
28 936 B = 896. `constraint_count_is_sane` now asserts the arity, so the number
cannot drift quietly again.

## A second, subtler ordering bug found in review

Adding `execution_id` was allocated next to the other receipt scalars — the
natural place — while `public_inputs()` appended it after the allow-list. Every
individual input was correct; the proof still failed with `InvalidProof`,
because the circuit's public inputs are ordered by **allocation**, so the
verifier was supplying a permuted vector.

Two things follow, and both are now permanent:

1. **The circuit's allocation order IS the public-input order.** `public_inputs()`
   must mirror it, not tidy it.
2. A test (`public_input_order_matches_the_allocation_order`) compares the
   constraint system's `instance_assignment` to `public_inputs()` element by
   element. It was checked against a deliberately permuted vector and fails, so
   it is a guard rather than decoration.

## What is still not measured

* Peak RSS for **this** circuit under the parallel feature. (29 MB was measured
  serial on the droplet, for the smaller probe circuit.)
* Proving on the droplet for this circuit: the release binary here is a Windows
  PE, so the droplet needs its own `cargo build --release` (~3 min on 2 vCPU).
* Gas for an on-chain verifier: none exists yet.
