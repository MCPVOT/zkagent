# Measurements — raw method and output

Anything quoted in ARCHITECTURE.md §7 or the skill's `substrate-notes.md` should
trace back to a command here. Re-run and replace, never copy from memory.

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
cargo test
```
```
running 18 tests   ... test result: ok. 18 passed; 0 failed   (zkagent-core)
running 13 tests   ... test result: ok. 13 passed; 0 failed   (zkagent-proofs)
running  8 tests   ... test result: ok.  8 passed; 0 failed   (zkagent-verifier)
```

## End-to-end CLI, including negative controls

```bash
Z=target/debug/zkagent.exe
$Z setup  --seed 7 --out keys/
$Z policy --max-amount 1000 --max-per-action 300 --expires-at 2000 \
          --chain-id 1 --targets 3,7,9 --seed 99 --out policy.json
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
