# Measurements — raw method and output

Anything quoted in ARCHITECTURE.md §7 or the skill's `substrate-notes.md` should
trace back to a command here. Re-run and replace, never copy from memory.

## Circuit size and public-input arity

```bash
cargo test -p zkagent-proofs constraint_count_is_sane -- --nocapture
```
```
constraints = 3265, instance variables = 15
test result: ok. 1 passed
```
15 instance variables = 14 public inputs + the constant-one slot. The test
asserts both numbers, so a regression fails rather than shifting silently.

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
echo '{"total_amount":400,"action_count":2,"completed_at":1500,"chain_id":1}' > receipt.json
echo '[{"target":3,"amount":250,"trace_digest":11},{"target":7,"amount":150,"trace_digest":22}]' > actions.json
$Z prove  --keys keys/ --policy policy.json --receipt receipt.json --actions actions.json --out proof.json
$Z verify --keys keys/ --policy policy.json --receipt receipt.json --proof proof.json --now 1600
```
```
ACCEPT
inputs: 14 | format: 1 | proof bytes: 128
pk.bin 648816   vk.bin 712   proof.json 2170
```
Timings in the debug profile: prove 1.28 s, verify 46 ms (wall clock).

Negative controls, all exercised through the real binary:

| Command | Output | Exit |
|---|---|---|
| verify with `total_amount: 999` | `REJECT: public inputs do not match the supplied policy/receipt` | 1 |
| prove with amount 400 (cap 300) | `error: policy rejected: action amount 400 exceeds per-action cap 300` | 2 |
| prove with target 4 (not in {3,7,9}) | `error: policy rejected: target 4 is not in the allow-list` | 2 |

## Known measurement gap

Release-profile timings for THIS circuit (3265 constraints) are not yet recorded.
Do not quote the probe's 161 ms prove figure as this circuit's number — the probe
measured 2162 constraints. Run `cargo build --release` and re-time before
publishing.
