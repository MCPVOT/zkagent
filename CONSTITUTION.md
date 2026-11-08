# Constitution

Rules that outrank convenience, features and deadlines. Each one exists because breaking it is
invisible at the call site and expensive later, and where a test pins it, the test is named.

## 1. The verdict is the product

A caller acts on `verdict`, not on an exit code and never on the text of an English message.
`accept`, `reject` and `could not verify` are three different things, and the third is not a
failed reject. Anything that turns a rejection into a success breaks the product, even if every
number looks right.

Pinned by: `tests/test_guards.py` (an exit 0 beside a reject is not an acceptance; unparseable
verifier output is not an acceptance).

## 2. Fail closed on state

An unreadable state file, an unreadable replay ledger, or an index that disagrees with the receipts
on disk is an error, never an empty state. Treating damage as a fresh start silently resets the
execution-id range and the replay guard, which is the state an attacker would choose.

Pinned by: `replay_guard_lost` and `state_unreadable` cases in `tests/test_guards.py`.

## 3. One ledger, one namespace

A piece of evidence is consumed once. Executions and sessions are two ways to present the same
work, so claiming one must block the other in both directions. Two sections that never speak is how
the same receipt gets accepted twice.

Pinned by: `TestCrossModeReplay`.

## 4. A refusal must leave a trace

If a cap is refused, widening the cap and asking again is not evidence that the session stayed
inside a limit. Refusals are recorded, widening is refused, and a deliberate widening is accepted
only when it is asked for explicitly and recorded on the receipt.

Pinned by: `TestCapWidening`.

## 5. Privacy by construction, not by policy

The proof publishes totals, the action count and the policy. It never publishes what the agent did.
Disclosure reveals exactly one slot with its inclusion path, and nothing else. No argument, prompt
or tool output is ever written to a receipt.

Pinned by: the receipt schema in `crates/zkagent-core` and the disclosure path in
`crates/zkagent-service`.

## 6. No silent widening of a trusted surface

The circuit's slot count, the public input count, the artifact format version and the verifying key
are public interface. Changing any of them is a format change: it needs a version bump, a release,
and a note in `docs/ARCHITECTURE.md`, not a quiet commit.

## 7. Say what is not proved

The ledger is written by the agent about itself. A receipt is not a complete account of what an
agent did, and the trusted setup is single-party. Every document that describes the product says
so, in those words, next to the claim it limits.

## 8. Tests pin consequences, not coverage

A test that exercises a happy path proves the code runs. The guards in `tests/test_guards.py` exist
to force the failure and assert what happened to the ledger afterwards. When a bug is found by
probe, the probe becomes a guard test in the same commit as the fix.
