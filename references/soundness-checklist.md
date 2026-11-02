# Soundness checklist

`tools/loop.py next` names this file when the ledger shows **three
consecutive failures**. The point of reading it then is to stop repeating the
same shape of attempt: a failed approach repeated a fourth time is usually a
wrong model of the problem, not a bad roll of the dice.

Read it **before** the next attempt, not after it fails again.

## What "sound" means here

A proof must only verify when the private actions really do justify the
receipt, under the policy the human signed. Three ways to get that wrong:

- **soundness** — a false statement verifies (the circuit accepts a witness
  that does not justify the receipt);
- **completeness** — a true statement cannot be proven (an honest execution is
  refused);
- **privacy** — the proof or an artifact reveals more than the architecture
  says is public.

Soundness outranks everything else here. A soundness bug shipped green is
worse than a missing feature.

## Before you try again

1. **Name the failure precisely.** Which tier, which constraint, which
   witness? "The circuit is wrong" is not a diagnosis. If you cannot write
   the failing case as one input and one expected verdict, you do not yet
   understand it.
2. **Find the negative test.** Every constraint needs a test where a witness
   *violating* that constraint fails to satisfy the system. A constraint with
   no negative test is a constraint nobody has checked is load-bearing.
   If the failing case has no negative test, write that test first — that is
   the RED commit.
3. **Check the shape, not just the values.**
   - `circuit_shape_is_data_independent` — the constraint system built at
     setup must equal the one built when proving. Groth16 is circuit
     specific; if they differ, every honest proof fails with `InvalidProof`.
   - `public_input_order_matches_the_allocation_order` — public inputs are
     ordered by **allocation**, not by what reads naturally. Put
     `execution_id` next to the other receipt scalars and every individual
     input is still correct while every honest proof is rejected.
   - `constraint_count_is_sane` — asserts the count *and* the arity, so a
     gadget that silently allocates per-bit public inputs fails here rather
     than at proving time.
4. **Check the integer width.** Every compared integer is a 64-bit `UInt`.
   Without the bit decomposition a prover can supply `p - k` and pass a
   "sums to zero" check while real value moved.
5. **Check the allow-list padding.** It repeats a **real** target. A sentinel
   value would be a value an action could match directly, which silently
   widens the allowed set.
6. **Check the replay path.** Every receipt carries a non-zero
   `execution_id`, and it is a public input: without it, two identical
   executions produce identical public inputs and a proof could be
   re-presented forever. A replay state file that cannot be parsed must fail
   **closed** — an unreadable ledger is never "nothing seen yet".
7. **Check the authority order.** The signature is verified *before* the
   public-input binding, so a tampered policy is reported as
   `policy signature is not valid for this policy` rather than as a generic
   mismatch that hides the forgery. A policy signed with no key must be
   refused: an authorisation root must never come from a silent default.

## After the attempt, before the claim

- [ ] The new negative test fails on the old code and passes on the new.
- [ ] Every existing rejection test still passes. Never weaken a test to make
      a change pass; never remove a negative test.
- [ ] The constraint was not loosened to make an awkward case pass. The
      circuit *is* the claim.
- [ ] The protocol rule stayed in one layer (`zkagent-service`). Re-implementing
      the replay gate, policy validation or the fail-closed rule in a shell is
      a bug even when both copies agree today.
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`
      and `cargo test` are green, and the output is in the PR.
- [ ] The PR body names the soundness property that changed and the test
      that proves it.

## What the tiers cover, and the gap that stays open

`docs/TESTING.md` defines the tiers: pure unit tests, circuit tests with one
negative per constraint, end-to-end through the service layer, and hostile
artifacts. Those tests may never be skipped, because they are the tests whose
absence lets an unsound circuit ship green.

**Tier 4 — cross-verification — is implemented in one direction.** `snarkjs`
(JavaScript) verifies our Groth16/BN254 proofs after a serialization conversion,
and refuses a tampered public input, proof coordinate or verifying-key entry:
`python tools/crossverify/run.py`, run in CI on ubuntu. What that does not cover:
`snarkjs` itself is not proven correct, a second *language* (gnark/Go) is still
absent, and the trusted setup is untouched by any of it. Two implementations
agreeing is one fewer reason to doubt us, not a soundness proof.
