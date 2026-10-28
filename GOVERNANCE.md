# Governance

Short, because a governance document that cannot be read is not a governance
document.

## 1. Supremacy

**Soundness outranks everything else in this repository.**

A change that makes the protocol easier to use, faster to prove, or nicer to look
at, but that weakens a claim, is rejected. A reviewer may reject a change that
passes CI. CI cannot see a weakened claim; a person can.

This document outranks `CONTRIBUTING.md`, the PR template and any comment on an
issue. Nothing in this repository outranks the soundness of the system.

## 2. Judged by the work

Contributions are judged on the work and its evidence. Not on who made them, not
on where they work, not on their politics, religion, nationality, or on whether
they are a person or a program.

- **No test of belief.** Nobody has to agree with anything to use, study, modify
  or distribute this software, to open an issue, or to open a pull request.
- **AI-assisted contributions are welcome**, and are judged exactly like any
  other. Disclose the tooling in the PR description, because a reviewer needs to
  know what to check: an agent's confident summary is not evidence, and the tests
  are.
- **Credit is by work.** Merged pull requests are credited on the automated
  leaderboard, to the originating author, even when a maintainer re-lands the
  work. The rule is enforced by `tools/leaderboard/generate.py` and tested.

## 3. Who decides

- **Maintainer decides** on direction, scope and merging.
- **A soundness objection blocks a merge** until it is answered in writing. This
  is the one place where a non-maintainer's objection has the same force: "this
  makes a false statement verify" is not a matter of taste, and it does not need
  seniority to be true.
- **Disagreement is resolved with a test.** If two people disagree about what the
  code does, the answer is a failing test, not a longer argument.

## 4. What is never traded away

These are not negotiable for convenience, performance, or a deadline:

- a negative test is never deleted to make a change pass;
- a constraint is never loosened to make an awkward witness verify;
- an authorisation root never comes from a default;
- an unreadable replay ledger is never treated as empty;
- the private witness is never logged, serialized into an artifact, or included
  in an error message.

## 5. Changing this document

Open a PR. Say which rule changes, why, and what it costs. A change to §1 or §4
needs a written justification in the PR and is the maintainer's call alone.

## 6. Scope

This repository is the reference implementation of the attestation primitive and
its shells. Protocol work that requires a trusted setup ceremony, an on-chain
verifier, or a revocation service is described in `docs/ARCHITECTURE.md` as a
known gap until it lands here.

## 7. Independence

This is an independent implementation. It is not affiliated with, endorsed by, or
speaking for any other project. Where it borrows a pattern, the pattern is
credited in the file that uses it.
