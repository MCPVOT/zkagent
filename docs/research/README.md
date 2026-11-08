# Research corpus

Nine reports, each owning a slice. This index exists so a reader can tell what a
report **establishes**, which decision it drove, and what it **does not** prove —
because a cited report still only covers its slice.

| # | Report | Slice | What it establishes | Decision it drove | What it does NOT prove |
|---|---|---|---|---|---|
| 01 | [`01-proving-stack-landscape.md`](01-proving-stack-landscape.md) | Proof systems | Groth16/BN254 is the right fit for a small, fixed-shape statement | Pin Groth16 + arkworks; **no zkVM for v0** | That a bigger statement would not need another stack |
| 02 | [`02-agent-human-security-primitive.md`](02-agent-human-security-primitive.md) | Protocol shape | The human-signs-policy / agent-proves-execution primitive | The A2H design in `ARCHITECTURE.md` | That agents will behave adversarially in ways tested here |
| 03 | [`03-ecosystem-intel.md`](03-ecosystem-intel.md) | Landscape | Who else is working the problem, and what they claim | Context only, no hard decision | Any claim made by a vendor in it |
| 04 | [`04-rust-repo-audit.md`](04-rust-repo-audit.md) | Reusable code | Which existing Rust repos are worth building on | Build our own; reuse crates not projects | That reused crates are free of defects |
| 05 | [`05-rust-implementation-design.md`](05-rust-implementation-design.md) | Implementation | arkworks 0.6.0's breaking API shape, and a working probe circuit | **Pin 0.5.x**, not 0.6.0; Ed25519 over arkworks Schnorr | That the probe circuit *is* the shipped circuit (it is not — see provenance) |
| 06 | [`06-zk-attestation-literature.md`](06-zk-attestation-literature.md) | Academic literature | 40 sources; every agent-domain paper proves **one action** is compliant; none proves the **set** is complete | Borrow zkLedger's completeness framing; do not claim open-ended policy compliance | That our design is novel, and that arithmetic completeness equals completeness against reality |
| 07 | [`07-zkml-zkvm-systems.md`](07-zkml-zkvm-systems.md) | zkML / zkVM | Measured proof sizes, times and memory floors per system | Fixed-shape Groth16 confirmed; **the 3 GB droplet cannot run any zkVM prover** (3.3–16 GB floor) | Benchmark precision: single runs, no intervals; vendor numbers are labelled as vendor claims |
| 08 | [`08-a2a-protocols-and-trust.md`](08-a2a-protocols-and-trust.md) | A2A / interop | A2A v1.0.0 leaves authorization "implementation-specific" (§7.5); no attenuation rule; `revok` appears once in 182 KB | Where ZK adds something a protocol does not: execution binding, predicate disclosure, revocation | That a protocol will adopt a ZK binding; that the specs stay as read |
| 09 | [`09-a2h-delegation-revocation.md`](09-a2h-delegation-revocation.md) | Delegation / revocation | Epoch-rooted sparse-Merkle non-membership is the implementable revocation path; delegation-hop and trace-root costs | Revocation design (not yet implemented) | The constraint law was measured on a **0.6.0 probe tree**, not this repo's pinned 0.5.x |

## Measurement provenance

This corpus mixes two kinds of number, and they are not interchangeable.

| Kind | Source | Trust it for |
|---|---|---|
| **Project-measured** | the shipped binary in this repo, on the machine named in `docs/MEASUREMENTS.md` | claims about *this* code |
| **Research-probe** | a separate probe program, often on an **arkworks 0.6.0** tree | order-of-magnitude reasoning, gadget costs |
| **Borrowed** | a paper or a vendor benchmark | context only, never a project claim |

The numbers that are easy to confuse:

| Number | Value | Provenance |
|---|---|---|
| shipped circuit size | **7 442 constraints, 16 public inputs** | project-measured (`constraint_count_is_sane`) |
| probe circuit size (doc 05 §4.2) | 2 162 constraints, 9 public inputs | research probe on **0.6.0**, an earlier circuit shape |
| shipped proof | 128 B | project-measured |
| shipped verify | ~48–91 ms on a laptop CPU | project-measured |
| SMT non-membership gadget | `c(d) = 243·d + 2` (depth 12 → +2 918) | research probe on **0.6.0**; re-measure before budgeting |
| delegation hop | 1 021 constraints | research probe on **0.6.0** |
| zkVM prove floors | 3.3–16 GB RAM | borrowed from a third-party benchmark |

**Do not cite a research-probe number as this project's measurement.** If a
number needs to appear in a README or a grant, re-measure it on the shipped tree
and put it in `docs/MEASUREMENTS.md`.

## The three gaps the corpus agrees on

Independently reached by 06, 07, 08 and 09, which is why they are worth trusting:

1. **Execution binding.** A proof binds the statement that was written, not the
   behaviour that occurred. CVA [2607.21325] names it the open problem; PACE
   [2608.17220] calls our unconstrained `trace_digest` a "field provenance" bug.
2. **Completeness.** Every agent-domain paper proves one action is compliant.
   None proves the *set* is complete, so omission is the attack that survives
   them all. Our receipt's `count` + `total` is a weak completeness argument
   relative to the receipt — not relative to reality.
3. **Revocation.** No A2A-family specification defines it; `revok` appears once in
   the A2A spec, about keys. ShadowPath [2608.19937] is the implementable path.

## Standing rules for this corpus

- Every claim carries a source beside it. `UNVERIFIED` is an acceptable value.
- A measurement names the tree it was taken on.
- Counter-evidence is kept, not pruned: 07 keeps the Hollow-LLM attack, 06 keeps
  the correction of two arXiv IDs that memory got wrong.
- Nothing here is deleted when it becomes inconvenient. A superseded number stays
  with the note that superseded it.

## Adding a slice

Number it `NN-topic.md`, add a row above, and state in the header: the question,
the method, the date, and what you could not verify. A slice whose limitations
are not written down reads as if it had none.

Then register it in the manifest, which is what makes the corpus version-controlled
rather than merely committed:

1. add an entry to `corpus.json` (`id`, `path`, `title`, `as_of`, `status`,
   `slices`, `sources_checked`);
2. link it from the table above — the check fails if a report is not linked, because
   a report nobody indexes is a report nobody finds;
3. run `python tools/research/check.py` (CI runs it too).

`as_of` is the date the sources were read. If a report states no date, use the date
it entered the repository (`git log --diff-filter=A --date=short -- <path>`) and say
so in the report's header. `sources_checked` is the last date somebody re-opened the
cited URLs; it is the field that tells you which reports are rotting.

What the check does **not** do: resolve URLs or judge a claim. Both are network
tests that would make CI flaky and would still prove nothing about the claim. The
manifest records when a human or agent last looked; it cannot record whether they
were convinced.

