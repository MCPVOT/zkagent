# Releases

A version is `v<semver>+<YYYY-MM-DD>`: semver for the contract (code and artifact
format), the date for the day it was cut. The git tag carries the same string, so
a version always resolves to a commit someone can check out and rebuild.

The artifact format is the part that matters across versions: `FORMAT_VERSION`
gates what a verifier will accept, and a mismatch is refused loudly rather than
reinterpreted.

## 0.2.0+2026-11-02 — the trace root is bound (format 3)

- **Circuit:** 7 442 constraints, 16 public inputs (was 3 333 / 15). The MiMC trace
  root costs 4 620 constraints: seven 2-to-1 nodes over the eight padded digests at
  660 each, replacing 511 constraints of per-digest decompositions.
- **What changed for a verifier:** `trace_root` is a public input, and the prover
  supplies a Merkle path per action. A receipt can no longer float free of the
  private witness it summarises — change the root and the public inputs change, and
  the proof is refused.
- **Format 3.** A format-2 proof is rejected, not guessed at.
- **Measured** on the seat (mcpvot, Ryzen 5 4600H, release build): setup 0.12 s,
  prove 0.680–0.694 s over three runs, verify 0.007 s, publish 0.021 s.
  vk 776 B, pk 1 449 328 B, proof 128 bytes (2 319 B as JSON).
- **Tests:** 119, up from 108.

## 0.1.0+2026-11-02 — baseline (format 2)

- Policy proof without trace binding: 3 333 constraints, 15 public inputs.
- Tagged from master `6f4be0f` immediately before 0.2.0, so the difference between
  "policy only" and "policy plus trace" is a real diff rather than a recollection.
