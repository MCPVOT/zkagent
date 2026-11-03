# Security policy

This repository implements a zero-knowledge proof system. A bug here is not a
display glitch: it can make a false statement verify, or make a true one
impossible to prove.

## Reporting

**Do not open a public issue, and do not open a public PR that demonstrates the
bug.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/MCPVOT/zkagent/security/advisories/new)
(Security → Advisories → Report a vulnerability).

Please include:

- what the protocol claims, and what your input makes it do instead;
- the smallest artifact that shows it — a receipt, an actions list, a proof, or
  the exact commands;
- whether it is a **soundness** bug (a false statement verifies), a
  **completeness** bug (a true statement cannot be proven), or a
  **privacy** bug (the proof leaks information about the private witness).

## What counts as a security bug here

In priority order:

1. **Soundness.** A verifier accepts a proof for a receipt that the private
   actions do not actually justify, or accepts a policy it should refuse.
2. **Authority bypass.** A policy signature verifies under the wrong key, a
   tampered policy is accepted, or an unauthorised policy is honoured.
3. **Replay.** The same execution is accepted twice, or an unreadable replay
   ledger is treated as an empty one.
4. **Witness leak.** The proof or any artifact reveals information about the
   private actions beyond what the architecture says is public.
5. **Availability.** A crafted artifact makes a verifier panic, hang or exhaust
   memory. The verifier must never panic on hostile input.

## Known and documented limitations

These are stated in `docs/ARCHITECTURE.md` and are **not** vulnerabilities:

- the trusted setup is single-party, so whoever ran it could have forged a
  proving key (see §6 of the architecture);
- there is no revocation before expiry;
- there is no on-chain verifier;
- Ed25519 signature verification is off-chain;
- the per-action `trace_digest` is committed to a public MiMC Merkle root and
  constrained in-circuit, but nothing ties a digest to a real-world side effect:
  that still needs an oracle or a TEE that signs the trace;
- the replay ledger only grows and assumes a single writer.

Reporting one of those is still welcome, but it will be treated as a design
discussion rather than a vulnerability.

## What never enters this repository

- `authority.hex` or any authority secret
- `keys/pk.bin`, `keys/vk.bin` produced by a real deployment
- a `seen.json` from a real deployment
- `.env` files, tokens, or CI secrets

If you find a secret committed here, report it privately with the same form. Do
not paste the secret into an issue.

## Supported versions

Pre-1.0, only `master` is supported. Fixes land on `master`; there are no
maintenance branches yet.
