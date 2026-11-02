# Infrastructure

Where zkagent runs, and what each machine is allowed to be trusted with.

All nodes are on one Tailscale tailnet (`tailbe8207.ts.net`). Other nodes on it
belong to other projects and are deliberately not listed here: this document is
the ZK workstream's inventory, not the network's.

## Nodes

| Node | Tailscale IP | OS | Role | Observed |
|---|---|---|---|---|
| **Nastra** | 100.79.140.113 | Windows 11 | primary development host: builds, proves, verifies, runs CI-locally | online (this host) |
| **hoodbot-brain** | 100.111.194.19 | Linux, 2 vCPU / 3 GB, no GPU | droplet: candidate proving service and always-on MCP server | reachable |
| **organix** | 100.81.134.62 | Windows | previous laptop: builds and verifies | offline, last seen 1 day ago |
| **organixs** | 100.64.216.53 | Android | phone: verifier only | idle |

## What runs where, and why

**Proving is the expensive half; verification is cheap.** From
`docs/MEASUREMENTS.md`, on a laptop CPU: prove 0.66–0.70 s, verify 0.048–0.091 s.
That asymmetry decides the placement.

| Workload | Where it fits | Why |
|---|---|---|
| trusted setup (`zkagent setup`) | one machine, once | key material is circuit-specific and must not be regenerated casually |
| proving | the machine that holds the witness | the private actions should never leave the host that has them |
| verification | anywhere, including a phone | ~50–90 ms and a 712-byte verifying key |
| MCP server | an always-on node | a harness needs it available, not fast |
| block store (IPFS) | any node with disk | blocks are small: vk 712 B, proof ~2 KB, policy ~0.5 KB |

## Proving on the droplet: measured, or estimated?

**Estimated, and stated as such.** Research report 07 measured 128-byte proofs at
0.66–0.70 s on a Ryzen 7 7800X3D with a Groth16 prover peaking around 29 MB RSS.
The droplet has 2 vCPU / 3 GB, so it *should* prove comfortably — the memory floor
is two orders of magnitude below its capacity.

It has **not** been measured there, because the droplet has no Rust toolchain
build of this tree yet and the laptop cannot cross-compile to it. To turn the
estimate into a number:

```bash
# on hoodbot-brain
git clone git@github.com:MCPVOT/zkagent.git && cd zkagent
cargo build --release
./target/release/zkagent setup --seed 7 --out keys/
time ./target/release/zkagent prove --keys keys/ --policy policy.json \
      --receipt receipt.json --actions actions.json --out proof.json
```

Until that runs, no document in this repo may quote a droplet proving time.

## What a zkVM would need (and why there is none here)

Every zkVM prover in the 2026 benchmark in `docs/research/07` needs **3.3–16 GB**;
the Groth16 wrap alone wants ~14 GB. The droplet has 3 GB. This is the concrete
reason the v0 statement is a fixed-shape Groth16 circuit: it is the only proof
system that fits the infrastructure, and the statement is small enough that a
circuit is the honest choice rather than a compromise.

## Verification needs no infrastructure

A verifier needs three things, none of which require a server:

1. the verifying key (712 bytes — by CID, see `docs/IPFS.md`);
2. the manifest, receipt and proof (a few KB);
3. a clock, for the future-dating check.

That is why the phone is on the list: verification is the part that should be
portable, and it is.

## Adding a node

1. Join it to the tailnet.
2. Decide its role from the table above — do not give a node a role it cannot
   justify (a phone does not prove).
3. If it proves, record its measured prove/verify time in `docs/MEASUREMENTS.md`
   with the command used. An unmeasured node is a guess, and this file says so.
