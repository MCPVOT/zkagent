# Embedding zkagent

`zkagent` is a **library first**. The CLI is one shell over it, the MCP server is
another, and a Tauri app (or any plugin host) is a third. This document is the
map of those shells and the rules they inherit.

## The layers

```text
  zkagent-core      vocabulary: policy, receipt, authority, replay state
  zkagent-proofs    the Groth16 circuit and the prover
  zkagent-verifier  pure verification: (proof, inputs) -> verdict, no state
  zkagent-service   the four operations, over files  <<< embed this
  zkagent-cli       shell: arguments -> service -> human output
  zkagent-mcp       shell: JSON-RPC -> service -> tool results
```

`zkagent-service` is the only layer an embedder needs:

```toml
[dependencies]
zkagent-service = "0.1"
```

`Verdict`, `RejectReason` and `ProofBytes` are re-exported from it, so one
dependency is enough to name every value you will handle.

## The four operations

| Function | Does | Files it touches |
|---|---|---|
| `setup(keys_dir, seed)` | trusted setup, writes the key pair | `keys/vk.bin`, `keys/pk.bin` |
| `authorize(policy_path, spec, key)` | builds + signs a policy | `policy.json`, maybe the key file |
| `prove(keys_dir, policy_path, receipt, actions)` | produces the proof | reads the above |
| `verify(keys_dir, policy_path, receipt, proof, now, seen)` | verifies + replay gate | reads the above, maybe `seen.json` |

`prove` is the one-shot shape: it reads and parses `pk.bin` (~258 ms) on every
call. A host that proves more than once per process splits it:

| Function | Does |
|---|---|
| `load_keys(keys_dir)` | reads + parses the key pair, once |
| `prove_with_keys(keys, policy_path, receipt, actions)` | proves with that pair, touching no key file |

The host then owns staleness: it must notice that a key was regenerated and
reload instead of proving with the old one. `zkagent-mcp` does it with a
fingerprint of both key files (length, mtime, ctime, and a hash of the head and
tail of each); see `crates/zkagent-mcp/src/keycache.rs` and the "MCP server pays
the key load once" section of `docs/MEASUREMENTS.md` for the numbers.

## Rules every host inherits

These live in `zkagent-service`, so a host cannot get them wrong by forgetting:

1. **No printing.** The library never writes to stdout or stderr.
2. **No global state.** Everything is a parameter; two workspaces can coexist.
3. **No panics.** Every failure is a `ServiceError` carrying a path or a value.
4. **Fail closed on state.** An unreadable replay ledger is an error, never an
   empty set. A corrupt `seen.json` must stop verification, not bypass it.
5. **An acceptance that cannot be recorded is refused.** If the verifier cannot
   persist the execution id, the verification is not reported as accepted.
6. **The authority key is never defaulted.** `AuthorityKey::Seed` exists for
   tests and is flagged as `used_demo_key`; `AuthorityKey::File` creates real
   CSPRNG key material with mode `0600`.

## 1. A plain Rust host

```rust
use zkagent_service::{authorize, prove, read_actions, read_receipt, setup, verify,
                       AuthorityKey, PolicySpec};

let keys = std::path::Path::new("keys");
let policy_path = std::path::Path::new("policy.json");

setup(keys, 7)?;

let spec = PolicySpec {
    max_amount: 1_000,
    max_per_action: 300,
    expires_at: 2_000,
    chain_id: 1,
    targets: vec![3, 7, 9],
};
authorize(&policy_path, &spec, &AuthorityKey::File("authority.hex".into()))?;

let receipt = read_receipt("receipt.json".as_ref())?;
let actions = read_actions("actions.json".as_ref())?;
let proof = prove(keys, &policy_path, &receipt, &actions)?;

let outcome = verify(
    keys,
    &policy_path,
    &receipt,
    &proof,
    Some(1_700_000_000),
    Some("seen.json".as_ref()),
)?;
assert!(outcome.accepted());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## 2. A Tauri app

The Tauri command layer is three functions that take JSON-serialisable
arguments and call one service function each. A complete, compiling example
lives in `examples/tauri-plugin`:

```rust
#[tauri::command]
fn verify_execution(
    keys_dir: String,
    policy_path: String,
    receipt_path: String,
    proof_path: String,
    seen_path: Option<String>,
    now: Option<u64>,
) -> CommandResult {
    // ... read the artifacts, call zkagent_service::verify, map the error ...
}
```

Register it:

```rust
tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![verify_execution])
    .run(tauri::generate_context!())
```

and call it from the frontend:

```js
const verdict = await invoke("verify_execution", {
  keysDir: "/home/user/.zkagent/keys",
  policyPath: "/home/user/.zkagent/policy.json",
  receiptPath: "/home/user/.zkagent/receipt.json",
  proofPath: "/home/user/.zkagent/proof.json",
  seenPath: "/home/user/.zkagent/seen.json",
  now: Math.floor(Date.now() / 1000),
});
```

The example crate keeps Tauri **optional** (`--features tauri`) so it compiles
and tests on a headless CI runner without the WebView dependency tree.

## 3. An agent harness (MCP)

The `zkagent-mcp` binary speaks JSON-RPC 2.0 over stdio:

```bash
zkagent-mcp
```

Tools: `zkagent_setup`, `zkagent_authorize`, `zkagent_prove`, `zkagent_verify`,
`zkagent_status`. Every tool is path-based, so the harness chooses where the
workspace lives.

Point a harness at it (the shape varies by harness):

```json
{
  "mcpServers": {
    "zkagent": {
      "command": "zkagent-mcp",
      "args": []
    }
  }
}
```

In Hermes, the same server is configured as a local MCP server and its tools
become callable directly.

**stdout is the protocol channel.** Nothing else may be written there. The
server prints diagnostics to stderr only, and the CI job asserts that a
full MCP round-trip produces exactly one response per request.

## 4. The CLI

```bash
zkagent setup  --seed 7 --out keys/
zkagent policy --max-amount 1000 --max-per-action 300 --expires-at 2000 \
               --chain-id 1 --targets 3,7,9 --authority-key authority.hex --out policy.json
zkagent prove  --keys keys/ --policy policy.json --receipt receipt.json \
               --actions actions.json --out proof.json
zkagent verify --keys keys/ --policy policy.json --receipt receipt.json \
               --proof proof.json --now 1600 --seen seen.json
```

Exit codes: `0` accept, `1` rejected, `2` usage or I/O error.

## What an embedder must NOT re-implement

Each of these is a rule, and re-implementing it is how two shells drift apart:

| Rule | Where it lives |
|---|---|
| policy validation | `zkagent_core::Policy::new` |
| the replay gate | `zkagent_service::verify` |
| fail-closed on unreadable state | `zkagent_service::verify` |
| refusing an unrecordable acceptance | `zkagent_service::verify` |
| the authority key never defaulting | `zkagent_service::resolve_authority` |
| the public-input order and binding | `zkagent_proofs::public_inputs` |

If a host needs a rule that is not in that table, the rule is missing from the
library. Add it there, not in the host.
