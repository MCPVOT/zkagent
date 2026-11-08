# Schemas

Generated from the Rust structs by `tools/gen_schemas.py`. Do not edit by hand: the check in
CI fails when a field exists in code and not here.

`pub` fields are the wire surface. A field that is not `pub` is an implementation detail and
never appears in an artifact.

## `Action`

| field | type | meaning |
| --- | --- | --- |
| `target` | `u64` | The target the action touched (must be in the policy allow-list). |
| `amount` | `u64` | The value moved by this action. |
| `trace_digest` | `u64` | Free-form per-action commitment; the agent may use it to bind a transcript hash without revealing the transcript. |

## `ActionJson`

| field | type | meaning |
| --- | --- | --- |
| `target` | `u64` | Which target was acted on. |
| `amount` | `u64` | How much was spent. |
| `trace_digest` | `u64` | Digest of the transcript for this action. |

## `ActionWitness`

| field | type | meaning |
| --- | --- | --- |
| `target` | `u64` | Target touched. |
| `amount` | `u64` | Value moved. |
| `trace_digest` | `u64` | Per-action trace commitment. Bound to the public Merkle root. |

## `ArtifactRef`

| field | type | meaning |
| --- | --- | --- |
| `cid` | `String` | CIDv1 (raw, sha2-256) of the artifact bytes. |
| `bytes` | `u64` | Length of the artifact in bytes. |
| `sha256` | `String` | Lowercase hex sha2-256, so a human can check it with `sha256sum`. |

## `AttestationManifest`

| field | type | meaning |
| --- | --- | --- |
| `kind` | `String` | Always [`MANIFEST_KIND`]. |
| `version` | `u32` | The manifest format version. |
| `circuit` | `CircuitRef` | Circuit identity. |
| `policy` | `ArtifactRef` | The signed policy artifact. |
| `receipt` | `ArtifactRef` | The receipt artifact. |
| `proof` | `ArtifactRef` | The proof artifact. |
| `created_at` | `u64` | Unix seconds when the manifest was built. |

## `AuthorizedPolicy`

| field | type | meaning |
| --- | --- | --- |
| `policy` | `Policy` | The policy itself. |
| `authority_pubkey` | `Vec<u8>` | The authority public key. |
| `signature` | `SignatureBytes` | The signature over the policy commitment. |
| `used_demo_key` | `bool` | Whether the signing key came from a reproducible demo seed.  A shell should surface this: a demo key makes the policy forgeable. |
| `created_key_file` | `bool` | Whether a new key file was created during this call. |
| `warning` | `Option<String>` | A warning the host should show the user, if any. |

## `CircuitRef`

| field | type | meaning |
| --- | --- | --- |
| `vk` | `ArtifactRef` | The verifying key, by content. This *is* the circuit identity. |
| `constraints` | `usize` | Constraint count the circuit was measured at. |
| `public_inputs` | `usize` | Public-input count. |
| `format_version` | `u32` | Proof artifact format version. |

## `Disclosure`

| field | type | meaning |
| --- | --- | --- |
| `kind` | `String` | Always [`KIND`]. |
| `version` | `u32` | Always [`VERSION`]. |
| `index` | `usize` | Which of the eight slots is being revealed. |
| `leaf_digest` | `u64` | The revealed trace digest. |
| `root` | `String` | The root this path walks to, hex-encoded little-endian. |
| `path` | `Vec<PathStep>` | Sibling hashes, leaf level first. |

## `Keys`

| field | type | meaning |
| --- | --- | --- |
| `proving` | `ProvingKey<Bn254>` | Proving key. |
| `verifying` | `VerifyingKey<Bn254>` | Verifying key. |

## `PathStep`

| field | type | meaning |
| --- | --- | --- |
| `sibling` | `String` | The other child at this level, hex-encoded little-endian. |
| `left` | `bool` | True when the node being proven is the parent's left child. |

## `Policy`

| field | type | meaning |
| --- | --- | --- |
| `max_amount` | `u64` | Maximum total value the agent may move in a single execution. |
| `max_per_action` | `u64` | Maximum value the agent may move in any single action. |
| `expires_at` | `u64` | Unix timestamp (seconds) after which the policy is no longer valid. |
| `chain_id` | `u64` | Chain / network the policy is scoped to. Prevents cross-chain replay. |
| `allowed_targets` | `Vec<u64>` | Permitted action targets (opaque identifiers chosen by the human). |

## `PolicyConformanceCircuit`

| field | type | meaning |
| --- | --- | --- |
| `policy` | `PolicyPublic` | Public policy values. |
| `receipt` | `ReceiptPublic` | Public receipt values. |
| `actions` | `Vec<ActionWitness>` | Private actions, padded to exactly [`MAX_ACTIONS`] entries. |

## `PolicyJson`

| field | type | meaning |
| --- | --- | --- |
| `max_amount` | `u64` | Total cap over the whole execution. |
| `max_per_action` | `u64` | Cap over any single action. |
| `expires_at` | `u64` | Expiry, unix seconds, exclusive. |
| `chain_id` | `u64` | Chain id the execution must belong to. |
| `allowed_targets` | `Vec<u64>` | Allowed target ids. |

## `PolicyPublic`

| field | type | meaning |
| --- | --- | --- |
| `max_amount` | `u64` | Total cap. |
| `max_per_action` | `u64` | Per-action cap. |
| `expires_at` | `u64` | Expiry timestamp. |
| `allowed_targets` | `Vec<u64>` | Allow-list padded to [`MAX_POLICY_TARGETS`]. |

## `PolicySpec`

| field | type | meaning |
| --- | --- | --- |
| `max_amount` | `u64` | Total cap over the execution. |
| `max_per_action` | `u64` | Cap over any single action. |
| `expires_at` | `u64` | Expiry, unix seconds, exclusive. |
| `chain_id` | `u64` | Chain id. |
| `targets` | `Vec<u64>` | Allowed target ids. |

## `ProofBytes`

| field | type | meaning |
| --- | --- | --- |
| `format_version` | `u32` | Artifact format version. |
| `public_inputs` | `Vec<String>` | The public inputs, in circuit order, as hex-encoded canonical field encodings. Hex rather than decimal so the bytes are unambiguous and a reader can diff two artifacts without parsing big integers. |
| `proof` | `Vec<u8>` | Compressed proof bytes. |

## `ProvenExecution`

| field | type | meaning |
| --- | --- | --- |
| `receipt` | `Receipt` | The receipt as proven, with `trace_root` filled in from the witness. |
| `proof` | `ProofBytes` | The proof artifact, whose public inputs commit to `receipt`. |

## `PublishedBundle`

| field | type | meaning |
| --- | --- | --- |
| `manifest` | `AttestationManifest` | The manifest, naming every artifact by CID. |
| `blocks` | `Vec<(String` | `(cid, bytes)` for each artifact, ready to hand to a block store. |

## `Receipt`

| field | type | meaning |
| --- | --- | --- |
| `total_amount` | `u64` | Total value moved across all actions. |
| `action_count` | `u32` | Number of actions performed. |
| `completed_at` | `u64` | Unix timestamp at which the execution completed. |
| `chain_id` | `u64` | Chain / network the execution happened on. |
| `execution_id` | `u64` | Unique identifier for this execution, chosen by the agent.  This is the anti-replay measure. Without it, two identical executions produce identical public inputs, so a proof produced once could be re-presented forever and a verifier could not tell a fresh execution from a replayed proof. The verifier must reject an id it has already seen (see `Receipt::is_replay`) and must refuse `0`, which is reserved as "unset". |
| `trace_root` | `[u8; TRACE_ROOT_BYTES]` |  |

## `ReceiptJson`

| field | type | meaning |
| --- | --- | --- |
| `total_amount` | `u64` | Sum of all action amounts. |
| `action_count` | `u32` | Number of actions claimed. |
| `completed_at` | `u64` | When the execution completed, unix seconds. |
| `chain_id` | `u64` | Chain the execution ran on. |
| `execution_id` | `u64` | Unique id of this execution; must be non-zero. |
| `trace_root` | `[u8; zkagent_core::receipt::TRACE_ROOT_BYTES]` |  |

## `ReceiptPublic`

| field | type | meaning |
| --- | --- | --- |
| `total_amount` | `u64` | Total value moved. |
| `action_count` | `u64` | Number of actions. |
| `completed_at` | `u64` | Completion timestamp. |
| `execution_id` | `u64` | Unique execution id (anti-replay). Must be non-zero. |
| `trace_root` | `CircuitField` | Merkle root over the padded per-action trace digests, as a field element. |

## `ResolvedAuthority`

| field | type | meaning |
| --- | --- | --- |
| `authority` | `Authority` | The key. |
| `used_demo_key` | `bool` | Whether it came from a reproducible demo seed (forgeable by anyone). |
| `created_key_file` | `bool` | Whether a key file was created during this call. |
| `warning` | `Option<String>` | A warning the host should show the user, if any.  The service never prints; it hands the message back so every shell can decide how to surface it. |

## `SetupOutcome`

| field | type | meaning |
| --- | --- | --- |
| `keys_dir` | `PathBuf` | Directory the key pair was written to. |
| `verifying_key_bytes` | `usize` | Size of the verifying key, bytes. |
| `proving_key_bytes` | `usize` | Size of the proving key, bytes. |

## `SignatureBytes`

| field | type | meaning |
| --- | --- | --- |
| `bytes` | `Vec<u8>` | Raw signature bytes. |

## `SignedPolicyFile`

| field | type | meaning |
| --- | --- | --- |
| `policy` | `PolicyJson` | The policy fields. |
| `authority_pubkey` | `String` | Hex-encoded compressed Ed25519 authority public key. |
| `signature` | `String` | Hex-encoded Ed25519 signature over the policy commitment. |

## `Step`

| field | type | meaning |
| --- | --- | --- |
| `sibling` | `CircuitField` | The other child of this level's parent. |
| `node_is_left` | `bool` | True when the proven node is the parent's left child. |

## `VerifiedBundle`

| field | type | meaning |
| --- | --- | --- |
| `vk` | `Vec<u8>` | Verifying key bytes. |
| `policy` | `Vec<u8>` | Signed policy bytes. |
| `receipt` | `Vec<u8>` | Receipt bytes. |
| `proof` | `Vec<u8>` | Proof bytes. |

## `VerifyOutcome`

| field | type | meaning |
| --- | --- | --- |
| `verdict` | `Verdict` | The verdict. |
| `recorded` | `bool` | Whether the execution id was newly recorded in the replay state.  `false` means the verdict was `Accept` but the id was already present (which is a replay and therefore a rejection), or that no replay state was in use. |
