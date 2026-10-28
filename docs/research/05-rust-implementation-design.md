# 05 — Rust Implementation Design Spec (zkagent)

> **Provenance.** Every number in this report was measured on an **arkworks
> 0.6.0** probe tree, and the probe circuit is an earlier shape than the shipped
> v0. The shipped circuit measures **3 333 constraints / 15 public inputs**
> (`docs/MEASUREMENTS.md`). This report's 2 162 / 9 is the probe, not the
> product. See `README.md#measurement-provenance`.

Status: implementation-ready design. Every arkworks API in §2 was **compiled and executed** on this
machine against the exact pinned versions, not recalled from memory. The probe program whose output is
quoted in §4.6/§6.2 is the reference implementation of the circuit, and its full source is in
**Appendix B** — an engineer can copy it and have the protocol's core running in one build.

Verification environment (measured, not assumed):

| machine | rustc | arch | build time (clean, `--release`, -j2) | peak build RSS |
|---|---|---|---|---|
| laptop (Windows 11, git-bash) | 1.97.1 (8bab26f4e 2026-07-14) | x86_64-pc-windows-msvc | ~3 min | n/a |
| droplet `hoodbot@100.111.194.19` | 1.98.1 (48a229cea 2026-09-01) | 2 vCPU / 3.9 GB, no GPU | 3 m 14 s | 509 984 kB |

Everything below is CPU-only. No GPU, no trusted setup ceremony, no external service.

---

## 1. Workspace and dependency list

### 1.1 Layout

```
zkagent/
  Cargo.toml                  # [workspace] only, no [package]
  rust-toolchain.toml         # channel = "1.80" (see MSRV note)
  .cargo/config.toml          # vendored-source replacement (§8.3)
  vendor/                     # 95 MB, `cargo vendor --versioned-dirs`
  crates/
    zkagent-core/             # types + canonical encoding + hashing (no ark-groth16)
    zkagent-proofs/           # circuit + prover/verifier wrappers
    zkagent-verifier/         # CLI: verify receipt, plus solidity-calldata emitter
    zkagent-cli/              # CLI: policy sign, receipt prove, keygen
  tests/                      # workspace-level integration + negative tests
    common/mod.rs
    e2e_happy.rs
    neg_amount_over_max.rs
    neg_target_not_allowed.rs
    neg_wrong_policy_key.rs
    neg_replay_nonce.rs
    neg_tampered_receipt.rs
    neg_policy_swap.rs
  contracts/
    ZkAgentVerifier.sol
```

### 1.2 Exact dependency set

All versions below are what `Cargo.lock` resolved and what compiled. Nothing is a caret range you have
to re-derive.

| crate | version | licence (crates.io) | `rust-version` in crate | role |
|---|---|---|---|---|
| `ark-bn254` | 0.6.0 | MIT OR Apache-2.0 | — (inherits 1.75 from ark-ec) | `Bn254`, `Fr`, `G1Projective`, `G1Affine` |
| `ark-ff` | 0.6.0 | MIT OR Apache-2.0 | 1.75 | `PrimeField`, `BigInteger`, `ToConstraintField` |
| `ark-ec` | 0.6.0 | MIT OR Apache-2.0 | 1.75 | `AffineRepr::x()/y()`, `CurveGroup` |
| `ark-poly` | 0.6.0 | MIT/Apache-2.0 | 1.75 | transitively required by `ark-relations` |
| `ark-groth16` | 0.6.0 | MIT/Apache-2.0 | — | `Groth16`, `ProvingKey`, `VerifyingKey`, `Proof` |
| `ark-relations` | 0.6.0 | MIT/Apache-2.0 | — | `gr1cs::{ConstraintSynthesizer, ConstraintSystem}` |
| `ark-r1cs-std` | 0.6.0 | MIT/Apache-2.0 | — | `FpVar`, `UInt64`, `Boolean`, `CmpGadget`, `AllocVar` |
| `ark-crypto-primitives` | 0.6.0 (features `sponge`, `constraints`, `signature`) | MIT/Apache-2.0 | — | Poseidon sponge + gadget, Schnorr signature |
| `ark-serialize` | 0.6.0 | MIT OR Apache-2.0 | 1.75 | `CanonicalSerialize`, `Compress`, `Validate` |
| `ark-std` | 0.6.0 | MIT/Apache-2.0 | — | `rand` re-export, `cfg_iter!`, `OnceLock` re-export |
| `ark-snark` | 0.6.0 | MIT/Apache-2.0 | — | *optional*: the `SNARK` trait, if you want generic code (see §2.6) |
| `blake2` | 0.10.6 | MIT OR Apache-2.0 | — | `Blake2s256` as the Schnorr Fiat-Shamir digest |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 | — (0.10.9; the 0.11 line needs 1.85) | `human_pk_hash` (§4.4) |
| `serde` | 1.x + `derive` | MIT OR Apache-2.0 | — | policy/receipt JSON |
| `serde_json` | 1.x | MIT OR Apache-2.0 | — | canonical *bytes* are hand-rolled, JSON is transport only |
| `clap` | 4.x (`derive`) | MIT OR Apache-2.0 | 1.74 | CLI parsing |
| `hex` | 0.4 | MIT OR Apache-2.0 | — | display/parse |
| `thiserror` | 2.x | MIT OR Apache-2.0 | — | error enums |
| `anyhow` | 1.x | MIT OR Apache-2.0 | — | CLI top level only |

Rows pinned to a bare major (`serde`, `serde_json`, `clap`, `hex`, `thiserror`, `anyhow`) are **not** in
the probe — the reference circuit needs none of them. Every `ark-*`, `blake2` and `sha2` version above is
what `Cargo.lock` actually resolved and built; pin those exactly, and pin the six remaining to whatever
`cargo update -p <crate> --precise` lands on at first build, then freeze the lockfile.

Transitive closure: **76 crates for the host target** (`cargo tree --prefix none | sed 's/ (\*)$//' | awk '{print $1}' | sort -u | grep -v '^zkproto$' | wc -l` → 76); `Cargo.lock` holds 149 entries because it also pins Windows/wasm-only deps that never build here.
Notable transitives and licences: `rayon 1.12.0` (MIT OR Apache-2.0), `tracing 0.1.44` (MIT),
`merlin 3.0.0` (MIT), `indexmap 2.14.2` / `1.9.3` (MIT OR Apache-2.0), `hashbrown 0.17.1` / `0.12.3`
(MIT OR Apache-2.0), `num-bigint 0.4.8` (MIT OR Apache-2.0), `zeroize 1.9.1` (MIT OR Apache-2.0),
`digest 0.10.7` (MIT OR Apache-2.0), `generic-array 0.14.7` (MIT), `typenum 1.20.1` (MIT),
`derivative 2.2.0` (MIT OR Apache-2.0), `educe 0.6.0` (MIT), `itertools 0.14.0` (MIT OR Apache-2.0),
`ahash`/`foldhash` (MIT OR Apache-2.0). No copyleft, no `ring`, no `openssl-sys`, no `cc`-built C in the
critical path.

DEVIATION FROM THE BRIEF, CORRECTED: **there is no `ark-schnorr` crate.** crates.io search for
`ark-schnorr` returns nothing from arkworks (`schnorr`, `schnorr-rs`, `schnorr_fun`, `schnorr_pok` are
all third-party). The arkworks Schnorr implementation ships inside `ark-crypto-primitives` at
`signature/schnorr/mod.rs`, gated behind the non-default feature `signature`. Use
`ark_crypto_primitives::signature::schnorr::Schnorr<C, D>` (§2.5). Anything in the sibling research docs
referring to "ark-schnorr" should be corrected to this path.

### 1.3 MSRV

`ark-ff`, `ark-ec`, `ark-poly`, `ark-serialize` declare `rust-version = "1.75"`. `ark-groth16`,
`ark-relations`, `ark-r1cs-std`, `ark-crypto-primitives`, `ark-std`, `ark-bn254`, `ark-snark` declare no
`rust-version` at all — their *effective* MSRV is bounded by what they import from the 1.75 crates plus
`OnceLock` (`ark-std::sync::OnceLock` is a re-export, so 1.70+). Practical floor: **1.75**, which is what
`rust-toolchain.toml` should pin. Both target machines (1.97.1, 1.98.1) are far above it; the pin exists
so CI on a future toolchain does not silently drift the numbers in §4.6.

### 1.4 Offline / vendored build — verified

`cargo vendor --versioned-dirs vendor` produced **95 MB**. With

```toml
# .cargo/config.toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

`cargo build --release --offline` succeeded from a cold target dir in **2 m 46 s** and the binary printed
identical constraint counts and a `verify = true`. So: yes, the tree builds fully offline. Vendor the
directory into the repo or ship it as a release tarball; the 95 MB includes test/bench sources of
transitives, which is fine.

---

## 2. arkworks API surface — exact signatures

Everything in this section is copied from the crate sources as published on crates.io (the same bytes as
GitHub tag `v0.6.0`) or from the compiled probe. File paths are relative to the crate root in
`~/.cargo/registry/src/index.crates.io-*/`.

### 2.0 The 0.6.0 breaking changes that will bite an engineer working from older tutorials

1. `ark_relations::r1cs` **does not exist** in 0.6.0. The module is `ark_relations::gr1cs`
   (`ark-relations-0.6.0/src/lib.rs:37`). `r1cs` was renamed to `gr1cs` (Generalized R1CS).
2. `ConstraintSystemRef::enforce_constraint` now takes a predicate label as its first argument
   (`ark-relations-0.6.0/src/gr1cs/constraint_system.rs:241`). For plain R1CS semantics use
   `enforce_r1cs_constraint(a, b, c)` (`:431`), which is the drop-in replacement for the old
   `enforce_constraint`.
3. `Groth16::create_random_proof` **does not exist**. The methods are
   `create_random_proof_with_reduction` (`src/prover.rs:141`) and, for a generic entry point, the
   `SNARK::prove` trait method.
4. `generate_random_parameters_with_reduction` returns **only a `ProvingKey`**, not a tuple
   (`src/generator.rs:18`). The verifying key is `pk.vk.clone()`.
5. `Groth16` implements `SNARK` from **`ark-snark`**, not from `ark_crypto_primitives::snark`
   (0.5.0 used the latter: `groth16 v0.5.0 src/lib.rs:47` imports `ark_crypto_primitives::snark::*`).

### 2.1 Circuit trait

```rust
// ark-relations-0.6.0/src/gr1cs/mod.rs:54-61
pub trait ConstraintSynthesizer<F: Field> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> crate::gr1cs::Result<()>;
}
```

Import as `use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};`.
`Result` is `crate::gr1cs::Result`. Note `generate_constraints` takes `self` **by value** — the circuit
must be `Clone` if you want to synthesize twice (setup then prove), which is why every struct in §5 is
`#[derive(Clone)]`.

### 2.2 Constraint allocation

```rust
// ark-relations-0.6.0/src/gr1cs/constraint_system.rs
pub fn new_ref() -> ConstraintSystemRef<F>            // :142, on ConstraintSystem<F>
pub fn new_input_variable<Func>(&mut self, f: Func) -> crate::utils::Result<Variable>   // :591
    where Func: FnOnce() -> crate::utils::Result<F>
pub fn new_witness_variable<Func>(&mut self, f: Func) -> crate::utils::Result<Variable> // :606
pub fn num_constraints(&self) -> usize            // :210
pub fn num_instance_variables(&self) -> usize     // :218
pub fn num_witness_variables(&self) -> usize      // :223
pub fn is_satisfied(&self) -> crate::utils::Result<bool>   // :652
pub fn enforce_r1cs_constraint(
    &mut self,
    a: impl FnOnce() -> LinearCombination<F>,
    b: impl FnOnce() -> LinearCombination<F>,
    c: impl FnOnce() -> LinearCombination<F>,
) -> crate::gr1cs::Result<()>                     // :431
```

Gadget-level allocation comes from `ark-r1cs-std`'s `AllocVar`:

```rust
// ark-r1cs-std-0.6.0/src/alloc.rs:40-47
pub trait AllocVar<V: ?Sized, F: Field>: Sized {
    fn new_variable<T: Borrow<V>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError>;
    // provided: new_input(...) -> Result<Self, SynthesisError>
    // provided: new_witness(...), new_constant(...)
}
```

`Namespace<F>: From<ConstraintSystemRef<F>>` (`src/gr1cs/namespace.rs:12-18`), so you can pass
`cs.clone()` directly. `FpVar::new_input(cs.clone(), || Ok(x))` and `FpVar::new_witness(cs, || Ok(x))` are
what the probe uses and they compile as written.

### 2.3 Groth16 — setup, prove, verify

```rust
// ark-groth16-0.6.0/src/lib.rs:49-51
pub struct Groth16<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> { _p: PhantomData<(E, QAP)> }

// ark-groth16-0.6.0/src/generator.rs:18
pub fn generate_random_parameters_with_reduction<C>(
    circuit: C,
    rng: &mut impl Rng,          // ark_std::rand::Rng
) -> R1CSResult<ProvingKey<E>>
where C: ConstraintSynthesizer<E::ScalarField>, QAP: R1CSToQAP

// ark-groth16-0.6.0/src/prover.rs:141-152
pub fn create_random_proof_with_reduction<C>(
    circuit: C,
    pk: &ProvingKey<E>,
    rng: &mut impl Rng,
) -> R1CSResult<Proof<E>>
where C: ConstraintSynthesizer<E::ScalarField>

// ark-groth16-0.6.0/src/verifier.rs:13
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E>

// ark-groth16-0.6.0/src/verifier.rs:66-75
pub fn verify_proof(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::ScalarField],
) -> R1CSResult<bool>

// ark-groth16-0.6.0/src/verifier.rs:25-37  (preferred if the inputs are known up front)
pub fn prepare_inputs(pvk: &PreparedVerifyingKey<E>, public_inputs: &[E::ScalarField])
    -> R1CSResult<E::G1>
// ark-groth16-0.6.0/src/verifier.rs:41-47
pub fn verify_proof_with_prepared_inputs(
    pvk: &PreparedVerifyingKey<E>, proof: &Proof<E>, prepared_inputs: &E::G1,
) -> R1CSResult<bool>

// ark-groth16-0.6.0/src/prover.rs:231  (proof re-randomisation — see §9.2.5, receipts are NOT unique)
pub fn rerandomize_proof(...) -> R1CSResult<Proof<E>>
```

Data structures (`ark-groth16-0.6.0/src/data_structures.rs`):

```rust
pub struct Proof<E: Pairing> { pub a: E::G1Affine, pub b: E::G2Affine, pub c: E::G1Affine }   // :9-16
pub struct VerifyingKey<E: Pairing> {                                                          // :32
    pub alpha_g1: E::G1Affine, pub beta_g2: E::G2Affine,
    pub gamma_g2: E::G2Affine, pub delta_g2: E::G2Affine,
    pub gamma_abc_g1: Vec<E::G1Affine>,
}
pub struct PreparedVerifyingKey<E: Pairing> {                                                  // :88
    pub vk: VerifyingKey<E>, pub alpha_g1_beta_g2: E::TargetField,
    pub gamma_g2_neg_pc: E::G2Prepared, pub delta_g2_neg_pc: E::G2Prepared,
}
pub struct ProvingKey<E: Pairing> {                                                             // :126
    pub vk: VerifyingKey<E>, pub beta_g1: E::G1Affine,
    pub a_query: Vec<E::G1Affine>, pub h_query: Vec<E::G1Affine>, pub l_query: Vec<E::G1Affine>,
}
```

All four derive `CanonicalSerialize, CanonicalDeserialize` (`:7-8`, `:30-31`, `:86-87`, `:124-125`), so
`pk.serialize_compressed`, `vk.serialize_compressed`, `proof.deserialize_compressed` all work — measured
sizes in §4.6.

The verification equation actually implemented (`src/verifier.rs:41-63`) is
`e(A,B) = e(alpha,beta) · e(prepared_inputs, gamma) · e(C, delta)`, equivalently
`e(-A,B) · e(alpha,beta) · e(vk_x,gamma) · e(C,delta) == 1`. That is exactly the pairing-check form
EIP-197 exposes (§7).

BEWARE: `num_instance_variables()` returns **N+1** for N public inputs, because arkworks inserts a
constant `one` as instance variable 0. With 9 public inputs the probe reports `num_instance = 10`, and
`verify_proof` still takes the 9-element slice. If your verifier asserts
`proof_inputs.len() == cs.num_instance_variables()` it will be off by one.

### 2.4 Field / integer gadgets

```rust
// ark-r1cs-std-0.6.0/src/lib.rs:87-92
pub mod uint64 { pub type UInt64<F> = super::uint::UInt<64, u64, F>; }

// ark-r1cs-std-0.6.0/src/uint/cmp.rs:5-17
impl<const N: usize, T: PrimUInt, F: PrimeField + From<T>> CmpGadget<F> for UInt<N, T, F> {
    fn is_ge(&self, other: &Self) -> Result<Boolean<F>, SynthesisError>;
}
// ark-r1cs-std-0.6.0/src/cmp.rs:7-24
pub trait CmpGadget<F: Field>: GR1CSVar<F> + EqGadget<F> {
    fn is_gt(&self, other: &Self) -> Result<Boolean<F>, SynthesisError>;   // default: other.is_lt(self)
    fn is_ge(&self, other: &Self) -> Result<Boolean<F>, SynthesisError>;
    fn is_lt(&self, other: &Self) -> Result<Boolean<F>, SynthesisError>;   // default: !self.is_ge(other)
    fn is_le(&self, other: &Self) -> Result<Boolean<F>, SynthesisError>;   // default: other.is_ge(self)
}
```

`UInt64::to_fp()` converts to `FpVar<F>` (`src/uint/convert.rs`), and `FpVar::{one,zero}` are on the
`FieldVar` trait (`ark_r1cs_std::fields::FieldVar`) — you must `use ark_r1cs_std::fields::FieldVar;` or
`FpVar::one()` fails to resolve. The probe hit this exact error; it is the single most common papercut.

`Boolean<F>` → `FpVar<F>` is a plain `Into` (`let eq_f: FpVar<F> = eq_b.into();`), which is how the
allow-list product in §4.3 is built.

### 2.5 Schnorr (human policy signature)

```rust
// ark-crypto-primitives-0.6.0/src/signature/mod.rs:12-46
pub trait SignatureScheme {
    type Parameters: Clone + Send + Sync;
    type PublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: CanonicalSerialize + Clone + Default;
    type Signature: Clone + Default + Send + Sync;
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;
    fn keygen<R: Rng>(pp: &Self::Parameters, rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey), Error>;
    fn sign<R: Rng>(pp: &Self::Parameters, sk: &Self::SecretKey, message: &[u8], rng: &mut R)
        -> Result<Self::Signature, Error>;
    fn verify(pp: &Self::Parameters, pk: &Self::PublicKey, message: &[u8], signature: &Self::Signature)
        -> Result<bool, Error>;
}

// ark-crypto-primitives-0.6.0/src/signature/schnorr/mod.rs
pub struct Schnorr<C: CurveGroup, D: Digest> { /* PhantomData */ }        // :16
pub struct Parameters<C: CurveGroup, H: Digest> { pub generator: C::Affine, pub salt: [u8; 32] }  // :23
pub type PublicKey<C> = <C as CurveGroup>::Affine;                        // :29
pub struct SecretKey<C>(pub C::ScalarField);                              // :32
pub struct Signature<C: CurveGroup> {                                     // :35
    pub prover_response: C::ScalarField,
    pub verifier_challenge: C::ScalarField,
}
impl<C: CurveGroup + Hash, D: Digest + Send + Sync> SignatureScheme for Schnorr<C, D>  // :40
```

Three concrete facts that cost the probe a compile iteration each:

* `public_key` is **already affine** (`PublicKey<C> = C::Affine`). `pk.into_affine()` does not exist;
  use `pk.xy()` → `Option<(BaseField, BaseField)>` (`ark-ec-0.6.0/src/lib.rs:161`), then
  `pk.x()` / `pk.y()` (`:168`, `:173`).
* `Signature<C>` derives only `Clone, Default, Debug` (`:34`) — **no `CanonicalSerialize`**. You must
  encode it yourself: two `Fr` scalars, 32 bytes each compressed, 64 bytes total (measured). Wrap it in a
  newtype with a documented layout so the on-chain path and the CLI agree.
* `sign()` inside hashes `salt || commitment || message.serialize_compressed()` — i.e. the *canonical
  serialization of the message slice*, not the raw bytes (`:93-96`). Verify must hash the same encoding
  (`:134-137`). If you pass raw bytes anywhere, signatures silently never verify.

Signature over an `Fr` commitment in practice (from the probe, compiles and verifies):

```rust
type Sig = Schnorr<ark_bn254::G1Projective, blake2::Blake2s256>;
let pp = Sig::setup(&mut rng)?;
let (pk, sk) = Sig::keygen(&pp, &mut rng)?;
let mut msg = Vec::new();
policy_commitment.serialize_compressed(&mut msg)?;   // 32 bytes
let sig = Sig::sign(&pp, &sk, &msg, &mut rng)?;
assert!(Sig::verify(&pp, &pk, &msg, &sig)?);
```

### 2.6 Optional: generic SNARK plumbing

```rust
// ark-groth16-0.6.0/src/lib.rs:53-101
impl<E: Pairing, QAP: R1CSToQAP> SNARK<E::ScalarField> for Groth16<E, QAP> {
    type ProvingKey = ProvingKey<E>;  type VerifyingKey = VerifyingKey<E>;
    type Proof = Proof<E>;            type ProcessedVerifyingKey = PreparedVerifyingKey<E>;
    type Error = SynthesisError;
    fn circuit_specific_setup<C, R: RngCore>(circuit: C, rng: &mut R) -> Result<(ProvingKey<E>, VerifyingKey<E>), SynthesisError>;
    fn prove<C, R: RngCore>(pk: &ProvingKey<E>, circuit: C, rng: &mut R) -> Result<Proof<E>, SynthesisError>;
    fn process_vk(vk: &VerifyingKey<E>) -> Result<PreparedVerifyingKey<E>, SynthesisError>;
    fn verify_with_processed_vk(pvk: &PreparedVerifyingKey<E>, x: &[E::ScalarField], proof: &Proof<E>) -> Result<bool, SynthesisError>;
}
```

Only reach for this if you want to swap in another `ark-snark` backend. `add ark-snark = "0.6.0"` — it is
*not* re-exported by `ark-groth16` (only `use ark_snark::*;` internally, `src/lib.rs:44`).

### 2.7 Poseidon sponge (the in-circuit hash)

```rust
// ark-crypto-primitives-0.6.0/src/sponge/mod.rs
pub trait CryptographicSponge: Clone {                    // :106
    type Config;
    fn new(params: &Self::Config) -> Self;                // :111
    fn absorb(&mut self, input: &impl Absorb);            // :114
}
pub trait FieldBasedCryptographicSponge<CF: PrimeField>: CryptographicSponge {  // :163
    fn squeeze_field_elements<F: PrimeField>(&mut self, num_elements: usize) -> Vec<F>;  // :143 (default impl)
}

// ark-crypto-primitives-0.6.0/src/sponge/poseidon/mod.rs
pub struct PoseidonConfig<F: PrimeField> {                // :27
    pub full_rounds: usize, pub partial_rounds: usize, pub alpha: u64,
    pub ark: Vec<Vec<F>>, pub mds: Vec<Vec<F>>, pub rate: usize, pub capacity: usize,
}
pub struct PoseidonSponge<F: PrimeField> { pub parameters: PoseidonConfig<F>, /* state, mode */ }  // :54

// ark-crypto-primitives-0.6.0/src/sponge/poseidon/traits.rs:105
pub fn find_poseidon_ark_and_mds<F: PrimeField>(
    prime_bits: u64, rate: usize, full_rounds: u64, partial_rounds: u64, skip_matrices: u64,
) -> (Vec<Vec<F>>, Vec<Vec<F>>);

// ark-crypto-primitives-0.6.0/src/sponge/poseidon/constraints.rs
pub struct PoseidonSpongeVar<F: PrimeField> { pub cs: ConstraintSystemRef<F>, pub parameters: PoseidonConfig<F>, /* … */ }  // :19
impl<F: PrimeField> CryptographicSpongeVar<F, PoseidonSponge<F>> for PoseidonSpongeVar<F> {  // :183
    fn new(cs: ConstraintSystemRef<F>, params: &PoseidonConfig<F>) -> Self;                  // :187
    fn absorb(&mut self, input: &impl AbsorbGadget<F>) -> Result<(), SynthesisError>;        // :208
    fn squeeze_field_elements(&mut self, num: usize) -> Result<Vec<FpVar<F>>, SynthesisError>; // :266
}
```

`AbsorbGadget<F>` is implemented for `FpVar<F>`, `Boolean<F>`, `UInt8<F>`, and for `Vec<A>` / `&[A]` where
`A: AbsorbGadget<F>` (`src/sponge/constraints/absorb.rs:56,74,84,168,178`). So `sp.absorb(&vec_of_fpvar)`
compiles and is what the probe does. Features required: `sponge` **and** `constraints`
(`src/sponge/poseidon/mod.rs:11-13` gates the gadget module on `constraints`).

DEAD END, DOCUMENTED: `ark_crypto_primitives::sponge::rescue` exists but has no BN254 parameter set and
`merlin`/`STROBE` is transcript-only. Poseidon with Grain-LFSR-generated parameters is the only
arkworks-native option that also has an in-circuit counterpart. Do not use SHA-256 in-circuit
(`crh::sha256` costs ~27k constraints per block); the only place SHA-256 appears in this design is
`human_pk_hash`, computed natively (§4.4).

### 2.8 Serialization (`ark-serialize`)

Every type in the protocol (proof, vk, pk, `Fr` elements) travels as arkworks canonical bytes:

```rust
// ark-serialize-0.6.0/src/lib.rs
pub enum Compress   { No, Yes }          // :57
pub enum Validate   { No, Yes }          // :65

pub trait CanonicalSerialize {
    fn serialized_size(&self, compress: Compress) -> usize;                             // :135
    fn serialize_compressed<W: Write>(&self, writer: W) -> Result<(), SerializationError>;  // :138 (provided)
    fn serialize_uncompressed<W: Write>(&self, writer: W) -> Result<(), SerializationError>;
}
pub trait CanonicalDeserialize: Sized {
    fn deserialize_compressed<R: Read>(reader: R) -> Result<Self, SerializationError>;   // :184
    fn deserialize_compressed_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError>;  // :198
}
```

Rules for `zkagent-proofs`:

* Always `deserialize_compressed` (validating), never `..._unchecked`. The unchecked variant skips the
  subgroup check on curve points — for a verifier consuming an attacker-supplied proof that is a
  correctness bug, not a performance win.
* `Proof<Bn254>` serialises to **128 bytes** (`a`: 32 compressed G1, `b`: 64 compressed G2, `c`: 32);
  `VerifyingKey` to **552 bytes**; `ProvingKey` to **479 056 bytes** (all measured, §4.6).
* These lengths are protocol constants. Assert them in a unit test — a silent arkworks minor bump that
  changes an encoding must break the build, not the wire format.
* Canonical bytes are for storage/transport only. They are **not** calldata for the EVM; §7.3 converts.

---

## 3. Protocol objects and canonical encoding

`zkagent-core` owns these. **All hashing inputs are produced by one canonical encoder**; the encoder is
the security boundary, so it is hand-rolled and byte-stable, not derived from `serde_json`.

### 3.1 Domain separation

```rust
// crates/zkagent-core/src/domain.rs
pub const DOMAIN_POLICY:   &[u8; 16] = b"zkagent/policy:v";
pub const DOMAIN_RECEIPT:  &[u8; 16] = b"zkagent/rcept:v1";
pub const DOMAIN_SIG:      &[u8; 16] = b"zkagent/sig:v1::";
pub const PROTOCOL_VERSION: u8 = 1;
```

DESIGN: every hash preimage starts with the relevant tag. The verifier rejects an unknown tag before it
does any curve arithmetic. This is what stops a policy commitment from ever being reinterpreted as a
receipt commitment (§9.2, cross-object substitution).

### 3.2 Canonical byte encoding

DESIGN: fixed-width, big-endian, no optional fields, no map ordering problem.

| field | width | notes |
|---|---|---|
| `domain` | 16 | §3.1 tag, ASCII, zero-padded |
| `version` | 1 | `PROTOCOL_VERSION` |
| `chain_id` | 8 | u64 BE |
| `nonce` | 32 | `Fr` compressed (canonical, as produced by `CanonicalSerialize`) |
| `expiry` | 8 | u64 BE (unix seconds) |
| `max_spend` | 8 | u64 BE |
| `asset_id` | 32 | `Fr` compressed |
| `allowlist_len` | 1 | u8, must be `<= ALLOWLIST_LEN` |
| `allowlist` | 32 × ALLOWLIST_LEN | `Fr` compressed, **unused slots must be `Fr::zero()`** |
| `human_pk_hash` | 32 | `Fr` from SHA-256 of the compressed pk (§4.4) |

`Fr` "compressed" here means `CanonicalSerialize::serialize_compressed` — for BN254 that is 32 bytes
little-endian magnitude with three flag bits in the top of the last byte
(`ark-serialize-0.6.0/src/lib.rs:57` `Compress::Yes`; the `Fr` impl lives in `ark-ff`). It is *not* the
same encoding as `into_bigint().to_bytes_be()`. Mixing the two is the second most likely
interop bug in this project; §7 fixes the convention for the Solidity boundary explicitly.

Zero-padding unused allow-list slots is not cosmetic: the commitment hashes all `ALLOWLIST_LEN` slots, so
a policy that is "valid" under padding and one that is not produce different commitments only if the
padding is deterministic. Enforce `Fr::zero()` padding in `Policy::validate()`.

---

## 4. Circuit design

### 4.1 Statement proved

> "I know a policy P and a receipt R such that: `commit(P) = policy_commitment`, `commit(P, R) =
> receipt_commitment`, `R.amount ≤ P.max_spend`, `R.amount` is the integer `amount`,
> `R.target ∈ P.allowlist`, `now ≤ P.expiry`, and `R.asset_id / R.chain_id / R.nonce / R.expiry` equal
> the published values."

Public inputs (9, in this exact order — index 0..8 of the `&[Fr]` passed to `verify_proof`):

| # | name | who sets it | why public |
|---|---|---|---|
| 0 | `policy_commitment` | human signature covers it | binds proof to the signed policy |
| 1 | `human_pk_hash` | verifier recomputes from presented pk | attributes the receipt to a principal |
| 2 | `receipt_commitment` | agent, from its trace | the receipt ID / replay handle |
| 3 | `amount` | receipt | verifier must see the spend |
| 4 | `asset_id` | receipt | verifier must see the asset |
| 5 | `target` | receipt | verifier must see the tool/contract |
| 6 | `chain_id` | receipt | replay fence across chains |
| 7 | `nonce` | receipt | replay fence within a chain |
| 8 | `now` | verifier, at verification time | makes expiry a real constraint |

Private witness: `max_spend`, `expiry`, `allowlist[0..8]`, `allowlist_len`, `trace_digest`, and the
redundant copies used to reconcile `UInt64` and `FpVar` representations.

### 4.2 Constraints, in order (C1–C7)

| id | constraint | gadget | cost |
|---|---|---|---|
| C1 | `amount_u64.to_fp() == amount` and `now_u64.to_fp() == now` | `UInt64::to_fp`, `EqGadget::enforce_equal` | 64 + 64 bit-decomposition constraints + 2 |
| C2 | `amount_u64 ≤ max_spend_u64` | `CmpGadget::is_le` then `enforce_equal(Boolean::TRUE)` | ~68 |
| C3 | `now_u64 ≤ expiry_u64` | same | ~68 |
| C4 | `asset/target/chain/nonce` witness == public | 4 × `enforce_equal` on `FpVar` | 4 |
| C5 | `Π_i (1 - [allow[i] == target]) == 0` | `EqGadget::is_eq` + `FieldVar` mult | 8 × ~2 + 7 |
| C6 | `Poseidon(pk_hash, max, asset, chain, nonce, expiry, len, allow[0..8]) == policy_commitment` | `PoseidonSpongeVar` | 4 permutations × ≈290 = **1 162** (measured) |
| C7 | `Poseidon(policy_commitment, trace_digest, amount, asset, target, nonce, chain, expiry) == receipt_commitment` | `PoseidonSpongeVar` | 2 permutations × ≈290 = **580** (measured) |

**Measured total: 2 162 constraints** (2 163 witness variables, 9 public inputs + the arkworks `one`
constant = `num_instance_variables() == 10`). Breakdown, all measured on the probe: one rate-4 Poseidon
permutation costs **289–291 constraints** (`hash(4 elems) = 289`, `hash(8) = 580`, `hash(15) = 1 162`), so
C6 + C7 = 1 742 and C1–C5 account for the remaining **420**. The analytical check agrees: 8 full rounds ×
5 S-boxes × 3 mults + 57 partial rounds × 3 mults ≈ 291 per permutation, since `x^5` is 3
multiplications and the MDS/round-key steps are free linear combinations. The per-row figures in the
table above are analytical lower bounds (they sum to ~293); the **420** measured for C1–C5 is authoritative
— the difference is `UInt64` allocation and bit-decomposition bookkeeping that the per-row view hides.

### 4.3 The two constraints people get wrong

**`amount <= max`.** Do not write this as an `FpVar` comparison. If `amount` is an `FpVar` there is no
order on `Fr`, and any "compare as field elements" trick is either a different relation or unsound.
The correct construction, and the one in the probe:

```rust
let amount_u = UInt64::new_witness(cs.clone(), || Ok(receipt.amount))?;   // true u64 in-circuit
amount_u.to_fp()?.enforce_equal(&amount_pub)?;                            // pins the integer
amount_u.is_le(&max_spend)?.enforce_equal(&Boolean::TRUE)?;               // 64-bit compare
```

`enforce_equal(amount_pub)` is what rules out the otherwise-fatal aliasing `amount = 2^64 + k` (both
would satisfy a naive `UInt64` decomposition of a different witness). This is why `amount` is a `u64` in
the data model and not an `Fr`.

**`target in allow-list`.** Because the allow-list is *private*, no Merkle path is needed — the list
itself is witness. Membership becomes:

```rust
let mut prod = FpVar::one();
for a in &allow_vars {
    let eq_f: FpVar<Fr> = a.is_eq(&target_w)?.into();
    prod = prod * (FpVar::one() - eq_f);
}
prod.enforce_equal(&FpVar::zero())?;      // product is 0 iff at least one slot matched
```

O(K) constraints total, no path, no tree. Say it plainly: **this does not scale to a large allow-list.**
At K = 8 the cost is ~23 constraints; at K = 1 000 it would be ~3 000 constraints and a 32 KB proving key
per list. If you ever need K > ~64, switch to a Poseidon Merkle root inside the policy and an O(log K)
path — the commitment arity drops and the membership cost becomes ~290·log2(K).

### 4.4 The policy commitment and how the proof is bound to the human key

```
policy_commitment = Poseidon_rate4_cap1( DOMAIN_POLICY ,
                                         human_pk_hash, max_spend, asset_id, chain_id,
                                         nonce, expiry, allowlist_len, allowlist[0..8] )
```

* Poseidon over BN254 `Fr`, `rate = 4`, `capacity = 1`, `alpha = 5`, `full_rounds = 8`,
  `partial_rounds = 57`, parameters generated once with
  `find_poseidon_ark_and_mds::<Fr>(254, 4, 8, 57, 0)` (measured: 3.7 ms to generate).
  DESIGN: freeze the resulting `ark`/`mds` tables into `zkagent-proofs/src/params.rs` as
  `const`/`include_bytes!` data plus a `poseidon_bn254()` accessor, and add a test that re-derives them
  and compares. Generating at runtime means a dependency bump can silently change every commitment.
* The `DOMAIN_POLICY` tag is absorbed as the first element (as `Fr::from_be_bytes_mod_order(b"zkagent/...")`),
  not prepended as bytes — the sponge takes field elements only. **The Appendix B reference code predates
  this line and hashes 15 elements only.** Adding the tag makes it 16 → 5 sponge blocks → +290
  constraints (measured rate-4 block cost), i.e. **≈2 452 total**. Add it; the numbers in §4.2/§4.6 are
  for the 15-element version and every one of them shifts by that constant.
* `human_pk_hash = Fr::from_be_bytes_mod_order(SHA256(pk.serialize_compressed()))`
  (`ark_ff::PrimeField::from_be_bytes_mod_order`). It is a hash-to-field tag, not an algebraic
  commitment, which is fine because the real binding is the signature.

Binding, end to end:

1. Human computes `policy_commitment`, signs `serialize_compressed(policy_commitment)` with
   `Schnorr<G1Projective, Blake2s256>` (64-byte signature), publishes `pk` with the policy (or the policy
   kept private with only the commitment + signature public — both modes use the identical object).
2. Agent proves the circuit with `policy_commitment` as public input 0, and `human_pk_hash` as input 1.
3. Verifier does, in this order:
   a. `human_pk_hash == Fr::from_be_bytes_mod_order(SHA256(pk_bytes))` — native, no proof needed
      (this closes the "policy names a different principal" hole, see §9.2.3).
   b. `Schnorr::verify(&pp, &pk, &serialize_compressed(policy_commitment), &sig) == true`.
   c. `Groth16::verify_proof(&pvk, &proof, &public_inputs)`.
   d. `policy_commitment ∉ revocation_set[human_pk]`.
   e. `(human_pk, nonce) ∉ spent_nonces`.

Because the signature is over the *commitment* and the commitment is a public input to a proof that
constrains the *policy*, a proof cannot be lifted to a different policy: changing any field changes the
commitment, which changes a public input, which makes the pairing check false (measured, §4.6), and
changes the message the human signed (measured: `NEG swapped policy vs sig(A) verify = false`).
Note that the circuit alone does **not** catch a policy swap — see §4.6's `policy swapped (commit)
satisfied = true`. This is a real, measured dividing line: the circuit proves consistency; the signature
proves authorization. Neither replaces the other.

### 4.5 What is achievable, and what is not — honest cost

Achievable in Groth16 today, on CPU:

* Comparison and range checks over 64-bit integers — cheap (~68 constraints).
* Private-set membership — cheap and *linear* (~3 constraints per slot).
* Poseidon commitments of the sizes here — ~290 constraints per permutation, 6 permutations for the whole
  protocol.
* End-to-end proving: **382 ms on 2 vCPU with 29 MB RSS** (§4.6).

**NOT achievable, and the design does not pretend otherwise:** this circuit does not execute the agent's
trace. A general "prove the agent's program ran correctly" circuit is a VM-in-a-circuit — a RISC-V or
EVM interpreter — which for arkworks Groth16 means 10⁵–10⁶ constraints per executed step budget, SNARK
keys in the hundreds of MB, and proving times in minutes to hours with multiple GB of RAM. That needs a
different proving system (folding: Nova/HyperNova, or STARKs with an efficient CPU AIR) and is explicitly
out of scope for v1.

Consequence, stated once and loudly: **a valid receipt proves that the declared fields of a receipt are
within a genuinely signed policy. It does not prove the agent actually did what the trace says.** The
`trace_digest` is a commitment to a private blob; binding it prevents the agent from swapping the blob
after the fact, but nothing in the circuit constrains the blob's contents. §9.2.1 gives the mitigation
(verify the declared amount against an external, unforgeable effect — an on-chain transfer, an API
receipt signed by the counterparty).

### 4.6 Measured behaviour (this exact circuit)

Laptop (x86_64-msvc, rustc 1.97.1), `--release`:

```
poseidon param gen: 3.6865ms
human_pk compressed len = 32
policy sig len = 32 bytes; verify = true      # 32 = commitment; sig itself = 64 bytes (below)
num_constraints  = 2162
num_instance     = 10
num_witness      = 2163
hash(15 elems)   = 1162          # 4 Poseidon blocks = policy commitment
hash(8 elems)    = 580           # 2 Poseidon blocks = receipt commitment
hash(4 elems)    = 289           # 1 Poseidon block, for scale
satisfied        = true
NEG amount>max                   satisfied = false
NEG target not in allowlist      satisfied = false
NEG expired receipt              satisfied = false
NEG policy swapped (commit)      satisfied = true     <-- circuit cannot see this; see §4.4
setup            = 107.5256ms
vk bytes         = 552
pk bytes         = 479056
prove            = 161.1699ms
proof bytes      = 128
verify           = true in 2.0869ms
NEG wrong policy commitment verifies = false
NEG tampered amount verifies         = false
NEG replayed nonce verifies          = false
NEG foreign vk verifies              = false
NEG swapped policy vs sig(A) verify   = false
NEG sig(sk1) verified against pk3     = false
schnorr sig encoded bytes = 64
```

Droplet (2 vCPU, 3.9 GB, rustc 1.98.1) — same binary, same numbers, slower:

```
setup  = 395.8 ms      prove  = 382.4 ms      verify = 3.48 ms
proof  = 128 bytes      vk = 552 bytes         pk = 479 056 bytes
whole process: 1.39 s wall, 29 060 kB peak RSS
```

Reproduce with `cargo run --release` after copying `src/{main,circuit,params}.rs` from this spec's probe;
the numbers are deterministic apart from the timings.


---

## 5. Crate-by-crate sketch

Signatures below are the ones the engineer should write. Every arkworks type in them was exercised in the
probe. `Fr` = `ark_bn254::Fr`, `Bn254` = `ark_bn254::Bn254`, `G1 = ark_bn254::G1Projective`.

### 5.1 `zkagent-core`

Dependencies: `ark-bn254`, `ark-crypto-primitives` (features `sponge`, `signature`), `ark-ff`, `ark-ec`,
`ark-serialize`, `ark-std`, `sha2`, `blake2`, `serde`, `thiserror`. **No `ark-groth16`** — core must stay
usable by a verifier-only consumer and by the SDF/JSON tooling.

```rust
// src/lib.rs
pub mod canon;      // canonical byte encoding (§3.2)
pub mod domain;     // §3.1
pub mod error;      // CoreError
pub mod poseidon;   // frozen params + native sponge
pub mod policy;
pub mod receipt;
pub mod signature;  // Schnorr wrapper, signature encoding

pub type Fr = ark_bn254::Fr;
pub const ALLOWLIST_LEN: usize = 8;
```

```rust
// src/poseidon.rs
pub fn bn254_poseidon() -> &'static ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>;
pub fn poseidon_hash(input: &[Fr]) -> Fr;            // absorb all, squeeze 1
pub fn poseidon_hash2(a: Fr, b: Fr) -> Fr;
pub fn assert_params_are_canonical() -> Result<(), CoreError>;  // re-derives tables, compares (§4.4)
```

```rust
// src/policy.rs
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Policy {
    pub version: u8,
    pub human_pk_hash: Fr,
    pub max_spend: u64,
    pub asset_id: Fr,
    pub chain_id: u64,
    pub nonce: Fr,
    pub expiry: u64,
    pub allowlist: [Fr; ALLOWLIST_LEN],
    pub allowlist_len: u8,
}

impl Policy {
    pub fn validate(&self) -> Result<(), CoreError>;      // len<=8, zero padding, expiry>0, version==1
    pub fn canonical_bytes(&self) -> Vec<u8>;             // §3.2, domain-tagged
    pub fn commitment(&self) -> Fr;                        // Poseidon over the field vector
    pub fn is_target_allowed(&self, target: Fr) -> bool;   // native fast path for the CLI
}
```

```rust
// src/receipt.rs
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Receipt {
    pub amount: u64,          // NOTE: u64, not Fr — see §4.3
    pub asset_id: Fr,
    pub target: Fr,
    pub chain_id: u64,
    pub nonce: Fr,
    pub expiry: u64,
    pub trace_digest: Fr,     // commitment to the private trace blob
}

impl Receipt {
    pub fn validate(&self) -> Result<(), CoreError>;
    pub fn canonical_bytes(&self, policy_commitment: Fr) -> Vec<u8>;
    pub fn commitment(&self, policy_commitment: Fr) -> Fr;   // C7 preimage, same order as the circuit
}
```

```rust
// src/signature.rs
pub type HumanKeys = ark_crypto_primitives::signature::schnorr::Schnorr<
    ark_bn254::G1Projective, blake2::Blake2s256>;
pub type HumanPublicKey = <HumanKeys as SignatureScheme>::PublicKey;   // = G1Affine
pub type HumanSecretKey = <HumanKeys as SignatureScheme>::SecretKey;   // = SecretKey<G1>
pub type HumanParams    = <HumanKeys as SignatureScheme>::Parameters;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySignature { pub prover_response: Fr, pub verifier_challenge: Fr }  // 64 bytes BE

impl PolicySignature {
    pub fn to_bytes(&self) -> [u8; 64];
    pub fn from_bytes(b: &[u8; 64]) -> Result<Self, CoreError>;
    pub fn from_native(s: &<HumanKeys as SignatureScheme>::Signature) -> Self;
    pub fn to_native(&self) -> <HumanKeys as SignatureScheme>::Signature;
}

pub fn human_key_hash(pk: &HumanPublicKey) -> Result<Fr, CoreError>;   // SHA256(pk compressed) mod r
pub fn sign_policy(params: &HumanParams, sk: &HumanSecretKey, commitment: Fr, rng: &mut impl Rng)
    -> Result<PolicySignature, CoreError>;
pub fn verify_policy_signature(params: &HumanParams, pk: &HumanPublicKey, commitment: Fr,
    sig: &PolicySignature) -> Result<bool, CoreError>;
```

`PolicySignature::to_bytes` must be fixed-width and documented, because `Signature<C>` has no
`CanonicalSerialize` (§2.5). Layout: `prover_response` 32 bytes BE, then `verifier_challenge` 32 bytes BE,
each via `Fr::into_bigint().to_bytes_be()` **left-padded to 32**.

### 5.2 `zkagent-proofs`

Dependencies: core + `ark-groth16`, `ark-relations`, `ark-r1cs-std`, `ark-crypto-primitives`
(features `sponge`, `constraints`), `ark-ec`, `ark-ff`, `ark-serialize`, `ark-std`.

```rust
// src/lib.rs
pub mod circuit;     // ConformanceCircuit + Witness  (§4.2), copied verbatim from the probe
pub mod prove;
pub mod verify;
pub mod bundle;
pub mod error;
pub const PUBLIC_INPUT_LEN: usize = 9;
```

```rust
// src/circuit.rs — the shape that compiled
pub struct ConformanceCircuit {
    pub cfg: PoseidonConfig<Fr>,
    // public, in §4.1 order
    pub policy_commitment: Fr, pub human_pk_hash: Fr, pub receipt_commitment: Fr,
    pub amount: Fr, pub asset_id: Fr, pub target: Fr,
    pub chain_id: Fr, pub nonce: Fr, pub now: Fr,
    // private
    pub w: Option<Witness>,
}
pub struct Witness { pub policy: Policy, pub receipt: Receipt, pub now_u64: u64 }
impl ConstraintSynthesizer<Fr> for ConformanceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError>;
}
```

```rust
// src/prove.rs
pub struct Parameters { pub pk: ProvingKey<Bn254>, pub vk: VerifyingKey<Bn254> }

/// Deterministic, satisfiable dummy witness so setup does not depend on a real receipt.
pub fn setup_circuit() -> ConformanceCircuit;

pub fn setup(rng: &mut impl Rng) -> Result<Parameters, ProofError>;      // ~108 ms laptop / 396 ms droplet
pub fn prove(p: &Parameters, policy: &Policy, receipt: &Receipt, now: u64, rng: &mut impl Rng)
    -> Result<ProofBundle, ProofError>;
pub fn prove_with_circuit(pk: &ProvingKey<Bn254>, circuit: ConformanceCircuit, rng: &mut impl Rng)
    -> Result<Proof<Bn254>, ProofError>;
```

```rust
// src/verify.rs
pub fn verify(vk: &VerifyingKey<Bn254>, bundle: &ProofBundle) -> Result<(), ProofError>;
pub fn check_public_inputs(bundle: &ProofBundle) -> Result<(), ProofError>;   // length + derivable fields
pub fn vk_hash(vk: &VerifyingKey<Bn254>) -> Fr;   // Poseidon over compressed vk bytes; pin in the verifier
```

```rust
// src/bundle.rs
#[derive(Clone)]
pub struct ProofBundle {
    pub proof: Proof<Bn254>,             // 128 bytes compressed
    pub policy_commitment: Fr,
    pub human_pk_hash: Fr,
    pub receipt_commitment: Fr,
    pub amount: u64, pub asset_id: Fr, pub target: Fr,
    pub chain_id: u64, pub nonce: Fr, pub now: u64,
    pub vk_hash: Fr,
}
impl ProofBundle {
    pub fn public_inputs(&self) -> Vec<Fr>;         // exactly 9, in §4.1 order — unit-test the order
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(b: &[u8]) -> Result<Self, ProofError>;
}
```

### 5.3 `zkagent-verifier`

Depends on core + proofs. This crate is the *policy decision point*; it must never trust anything in the
bundle that it can recompute.

```rust
pub struct VerifyContext<'a> {
    pub params: &'a PoseidonConfig<Fr>,
    pub human: &'a HumanParams,
    pub human_pk: &'a HumanPublicKey,
    pub policy_signature: &'a PolicySignature,
    pub stated_policy: Option<&'a Policy>,   // Some(..) = disclosure mode (§4.4)
    pub now: u64,
    pub revoked_policies: &'a std::collections::HashSet<Fr>,
    pub spent_nonces: &'a dyn NonceRegistry,
    pub expected_vk_hash: Fr,
}

pub trait NonceRegistry {
    fn is_spent(&self, human_pk_hash: Fr, nonce: Fr) -> bool;
    fn mark_spent(&self, human_pk_hash: Fr, nonce: Fr) -> Result<(), VerifyError>;  // CLI path only
}

pub enum Verdict { Accept { receipt_commitment: Fr }, Reject(VerifyError) }

pub fn verify_receipt(bundle: &ProofBundle, vk: &VerifyingKey<Bn254>, ctx: &VerifyContext<'_>)
    -> Result<Verdict, VerifyError>;

pub fn solidity_calldata(bundle: &ProofBundle, vk: &VerifyingKey<Bn254>) -> Result<String, VerifyError>;
```

`verify_receipt` evaluates, in this order — the order matters because it is cheapest-first, and because
steps 1–3 are what make step 8 mean anything:

1. `bundle.vk_hash == ctx.expected_vk_hash` (pins the circuit; a swapped vk is otherwise a silent
   policy change).
2. `human_key_hash(ctx.human_pk) == bundle.human_pk_hash` (native, no proof needed — §4.4).
3. `verify_policy_signature(params, human_pk, bundle.policy_commitment, sig)` — the authorization check.
4. Disclosure mode only (`ctx.stated_policy.is_some()`): `ctx.stated_policy.commitment() ==
   bundle.policy_commitment` **and** `ctx.stated_policy.max_spend >= bundle.amount` — the verifier's own
   arithmetic, not the proof's, so a buggy circuit cannot hide behind it.
5. `!revoked_policies.contains(&bundle.policy_commitment)`.
6. `!spent_nonces.is_spent(human_pk_hash, bundle.nonce)`.
7. `bundle.now` within `[ctx.now - SKEW, ctx.now + SKEW]`, `SKEW = 300` (DESIGN).
8. `Groth16::<Bn254>::verify_proof(&prepare_verifying_key(vk), &bundle.proof, &bundle.public_inputs())`.
9. On accept, `spent_nonces.mark_spent(...)` (CLI) — this is the only side effect.

CLI contract (`zkagent-verifier verify --bundle b.json --vk vk.bin ...`):

| exit | meaning |
|---|---|
| 0 | verified and accepted |
| 2 | statement rejected by policy (expired, revoked, nonce spent, disclosure mismatch) |
| 3 | cryptographic failure (bad signature, bad proof, wrong vk) |
| 4 | malformed input (parse, length, version, unknown domain tag) |
| 5 | I/O or configuration error |

### 5.4 `zkagent-cli`

`zkagent keygen`, `zkagent policy sign --in policy.json --out signed.json`,
`zkagent receipt prove --policy signed.json --receipt receipt.json --pk pk.bin --out bundle.json`,
`zkagent receipt verify ...`. Thin wrappers over 5.1–5.3; no logic of its own. `zkagent setup --out params/`
writes `pk.bin` (479 056 B) and `vk.bin` (552 B) and prints the `vk_hash` that must be pasted into
`VerifyContext::expected_vk_hash`.

---

## 6. Test plan (runnable, with expected exit behaviour)

Layer 1 is pure `#[test]`, no proving key needed (fast, runs in every CI). Layer 2 needs one setup pass
(~110 ms laptop / ~400 ms droplet) and is what proves the protocol.

### 6.1 Layer 1 — core, no proving

| test | fixture | assertion |
|---|---|---|
| `canon_is_stable` | fixed `Policy` | `canonical_bytes()` hashed with SHA-256 equals a hard-coded hex constant; guards accidental layout drift |
| `canon_rejects_bad_version` | version = 2 | `Policy::validate()` → `Err(UnsupportedVersion)`, CLI exit 4 |
| `allowlist_padding_enforced` | `allowlist_len = 2`, slot 5 nonzero | `validate()` → `Err(NonZeroPadding)` |
| `allowlist_len_bounds` | `allowlist_len = 9` | `Err(TooManyTargets)` |
| `commitment_is_order_sensitive` | swap `max_spend`/`expiry` fields in the preimage | commitments differ (catches field-order typos in C6) |
| `poseidon_params_canonical` | §5.1 `assert_params_are_canonical` | re-derived `ark`/`mds` byte-equal to the frozen tables |
| `sig_roundtrip` | sign, `to_bytes`, `from_bytes`, verify | verify == true (guards the 64-byte manual encoding) |
| `sig_covers_commitment` | sign commitment A, verify against commitment B | verify == false |

### 6.2 Layer 2 — circuit and protocol

| test | construction | expected | observed |
|---|---|---|---|
| `e2e_happy` | valid policy + receipt, `amount = 500 000 ≤ max = 1 000 000`, `target` = allow[1], `now < expiry` | `cs.is_satisfied() == true`; `verify_proof == true`; CLI exit 0 | pass, verify in 2.1 ms |
| `neg_amount_over_max` | `amount = 2 000 000` | `is_satisfied() == false`; if forced through proving, `verify_proof == false`; CLI exit 2 | pass (`satisfied = false`) |
| `neg_target_not_allowed` | `target = 9999`, not in list | `is_satisfied() == false`; CLI exit 2 | pass |
| `neg_expired` | `now = 2 100 000 000 > expiry` | `is_satisfied() == false`; CLI exit 2 | pass |
| `neg_wrong_policy_key` | verify signature with a different `human_pk` | `verify_policy_signature == false`; CLI exit 3 | pass |
| `neg_policy_swap` | valid sig over policy A, present policy B's commitment | sig verify `false`; **circuit alone is satisfied** — assert both, so the test documents the boundary | pass (`satisfied = true`, `sig verify = false`) |
| `neg_replay_nonce` | same proof, `nonce` mutated in public inputs | `verify_proof == false` (pairing) **and** `NonceRegistry::is_spent` rejects on second accept; CLI exit 2 | pass both |
| `neg_tampered_receipt` | mutate `amount` in the public inputs of a valid proof | `verify_proof == false`; CLI exit 3 | pass |
| `neg_tampered_proof` | flip one byte in `proof.a` | `deserialize_compressed` errors or `verify_proof == false`; CLI exit 3 or 4 | expected |
| `neg_foreign_vk` | verify with a freshly generated vk | `verify_proof == false`; `vk_hash` mismatch rejects earlier; CLI exit 3 | pass |
| `neg_public_input_order` | build `public_inputs()` with amount and target swapped | `verify_proof == false` — this is the test that catches a reordering refactor | expected |

`neg_amount_over_max` detail, because it is the test people fake: you cannot "prove" it with
`create_random_proof_with_reduction` on an unsatisfiable circuit — arkworks will return an error from
`generate_constraints`/`is_satisfied`, and if you ignore that, the prover produces a proof for a
satisfying assignment it never had. Write the test as: synthesize into a `ConstraintSystem`, assert
`is_satisfied() == false`, and separately assert that `prove()` returns `Err(ProofError::Unsatisfiable)`.
The reference implementation does the former (`cs.is_satisfied()`), which is why §4.6 shows
`satisfied = false` rather than a failed pairing.

---

## 7. On-chain verifier path (Solidity)

### 7.1 What the EVM gives you

`alt_bn128` pairing check, precompile at `0x08`, per EIP-197: input is `k` pairs of `(G1, G2)`, **192
bytes per pair** — G1 as `(x, y)` 32 bytes each, G2 as `(x_i, x_r, y_i, y_r)` where the `F_p^2` element
`a·i + b` is encoded as `(a, b)`, i.e. **imaginary part first**. Infinity is `(0, 0)`, `F_p` values are
32-byte big-endian and must be `< p`. Output is 32 bytes: 1 if `Σ aᵢ·bᵢ = 0`. Gas `80 000·k + 100 000`;
`k = 4` for a Groth16 verify with any number of public inputs ⇒ 420 000 gas. G2 elements must additionally
be checked to have order `q` — the precompile does this for you, but a hand-rolled G2 deserialiser on the
Rust side must not skip it.

### 7.2 The four-pair check

arkworks verifies `e(A,B) = e(alpha,beta)·e(vk_x,gamma)·e(C,delta)` (`ark-groth16-0.6.0/src/verifier.rs:41-63`).
EIP-197 wants a product equal to 1, so the on-chain form is

```
e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1
```

with `A` negated as `(x, p - y)`. `vk_x = gamma_abc_g1[0] + Σ pubInput[i]·gamma_abc_g1[i+1]` — note the
`+1` skip, because `gamma_abc_g1[0]` is the constant term, mirroring arkworks' `prepare_inputs`
(`src/verifier.rs:25-37`, which starts from `gamma_abc_g1[0]` and zips inputs with `.skip(1)`).

### 7.3 Encoding conversion — the actual work

arkworks `serialize_compressed` is **not** EIP-197 calldata. `zkagent-verifier` must emit a converter:

```rust
pub fn solidity_points(proof: &Proof<Bn254>, vk: &VerifyingKey<Bn254>, inputs: &[Fr])
    -> ([[u8; 32]; 2], [[u8; 32]; 4], /* vk alpha,beta,gamma,delta */);
// per point: x = AffineRepr::x()  (ark-ec-0.6.0/src/lib.rs:168)
//            y = AffineRepr::y()  (ark-ec-0.6.0/src/lib.rs:173)
//            each -> into_bigint().to_bytes_be(), left-padded to 32  (ark-ff BigInteger::to_bytes_be)
```

Rules, all of them load-bearing:

* G1 → 64 bytes `x || y` big-endian. G2 → 128 bytes `x_i || x_r || y_i || y_r` (imaginary first).
* arkworks `Fq` *is* the EVM `F_p` for BN254 (`p = 21888242871839275222246405745257275088696311157297823662689037894645226208583`,
  EIP-197), so no rescaling — but you must reject values `>= p`, which arkworks guarantees by construction
  and a Solidity-side sanity check should re-assert.
* `A` is negated; `B`, `alpha`, `beta`, `gamma`, `delta`, `C` are not.
* Never parse the 128-byte compressed proof on-chain. Compressed encoding uses flag bits in the top of the
  last byte (ark-serialize `Compress::Yes`), which the EVM has no way to interpret.
* `gamma_abc_g1` has `1 + PUBLIC_INPUT_LEN = 10` points for this circuit (measured `vk` = 552 bytes
  compressed, consistent with 4 G2 points + 10 G1 points + length prefixes).

Contract shape (Solidity ≥0.8.20, no dependencies):

```solidity
contract ZkAgentVerifier {
    // vk fields as uint256[2]/uint256[4] constants or constructor args
    function verify(uint256[9] calldata pub, uint256[2] calldata a,
                    uint256[4] calldata b, uint256[2] calldata c) external view returns (bool);
    function verifyAndConsume(uint256[9] calldata pub, /* … */, bytes32 receiptCommitment,
                              uint64 nonce, uint256 expiry) external returns (bool);
}
```

`verifyAndConsume` must (a) require `block.timestamp <= expiry` using its **own** clock — never trust the
`now` public input, which exists to make the ZK statement self-contained, not to be authoritative on-chain;
(b) `require(!usedNonces[keccak256(abi.encode(pub[1], nonce))])` and set it; (c) emit the
`receipt_commitment`. Step (a) is the on-chain analogue of §9.2.4's clock attack.

DESIGN: the on-chain path is v2 scope. v1 ships the Rust verifier plus a `--emit-calldata` flag whose
output is diffed against a golden file in CI, and the Solidity contract is only deployed once that diff is
stable. Reasons: the G2/F_p^2 ordering and the A-negation are exactly the two silent-failure bugs in every
hand-written Groth16 verifier, and a golden-file diff catches them without a node.

---

## 8. Build and test commands

### 8.1 Windows git-bash (laptop, rustc 1.97.1)

```bash
# from C:/Users/Organix
cd Desktop/zkagent
rustup show                                   # confirm 1.80+ (toolchain file pins it)
cargo build --workspace --release
cargo test  --workspace                       # layer 1 + layer 2
cargo test  --workspace --release -- --nocapture   # timings + constraint counts
cargo run   --release -p zkagent-cli -- keygen --out keys/human.json
cargo run   --release -p zkagent-cli -- setup --out params/
```

Add `export CARGO_BUILD_JOBS=4` if you are memory-constrained; nothing here needs more.

### 8.2 Droplet (2 vCPU / 3.9 GB, rustc 1.98.1)

```bash
# sync from the laptop first (git-bash; native paths, no /c/ prefix for scp targets)
rsync -az --exclude target --exclude vendor Desktop/zkagent/ hoodbot@100.111.194.19:~/zkagent/

ssh hoodbot@100.111.194.19
export PATH=$HOME/.cargo/bin:$PATH            # cargo is at ~/.cargo/bin, NOT on the default PATH
cd ~/zkagent
export CARGO_BUILD_JOBS=2                     # measured: peak rustc RSS 509 MB with -j2
export RAYON_NUM_THREADS=2                    # ark-groth16 uses rayon for MSM; 2 = the vCPU count
cargo build --workspace --release            # 3 m 14 s clean, from a cold target/
cargo test  --workspace                      # ~2 s after build
```

Do not use `-j$(nproc)` blindly: with 2 vCPU the wall time is rayon-bound anyway, and a `-j8` build on a
3.9 GB box is what OOM-kills CI.

### 8.3 Vendoring (once, on a networked machine)

```bash
cargo vendor --versioned-dirs vendor         # 95 MB
mkdir -p .cargo
cat > .cargo/config.toml <<'CFG'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
CFG
cargo build --release --offline              # verified: 2 m 46 s cold, identical output
```

Commit `vendor/` or ship it as a release artifact. Verify offline-ness by deleting `~/.cargo/registry/src`
in a throwaway container — with source replacement in place, cargo never reads it.

### 8.4 Release profile for modest memory

```toml
# workspace Cargo.toml
[profile.release]
opt-level = 3
lto = "thin"          # "fat" costs ~2x build time for no measurable proving gain here
codegen-units = 4     # 1 is ~25% slower to build; neither affects proving throughput
panic = "unwind"       # keep unwinding: clap/serde paths rely on it for errors
overflow-checks = true # cheap for this workload; catches canonicalisation bugs at runtime
debug = false
strip = "symbols"      # binary is ~3.3 MB otherwise; ~2 MB stripped
```

Measured peak RSS at runtime: **29 MB** for the whole probe (setup + prove + verify). Peak *build* RSS:
509 MB. So the protocol itself is nowhere near the 3.9 GB box's limit — the build is the binding
constraint, which is why `CARGO_BUILD_JOBS=2` is the only tuning that matters.

---

## 9. Attack surface and non-goals

### 9.1 Attacks this design prevents

| attack | prevented by | where |
|---|---|---|
| agent overstates an allowed spend | C2 fails to satisfy; prover cannot produce a verifying proof | §4.2 |
| agent uses an unapproved tool/contract | C5 product is nonzero | §4.2 |
| agent reuses an expired policy | C3 (`now ≤ expiry`) + verifier clock check | §4.2, §5.3 |
| policy substitution (proving against a laxer policy) | signature is over `policy_commitment`, which is public input 0 | §4.4 |
| receipt binding to the wrong principal | `human_pk_hash` is public input 1, recomputed by the verifier | §4.4 |
| cross-chain replay | `chain_id` inside both commitments and public input 6 | §4.1 |
| within-chain replay | `nonce` public input 7 + `NonceRegistry` | §5.3 |
| proof reuse for a different statement | any public-input change breaks the pairing check (measured) | §4.6 |
| circuit substitution (prover ships their own vk) | `vk_hash` pinned in `VerifyContext` | §5.2 |
| revocation bypass | `revoked_policies` checked before the pairing | §5.3 |

### 9.2 Attacks this design does NOT prevent — read this section before claiming anything

1. **The trace is not verified.** Nothing constrains `trace_digest` to be the hash of a *real* execution.
   An agent can fabricate a compliant receipt for work it did not do, or did badly. The only mitigation is
   external: reconcile `amount`/`target` against an unforgeable effect (an on-chain transfer, a
   counterparty-signed acknowledgement) before treating the receipt as evidence.
2. **Policy is private by default ⇒ the verifier cannot audit the delegation.** A verifier in commitment-only
   mode learns "some signed policy with these parameters permitted this". It does not learn `max_spend`. A
   human who signs a policy with `max_spend = u64::MAX` gets proofs that verify. Disclosure mode exists for
   agents that want auditable receipts; the default is privacy, and privacy means unauditable.
3. **`human_pk_hash` is only as binding as the verifier's honesty.** Step 2 of `verify_receipt` closes it for
   a verifier that implements it; any third-party verifier that skips the check accepts a proof whose
   internal policy names a different principal. It is a *convention* enforced by one implementation.
4. **The prover's clock is unverifiable in-application.** `now` is an input. `neg_clock_rollback` (an agent
   proving at `now = 0` against an expired policy) is only stopped because the verifier (and the contract,
   §7.3) overrides `now` with its own. An offline receipt that is verified later cannot prove *when* it
   was produced; it only proves "produced at a time the prover claimed". Timestamping needs an external
   anchor (an L1 block hash, an RFC 3161 token) and is out of scope.
5. **Proofs are not unique.** `create_random_proof_with_reduction` takes fresh `r, s`, and
   `rerandomize_proof` (`ark-groth16-0.6.0/src/prover.rs:231`) re-randomises an existing proof. Two
   different byte strings can be valid for the same statement, and a re-randomised proof still verifies.
   So: never use proof bytes as a receipt ID; use `receipt_commitment`. Never use "I have seen this proof
   before" as replay detection; use the nonce registry.
6. **Trusted setup.** Groth16 needs a per-circuit CRS. `generate_random_parameters_with_reduction` with a
   local RNG is a *single-party* setup: whoever ran it holds the toxic waste and can forge proofs for
   arbitrary statements under that `vk`. For a dev/prototype deployment this is acceptable **only** because
   `vk_hash` pins the vk — but it means the operator of that setup ceremony is trusted absolutely. Shipping
   this requires a multi-party ceremony (snarkjs/`powersoftau`-style) and the resulting `vk` hash being
   pinned in the client. Say this out loud in any security claim; it is the largest caveat in the design.
7. **No witness privacy against the prover's own machine.** The agent's `max_spend`/allow-list sit in its
   RAM while proving. If the agent host is compromised, the policy leaks. Nothing in Groth16 helps.
8. **Fixed-size allow-list.** `ALLOWLIST_LEN = 8` is in the circuit's shape. Changing it changes the
   constraint count, the proving key, and the `vk_hash` — i.e. it is a protocol version bump, not a config
   value. Same for `PUBLIC_INPUT_LEN`.
9. **No deniability, no unlinkability.** Every accepted receipt is linkable to `human_pk_hash` and the
   policy commitment by design. If a use case needs unlinkable receipts, that is a different protocol
   (nullifiers + a set-membership proof), not a flag.
10. **Side channels.** arkworks is not constant-time. Timing on `is_satisfied`, field inversion in the
    `is_eq` gadget, and MSM timing can leak witness structure to a local observer. Irrelevant for a
    server-side prover you control; fatal if you ever run proving on a hostile machine.
11. **`Fr` ≠ `u64` aliasing.** The only defence is C1's `UInt64::to_fp() == public` check. Any future
    field added to the statement as a bare `Fr` that is *semantically* an integer reintroduces the
    `p + k` ambiguity. This is a standing rule, not a one-time fix.

### 9.3 Non-goals (v1)

General computation proofs (§4.5), on-chain deployment (§7), multi-party setup (§9.2.6), key rotation and
delegation chains, receipt aggregation, hardware attestation, post-quantum parameters (BN254 is ~100-bit
security against GNFS — fine for 2026, not for 2040).

---

## Appendix A — provenance of every number in this document

| claim | how it was established |
|---|---|
| versions, licences | crates.io API (`https://crates.io/api/v1/crates/<name>`, browser User-Agent; plain curl gets 403) |
| `rust-version` per crate | `Cargo.toml` in `~/.cargo/registry/src/index.crates.io-*/<crate>-0.6.0/` |
| every arkworks signature in §2 | read from the same registry sources at the cited `file:line`; then **compiled** |
| 2 162 constraints, 128-byte proof, 552-byte vk, 479 056-byte pk | probe output, §4.6 |
| setup/prove/verify timings | probe output on laptop and droplet, §4.6 |
| 29 MB runtime RSS, 509 MB build RSS | `/usr/bin/time -v` on the droplet |
| 3 m 14 s clean build on 2 vCPU | `cargo build --release -j2` on the droplet |
| offline vendored build works | `cargo vendor` (95 MB) + source replacement + `cargo build --release --offline`, 2 m 46 s |
| 78-crate transitive closure | `cargo tree --prefix none \| awk '{print $1}' \| sort -u \| wc -l` |
| EIP-197 encoding, 192 B/pair, gas 80 000·k + 100 000, F_p^2 as `(a, b)` | `https://eips.ethereum.org/EIPS/eip-197` §Encoding, §Gas costs |
| `ark-schnorr` does not exist | crates.io search for `schnorr`, 30 results, none from arkworks |
| the Appendix B source compiles and reproduces §4.6 | built with `cargo build --offline --release` after `cargo vendor`; ran twice (laptop + droplet) |
| 289/580/1 162 constraints per 1/2/4 Poseidon blocks | measured by a stripped circuit (`HashOnly`) that absorbs N witness `FpVar`s and squeezes 1 |

Everything marked DESIGN is ours and arguable: domain tags, byte layout, `SKEW = 300 s`, exit-code
assignment, `ALLOWLIST_LEN = 8`, Poseidon parameter choice (`254, 4, 8, 57, 0`), the 9-input statement
split, and the decision to keep `max_spend` private by default.

---

## Appendix B — reference circuit source (compiles as-is, arkworks 0.6.0)

This is the exact code that produced every number in §4.6. It is not pseudocode: `cargo build --release`
against the §1.2 pin and it runs. Two files, no dependencies beyond §1.2.

Two known deltas between this reference code and the spec above, both deliberate, both one-line fixes:
the domain tag is not yet absorbed (§4.4 — +290 constraints), and `Policy.chain_id` is an `Fr` here but a
`u64` in §5.1 (convert with `Fr::from(chain_id)` at the boundary).

### B.1 `src/params.rs`

```rust
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_std::sync::OnceLock;

pub const FULL_ROUNDS: u64 = 8;
pub const PARTIAL_ROUNDS: u64 = 57;
pub const ALPHA: u64 = 5;
pub const RATE: usize = 4;
pub const CAPACITY: usize = 1;

static CFG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();

pub fn bn254_poseidon() -> &'static PoseidonConfig<Fr> {
    CFG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            254,
            RATE,
            FULL_ROUNDS,
            PARTIAL_ROUNDS,
            0,
        );
        PoseidonConfig {
            full_rounds: FULL_ROUNDS as usize,
            partial_rounds: PARTIAL_ROUNDS as usize,
            alpha: ALPHA,
            ark,
            mds,
            rate: RATE,
            capacity: CAPACITY,
        }
    })
}

```

### B.2 `src/circuit.rs`

```rust

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_r1cs_std::{
    alloc::AllocVar, cmp::CmpGadget, eq::EqGadget, fields::fp::FpVar, fields::FieldVar,
    prelude::Boolean, uint64::UInt64,
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub const ALLOWLIST_LEN: usize = 8;

#[derive(Clone, Debug)]
pub struct Policy {
    pub human_pk_hash: Fr,
    pub max_spend: u64,
    pub asset_id: Fr,
    pub chain_id: Fr,
    pub nonce: Fr,
    pub expiry: u64,
    pub allowlist: [Fr; ALLOWLIST_LEN],
    pub allowlist_len: u8,
}

#[derive(Clone, Debug)]
pub struct Receipt {
    pub amount: u64,
    pub asset_id: Fr,
    pub target: Fr,
    pub nonce: Fr,
    pub chain_id: Fr,
    pub expiry: u64,
    pub trace_digest: Fr,
}

pub fn sponge_hash(cfg: &PoseidonConfig<Fr>, input: &[Fr]) -> Fr {
    let mut s = PoseidonSponge::<Fr>::new(cfg);
    s.absorb(&input.to_vec());
    s.squeeze_field_elements::<Fr>(1)[0]
}

pub fn policy_commitment(cfg: &PoseidonConfig<Fr>, p: &Policy) -> Fr {
    let mut v = vec![
        p.human_pk_hash,
        Fr::from(p.max_spend),
        p.asset_id,
        p.chain_id,
        p.nonce,
        Fr::from(p.expiry),
        Fr::from(p.allowlist_len as u64),
    ];
    v.extend_from_slice(&p.allowlist);
    sponge_hash(cfg, &v)
}

pub fn receipt_commitment(cfg: &PoseidonConfig<Fr>, policy_commitment: Fr, r: &Receipt) -> Fr {
    sponge_hash(
        cfg,
        &[
            policy_commitment,
            r.trace_digest,
            Fr::from(r.amount),
            r.asset_id,
            r.target,
            r.nonce,
            r.chain_id,
            Fr::from(r.expiry),
        ],
    )
}

#[derive(Clone, Debug)]
pub struct ConformanceCircuit {
    pub cfg: PoseidonConfig<Fr>,
    // public
    pub policy_commitment: Fr,
    pub human_pk_hash: Fr,
    pub receipt_commitment: Fr,
    pub amount: Fr,
    pub asset_id: Fr,
    pub target: Fr,
    pub chain_id: Fr,
    pub nonce: Fr,
    pub now: Fr,
    // private
    pub w: Option<Witness>,
}

#[derive(Clone, Debug)]
pub struct Witness {
    pub policy: Policy,
    pub receipt: Receipt,
    pub now_u64: u64,
}

impl ConstraintSynthesizer<Fr> for ConformanceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let cfg = self.cfg;
        let w = self.w.clone();

        let pc = FpVar::new_input(cs.clone(), || Ok(self.policy_commitment))?;
        let pk_hash = FpVar::new_input(cs.clone(), || Ok(self.human_pk_hash))?;
        let rc = FpVar::new_input(cs.clone(), || Ok(self.receipt_commitment))?;
        let amount_pub = FpVar::new_input(cs.clone(), || Ok(self.amount))?;
        let asset_pub = FpVar::new_input(cs.clone(), || Ok(self.asset_id))?;
        let target_pub = FpVar::new_input(cs.clone(), || Ok(self.target))?;
        let chain_pub = FpVar::new_input(cs.clone(), || Ok(self.chain_id))?;
        let nonce_pub = FpVar::new_input(cs.clone(), || Ok(self.nonce))?;
        let now_pub = FpVar::new_input(cs.clone(), || Ok(self.now))?;

        let max_spend = UInt64::new_witness(cs.clone(), || {
            Ok(w.as_ref().map(|w| w.policy.max_spend).unwrap_or(0))
        })?;
        let expiry_u = UInt64::new_witness(cs.clone(), || {
            Ok(w.as_ref().map(|w| w.policy.expiry).unwrap_or(0))
        })?;
        let amount_u = UInt64::new_witness(cs.clone(), || {
            Ok(w.as_ref().map(|x| x.receipt.amount).unwrap_or(0))
        })?;
        let now_u = UInt64::new_witness(cs.clone(), || {
            Ok(w.as_ref().map(|x| x.now_u64).unwrap_or(0))
        })?;

        // C1: public amount/now are the canonical 64-bit integers (no mod-p aliasing)
        amount_u.to_fp()?.enforce_equal(&amount_pub)?;
        now_u.to_fp()?.enforce_equal(&now_pub)?;

        // C2: amount <= max_spend
        amount_u.is_le(&max_spend)?.enforce_equal(&Boolean::TRUE)?;

        // C3: now <= expiry
        now_u.is_le(&expiry_u)?.enforce_equal(&Boolean::TRUE)?;

        let asset_w = FpVar::new_witness(cs.clone(), || {
            Ok(w.as_ref().map(|x| x.policy.asset_id).unwrap_or_default())
        })?;
        let chain_w = FpVar::new_witness(cs.clone(), || {
            Ok(w.as_ref().map(|x| x.policy.chain_id).unwrap_or_default())
        })?;
        let nonce_w = FpVar::new_witness(cs.clone(), || {
            Ok(w.as_ref().map(|x| x.policy.nonce).unwrap_or_default())
        })?;
        let alen_w = FpVar::new_witness(cs.clone(), || {
            Ok(Fr::from(
                w.as_ref()
                    .map(|x| x.policy.allowlist_len as u64)
                    .unwrap_or(0),
            ))
        })?;
        let target_w = FpVar::new_witness(cs.clone(), || {
            Ok(w.as_ref().map(|x| x.receipt.target).unwrap_or_default())
        })?;
        let expiry_f = expiry_u.to_fp()?;
        let trace_w = FpVar::new_witness(cs.clone(), || {
            Ok(w.as_ref()
                .map(|x| x.receipt.trace_digest)
                .unwrap_or_default())
        })?;

        let mut allow_vars = Vec::with_capacity(ALLOWLIST_LEN);
        for i in 0..ALLOWLIST_LEN {
            allow_vars.push(FpVar::new_witness(cs.clone(), || {
                Ok(w.as_ref()
                    .map(|x| x.policy.allowlist[i])
                    .unwrap_or_default())
            })?);
        }

        // C4: public <-> witness bindings
        asset_w.enforce_equal(&asset_pub)?;
        target_w.enforce_equal(&target_pub)?;
        chain_w.enforce_equal(&chain_pub)?;
        nonce_w.enforce_equal(&nonce_pub)?;

        // C5: target membership in the private allowlist
        let mut prod = FpVar::one();
        for a in &allow_vars {
            let eq_b: Boolean<Fr> = a.is_eq(&target_w)?;
            let eq_f: FpVar<Fr> = eq_b.into();
            prod = prod * (FpVar::one() - eq_f);
        }
        prod.enforce_equal(&FpVar::zero())?;

        // C6: recompute the policy commitment
        let mut pv: Vec<FpVar<Fr>> = vec![
            pk_hash,
            max_spend.to_fp()?,
            asset_w,
            chain_w,
            nonce_w,
            expiry_f.clone(),
            alen_w,
        ];
        pv.extend(allow_vars.iter().cloned());
        let mut sp = PoseidonSpongeVar::<Fr>::new(cs.clone(), &cfg);
        sp.absorb(&pv)?;
        let pc_calc: FpVar<Fr> = sp.squeeze_field_elements(1)?[0].clone();
        pc_calc.enforce_equal(&pc)?;

        // C7: recompute the receipt commitment
        let rv: Vec<FpVar<Fr>> = vec![
            pc.clone(),
            trace_w,
            amount_u.to_fp()?,
            asset_pub.clone(),
            target_pub.clone(),
            nonce_pub.clone(),
            chain_pub.clone(),
            expiry_f.clone(),
        ];
        let mut sp2 = PoseidonSpongeVar::<Fr>::new(cs.clone(), &cfg);
        sp2.absorb(&rv)?;
        let rc_calc: FpVar<Fr> = sp2.squeeze_field_elements(1)?[0].clone();
        rc_calc.enforce_equal(&rc)?;

        Ok(())
    }
}

```

Driver (setup → prove → verify), in the shape `zkagent-proofs` should expose:

```rust
let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)?;
let vk = pk.vk.clone();                              // NOTE: returns pk only, no tuple
let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut rng)?;
let pvk = prepare_verifying_key(&vk);
let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)?;   // public_inputs.len() == 9
```
