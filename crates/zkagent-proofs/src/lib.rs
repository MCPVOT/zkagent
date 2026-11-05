//! `zkagent-proofs` — the proving layer.
//!
//! * [`circuit`] — the Groth16 statement and its constraints.
//! * [`prover`] — trusted setup, proving, and the on-disk key/proof format.
//!
//! The verifier lives in `zkagent-verifier` so that a checking-only deployment
//! does not need to link the prover.

#![deny(unsafe_code)]

pub mod circuit;
mod keyfile;
pub mod merkle;
pub mod prover;

pub use circuit::{build_circuit, public_inputs, CircuitField, PolicyConformanceCircuit};
