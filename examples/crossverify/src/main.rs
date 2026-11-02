//! Export a zkagent verifying key and proof in the shape `snarkjs` expects.
//!
//! This exists for one reason: Tier 4 in `references/soundness-checklist.md` says
//! that until a second, independent implementation consumes the same artifacts,
//! "this proof verifies" rests on one implementation. Groth16 over BN254 is a
//! standard — the arkworks encoding is not — so this probe converts and asks a
//! different implementation to check the same bytes.
//!
//! Coordinates are emitted as hex here and converted to decimal by
//! `tools/crossverify/run.py`, so this binary never has to render a big integer
//! and the conversion stays visible in one place.
//!
//! Usage:
//!     zkagent-crossverify <keys-dir> <proof.json>

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use serde_json::json;

fn fq(v: &Fq) -> String {
    format!("0x{}", hex::encode(v.into_bigint().to_bytes_be()))
}

fn fq2(v: &Fq2) -> Vec<String> {
    vec![fq(&v.c0), fq(&v.c1)]
}

fn g1(p: &G1Affine) -> Vec<String> {
    vec![fq(&p.x), fq(&p.y)]
}

fn g2(p: &G2Affine) -> Vec<Vec<String>> {
    vec![fq2(&p.x), fq2(&p.y)]
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: zkagent-crossverify <keys-dir> <proof.json>".into());
    }
    let keys = std::path::Path::new(&args[1]);
    let proof_path = std::path::Path::new(&args[2]);

    let vk_bytes = std::fs::read(keys.join("vk.bin")).map_err(|e| format!("vk.bin: {e}"))?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
        .map_err(|e| format!("verifying key: {e}"))?;

    let proof_doc = std::fs::read_to_string(proof_path).map_err(|e| format!("proof: {e}"))?;
    let proof_bytes: zkagent_proofs::prover::ProofBytes =
        serde_json::from_str(&proof_doc).map_err(|e| format!("proof json: {e}"))?;
    let proof: Proof<Bn254> = proof_bytes.to_proof().map_err(|e| e.to_string())?;
    let public: Vec<String> = proof_bytes
        .public_inputs_fr()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|f| format!("0x{}", hex::encode(f.into_bigint().to_bytes_be())))
        .collect();

    let doc = json!({
        "n_public": vk.gamma_abc_g1.len() - 1,
        "alpha": g1(&vk.alpha_g1),
        "beta": g2(&vk.beta_g2),
        "gamma": g2(&vk.gamma_g2),
        "delta": g2(&vk.delta_g2),
        "ic": vk.gamma_abc_g1.iter().map(g1).collect::<Vec<_>>(),
        "pi_a": g1(&proof.a),
        "pi_b": g2(&proof.b),
        "pi_c": g1(&proof.c),
        "public_inputs": public,
    });
    println!(
        "{}",
        serde_json::to_string(&doc).map_err(|e| e.to_string())?
    );
    Ok(())
}
