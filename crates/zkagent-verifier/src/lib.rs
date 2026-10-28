//! `zkagent-verifier` — the checking side of the protocol.
//!
//! A verifier holds three things: the policy (public, signed by the human),
//! the receipt (public, published by the agent), and the proof. It answers one
//! question: **did some execution that respects this policy produce this
//! receipt?**
//!
//! # The four checks, and why each is required
//!
//! 1. **Signature over the policy.** Proves the policy was authorised by the
//!    human. Without it, an agent could mint a policy with a huge cap and
//!    prove conformance to its own invention.
//! 2. **Public-input binding.** The verifier recomputes the expected public
//!    inputs from the policy and receipt it holds and compares them to the
//!    ones in the artifact. Without it, a valid proof about *different*
//!    values could be replayed.
//! 3. **Chain binding.** The receipt must be for the chain the policy covers,
//!    and the policy must not be expired at the receipt's completion time.
//! 4. **The Groth16 proof itself.** This is the part that carries the private
//!    execution: it says a conforming action set exists.
//!
//! Checks 1 and 3 are cheap and off-circuit; they are not redundant with the
//! proof, because the proof cannot see the human's signing key and cannot
//! express "this specific policy is authorised".

#![deny(missing_docs)]
#![deny(unsafe_code)]

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use zkagent_core::{Policy, Receipt};
use zkagent_proofs::circuit::public_inputs;
use zkagent_proofs::prover::{
    prepare, verifying_key_from_bytes, ProofBytes, FORMAT_VERSION,
};

/// The outcome of a verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every check passed.
    Accept,
    /// A specific check failed, with the reason.
    Reject(RejectReason),
}

/// Why a verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// The proof artifact was produced by a different circuit version.
    FormatMismatch {
        /// Version in the artifact.
        artifact: u32,
        /// Version this verifier understands.
        expected: u32,
    },
    /// The artifact's public inputs are not the ones this policy/receipt imply.
    PublicInputMismatch,
    /// The human's signature over the policy is invalid or missing.
    UnauthorisedPolicy,
    /// The receipt is for a different chain than the policy covers.
    ChainMismatch,
    /// The policy was expired when the execution completed.
    Expired,
    /// The Groth16 proof did not verify.
    InvalidProof,
    /// The proof could not be parsed.
    MalformedProof(String),
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FormatMismatch { artifact, expected } => write!(
                f,
                "artifact format v{artifact}, verifier expects v{expected}"
            ),
            Self::PublicInputMismatch => {
                write!(f, "public inputs do not match the supplied policy/receipt")
            }
            Self::UnauthorisedPolicy => write!(f, "policy signature is not valid for this policy"),
            Self::ChainMismatch => write!(f, "receipt chain does not match the policy chain"),
            Self::Expired => write!(f, "policy was expired at the receipt's completion time"),
            Self::InvalidProof => write!(f, "Groth16 proof did not verify"),
            Self::MalformedProof(m) => write!(f, "malformed proof: {m}"),
        }
    }
}

impl std::error::Error for RejectReason {}

/// Verifies a proof against a policy and receipt, given the human's public key
/// bytes and the verifying key bytes.
///
/// `now` is the verifier's clock, used only to refuse a *future* receipt; the
/// authoritative freshness check is `completed_at < expires_at`, which is
/// enforced inside the circuit.
pub fn verify(
    vk_bytes: &[u8],
    policy: &Policy,
    receipt: &Receipt,
    proof: &ProofBytes,
    authority_pubkey: &[u8],
    policy_signature: &[u8],
    now: Option<u64>,
) -> Verdict {
    // 1. Format.
    if proof.format_version != FORMAT_VERSION {
        return Verdict::Reject(RejectReason::FormatMismatch {
            artifact: proof.format_version,
            expected: FORMAT_VERSION,
        });
    }

    // 2. Public-input binding: recompute from OUR policy/receipt.
    let expected = public_inputs(policy, receipt);
    let claimed = match proof.public_inputs_fr() {
        Ok(v) => v,
        Err(e) => {
            return Verdict::Reject(RejectReason::MalformedProof(e.to_string()));
        }
    };
    if expected != claimed {
        return Verdict::Reject(RejectReason::PublicInputMismatch);
    }

    // 3. Authority: the human signed THIS policy.
    let sig = zkagent_core::SignatureBytes {
        bytes: policy_signature.to_vec(),
    };
    if !zkagent_core::verify_policy_signature(authority_pubkey, policy, &sig) {
        return Verdict::Reject(RejectReason::UnauthorisedPolicy);
    }

    // 4. Chain + freshness.
    if receipt.chain_id != policy.chain_id {
        return Verdict::Reject(RejectReason::ChainMismatch);
    }
    if policy.is_expired_at(receipt.completed_at) {
        return Verdict::Reject(RejectReason::Expired);
    }
    if let Some(now) = now {
        if receipt.completed_at > now {
            // A receipt dated in the future cannot be trusted; treat it as a
            // rejection rather than silently accepting a skewed clock.
            return Verdict::Reject(RejectReason::MalformedProof(
                "receipt completed_at is in the future".to_string(),
            ));
        }
    }

    // 5. The proof.
    let vk = match verifying_key_from_bytes(vk_bytes) {
        Ok(vk) => vk,
        Err(e) => return Verdict::Reject(RejectReason::MalformedProof(e.to_string())),
    };
    let raw_proof = match proof.to_proof() {
        Ok(p) => p,
        Err(e) => return Verdict::Reject(RejectReason::MalformedProof(e.to_string())),
    };
    let pvk = prepare(&vk);
    match Groth16::<Bn254>::verify_proof(&pvk, &raw_proof, &expected) {
        Ok(true) => Verdict::Accept,
        Ok(false) => Verdict::Reject(RejectReason::InvalidProof),
        Err(e) => Verdict::Reject(RejectReason::MalformedProof(format!("{e:?}"))),
    }
}

fn decode_pubkey(_bytes: &[u8]) -> Option<()> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_serialize::CanonicalSerialize;
    use zkagent_core::{policy_commitment, Action, Authority};
    use zkagent_proofs::prover::{prove, setup};

    fn policy() -> Policy {
        Policy::new(1_000, 300, 2_000, 1, vec![3, 7, 9]).unwrap()
    }
    fn actions() -> Vec<Action> {
        vec![
            Action {
                target: 3,
                amount: 250,
                trace_digest: 11,
            },
            Action {
                target: 7,
                amount: 150,
                trace_digest: 22,
            },
        ]
    }
    fn receipt() -> Receipt {
        Receipt {
            total_amount: 400,
            action_count: 2,
            completed_at: 1_500,
            chain_id: 1,
        }
    }

    struct Fixture {
        vk: Vec<u8>,
        pubkey: Vec<u8>,
        sig: Vec<u8>,
        proof: ProofBytes,
    }

    fn fixture() -> Fixture {
        let keys = setup(11).unwrap();
        let auth = Authority::from_seed(99);
        let p = policy();
        let sig = auth.sign_policy(&p);
        let proof = prove(&keys, &p, &receipt(), &actions()).unwrap();
        Fixture {
            vk: keys.verifying_key_bytes().unwrap(),
            pubkey: auth.public_key().as_bytes().to_vec(),
            sig: sig.bytes,
            proof,
        }
    }

    #[test]
    fn happy_path_accepts() {
        let f = fixture();
        assert_eq!(
            verify(&f.vk, &policy(), &receipt(), &f.proof, &f.pubkey, &f.sig, Some(1_600)),
            Verdict::Accept
        );
    }

    #[test]
    fn tampered_receipt_is_rejected() {
        // The whole point: change the claimed total and the binding fails.
        let f = fixture();
        let mut r = receipt();
        r.total_amount = 401;
        assert_eq!(
            verify(&f.vk, &policy(), &r, &f.proof, &f.pubkey, &f.sig, Some(1_600)),
            Verdict::Reject(RejectReason::PublicInputMismatch)
        );
    }

    #[test]
    fn wrong_authority_key_is_rejected() {
        let f = fixture();
        let other = Authority::from_seed(100);
        assert_eq!(
            verify(
                &f.vk,
                &policy(),
                &receipt(),
                &f.proof,
                other.public_key().as_bytes(),
                &f.sig,
                Some(1_600)
            ),
            Verdict::Reject(RejectReason::UnauthorisedPolicy)
        );
    }

    #[test]
    fn wrong_vk_is_rejected() {
        let f = fixture();
        let other = setup(12).unwrap().verifying_key_bytes().unwrap();
        match verify(&other, &policy(), &receipt(), &f.proof, &f.pubkey, &f.sig, Some(1_600)) {
            Verdict::Reject(_) => {}
            Verdict::Accept => panic!("a proof must not verify under a different key"),
        }
    }

    #[test]
    fn expired_receipt_is_rejected() {
        let f = fixture();
        let r = Receipt {
            total_amount: 400,
            action_count: 2,
            completed_at: 2_000,
            chain_id: 1,
        };
        assert_eq!(
            verify(&f.vk, &policy(), &r, &f.proof, &f.pubkey, &f.sig, Some(3_000)),
            Verdict::Reject(RejectReason::PublicInputMismatch)
        );
    }

    #[test]
    fn future_receipt_is_rejected() {
        let f = fixture();
        assert!(matches!(
            verify(&f.vk, &policy(), &receipt(), &f.proof, &f.pubkey, &f.sig, Some(1_000)),
            Verdict::Reject(_)
        ));
    }

    #[test]
    fn format_version_mismatch_is_rejected() {
        let f = fixture();
        let mut p = f.proof.clone();
        p.format_version = FORMAT_VERSION + 1;
        assert_eq!(
            verify(&f.vk, &policy(), &receipt(), &p, &f.pubkey, &f.sig, Some(1_600)),
            Verdict::Reject(RejectReason::FormatMismatch {
                artifact: FORMAT_VERSION + 1,
                expected: FORMAT_VERSION
            })
        );
    }

    #[test]
    fn commitment_is_stable_across_verifier_calls() {
        // Guards against a policy commitment that changes per call (e.g. one
        // built from a HashMap iteration order).
        let p = policy();
        assert_eq!(policy_commitment(&p), policy_commitment(&p));
    }
}
