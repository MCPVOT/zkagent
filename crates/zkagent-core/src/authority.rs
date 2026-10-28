//! Human authority: the human signs a policy, the verifier checks that
//! signature against the policy the proof was made about.
//!
//! # Why a signature at all
//!
//! A policy on its own says nothing about *who* granted it. Without a
//! signature anyone could mint a policy with an enormous cap and then prove
//! conformance to their own invention. The human's signature is what turns a
//! policy into an **authorisation**.
//!
//! # Why Ed25519 rather than a signature on BN254
//!
//! The proof lives on BN254 because Groth16 needs a pairing curve. The
//! signature does not have to share that curve: it signs a 32-byte hash, which
//! is curve-agnostic. Ed25519 buys a small, widely reviewed, deterministic
//! implementation with fixed 64-byte signatures and 32-byte keys, instead of
//! hand-rolled Schnorr over the proof curve whose generator/salt parameters
//! would have to be persisted and versioned by this protocol.
//!
//! The cost is that on-chain verification of the *signature* needs an Ed25519
//! precompile or an off-chain check. That is recorded in the architecture doc
//! and does not affect the proof, which is what a chain verifies.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::policy::Policy;

/// Length of an Ed25519 secret seed, in bytes.
pub const SECRET_KEY_BYTES: usize = 32;

/// Why real key material could not be produced or read.
#[derive(Debug)]
pub enum AuthorityError {
    /// The operating system's randomness source failed.
    Randomness(String),
    /// A secret key was not exactly [`SECRET_KEY_BYTES`] bytes.
    BadLength {
        /// The length that was supplied.
        got: usize,
    },
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityError::Randomness(d) => write!(f, "cannot generate a key: {d}"),
            AuthorityError::BadLength { got } => write!(
                f,
                "authority secret must be {SECRET_KEY_BYTES} bytes, got {got}"
            ),
        }
    }
}

impl std::error::Error for AuthorityError {}

/// The domain-separated digest a human signs for a policy.
///
/// The signature covers a *commitment* rather than the raw policy bytes, so its
/// size is independent of the allow-list length. The domain tag keeps this hash
/// from ever colliding with another hash used by the protocol.
pub fn policy_signing_message(policy: &Policy) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zkagent.commitment.policy.v1");
    hasher.update([0u8]);
    hasher.update(policy.canonical_bytes());
    let out = hasher.finalize();
    let mut msg = [0u8; 32];
    msg.copy_from_slice(&out);
    msg
}

/// Alias: the policy commitment *is* the signing message.
pub fn policy_commitment(policy: &Policy) -> [u8; 32] {
    policy_signing_message(policy)
}

/// A human's signing keypair for policy authorisation.
///
/// `Debug` is derived on purpose: `ed25519_dalek`'s own `Debug` for a signing
/// key prints only the verifying key and explicitly avoids the secret bytes,
/// so this cannot leak key material into a log line.
#[derive(Debug, Clone)]
pub struct Authority {
    signing: SigningKey,
}

impl Authority {
    /// Derives a keypair from a 64-bit seed.
    ///
    /// # This is a DEMO key, not a real one
    ///
    /// A 64-bit seed has 64 bits of entropy and is trivially brute-forced, and
    /// the CLI's old default (`--seed 99`) meant every policy produced by this
    /// tool was signed by the *same* key. Anyone can reproduce seed 99, so any
    /// policy signed that way is forgeable by anyone — which makes the whole
    /// authorisation layer decorative.
    ///
    /// Kept because tests and the demo flow need reproducible keys. Real
    /// deployments use [`Authority::generate`] once and then
    /// [`Authority::from_secret_bytes`] from a protected file or a KMS.
    pub fn from_seed(seed: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"zkagent.authority.seed.v1");
        hasher.update(seed.to_be_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Self {
            signing: SigningKey::from_bytes(&bytes),
        }
    }

    /// Build an authority from real 32-byte key material.
    ///
    /// This is the production constructor: the bytes come from a file the
    /// operator protects, a KMS, or [`Authority::generate`] once at setup.
    #[must_use]
    pub fn from_secret_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    /// Generate a fresh authority from the operating system's CSPRNG.
    ///
    /// # Errors
    /// Returns [`AuthorityError::Randomness`] if the OS randomness source
    /// fails. That is deliberately an error rather than a silent fallback to a
    /// predictable seed: a silent fallback would produce a forgeable key at the
    /// one moment nobody is watching.
    pub fn generate() -> Result<Self, AuthorityError> {
        let mut bytes = [0u8; SECRET_KEY_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|e| AuthorityError::Randomness(e.to_string()))?;
        Ok(Self::from_secret_bytes(&bytes))
    }

    /// The raw secret seed, for persisting to protected storage.
    ///
    /// Treat the return value as a secret: do not log it, and do not pass it
    /// through a command-line argument (it would land in shell history and the
    /// process table).
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        self.signing.to_bytes()
    }

    /// Parse 32 secret bytes from a slice of unknown length.
    ///
    /// # Errors
    /// Returns [`AuthorityError::BadLength`] when the slice is not 32 bytes.
    pub fn secret_from_slice(bytes: &[u8]) -> Result<[u8; SECRET_KEY_BYTES], AuthorityError> {
        bytes
            .try_into()
            .map_err(|_| AuthorityError::BadLength { got: bytes.len() })
    }

    /// The public key, published alongside the policy.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Signs a policy.
    pub fn sign_policy(&self, policy: &Policy) -> SignatureBytes {
        let msg = policy_signing_message(policy);
        let sig = self.signing.sign(&msg);
        SignatureBytes {
            bytes: sig.to_bytes().to_vec(),
        }
    }
}

/// A serialised authority signature (64 bytes for Ed25519).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureBytes {
    /// Raw signature bytes.
    pub bytes: Vec<u8>,
}

/// Verifies an authority signature over a policy.
///
/// A malformed key or signature yields `false` rather than an error: a verifier
/// must treat "cannot parse" exactly like "not authorised".
pub fn verify_policy_signature(
    public_key_bytes: &[u8],
    policy: &Policy,
    signature: &SignatureBytes,
) -> bool {
    let Ok(pk_arr): Result<[u8; 32], _> = public_key_bytes.try_into() else {
        return false;
    };
    let Ok(pk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = signature.bytes.as_slice().try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    let msg = policy_signing_message(policy);
    // `verify_strict` rejects small-order and non-canonical public keys that
    // the permissive `verify` accepts.
    pk.verify_strict(&msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::new(1_000, 250, 1_700_000_000, 1, vec![3, 7, 9]).unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let auth = Authority::from_seed(42);
        let p = policy();
        let sig = auth.sign_policy(&p);
        assert!(verify_policy_signature(
            auth.public_key().as_bytes(),
            &p,
            &sig
        ));
    }

    #[test]
    fn signature_does_not_verify_for_a_different_policy() {
        let auth = Authority::from_seed(42);
        let sig = auth.sign_policy(&policy());
        let other = Policy::new(1_000, 250, 1_700_000_000, 1, vec![3, 7, 10]).unwrap();
        assert!(!verify_policy_signature(
            auth.public_key().as_bytes(),
            &other,
            &sig
        ));
    }

    #[test]
    fn signature_does_not_verify_under_a_different_key() {
        let auth = Authority::from_seed(42);
        let impostor = Authority::from_seed(43);
        let p = policy();
        let sig = auth.sign_policy(&p);
        assert!(!verify_policy_signature(
            impostor.public_key().as_bytes(),
            &p,
            &sig
        ));
    }

    #[test]
    fn a_flipped_signature_bit_is_rejected() {
        let auth = Authority::from_seed(42);
        let p = policy();
        let mut sig = auth.sign_policy(&p);
        sig.bytes[0] ^= 0x01;
        assert!(!verify_policy_signature(
            auth.public_key().as_bytes(),
            &p,
            &sig
        ));
    }

    #[test]
    fn malformed_key_or_signature_is_a_rejection_not_a_panic() {
        let auth = Authority::from_seed(42);
        let p = policy();
        let sig = auth.sign_policy(&p);
        assert!(!verify_policy_signature(&[0u8; 4], &p, &sig));
        assert!(!verify_policy_signature(
            auth.public_key().as_bytes(),
            &p,
            &SignatureBytes {
                bytes: vec![0u8; 3]
            }
        ));
    }

    #[test]
    fn commitment_changes_when_any_field_changes() {
        let base = policy_commitment(&policy());
        let bumped = Policy::new(1_001, 250, 1_700_000_000, 1, vec![3, 7, 9]).unwrap();
        assert_ne!(base, policy_commitment(&bumped));
    }

    #[test]
    fn generated_keys_differ_and_sign() {
        let a = Authority::generate().expect("OS randomness available");
        let b = Authority::generate().expect("OS randomness available");
        assert_ne!(
            a.public_key().as_bytes(),
            b.public_key().as_bytes(),
            "two generated keys must not collide"
        );

        let p = policy();
        let sig = a.sign_policy(&p);
        assert!(verify_policy_signature(a.public_key().as_bytes(), &p, &sig));
        assert!(!verify_policy_signature(
            b.public_key().as_bytes(),
            &p,
            &sig
        ));
    }

    #[test]
    fn a_persisted_secret_restores_the_same_authority() {
        let original = Authority::generate().expect("OS randomness available");
        let saved = original.secret_bytes();

        let restored = Authority::from_secret_bytes(&saved);
        assert_eq!(
            original.public_key().as_bytes(),
            restored.public_key().as_bytes()
        );

        // And a signature made after the round-trip still verifies against the
        // published key — the property a persisted key exists to provide.
        let p = policy();
        let sig = restored.sign_policy(&p);
        assert!(verify_policy_signature(
            original.public_key().as_bytes(),
            &p,
            &sig
        ));
    }

    #[test]
    fn a_short_secret_is_an_error_never_a_zero_padded_key() {
        // Zero-padding a truncated key would silently produce a DIFFERENT key
        // than the operator means, so the length must be exact.
        assert!(matches!(
            Authority::secret_from_slice(&[7u8; 31]),
            Err(AuthorityError::BadLength { got: 31 })
        ));
        assert!(Authority::secret_from_slice(&[7u8; 32]).is_ok());
    }
}
