//! Reading a proving key from its compressed bytes, in parallel.
//!
//! # Why this exists (measured, not assumed)
//!
//! `pk.bin` is ~1.45 MB and almost all of it is compressed G1/G2 points: 45 291
//! of them at 32/64 bytes each. Decompressing one point means solving
//! `y² = x³ + b`, i.e. a field square root, and arkworks' `Vec<Affine>` reader
//! does that **one point at a time**. Measured on this laptop, that single
//! sequential loop was **734 ms** of a 920 ms `zkagent prove` — 80% of the wall
//! clock, and four times the cost of the actual Groth16 arithmetic (175 ms).
//!
//! (The subgroup checks are already parallel inside `ark-serialize`: it reads
//! each element with `Validate::No` and then runs `batch_check` over the vector
//! with rayon. Only the square roots are serial.)
//!
//! # The format is unchanged
//!
//! This is the same byte format, read in the same order, with the same
//! validation — the point encoding, the `u64` length prefixes and the field
//! order all come from arkworks. The only difference is that each point's square
//! root is computed on a worker thread instead of in a `for` loop, and the
//! result keeps its index. A test asserts the parallel reader and
//! `ProvingKey::deserialize_compressed` agree byte for byte on a real key.
//!
//! # Why not store the key uncompressed instead
//!
//! That would trade a square root per point for twice the bytes (and still pay
//! the on-curve/subgroup checks), and it would change the key format every
//! operator has on disk. Parallel decompression keeps the artifact and doubles
//! down on the fact that the work is embarrassingly parallel.

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Validate,
};
use rayon::prelude::*;

/// Reads one point with the same compression and validation mode the derived
/// `ProvingKey` reader uses.
fn read_point<P: CanonicalDeserialize>(reader: &mut &[u8]) -> Result<P, SerializationError> {
    P::deserialize_with_mode(&mut *reader, Compress::Yes, Validate::Yes)
}

/// Reads a `u64`-length-prefixed vector of points whose compressed encoding is
/// a fixed `elem` bytes wide, decompressing the points in parallel.
///
/// Mirrors `impl CanonicalDeserialize for Vec<T>`: a `u64` length, then exactly
/// that many encodings, each validated. The length is bounds-checked against the
/// bytes actually remaining before anything is allocated, so a corrupt or
/// hostile length is an error rather than an allocation.
fn read_points<P>(reader: &mut &[u8], elem: usize) -> Result<Vec<P>, SerializationError>
where
    P: CanonicalDeserialize + Send + Sync,
{
    let len = u64::deserialize_with_mode(&mut *reader, Compress::Yes, Validate::Yes)?;
    let len = usize::try_from(len).map_err(|_| SerializationError::NotEnoughSpace)?;
    let need = len
        .checked_mul(elem)
        .ok_or(SerializationError::NotEnoughSpace)?;
    if reader.len() < need {
        return Err(SerializationError::NotEnoughSpace);
    }
    let (block, tail) = reader.split_at(need);
    *reader = tail;

    block
        .par_chunks_exact(elem)
        .map(|chunk| P::deserialize_with_mode(chunk, Compress::Yes, Validate::Yes))
        .collect()
}

/// The compressed width of one point of this curve, derived from the type
/// rather than hardcoded, so a curve change cannot silently mis-slice the block.
fn compressed_width<P: CanonicalSerialize>(point: &P) -> usize {
    point.compressed_size()
}

/// Deserialises a `ProvingKey<Bn254>` from its compressed bytes.
///
/// Byte-for-byte the same format as `ProvingKey::deserialize_compressed`; the
/// large point vectors are decompressed in parallel. Trailing bytes are ignored,
/// exactly as the derived reader ignores them.
///
/// # Errors
/// [`SerializationError`] on a truncated, corrupt or off-curve key — the same
/// conditions, and the same validation, as the sequential reader.
pub(crate) fn proving_key_from_bytes(
    bytes: &[u8],
) -> Result<ProvingKey<Bn254>, SerializationError> {
    let g1 = compressed_width(&G1Affine::default());
    let g2 = compressed_width(&G2Affine::default());

    let mut reader = bytes;
    // Field order is the declaration order of `ProvingKey`, which is also the
    // order its derived serialiser writes.
    let vk =
        VerifyingKey::<Bn254>::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes)?;
    let beta_g1 = read_point(&mut reader)?;
    let delta_g1 = read_point(&mut reader)?;
    let a_query = read_points(&mut reader, g1)?;
    let b_g1_query = read_points(&mut reader, g1)?;
    let b_g2_query = read_points(&mut reader, g2)?;
    let h_query = read_points(&mut reader, g1)?;
    let l_query = read_points(&mut reader, g1)?;

    Ok(ProvingKey {
        vk,
        beta_g1,
        delta_g1,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parallel reader must be a drop-in for the derived one: same points,
    /// same order, same bytes after a round trip.
    #[test]
    fn parallel_reader_agrees_with_the_derived_reader() {
        let keys = crate::prover::setup(7).expect("setup");
        let bytes = keys.proving_key_bytes().expect("serialise the proving key");

        let sequential =
            ProvingKey::<Bn254>::deserialize_compressed(&bytes[..]).expect("sequential read");
        let parallel = proving_key_from_bytes(&bytes).expect("parallel read");

        assert_eq!(sequential, parallel, "the two readers disagree");
        // And the key is unchanged, so a serialised key stays readable by any
        // other implementation of this format.
        let mut reserialised = Vec::new();
        parallel
            .serialize_compressed(&mut reserialised)
            .expect("re-serialise");
        assert_eq!(reserialised, bytes);
    }

    /// A truncated key must be an error, never a panic or a partial key.
    #[test]
    fn a_truncated_key_is_an_error() {
        let keys = crate::prover::setup(7).expect("setup");
        let bytes = keys.proving_key_bytes().expect("serialise the proving key");
        assert!(proving_key_from_bytes(&bytes[..bytes.len() / 2]).is_err());
        assert!(proving_key_from_bytes(&[]).is_err());
    }
}
