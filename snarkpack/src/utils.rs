use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::cfg_iter_mut;
use digest::Digest;
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub fn rng_from_seed_bytes(seed: impl CanonicalSerialize) -> impl Rng {
    let buf_size = seed.uncompressed_size();
    let mut buf = Vec::with_capacity(buf_size);
    seed.serialize_uncompressed(&mut buf).unwrap();
    let hash = blake2::Blake2s256::digest(&buf);

    ChaChaRng::from_seed(hash.into())
}

/// Returns the vector used for the linear combination fo the inner pairing product
/// between A and B for the Groth16 aggregation: A^r * B. It is required as it
/// is not enough to simply prove the ipp of A*B, we need a random linear
/// combination of those.
pub(crate) fn structured_scalar_power<F: Field>(num: usize, s: &F) -> Vec<F> {
    let mut powers = vec![F::one()];
    for i in 1..num {
        powers.push(powers[i - 1] * s);
    }
    powers
}

/// compress is similar to commit::{V,W}KEY::compress: it modifies the `vec`
/// vector by setting the value at index $i:0 -> split$  $vec[i] = vec[i] +
/// vec[i+split]^scaler$. The `vec` vector is half of its size after this call.
pub(crate) fn compress<C: AffineRepr>(vec: &mut Vec<C>, split: usize, scalar: &C::ScalarField) {
    let (left, right) = vec.split_at_mut(split);
    cfg_iter_mut!(left)
        .zip(right)
        .for_each(|(a_l, a_r)| *a_l = (*a_r * *scalar + *a_l).into());
    let len = left.len();
    vec.resize(len, C::zero());
}
