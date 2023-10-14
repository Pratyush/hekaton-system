use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::cfg_iter;
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

/// Computes the powers `r^0, r^1, ..., r^{num-1}`.
pub(crate) fn structured_scalar_power<F: Field>(num: usize, r: F) -> Vec<F> {
    let mut powers = vec![F::one()];
    for i in 1..num {
        powers.push(powers[i - 1] * r);
    }
    powers
}

/// compress is similar to commit::{V,W}KEY::compress: it modifies the `vec`
/// vector by setting the value at index $i:0 -> split$  $vec[i] = vec[i] +
/// vec[i+split]^scaler$. The `vec` vector is half of its size after this call.
pub(crate) fn compress<C: AffineRepr>(vec: &mut Vec<C>, split: usize, scalar: C::ScalarField) {
    let (left, right) = vec.split_at(split);
    let left_group = cfg_iter!(left)
        .zip(right)
        .map(|(&l, &r)| l + r * scalar)
        .collect::<Vec<_>>();
    assert_eq!(left_group.len(), left.len());
    *vec = C::Group::normalize_batch(&left_group);
}

/// Creates parallel iterator over mut refs if `parallel` feature is enabled.
/// Additionally, if the object being iterated implements
/// `IndexedParallelIterator`, then one can specify a minimum size for
/// iteration.
#[macro_export]
macro_rules! cfg_fold {
    ($e: expr, $default: expr, $fold_fn: expr) => {{
        #[cfg(feature = "parallel")]
        let result = $e.fold_with($default, $fold_fn);

        #[cfg(not(feature = "parallel"))]
        let result = $e.fold($default, $fold_fn);

        result
    }};
}
