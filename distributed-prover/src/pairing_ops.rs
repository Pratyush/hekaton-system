use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::Field;
use ark_std::cfg_iter;
use rayon::prelude::*;

pub(crate) fn pairing_miller_affine<E: Pairing>(
    left: &[E::G1Affine],
    right: &[E::G2Affine],
) -> MillerLoopOutput<E> {
    assert_eq!(left.len(), right.len());

    let left = cfg_iter!(left)
        .map(|e| E::G1Prepared::from(*e))
        .collect::<Vec<_>>();
    let right = cfg_iter!(right)
        .map(|e| E::G2Prepared::from(*e))
        .collect::<Vec<_>>();

    E::multi_miller_loop(left, right)
}

/// Returns the miller loop result of the inner pairing product
pub(crate) fn pairing<E: Pairing>(left: &[E::G1Affine], right: &[E::G2Affine]) -> PairingOutput<E> {
    let miller_result = pairing_miller_affine::<E>(left, right);
    E::final_exponentiation(miller_result).expect("invalid pairing")
}

/// Multiplies a set of group elements by a same-sized set of scalars. outputs the vec of results
pub fn scalar_pairing<G: AffineRepr>(gp: &[G], scalars: &[G::ScalarField]) -> Vec<G> {
    let proj_results = cfg_iter!(gp)
        .zip(scalars)
        .map(|(si, ri)| *si * *ri)
        .collect::<Vec<_>>();

    G::Group::normalize_batch(&proj_results)
}

/// Returns a vector `(0, s, s^2, ..., s^{num-1})`
pub(crate) fn structured_scalar_power<F: Field>(num: usize, s: F) -> Vec<F> {
    let mut powers = vec![F::one()];
    for i in 1..num {
        powers.push(powers[i - 1] * s);
    }
    powers
}
