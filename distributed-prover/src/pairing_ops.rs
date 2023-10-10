use ark_crypto_primitives::crh::sha256::{digest::Digest, Sha256};
use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    scalar_mul::{fixed_base::FixedBase, variable_base::VariableBaseMSM},
    AffineRepr, CurveGroup, Group,
};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::One;
use rand::RngCore;
use rayon::prelude::*;

pub(crate) fn pairing_miller_affine<E: Pairing>(
    left: &[E::G1Affine],
    right: &[E::G2Affine],
) -> MillerLoopOutput<E> {
    assert_eq!(left.len(), right.len());

    let left = left
        .par_iter()
        .map(|e| E::G1Prepared::from(*e))
        .collect::<Vec<_>>();
    let right = right
        .par_iter()
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
    let proj_results = gp
        .par_iter()
        .zip(scalars)
        .map(|(si, ri)| *si * *ri)
        .collect::<Vec<_>>();

    G::Group::normalize_batch(&proj_results)
}

pub(crate) fn msm<G: AffineRepr>(left: &[G], right: &[G::ScalarField]) -> G::Group {
    assert_eq!(
        left.len(),
        right.len(),
        "cannot MSM over different sized inputs"
    );
    VariableBaseMSM::msm(left, right).unwrap()
}

/// Returns powers of a generator
pub(crate) fn structured_generators_scalar_power<G: CurveGroup>(
    num: usize,
    g: &G,
    s: &G::ScalarField,
) -> Vec<G::Affine> {
    assert!(num > 0);
    let mut powers_of_scalar = Vec::with_capacity(num);
    let mut pow_s = G::ScalarField::one();
    for _ in 0..num {
        powers_of_scalar.push(pow_s);
        pow_s *= s;
    }
    let scalar_bits = G::ScalarField::MODULUS_BIT_SIZE as usize;
    let window_size = FixedBase::get_mul_window_size(num);
    let g_table = FixedBase::get_window_table::<G>(scalar_bits, window_size, g.clone());
    let powers_of_g =
        FixedBase::msm::<G>(scalar_bits, window_size, &g_table, &powers_of_scalar[..]);
    powers_of_g.into_iter().map(|v| v.into_affine()).collect()
}

/// Returns a vector `(0, s, s^2, ..., s^{num-1})`
pub(crate) fn structured_scalar_power<F: Field>(num: usize, s: F) -> Vec<F> {
    let mut powers = vec![F::one()];
    for i in 1..num {
        powers.push(powers[i - 1] * s);
    }
    powers
}
