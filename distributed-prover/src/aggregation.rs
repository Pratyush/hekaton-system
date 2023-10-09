use crate::util::G16Com;

use core::borrow::Borrow;

use ark_crypto_primitives::crh::sha256::{digest::Digest, Sha256};
use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    scalar_mul::fixed_base::FixedBase,
    CurveGroup, Group,
};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::One;
use rand::RngCore;
use rayon::prelude::*;

macro_rules! try_par {
    ($(let $name:ident = $f:expr),+) => {
        $(
            let mut $name = None;
        )+
            rayon::scope(|s| {
                $(
                    let $name = &mut $name;
                    s.spawn(move |_| {
                        *$name = Some($f);
                    });)+
            });
        $(
            let $name = $name.unwrap()?;
        )+
    };
}

macro_rules! par {
    ($(let $name:ident = $f:expr),+) => {
        $(
            let mut $name = None;
        )+
            rayon::scope(|s| {
                $(
                    let $name = &mut $name;
                    s.spawn(move |_| {
                        *$name = Some($f);
                    });)+
            });
        $(
            let $name = $name.unwrap();
        )+
    };

    ($(let ($name1:ident, $name2:ident) = $f:block),+) => {
        $(
            let mut $name1 = None;
            let mut $name2 = None;
        )+
            rayon::scope(|s| {
                $(
                    let $name1 = &mut $name1;
                    let $name2 = &mut $name2;
                    s.spawn(move |_| {
                        let (a, b) = $f;
                        *$name1 = Some(a);
                        *$name2 = Some(b);
                    });)+
            });
        $(
            let $name1 = $name1.unwrap();
            let $name2 = $name2.unwrap();
        )+
    }
}

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
    let powers_of_g = FixedBase::msm::<G>(
        //let powers_of_g = msm::fixed_base::multi_scalar_mul::<G>(
        scalar_bits,
        window_size,
        &g_table,
        &powers_of_scalar[..],
    );
    powers_of_g.into_iter().map(|v| v.into_affine()).collect()
}

/// Commits to the full set of CP-Groth16 stage 0 commitments
pub(crate) fn commit_to_g16_coms<E: Pairing>(
    ck: &SuperComCommittingKey<E>,
    coms: &[G16Com<E>],
) -> IppCom<E> {
    par! {
        let t = pairing::<E>(coms, &ck.v1),
        let u = pairing::<E>(coms, &ck.v2)
    };
    IppCom { t, u }
}

/// The output of the `CM_D` commitment method
#[derive(PartialEq, CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct IppCom<E: Pairing> {
    pub t: PairingOutput<E>,
    pub u: PairingOutput<E>,
}

/// This is the key used to produce the commitment over the Groth16 commitments, i.e., the
/// supercommitment. This is a `CM_1` committing key, i.e., it only contains the values necessary
/// to commit to the left-hand input.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SuperComCommittingKey<E: Pairing> {
    v1: Vec<E::G2Affine>,
    v2: Vec<E::G2Affine>,
}

impl<E: Pairing> Default for SuperComCommittingKey<E> {
    fn default() -> Self {
        SuperComCommittingKey {
            v1: Vec::with_capacity(0),
            v2: Vec::with_capacity(0),
        }
    }
}

impl<E: Pairing> SuperComCommittingKey<E> {
    /// Generates a key that can commit to up to `size` commitments. This is a trusted setup
    pub fn gen<R: RngCore>(mut rng: R, size: usize) -> Self {
        let h = E::G2::generator();
        let u = E::ScalarField::rand(&mut rng);
        let v = E::ScalarField::rand(&mut rng);

        par! {
            let v1 = structured_generators_scalar_power(size, &h, &u),
            let v2 = structured_generators_scalar_power(size, &h, &v)
        }

        SuperComCommittingKey { v1, v2 }
    }
}
