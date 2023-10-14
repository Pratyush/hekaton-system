pub use ark_bls12_381::{G1Affine, G1Projective, Fr as G1ScalarField, Fq as G1BaseField};
use ark_ec::{AffineRepr, CurveConfig};
use ark_ff::PrimeField;

pub const G1_SCALAR_SIZE: u32 =
    <<G1Affine as AffineRepr>::ScalarField as PrimeField>::MODULUS_BIT_SIZE;
pub const G1_SCALAR_SIZE_GLV: u32 = 128u32;
pub const GROUP_SIZE_IN_BITS: usize = 6;
pub const GROUP_SIZE: usize = 1 << GROUP_SIZE_IN_BITS;

pub type G1BigInt = <<G1Affine as AffineRepr>::ScalarField as PrimeField>::BigInt;

pub type BigInt<P> = <<P as CurveConfig>::ScalarField as PrimeField>::BigInt;
