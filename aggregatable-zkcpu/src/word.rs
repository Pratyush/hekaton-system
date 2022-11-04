use core::{
    fmt::Debug,
    ops::{BitAnd, BitOr, BitXor, Div, Not, Rem},
};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    bits::{uint32::UInt32, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::r1cs::SynthesisError;

pub trait WordVar<F: PrimeField>: Debug + EqGadget<F> + CondSelectGadget<F> {
    type Signed: Eq + Ord + Copy;

    type NativeWord: tinyram_emu::word::Word;

    const BITLEN: usize;

    /// Returns the zero word
    fn zero() -> Self;

    /// Convert `self` to a field element
    fn to_fpvar(&self) -> FpVar<F>;

    /// Convert `self` to its big-endian bit representation
    fn to_bits_be(&self) -> Result<Vec<Boolean<F>>, SynthesisError>;

    /// Convert `self` to a `BIT_SIZE`-bit signed integer.
    fn to_signed(self) -> Self::Signed;

    /// Returns `(self + 1, overflow)`
    fn checked_increment(&self) -> (Self, Boolean<F>);

    /// Computes the sum of `self` and `other`, and returns the carry bit (if any).
    fn carrying_add(&self, other: &Self) -> Result<(Self, Boolean<F>), SynthesisError>;
}

//impl<F: PrimeField> WordVar<F> for UInt32<F> {}
