use core::{
    fmt::Debug,
    ops::{BitAnd, BitOr, BitXor, Div, Not, Rem},
};

use tinyram_emu::word::Word;

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
    type NativeWord: tinyram_emu::word::Word;

    const BITLEN: usize = Self::NativeWord::BITLEN;

    /// Returns the 0 word
    fn zero() -> Self;

    /// Returns the 1 word
    fn one() -> Self;

    /// Convert `self` to a field element
    fn to_fpvar(&self) -> Result<FpVar<F>, SynthesisError>;

    /// Convert `self` to its big-endian bit representation
    fn to_bits_be(&self) -> Vec<Boolean<F>>;

    /// Returns `(self + 1, overflow)`
    fn checked_increment(&self) -> Result<(Self, Boolean<F>), SynthesisError> {
        self.carrying_add(&Self::one())
    }

    /// Computes the sum of `self` and `other`, and returns the carry bit (if any).
    fn carrying_add(&self, other: &Self) -> Result<(Self, Boolean<F>), SynthesisError>;
}

impl<F: PrimeField> WordVar<F> for UInt32<F> {
    type NativeWord = u32;

    fn zero() -> Self {
        UInt32::constant(0)
    }

    fn one() -> Self {
        UInt32::constant(1)
    }

    fn to_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
        Boolean::le_bits_to_fp_var(&self.to_bits_le())
    }

    fn to_bits_be(&self) -> Vec<Boolean<F>> {
        let mut v = self.to_bits_le();
        v.reverse();
        v
    }

    fn carrying_add(&self, other: &Self) -> Result<(Self, Boolean<F>), SynthesisError> {
        // Do the full addition and convert to little endian. The BITLEN bit is the carry bit
        let sum = self.to_fpvar()? + &other.to_fpvar()?;
        let sum_bits = sum.to_bits_le()?;

        // Extract the carry bit
        let carry = sum_bits[Self::BITLEN].clone();
        // Get the lower bits
        let lower_bits = &sum_bits[..Self::BITLEN];

        Ok((Self::from_bits_le(lower_bits), carry))
    }
}
