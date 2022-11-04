use core::{
    fmt::Debug,
    ops::{BitAnd, BitOr, BitXor, Div, Not, Rem},
};

use tinyram_emu::word::Word;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    bits::{uint16::UInt16, uint32::UInt32, uint64::UInt64, uint8::UInt8, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::r1cs::SynthesisError;

pub type DoubleWordVar<W> = (W, W);

pub trait WordVar<F: PrimeField>: Debug + EqGadget<F> + CondSelectGadget<F> {
    type NativeWord: tinyram_emu::word::Word;

    const BITLEN: usize = Self::NativeWord::BITLEN;

    /// Returns the 0 word
    fn zero() -> Self;

    /// Returns the 1 word
    fn one() -> Self;

    /// Convert `self` to a field element
    fn as_fpvar(&self) -> Result<FpVar<F>, SynthesisError>;

    /// Convert `self` to its big-endian bit representation
    fn as_be_bits(&self) -> Vec<Boolean<F>>;

    /// Returns `(self + 1, overflow)`
    fn checked_increment(&self) -> Result<(Self, Boolean<F>), SynthesisError> {
        self.carrying_add(&Self::one())
    }

    /// Computes the sum of `self` and `other`, and returns the carry bit (if any).
    fn carrying_add(&self, other: &Self) -> Result<(Self, Boolean<F>), SynthesisError>;
}

macro_rules! impl_word {
    ($word_var: ident, $native_word: ty) => {
        impl<F: PrimeField> WordVar<F> for $word_var<F> {
            type NativeWord = $native_word;

            fn zero() -> Self {
                Self::constant(0)
            }

            fn one() -> Self {
                Self::constant(1)
            }

            fn as_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
                Boolean::le_bits_to_fp_var(&self.to_bits_le())
            }

            fn as_be_bits(&self) -> Vec<Boolean<F>> {
                let mut v = self.to_bits_le();
                v.reverse();
                v
            }

            fn carrying_add(&self, other: &Self) -> Result<(Self, Boolean<F>), SynthesisError> {
                // Do the full addition and convert to little endian. The BITLEN bit is the carry
                // bit
                let sum = self.as_fpvar()? + &other.as_fpvar()?;
                let sum_bits = sum.to_bits_le()?;

                // Extract the carry bit
                let carry = sum_bits[Self::BITLEN].clone();
                // Get the lower bits
                let lower_bits = &sum_bits[..Self::BITLEN];

                Ok((Self::from_bits_le(lower_bits), carry))
            }
        }
    };
}

impl_word!(UInt16, u16);
impl_word!(UInt32, u32);
impl_word!(UInt64, u64);

// Ugh, we need to implement this separately because UInt8 impls ToBitsGadget, so its to_bits_le()
// method returns a Result rather than a plain Vec (though it is still infallible)
impl<F: PrimeField> WordVar<F> for UInt8<F> {
    type NativeWord = u8;

    fn zero() -> Self {
        Self::constant(0)
    }

    fn one() -> Self {
        Self::constant(1)
    }

    fn as_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
        Boolean::le_bits_to_fp_var(&self.to_bits_le().unwrap())
    }

    fn as_be_bits(&self) -> Vec<Boolean<F>> {
        <Self as ToBitsGadget<F>>::to_bits_be(&self).unwrap()
    }

    fn carrying_add(&self, other: &Self) -> Result<(Self, Boolean<F>), SynthesisError> {
        // Do the full addition and convert to little endian. The BITLEN bit is the carry
        // bit
        let sum = self.as_fpvar()? + &other.as_fpvar()?;
        let sum_bits = sum.to_bits_le()?;

        // Extract the carry bit
        let carry = sum_bits[Self::BITLEN].clone();
        // Get the lower bits
        let lower_bits = &sum_bits[..Self::BITLEN];

        Ok((Self::from_bits_le(lower_bits), carry))
    }
}
