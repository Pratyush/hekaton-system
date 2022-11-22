use core::{
    fmt::Debug,
    marker::PhantomData,
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

pub struct DoubleWordVar<W: WordVar<F>, F: PrimeField> {
    w0: W,
    w1: W,
    _marker: PhantomData<F>,
}

impl<W: WordVar<F>, F: PrimeField> DoubleWordVar<W, F> {
    /// Creates a `DoubleWordVar` from two `Word`s
    pub(crate) fn new(dword: (W, W)) -> Self {
        Self {
            w0: dword.0,
            w1: dword.1,
            _marker: PhantomData,
        }
    }

    /// Returns the bits of this dword in little-endian order
    pub(crate) fn as_le_bits(&self) -> Vec<Boolean<F>> {
        [self.w1.as_le_bits(), self.w0.as_le_bits()].concat()
    }
}

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

    /// Convert `self` to its little-endian bit representation
    fn as_le_bits(&self) -> Vec<Boolean<F>>;

    /// Convert from little-endian bit representation to `self'
    fn from_le_bits(bits: &[Boolean<F>]) -> Self;

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

            fn as_le_bits(&self) -> Vec<Boolean<F>> {
                self.to_bits_le()
            }

            fn as_be_bits(&self) -> Vec<Boolean<F>> {
                let mut v = self.to_bits_le();
                v.reverse();
                v
            }

            fn from_le_bits(bits: &[Boolean<F>]) -> Self {
                Self::from_bits_le(bits)
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

    fn as_le_bits(&self) -> Vec<Boolean<F>> {
        <Self as ToBitsGadget<F>>::to_bits_le(&self).unwrap()
    }

    fn as_be_bits(&self) -> Vec<Boolean<F>> {
        <Self as ToBitsGadget<F>>::to_bits_be(&self).unwrap()
    }

    fn from_le_bits(bits: &[Boolean<F>]) -> Self {
        Self::from_bits_le(bits)
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
