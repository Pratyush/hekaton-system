use core::{borrow::Borrow, fmt::Debug};
use std::ops::{BitAnd, BitOr, BitXor};

use tinyram_emu::word::Word;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    cmp::CmpGadget,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
    uint16::UInt16,
    uint32::UInt32,
    uint64::UInt64,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};

pub(crate) type DoubleWord<W> = (W, W);

#[derive(Clone)]
pub struct DoubleWordVar<W: WordVar<F>, F: PrimeField>(pub(crate) W, pub(crate) W);

impl<W: WordVar<F>, F: PrimeField> EqGadget<F> for DoubleWordVar<W, F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        Ok(self.0.is_eq(&other.0)? & self.w1.is_eq(&other.w1)?)
    }
}

impl<W: WordVar<F>, F: PrimeField> AllocVar<DoubleWord<W::Native>, F> for DoubleWordVar<W, F> {
    fn new_variable<T: Borrow<DoubleWord<W::Native>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|double_word| {
            let double_word = double_word.borrow();
            W::new_variable(ns!(cs, "w0"), || Ok(double_word.0), mode).and_then(|w0| {
                W::new_variable(ns!(cs, "w1"), || Ok(double_word.1), mode)
                    .map(|w1| DoubleWordVar(w0, w1))
            })
        })
    }
}

impl<W: WordVar<F>, F: PrimeField> R1CSVar<F> for DoubleWordVar<W, F> {
    type Value = DoubleWord<W::Native>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.w0.cs().or(self.w1.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok((self.w0.value()?, self.w1.value()?))
    }
}

impl<W: WordVar<F>, F: PrimeField> DoubleWordVar<W, F> {
    pub(crate) fn zero() -> Self {
        Self(W::zero(), W::zero())
    }

    /// Returns the bits of this double word in little-endian order

    pub(crate) fn as_le_bits(&self) -> Vec<Boolean<F>> {
        todo!()
        // [self.1.as_le_bits(), self.0.as_le_bits()].concat()
    }

    /// Stuffs the two words in this double word into a single field element
    pub(crate) fn as_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
        // Return w0 || w1
        let shifted_w0 = self.0.as_fpvar()? * F::from(1u64 << W::Native::BIT_LENGTH);
        Ok(shifted_w0 + self.1.as_fpvar()?)
    }
}

pub trait WordVar<F: PrimeField>:
    Debug
    + EqGadget<F>
    + CmpGadget<F>
    + BitXor<Output = Self>
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + AllocVar<Self::Native, F>
    + CondSelectGadget<F>
    + R1CSVar<F, Value = Self::Native>
{
    type Native: tinyram_emu::word::Word;

    const BIT_LENGTH: usize = Self::Native::BIT_LENGTH;

    /// Returns the 0 word
    fn zero() -> Self;

    /// Returns the 1 word
    fn one() -> Self;

    /// Returns the constant given by `w`
    fn constant(w: Self::Native) -> Self;

    /// Convert `self` to a field element
    fn as_fpvar(&self) -> Result<FpVar<F>, SynthesisError>;

    /// Convert `self` to a field element
    fn as_native(&self) -> Result<Self::Native, SynthesisError>;

    /// Convert `self` to its little-endian bit representation
    fn as_le_bits(&self) -> Vec<Boolean<F>>;

    /// Convert `self` to its big-endian bit representation
    fn as_be_bits(&self) -> Vec<Boolean<F>> {
        let mut v = self.as_le_bits();
        v.reverse();
        v
    }

    /// Unpacks this Word into its constituent bytes
    fn unpack(&self) -> Vec<UInt8<F>> {
        // Unpack simply returns the little-endian byte repr
        self.as_le_bits()
            .chunks(8)
            .map(UInt8::from_bits_le)
            .collect()
    }

    // Packs the given byte sequence into this Word. `bytes.len()` MUST equal `Self::Bitlen / 8`
    fn pack(&self, bytes: &[UInt8<F>]) -> Self {
        assert_eq!(bytes.len(), Self::BIT_LENGTH / 8);
        // Pack simply puts the bytes into the word in little-endian order
        let bits: Vec<_> = bytes.iter().flat_map(|b| b.to_bits_le().unwrap()).collect();
        Self::from_le_bits(&bits)
    }

    /// Convert from little-endian bit representation to `self'. `bits.len()` MUST be
    /// `Self::Bitlen`
    fn from_le_bits(bits: &[Boolean<F>]) -> Self;

    /// Returns `(self + 1, overflow)`
    fn checked_increment(&self) -> Result<(Self, Boolean<F>), SynthesisError> {
        self.carrying_add(&Self::one())
    }

    /// Computes the `self + other`, and returns the carry bit (if any).
    fn carrying_add(&self, other: &Self) -> Result<(Self, Boolean<F>), SynthesisError>;
}

macro_rules! impl_word {
    ($word_var: ident, $native_word: ty) => {
        impl<F: PrimeField> WordVar<F> for $word_var<F> {
            type Native = $native_word;

            fn zero() -> Self {
                Self::constant(0)
            }

            fn one() -> Self {
                Self::constant(1)
            }

            fn constant(w: Self::Native) -> Self {
                $word_var::constant(w)
            }

            fn as_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
                Boolean::le_bits_to_fp(&self.to_bits_le()?)
            }

            fn as_native(&self) -> Result<Self::Native, SynthesisError> {
                self.value()
            }

            fn as_le_bits(&self) -> Vec<Boolean<F>> {
                self.to_bits_le().unwrap()
            }

            fn as_be_bits(&self) -> Vec<Boolean<F>> {
                let mut v = self.to_bits_le().unwrap();
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

impl_word!(UInt8, u8);
impl_word!(UInt16, u16);
impl_word!(UInt32, u32);
impl_word!(UInt64, u64);
