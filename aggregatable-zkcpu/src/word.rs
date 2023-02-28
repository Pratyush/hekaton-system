use crate::circuit_defs::InOutAllocVar;

use core::{borrow::Borrow, fmt::Debug, marker::PhantomData};

use tinyram_emu::word::Word;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::{uint16::UInt16, uint32::UInt32, uint64::UInt64, uint8::UInt8, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};

pub(crate) type DWord<W> = (W, W);

#[derive(Clone)]
pub struct DWordVar<W: WordVar<F>, F: PrimeField> {
    pub(crate) w0: W,
    pub(crate) w1: W,
    _marker: PhantomData<F>,
}

impl<W: WordVar<F>, F: PrimeField> EqGadget<F> for DWordVar<W, F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        self.w0.is_eq(&other.w0)?.and(&self.w1.is_eq(&other.w1)?)
    }
}

impl<W: WordVar<F>, F: PrimeField> AllocVar<DWord<W::NativeWord>, F> for DWordVar<W, F> {
    fn new_variable<T: Borrow<DWord<W::NativeWord>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|dword| {
            let dword = dword.borrow();
            W::new_variable(ns!(cs, "w0"), || Ok(dword.0), mode).and_then(|w0| {
                W::new_variable(ns!(cs, "w1"), || Ok(dword.1), mode).map(|w1| DWordVar {
                    w0,
                    w1,
                    _marker: PhantomData,
                })
            })
        })
    }
}

impl<W: WordVar<F>, F: PrimeField> R1CSVar<F> for DWordVar<W, F> {
    type Value = DWord<W::NativeWord>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.w0.cs().or(self.w1.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok((self.w0.value()?, self.w1.value()?))
    }
}

impl<W: WordVar<F>, F: PrimeField> DWordVar<W, F> {
    pub(crate) fn zero() -> Self {
        Self {
            w0: W::zero(),
            w1: W::zero(),
            _marker: PhantomData,
        }
    }

    /// Returns the bits of this dword in little-endian order
    pub(crate) fn as_le_bits(&self) -> Vec<Boolean<F>> {
        [self.w1.as_le_bits(), self.w0.as_le_bits()].concat()
    }

    /// Stuffs the two words in this dword into a single field element
    pub(crate) fn as_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
        // Return w0 || w1
        let shifted_w0 = self.w0.as_fpvar()? * F::from(1u64 << W::NativeWord::BITLEN);
        Ok(shifted_w0 + self.w1.as_fpvar()?)
    }
}

pub trait WordVar<F: PrimeField>:
    Debug
    + EqGadget<F>
    + AllocVar<Self::NativeWord, F>
    + CondSelectGadget<F>
    + R1CSVar<F, Value = Self::NativeWord>
{
    type NativeWord: tinyram_emu::word::Word;

    const BITLEN: usize = Self::NativeWord::BITLEN;

    /// Returns the 0 word
    fn zero() -> Self;

    /// Returns the 1 word
    fn one() -> Self;

    /// Returns the constant given by `w`
    fn constant(w: Self::NativeWord) -> Self;

    /// Convert `self` to a field element
    fn as_fpvar(&self) -> Result<FpVar<F>, SynthesisError>;

    /// Convert `self` to a field element
    fn as_native(&self) -> Result<Self::NativeWord, SynthesisError>;

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
        assert_eq!(bytes.len(), Self::BITLEN / 8);
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

    /// Computes the `self ⊕ other`
    fn xor(&self, other: &Self) -> Result<Self, SynthesisError>;
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

            fn constant(w: Self::NativeWord) -> Self {
                $word_var::constant(w)
            }

            fn as_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
                Boolean::le_bits_to_fp_var(&self.to_bits_le())
            }

            fn as_native(&self) -> Result<Self::NativeWord, SynthesisError> {
                self.value()
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

            /// Computes the `self ⊕ other`
            fn xor(&self, other: &Self) -> Result<Self, SynthesisError> {
                let xored_bits: Result<Vec<_>, _> = self
                    .as_le_bits()
                    .into_iter()
                    .zip(other.as_le_bits().into_iter())
                    .map(|(a, b)| a.xor(&b))
                    .collect();

                Ok(Self::from_le_bits(&xored_bits?))
            }
        }
    };
}

impl<F: PrimeField> InOutAllocVar<u8, F> for UInt8<F>
where
    Self: Sized,
{
    fn new_inout<T: Borrow<u8>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<(T, T), SynthesisError>,
    ) -> Result<(Self, Self), SynthesisError> {
        let cs = cs.into().cs();

        let (in_val, out_val) = f()?;
        let (in_val, out_val) = (in_val.borrow(), out_val.borrow());

        // Explode the words into little-endian bits
        let mut in_val_bits = [false; 8];
        let mut out_val_bits = [false; 8];
        in_val_bits
            .iter_mut()
            .zip(out_val_bits.iter_mut())
            .enumerate()
            .for_each(|(i, (inv, outv))| {
                *inv = (in_val >> i) & 1 == 1;
                *outv = (out_val >> i) & 1 == 1;
            });

        // Witness all the booleans in order
        let mut in_vars = Vec::new();
        let mut out_vars = Vec::new();
        for (in_val, out_val) in in_val_bits.iter().zip(out_val_bits) {
            in_vars.push(Boolean::new_input(ns!(cs, "input"), || Ok(in_val))?);
            out_vars.push(Boolean::new_input(ns!(cs, "output"), || Ok(out_val))?);
        }

        // Make a UInt8 from the Booleans
        Ok((
            UInt8::from_bits_le(&in_vars),
            UInt8::from_bits_le(&out_vars),
        ))
    }
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

    fn constant(w: Self::NativeWord) -> Self {
        UInt8::constant(w)
    }

    fn as_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
        Boolean::le_bits_to_fp_var(&self.to_bits_le().unwrap())
    }

    fn as_native(&self) -> Result<Self::NativeWord, SynthesisError> {
        self.value()
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

    /// Computes the `self ⊕ other`
    fn xor(&self, other: &Self) -> Result<Self, SynthesisError> {
        let xored_bits: Result<Vec<_>, _> = self
            .as_le_bits()
            .into_iter()
            .zip(other.as_le_bits().into_iter())
            .map(|(a, b)| a.xor(&b))
            .collect();

        Ok(Self::from_le_bits(&xored_bits?))
    }
}
