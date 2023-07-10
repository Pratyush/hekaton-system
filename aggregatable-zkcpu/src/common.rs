//! Contains data pub(crate) types used in various parts of the ZKCPU

use crate::{word::WordVar, TinyRamExt};

use tinyram_emu::{instructions::Opcode, word::Word, TinyRam};

use core::cmp::Ordering;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar, uint8::UInt8, R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::log2;

/// Program counter, in ZK land
pub(crate) type PcVar<W> = W;

/// An instruction opcode, in ZK land
pub(crate) struct OpcodeVar<F: PrimeField>(pub(crate) UInt8<F>);

impl<F: PrimeField> OpcodeVar<F> {
    pub(crate) const BIT_LENGTH: usize = 5;

    pub(crate) fn to_bits_be(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        // Return the bottom BITLEN bits
        self.0.to_bits_be().map(|bits| {
            let start = (<Self as R1CSVar<_>>::Value::BITS as usize) - Self::BIT_LENGTH;
            bits[start..start + Self::BIT_LENGTH].to_vec()
        })
    }

    pub(crate) fn from_bits_le(bits: &[Boolean<F>]) -> Self {
        assert_eq!(bits.len(), Self::BIT_LENGTH);

        // Pad out the remaining bits to get to a byte
        let mut padded_bits = vec![Boolean::FALSE; 8];
        padded_bits[..Self::BIT_LENGTH].clone_from_slice(bits);
        Self(UInt8::from_bits_le(&padded_bits))
    }
}

impl<F: PrimeField> R1CSVar<F> for OpcodeVar<F> {
    type Value = Opcode;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.0.value()
    }
}

/// An index into the registers, in ZK land
// This is a UInt8 because the number of registers cannot exceed 256
#[derive(Clone)]
pub(crate) struct RegIdxVar<F: PrimeField>(pub(crate) UInt8<F>);

impl<F: PrimeField> R1CSVar<F> for RegIdxVar<F> {
    type Value = u8;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.0.value()
    }
}

impl<'a, F: PrimeField> ToBitsGadget<F> for &'a RegIdxVar<F>
where
    F: PrimeField,
{
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        self.0.to_bits_le()
    }
}

impl<F: PrimeField> ToBitsGadget<F> for RegIdxVar<F> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        <&Self>::to_bits_le(&self)
    }
}

impl<F: PrimeField> RegIdxVar<F> {
    pub(crate) const BIT_LENGTH: usize = 8;

    pub(crate) fn zero() -> Self {
        RegIdxVar(UInt8::zero())
    }

    pub(crate) fn from_le_bits(bits: &[Boolean<F>]) -> Self {
        assert!(bits.len() <= 8);

        // Pad out the remaining bits to get to a byte
        let mut padded_bits = vec![Boolean::FALSE; 8];
        padded_bits[..bits.len()].clone_from_slice(bits);
        Self(UInt8::from_bits_le(&padded_bits))
    }

    /// Returns the least significant `⌈log₂ NUM_REGS⌉` bits of this index. This is so it can be
    /// used as a selector into an array of registers.
    pub(crate) fn as_selector<T: TinyRam>(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let selector_bitlen = log2(T::NUM_REGS) as usize;
        let mut bits = self.0.to_bits_be()?;
        // Select the bottom selector_bitlen bits
        Ok(bits.split_off(8 - selector_bitlen))
    }

    /// Retrieves the value of this register index in the register set. Guarantees that `Self` is
    /// less than `NUM_REGS`
    pub(crate) fn value<T: TinyRamExt<F = F>>(
        &self,
        regs: &[T::WordVar],
    ) -> Result<T::WordVar, SynthesisError> {
        // Check that this register index is less than NUM_REGS
        let num_regs = FpVar::Constant(F::from(T::NUM_REGS as u64));
        self.to_fpvar()?
            .enforce_cmp(&num_regs, Ordering::Less, false)?;

        // Get the value from the register set
        T::WordVar::conditionally_select_power_of_two_vector(&self.as_selector::<T>()?, regs)
    }

    pub(crate) fn to_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
        self.0.to_fp()
    }
}

/// An index into RAM, in ZK land
pub(crate) type RamIdxVar<W> = W;

/// The set of CPU registers
pub(crate) type RegistersVar<W> = Vec<W>;

pub(crate) struct ImmOrRegisterVar<T: TinyRamExt> {
    pub(crate) is_imm: Boolean<T::F>,
    pub(crate) val: T::WordVar,
}

impl<T: TinyRamExt> ImmOrRegisterVar<T> {
    /// Returns the least significant `⌈log₂ NUM_REGS⌉` bits of this index. This is so it can be
    /// used as a selector into an array of registers.
    pub(crate) fn as_selector(&self) -> Result<Vec<Boolean<T::F>>, SynthesisError> {
        let selector_bitlen = log2(T::NUM_REGS) as usize;
        let mut bits = self.val.as_be_bits();
        // Select the bottom selector_bitlen bits
        Ok(bits.split_off(T::WordVar::BIT_LENGTH - selector_bitlen))
    }

    /// Returns the immediate value, or retrieves the value of this register index in the register
    /// set. In the latter case, guarantees that `self.val` is less than `NUM_REGS`.
    pub(crate) fn value(&self, regs: &[T::WordVar]) -> Result<T::WordVar, SynthesisError> {
        // We read imm_or_reg as both a register and an immediate, and then select the correct one
        // Check that, if this is a register index, it is less than NUM_REGS
        let num_regs = T::WordVar::constant(T::Word::from_u64(T::NUM_REGS as u64));
        self.val
            .is_lt(&num_regs)?
            .conditional_enforce_equal(&Boolean::TRUE, &!self.is_imm.clone())?;

        // If so, read the value from the register list.
        let reg_val =
            T::WordVar::conditionally_select_power_of_two_vector(&self.as_selector()?, regs)?;

        // Select the immediate or register value
        self.is_imm.select(&self.val, &reg_val)
    }
}
