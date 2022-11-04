//! Contains data pub(crate) types used in various parts of the ZKCPU

use crate::word::WordVar;

use core::cmp::Ordering;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    bits::ToBitsGadget, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;

/// Program counter, in ZK land
pub(crate) type PcVar<W> = W;

/// An instruction opcode, in ZK land
pub(crate) type OpcodeVar<F> = UInt8<F>;

/// An index into the registers, in ZK land
pub(crate) struct RegIdxVar<F: PrimeField>(UInt8<F>);

impl<F: PrimeField> RegIdxVar<F> {
    pub(crate) fn to_bits_be(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        self.0.to_bits_be()
    }

    /// Returns the least significant `⌈log₂ NUM_REGS⌉` bits of this index. This is so it can be
    /// used as a selector into an array of registers.
    pub(crate) fn as_selector<const NUM_REGS: usize>(
        &self,
    ) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let selector_bitlen = f32::from(NUM_REGS as u16).log2().ceil() as usize;
        let mut bits = self.0.to_bits_be()?;
        // Select the bottom selector_bitlen bits
        Ok(bits.split_off(8 - selector_bitlen))
    }

    /// Retrieves the value of this register index in the register set. Guarantees that `Self` is
    /// less than `NUM_REGS`
    pub(crate) fn value<const NUM_REGS: usize, W: WordVar<F>>(
        &self,
        regs: &[W],
    ) -> Result<W, SynthesisError> {
        // Check that this register index is less than NUM_REGS
        let num_regs = FpVar::Constant(F::from(NUM_REGS as u64));
        self.to_fpvar()?
            .enforce_cmp(&num_regs, Ordering::Less, false)?;

        // Get the value from the register set
        W::conditionally_select_power_of_two_vector(&self.as_selector::<NUM_REGS>()?, regs)
    }

    pub(crate) fn to_fpvar(&self) -> Result<FpVar<F>, SynthesisError> {
        Boolean::le_bits_to_fp_var(&self.0.to_bits_le()?)
    }
}

/// An index into RAM, in ZK land
pub(crate) type RamIdxVar<W> = W;

/// The set of CPU registers
pub(crate) type RegistersVar<W> = Vec<W>;

pub(crate) struct ImmOrRegisterVar<W, F>
where
    W: WordVar<F>,
    F: PrimeField,
{
    pub(crate) is_imm: Boolean<F>,
    pub(crate) val: W,
}

impl<W: WordVar<F>, F: PrimeField> ImmOrRegisterVar<W, F> {
    /// Returns the least significant `⌈log₂ NUM_REGS⌉` bits of this index. This is so it can be
    /// used as a selector into an array of registers.
    pub(crate) fn as_selector<const NUM_REGS: usize>(
        &self,
    ) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let selector_bitlen = f32::from(NUM_REGS as u16).log2().ceil() as usize;
        let mut bits = self.val.to_bits_be();
        // Select the bottom selector_bitlen bits
        Ok(bits.split_off(W::BITLEN - selector_bitlen))
    }

    /// Returns the immediate value, or retrieves the value of this register index in the register
    /// set. In the latter case, guarantees that `self.val` is less than `NUM_REGS`.
    pub(crate) fn value<const NUM_REGS: usize>(&self, regs: &[W]) -> Result<W, SynthesisError> {
        // We read imm_or_reg as both a register and an immediate, and then select the correct one
        let reg_val =
            W::conditionally_select_power_of_two_vector(&self.as_selector::<NUM_REGS>()?, regs)?;
        let imm_val = self.val.clone();

        // Check that, if this is a regsiter index, it is less than NUM_REGS
        let num_regs = FpVar::Constant(F::from(NUM_REGS as u64));
        imm_val
            .to_fpvar()?
            .is_cmp(&num_regs, Ordering::Less, false)?
            .conditional_enforce_equal(&Boolean::TRUE, &self.is_imm.not())?;

        // Select the immediate or register value
        W::conditionally_select(&self.is_imm, &imm_val, &reg_val)
    }
}
