//! Contains data pub(crate) types used in various parts of the ZKCPU

use crate::word::WordVar;
use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, uint8::UInt8};

/// Program counter, in ZK land
pub(crate) type PcVar<W> = W;

/// An instruction opcode, in ZK land
pub(crate) type OpcodeVar<F> = UInt8<F>;

/// An index into the registers, in ZK land
pub(crate) type RegIdxVar<F> = UInt8<F>;

/// An index into RAM, in ZK land
pub(crate) type RamIdxVar<W> = W;

/// The set of CPU registers
pub(crate) type RegistersVar<W> = Vec<W>;

pub(crate) struct ImmOrRegisterVar<W, F>
where
    W: WordVar<F>,
    F: PrimeField,
{
    is_imm: Boolean<F>,
    val: W,
}
