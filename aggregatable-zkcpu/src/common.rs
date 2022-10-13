//! Contains data pub(crate) types used in various parts of the ZKCPU

use ark_r1cs_std::{fields::fp::FpVar, uint32::UInt32};

/// An index into RAM
pub(crate) type RamIdx = u32;
/// An index into RAM, in ZK land
pub(crate) type RamIdxVar<F> = FpVar<F>;

/// Program counter
pub(crate) type Pc = u32;
/// Program counter, in ZK land
pub(crate) type PcVar<F> = UInt32<F>;

/// A CPU word
pub(crate) type Word = u32;
/// A CPU word, in ZK land
pub(crate) type WordVar<F> = UInt32<F>;

/// A CPU instruction
pub(crate) type Instr = Word;
/// A CPU instruction, in ZK land
pub(crate) type InstrVar<F> = WordVar<F>;
