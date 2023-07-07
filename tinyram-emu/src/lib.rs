#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]
#![forbid(unsafe_code)]

use strum::Display;
use word::Word;

pub mod instructions;
pub mod parser;
pub mod register;
pub mod word;

pub mod cpu;
pub mod mmu;
pub mod tape;

pub mod test_utils;

pub trait TinyRam: Sized + Copy + 'static {
    type Word: word::Word;
    const ARCH: TinyRamArch;
    const NUM_REGS: u8;
    const DOUBLE_WORD_BYTE_LENGTH: usize = 2 * Self::Word::BYTE_LENGTH;
    const SERIALIZED_INSTR_BYTE_LENGTH: usize = Self::DOUBLE_WORD_BYTE_LENGTH;

    fn header() -> String {
        format!(
            "; TinyRAM V=2.000 M={} W={} K={}\n",
            Self::ARCH,
            Self::Word::BIT_LENGTH,
            Self::NUM_REGS,
        )
    }
}

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq)]
pub enum TinyRamArch {
    #[strum(serialize = "hv")]
    Harvard,
    #[strum(serialize = "vn")]
    VonNeumann,
}

/// Contains important metadata about the program being run
#[derive(Clone, Copy, Debug)]
pub struct ProgramMetadata {
    /// The architecture of the CPU
    pub arch: TinyRamArch,
    /// The size, in words, of the primary input tape
    pub primary_input_len: u32,
    /// The size, in words, of the aux input tape
    pub aux_input_len: u32,
}
