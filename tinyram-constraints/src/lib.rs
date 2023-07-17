use ark_ff::PrimeField;
use tinyram_emu::TinyRam;

pub mod circuit_defs;
mod common;
pub mod cpu;
pub mod transcript_checker;
pub mod transcript_utils;

pub mod mmu;
pub mod tape;

mod util;
mod word;

#[cfg(test)]
pub(crate) mod test_utils;

pub mod option;

pub trait TinyRamExt: TinyRam {
    type F: PrimeField;
    type WordVar: word::WordVar<Self::F, Native = Self::Word>;
}
