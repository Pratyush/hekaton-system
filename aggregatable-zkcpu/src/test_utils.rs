use std::marker::PhantomData;

use ark_bls12_381::Fr;
use ark_ff::Field;
use tinyram_emu::{TinyRam, TinyRamArch};

use crate::{word::WordVar, TinyRamExt};

#[derive(Copy, Clone)]
pub struct TinyRamVN<W: WordVar<F>, const NUM_REGS: u8, F: Field> {
    _word: PhantomData<W>,
}

impl<W: WordVar<F>, const NUM_REGS: u8, F: Field> TinyRam for TinyRamVN<W, NUM_REGS, F> {
    const ARCH: TinyRamArch = TinyRamArch::VonNeumann;
    const NUM_REGS: u8 = NUM_REGS;
    type Word = W::Native;
}

impl<W: WordVar<F>, const NUM_REGS: u8, F: Field> TinyRamExt for TinyRamVN<W, NUM_REGS, F> {
    type F = F;
    type WordVar = W;
}

pub type TinyRamVN16 = TinyRamVN<u16, 16, Fr>;
pub type TinyRamVN32 = TinyRamVN<u32, 16, Fr>;
pub type TinyRamVN64 = TinyRamVN<u64, 16, Fr>;

///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

#[derive(Copy, Clone)]
pub struct TinyRamHv<W: WordVar<F>, const NUM_REGS: u8, F: Field> {
    _word: PhantomData<W>,
}

impl<W: WordVar<F>, const NUM_REGS: u8, F: Field> TinyRam for TinyRamHv<W, NUM_REGS, F> {
    const ARCH: TinyRamArch = TinyRamArch::Harvard;
    const NUM_REGS: u8 = NUM_REGS;
    type Word = W::Native;
}

impl<W: WordVar<F>, const NUM_REGS: u8, F: Field> TinyRamExt for TinyRamHv<W, NUM_REGS, F> {
    type F = F;
    type WordVar = W;
}

pub type TinyRamHv16 = TinyRamHv<u16, 16, Fr>;
pub type TinyRamHv32 = TinyRamHv<u32, 16, Fr>;
pub type TinyRamHv64 = TinyRamHv<u64, 16, Fr>;

#[macro_export]
macro_rules! iter_over_tinyram_configs {
    ($f: ident) => {{
        $f::<$crate::test_utils::TinyRamVN16>();
        $f::<$crate::test_utils::TinyRamVN32>();
        $f::<$crate::test_utils::TinyRamVN64>();

        $f::<$crate::test_utils::TinyRamHv16>();
        $f::<$crate::test_utils::TinyRamHv32>();
        $f::<$crate::test_utils::TinyRamHv64>();
    }};
}
