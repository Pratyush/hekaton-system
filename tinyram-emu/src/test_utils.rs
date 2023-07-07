use std::marker::PhantomData;

use crate::{word::Word, TinyRam, TinyRamArch};

#[derive(Copy, Clone)]
pub struct TinyRamVN<W: Word, const NUM_REGS: u8> {
    _word: PhantomData<W>,
}

impl<W: Word, const NUM_REGS: u8> TinyRam for TinyRamVN<W, NUM_REGS> {
    const ARCH: TinyRamArch = TinyRamArch::VonNeumann;
    const NUM_REGS: u8 = NUM_REGS;
    type Word = W;
}

pub type TinyRamVN16 = TinyRamVN<u16, 16>;
pub type TinyRamVN32 = TinyRamVN<u32, 16>;
pub type TinyRamVN64 = TinyRamVN<u64, 16>;

#[derive(Copy, Clone)]
pub struct TinyRamHv<W: Word, const NUM_REGS: u8> {
    _word: PhantomData<W>,
}

impl<W: Word, const NUM_REGS: u8> TinyRam for TinyRamHv<W, NUM_REGS> {
    const ARCH: TinyRamArch = TinyRamArch::Harvard;
    const NUM_REGS: u8 = NUM_REGS;
    type Word = W;
}

pub type TinyRamHv16 = TinyRamHv<u16, 16>;
pub type TinyRamHv32 = TinyRamHv<u32, 16>;
pub type TinyRamHv64 = TinyRamHv<u64, 16>;

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
