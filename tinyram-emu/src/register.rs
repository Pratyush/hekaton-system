use crate::word::Word;

use core::str::FromStr;

/// An index into the CPU registers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegIdx(pub u8);

impl RegIdx {
    pub fn value<W: Word>(&self, registers: &[W]) -> W {
        registers[self.0 as usize]
    }

    pub fn from_str(s: &str) -> Result<RegIdx, core::num::ParseIntError> {
        let b = u8::from_str(s)?;
        Ok(RegIdx(b))
    }
}

/// In TinyRAM, some instruction inputs are interpreted as either a register index or an immediate
/// (i.e., a constant). This enum captures that functionality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmOrRegister<W: Word> {
    Imm(W),
    Register(RegIdx),
}

impl<W: Word> ImmOrRegister<W> {
    /// Makes a new immediate or register. Will error if `is_imm == true` and `val` exceeds
    /// `W::MAX`
    pub fn new(val: u64, is_imm: bool) -> Result<Self, ()> {
        if is_imm {
            W::try_from(val).map(ImmOrRegister::Imm).map_err(|_| ())
        } else {
            u8::try_from(val)
                .map(|b| ImmOrRegister::Register(RegIdx(b)))
                .map_err(|_| ())
        }
    }

    /// Returns whether this is an Immediate value
    pub fn is_imm(&self) -> bool {
        match self {
            ImmOrRegister::Imm(_) => true,
            _ => false,
        }
    }

    /// Returns the value of this `ImmOrRegister` relative to the register set. If this is an
    /// `Imm`, then the internal value is returned. Otherwise, the relevant register value is
    /// returned.
    pub fn value(&self, registers: &[W]) -> W {
        match self {
            ImmOrRegister::Register(reg) => registers[reg.0 as usize],
            ImmOrRegister::Imm(imm) => *imm,
        }
    }

    /// Returns internal value of this `ImmOrRegister`. It can be either a constant or a reigster
    /// index.
    pub fn raw(&self) -> W {
        match self {
            // This unwrap is ok because reg.0 is a u8, which is always representable as a Word
            ImmOrRegister::Register(reg) => W::from_u64(reg.0 as u64).unwrap(),
            ImmOrRegister::Imm(imm) => *imm,
        }
    }
}

impl<W: Word> From<ImmOrRegister<W>> for u64 {
    fn from(x: ImmOrRegister<W>) -> u64 {
        match x {
            ImmOrRegister::Imm(w) => w.into(),
            ImmOrRegister::Register(RegIdx(r)) => r.into(),
        }
    }
}
