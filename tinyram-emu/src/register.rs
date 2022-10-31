use crate::word::Word;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register(pub u64);

impl Register {
    pub fn value<W: Word>(&self, registers: &[W]) -> W {
        registers[self.0 as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOrImm<W: Word> {
    Register(u64),
    Imm(W),
}

impl<W: Word> RegisterOrImm<W> {
    pub fn value(&self, registers: &[W]) -> W {
        match self {
            RegisterOrImm::Register(reg) => registers[*reg as usize],
            RegisterOrImm::Imm(imm) => *imm,
        }
    }
}
