use crate::{instructions::Instr, word::Word};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMemory(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramMemory<W: Word>(Vec<Instr<W>>);
