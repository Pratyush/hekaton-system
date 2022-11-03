use crate::{instructions::Instr, word::Word};

use std::collections::BTreeMap;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DataMemory<W: Word>(pub(crate) BTreeMap<W, u8>);

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ProgramMemory<W: Word>(pub(crate) Vec<Instr<W>>);
