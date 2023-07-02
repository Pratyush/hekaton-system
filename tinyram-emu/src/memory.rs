use crate::{instructions::Instr, word::Word};

use std::collections::BTreeMap;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DataMemory<W: Word>(BTreeMap<W, u8>);

impl<W: Word> DataMemory<W> {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(memory: BTreeMap<W, u8>) -> Self {
        Self(memory)
    }

    pub fn insert(&mut self, index: W, value: u8) -> Option<u8> {
        self.0.insert(index, value)
    }

    pub fn get(&self, index: W) -> Option<&u8> {
        self.0.get(&index)
    }

    pub fn get_mut(&mut self, index: W) -> Option<&mut u8> {
        self.0.get_mut(&index)
    }
}

impl<W: Word> std::ops::Index<W> for DataMemory<W> {
    type Output = u8;
    fn index(&self, index: W) -> &Self::Output {
        self.0.index(&index)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ProgramMemory<W: Word>(pub(crate) Vec<Instr<W>>);
