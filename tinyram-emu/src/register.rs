use crate::word::Word;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register(u64);


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOrImm<W: Word> {
    Register(u64),
    Imm(W),
}