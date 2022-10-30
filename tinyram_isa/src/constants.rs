use crate::{Mc, Word};

/// The maximum number of registers in our arch
pub(crate) const NUM_REGS: u32 = 1 << REGIDX_BITLEN;

/// The bitlength of an register index
pub(crate) const REGIDX_BITLEN: usize = 6;

/// The maximum number of opcodes in our ISA
pub(crate) const NUM_OPCODES: u32 = 1 << OPCODE_BITLEN;

/// The bitlength of an opcode
pub(crate) const OPCODE_BITLEN: usize = 5;

/// The bitlength of a machine code instruction
pub(crate) const MC_BITLEN: usize = core::mem::size_of::<Mc>() * 8;

/// The bitlength of the slots in our CPU's register
pub(crate) const WORD_BITLEN: usize = core::mem::size_of::<Word>() * 8;
