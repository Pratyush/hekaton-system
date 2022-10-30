mod constants;
pub mod instruction_set;
mod interpreter;
mod machine_code;

/// The size of the slots in our CPU's register
pub(crate) type Word = u32;

/// An index to a register
pub(crate) type RegIdx = Word;

/// An index to RAM
pub(crate) type RamIdx = Word;

// A machine code-encoded instruction
pub(crate) type Mc = u64;
