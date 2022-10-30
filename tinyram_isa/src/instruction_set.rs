//! Defines the types used to represent instructions in our CPU

use crate::{constants::NUM_REGS, RegIdx, Word};

/// In TinyRAM, some instruction inputs are interpreted as either a register index or an immediate
/// (i.e., a constant). This enum captures that functionality.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ImmediateOrReg {
    Immediate(Word),
    Reg(RegIdx),
}

impl ImmediateOrReg {
    pub(crate) fn new(val: Word, is_immediate: bool) -> ImmediateOrReg {
        match is_immediate {
            true => ImmediateOrReg::Immediate(val),
            false => {
                if val > NUM_REGS {
                    panic!("Cannot make an ImmediateOrReg::Reg out of the value {val}");
                }
                ImmediateOrReg::Reg(val as RegIdx)
            }
        }
    }

    /// Returns the contents of this enum as a word (i.e., that largest type that holds both a
    /// `RegIdx` and a `Word`)
    pub(crate) fn as_word(self) -> Word {
        match self {
            ImmediateOrReg::Immediate(w) => w,
            ImmediateOrReg::Reg(r) => r as Word,
        }
    }

    /// Returns whether this is an `Immediate`
    pub(crate) fn is_immediate(&self) -> bool {
        match self {
            ImmediateOrReg::Immediate(..) => true,
            ImmediateOrReg::Reg(..) => false,
        }
    }
}

/// A CPU instruction
#[derive(Debug, Eq, PartialEq)]
pub enum Op {
    /// Sets `*dest = *src1 + *src2`
    Add {
        src1: RegIdx,
        src2: ImmediateOrReg,
        dest: RegIdx,
    },

    /// Sets `*dest = *src1 | *src2`
    Or {
        src1: RegIdx,
        src2: ImmediateOrReg,
        dest: RegIdx,
    },

    /// Sets `*dest = *src1 ⊕ *src2`
    Xor {
        src1: RegIdx,
        src2: ImmediateOrReg,
        dest: RegIdx,
    },

    /// Sets `*dest = ~(*src1)`
    Not { src: ImmediateOrReg, dest: RegIdx },

    /// Sets `*dest = RAM[*src]`
    Loadw { src: ImmediateOrReg, dest: RegIdx },

    /// Sets `RAM[*dest] = *src`
    Storew { src: RegIdx, dest: ImmediateOrReg },

    /// Sets `flag = (*src1 == *src2)`
    Cmpe { src1: RegIdx, src2: ImmediateOrReg },

    /// Sets `pc = *target`
    Jmp { target: ImmediateOrReg },

    /// If `flag` is set, sets `pc = *target`. Else does nothing.
    Cjmp { target: ImmediateOrReg },

    /// Stops the CPU and returns *src
    Answer { src: ImmediateOrReg },
}

impl Op {
    pub(crate) fn opcode(&self) -> Opcode {
        match &self {
            &Op::Add { .. } => Opcode::Add,
            &Op::Or { .. } => Opcode::Or,
            &Op::Xor { .. } => Opcode::Xor,
            &Op::Not { .. } => Opcode::Not,
            &Op::Loadw { .. } => Opcode::Loadw,
            &Op::Storew { .. } => Opcode::Storew,
            &Op::Cmpe { .. } => Opcode::Cmpe,
            &Op::Jmp { .. } => Opcode::Jmp,
            &Op::Cjmp { .. } => Opcode::Cjmp,
            &Op::Answer { .. } => Opcode::Answer,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Opcode {
    Add = 0,
    Or = 1,
    Xor = 2,
    Not = 3,
    Loadw = 4,
    Storew = 5,
    Cmpe = 6,
    Jmp = 7,
    Cjmp = 8,
    Answer = 9,
}

impl TryFrom<u8> for Opcode {
    type Error = ();

    fn try_from(b: u8) -> Result<Self, ()> {
        match b {
            0 => Ok(Opcode::Add),
            1 => Ok(Opcode::Or),
            2 => Ok(Opcode::Xor),
            3 => Ok(Opcode::Not),
            4 => Ok(Opcode::Loadw),
            5 => Ok(Opcode::Storew),
            6 => Ok(Opcode::Cmpe),
            7 => Ok(Opcode::Jmp),
            8 => Ok(Opcode::Cjmp),
            9 => Ok(Opcode::Answer),
            _ => Err(()),
        }
    }
}
