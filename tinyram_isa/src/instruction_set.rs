//! Defines the types used to represent instructions in our CPU

use crate::{RegIdx, Word};

/// A CPU instruction
#[derive(Debug, Eq, PartialEq)]
pub enum Op {
    /// Sets `*dest = *src1 + *src2`
    Add {
        src1: RegIdx,
        src2: RegIdx,
        dest: RegIdx,
    },

    /// Sets `*dest = *src1 | *src2`
    Or {
        src1: RegIdx,
        src2: RegIdx,
        dest: RegIdx,
    },

    /// Sets `*dest = ~(*src1)`
    Not { src: RegIdx, dest: RegIdx },

    /// Sets `*dest = RAM[*base+offset]`
    Loadw {
        dest: RegIdx,
        base: RegIdx,
        offset: Word,
    },

    /// Sets `RAM[*base+offset] = *src`
    Storew {
        dest: RegIdx,
        base: RegIdx,
        offset: Word,
    },

    /// Sets `flag = (*reg1 == *reg2)`
    Cmpe { reg1: RegIdx, reg2: RegIdx },

    /// If `flag` is set, sets `pc = *target`. Else does nothing.
    Cjmp { target: RegIdx },

    /// Stops the CPU
    Halt,
}

impl Op {
    pub(crate) fn opcode(&self) -> Opcode {
        match &self {
            &Op::Add { .. } => Opcode::Add,
            &Op::Or { .. } => Opcode::Or,
            &Op::Not { .. } => Opcode::Not,
            &Op::Loadw { .. } => Opcode::Loadw,
            &Op::Storew { .. } => Opcode::Storew,
            &Op::Cmpe { .. } => Opcode::Cmpe,
            &Op::Cjmp { .. } => Opcode::Cjmp,
            &Op::Halt { .. } => Opcode::Halt,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Opcode {
    Add = 0,
    Or = 1,
    Not = 2,
    Loadw = 3,
    Storew = 4,
    Cmpe = 5,
    Cjmp = 6,
    Halt = 7,
}

impl TryFrom<u8> for Opcode {
    type Error = ();

    fn try_from(b: u8) -> Result<Self, ()> {
        match b {
            0 => Ok(Opcode::Add),
            1 => Ok(Opcode::Or),
            2 => Ok(Opcode::Not),
            3 => Ok(Opcode::Loadw),
            4 => Ok(Opcode::Storew),
            5 => Ok(Opcode::Cmpe),
            6 => Ok(Opcode::Cjmp),
            7 => Ok(Opcode::Halt),
            _ => Err(()),
        }
    }
}
