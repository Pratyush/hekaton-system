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

    /// Sets `*dest = ~(*src1, *src2)`
    Nor {
        src1: RegIdx,
        src2: RegIdx,
        dest: RegIdx,
    },

    /// Sets `*dest = RAM[*base+offset]`
    Lw {
        dest: RegIdx,
        base: RegIdx,
        offset: Word,
    },

    /// Sets `RAM[*base+offset] = *src`
    Sw {
        dest: RegIdx,
        base: RegIdx,
        offset: Word,
    },

    /// If `*reg1 == *reg2`, sets `pc = *target`. Else, does nothing.
    Beq {
        reg1: RegIdx,
        reg2: RegIdx,
        target: RegIdx,
    },

    /// Sets `*savepoint = pc+1`, then sets `pc = *target`
    Jalr { target: RegIdx, savepoint: RegIdx },

    /// Stops the CPU
    Halt,

    /// Does nothing
    NoOp,
}

impl Op {
    pub(crate) fn opcode(&self) -> Opcode {
        match &self {
            &Op::Add { .. } => Opcode::Add,
            &Op::Nor { .. } => Opcode::Nor,
            &Op::Lw { .. } => Opcode::Lw,
            &Op::Sw { .. } => Opcode::Sw,
            &Op::Beq { .. } => Opcode::Beq,
            &Op::Jalr { .. } => Opcode::Jalr,
            &Op::Halt { .. } => Opcode::Halt,
            &Op::NoOp { .. } => Opcode::NoOp,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Opcode {
    Add = 0,
    Nor = 1,
    Lw = 2,
    Sw = 3,
    Beq = 4,
    Jalr = 5,
    Halt = 6,
    NoOp = 7,
}

impl TryFrom<u8> for Opcode {
    type Error = ();

    fn try_from(b: u8) -> Result<Self, ()> {
        match b {
            0 => Ok(Opcode::Add),
            1 => Ok(Opcode::Nor),
            2 => Ok(Opcode::Lw),
            3 => Ok(Opcode::Sw),
            4 => Ok(Opcode::Beq),
            5 => Ok(Opcode::Jalr),
            6 => Ok(Opcode::Halt),
            7 => Ok(Opcode::NoOp),
            _ => Err(()),
        }
    }
}
