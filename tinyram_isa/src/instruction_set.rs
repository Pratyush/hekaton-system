//! Defines the types used to represent instructions in our CPU

pub(crate) const NUM_REGS: u32 = 64;

/// The size of the slots in our CPU's register
pub(crate) type Word = u32;

/// An index to a register
pub(crate) type RegIdx = u32;

/// An index into RAM
pub(crate) type RamIdx = u32;

/// A CPU instruction
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
        target: RamIdx,
    },

    /// Sets `*savepoint = pc+1`, then sets `pc = *target`
    Jalr { target: RegIdx, savepoint: RegIdx },

    /// Stops the CPU
    Halt,

    /// Does nothing
    NoOp,
}
