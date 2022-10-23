//! Defines the types used to represent instructions in our CPU

// Limit bits used for RegIdx
pub(crate) const NUM_REGS: u32 = 64;

// Number of bits used to represent registers. Must be >= log_2(NUM_REGS).
pub(crate) const BITS_FOR_REGS: u32 = 6;

// Limits the size offsets in instructions
pub(crate) const RAM_SIZE: u32 = 256;

// Number of bits used to represent RAM offsets. Must be >=log_2(RAM_SIZE).
pub(crate) const BITS_FOR_OFFSET: u32 = 8;

// Machine Code Type
pub(crate) type Mc = u64;

/// The size of the slots in our CPU's register
pub(crate) type Word = u32;

/// An index to a register
pub(crate) type RegIdx = Word;

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
        target: RegIdx,
    },

    /// Sets `*savepoint = pc+1`, then sets `pc = *target`
    Jalr { target: RegIdx, savepoint: RegIdx },

    /// Stops the CPU
    Halt,

    /// Does nothing
    NoOp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Checks to see NUM_REG_BITS >= log_2(NUM_REGS).
    fn enough_regidx_bits(){
        let req_bits_for_reg: u32 = (NUM_REGS as f64).log2().ceil() as u32;
        assert!(BITS_FOR_REGS<=req_bits_for_reg);
    }

    #[test]
    // Checks to see BITS_FOR_OFFSET >= log_2(RAM_SIZE).
    fn enough_ram_bits(){
        let req_bits_for_offset: u32 = (RAM_SIZE as f64).log2().ceil() as u32;
        assert!(BITS_FOR_OFFSET<=req_bits_for_offset);
    }
}
