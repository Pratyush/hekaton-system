use crate::instruction_set::*;

// Define a canonical opcode for each operation
impl From<&Op> for u32 {
    fn from(op: &Op) -> u32 {
        match op {
            Op::Add { .. } => 0,
            Op::Nor { .. } => 1,
            Op::Lw { .. } => 2,
            Op::Sw { .. } => 3,
            Op::Beq { .. } => 4,
            Op::Jalr { .. } => 5,
            Op::Halt { .. } => 6,
            Op::NoOp { .. } => 7,
        }
    }
}

impl Op {
    /*
     *  The machine code of an assembly command is encoded as follows.
     *  | unused space | var1 | var2 | var3 | op |
     *
     *  Note that if our instruction does not need a variable, then we shift
     *  over the free space in the program
     *
     *  op is 4 bits long, with canonical OpCodes defined above.
     *  For a var of type offset, our var is BITS_FOR_OFFSET bits long.
     *  For a var of type regIdx, our var is BITS_FOR_REGS bits long.
     */

    // Creates an Op out of machine code
    pub fn from_mc(machine_code: Mc) -> Self {
        let op: u32 = (machine_code & 0b1111) as u32;
        match op {
            0 | 1 | 4 => Op::decode_rrr(machine_code),
            5 => Op::decode_rr(machine_code),
            2 | 3 => Op::decode_rro(machine_code),
            6 | 7 => Op::decode_(machine_code),
            _ => panic!("Invalid OpCode provided"),
        }
    }

    // Decodes instructions that take in 3 registers
    // Nor, Add, Beq
    fn decode_rrr(machine_code: Mc) -> Self {
        let mut mc = machine_code;
        let op = mc & (1 << 4) - 1;
        mc -= op;
        let mut var3 = mc & (1 << 4 + BITS_FOR_REGS) - 1;
        var3 = var3 >> 4;
        mc -= var3;
        let mut var2 = mc & (1 << 4 + 2 * BITS_FOR_REGS) - 1;
        var2 = var2 >> 4 + BITS_FOR_REGS;
        mc -= var2;
        let mut var1 = mc & (1 << 4 + 3 * BITS_FOR_REGS) - 1;
        var1 = var1 >> 4 + 2 * BITS_FOR_REGS;
        match op {
            0 => Op::Add {
                src1: var1 as RegIdx,
                src2: var2 as RegIdx,
                dest: var3 as RegIdx,
            },
            1 => Op::Nor {
                src1: var1 as RegIdx,
                src2: var2 as RegIdx,
                dest: var3 as RegIdx,
            },
            4 => Op::Beq {
                reg1: var1 as RegIdx,
                reg2: var2 as RegIdx,
                target: var3 as RegIdx,
            },
            _ => panic!("Invalid OpCode"),
        }
    }

    // Decodes instructions that take in 2 registers
    // Jalr
    fn decode_rr(machine_code: Mc) -> Self {
        let mut mc = machine_code;
        let op = mc & (1 << 4) - 1;
        mc -= op;
        let mut var2 = mc & (1 << 4 + BITS_FOR_REGS) - 1;
        mc -= var2;
        var2 = var2 >> 4;
        let mut var1 = mc & (1 << 4 + 2 * BITS_FOR_REGS) - 1;
        var1 = var1 >> 4 + BITS_FOR_REGS;
        match op {
            5 => Op::Jalr {
                target: var1 as RegIdx,
                savepoint: var2 as RegIdx,
            },
            _ => panic!("Invalid OpCode"),
        }
    }

    // Decodes instructions that take two registers and an offset
    // Lw, Sw
    fn decode_rro(machine_code: Mc) -> Self {
        let mut mc = machine_code;
        let op = mc & (1 << 4) - 1;
        mc -= op;
        let mut var3 = mc & (1 << 4 + BITS_FOR_OFFSET) - 1;
        mc -= var3;
        var3 = var3 >> 4;
        let mut var2 = mc & (1 << 4 + BITS_FOR_OFFSET + BITS_FOR_REGS) - 1;
        var2 = var2 >> 4 + BITS_FOR_OFFSET;
        mc -= var2;
        let mut var1 = mc & (1 << 4 + BITS_FOR_OFFSET + 2 * BITS_FOR_REGS) - 1;
        var1 = var1 >> 4 + BITS_FOR_OFFSET + BITS_FOR_REGS;
        match op {
            2 => Op::Lw {
                dest: var1 as RegIdx,
                base: var2 as RegIdx,
                offset: var3 as Word,
            },
            3 => Op::Sw {
                dest: var1 as RegIdx,
                base: var2 as RegIdx,
                offset: var3 as Word,
            },
            _ => panic!("Invalid OpCode"),
        }
    }

    // Decodes instructions that take in no parameters
    // Halt, No-Op
    fn decode_(machine_code: Mc) -> Self {
        if machine_code == 6 {
            return Op::Halt;
        } else if machine_code == 7 {
            return Op::NoOp;
        } else {
            panic!("Empty space in Halt/NoOp operation is being used");
        }
    }

    // Converts our operation to machine code
    pub fn to_mc(&self) -> Mc {
        let opcode: u32 = self.into();
        return match *self {
            Op::Add { src1, src2, dest } => Op::encode_rrr(src1, src2, dest, opcode),
            Op::Nor { src1, src2, dest } => Op::encode_rrr(src1, src2, dest, opcode),
            Op::Lw { dest, base, offset } => Op::encode_rro(dest, base, offset, opcode),
            Op::Sw { dest, base, offset } => Op::encode_rro(dest, base, offset, opcode),
            Op::Beq { reg1, reg2, target } => Op::encode_rrr(reg1, reg2, target, opcode),
            Op::Jalr { target, savepoint } => Op::encode_rr(target, savepoint, opcode),
            Op::Halt => Op::encode_(opcode),
            Op::NoOp => Op::encode_(opcode),
        };
    }

    // Encodes instructions that take in 3 registers
    // Nor, Add, Beq
    fn encode_rrr(reg1: RegIdx, reg2: RegIdx, reg3: RegIdx, op: u32) -> Mc {
        Op::regidx_valid(reg1);
        Op::regidx_valid(reg2);
        Op::regidx_valid(reg3);

        let mut mc = op as Mc;
        mc += (reg3 << 4) as Mc;
        mc += (reg2 << 4 + BITS_FOR_REGS) as Mc;
        mc += (reg1 << 4 + 2 * BITS_FOR_REGS) as Mc;
        return mc;
    }

    // Encodes instructions that take in 2 registers
    // Jalr
    fn encode_rr(reg1: RegIdx, reg2: RegIdx, op: u32) -> Mc {
        Op::regidx_valid(reg1);
        Op::regidx_valid(reg2);

        let mut mc = op as Mc;
        mc += (reg2 << 4) as Mc;
        mc += (reg1 << 4 + BITS_FOR_REGS) as Mc;
        return mc;
    }

    // Encodes instructions that take two registers and an offset
    // Lw, Sw
    fn encode_rro(reg1: RegIdx, reg2: RegIdx, offset: u32, op: u32) -> Mc {
        Op::regidx_valid(reg1);
        Op::regidx_valid(reg2);
        Op::offset_valid(offset);

        let mut mc = op as Mc;
        mc += (offset << 4) as Mc;
        mc += (reg2 << 4 + BITS_FOR_OFFSET) as Mc;
        mc += (reg1 << 4 + BITS_FOR_OFFSET + BITS_FOR_REGS) as Mc;
        return mc;
    }

    // Encodes instructions that take in no parameters
    // Halt, No-Op
    fn encode_(op: u32) -> Mc {
        return op as Mc;
    }

    // Panics if a Register Index overflows its allocated space in machine code
    fn regidx_valid(reg: RegIdx) {
        // Note we enumerate our registers [0,...,NUM_REGS-1]
        if reg >= NUM_REGS {
            panic!("Register Index exceeds our number of registers");
        }
    }

    // Panics if a RAM offset overflows its allocated space in machine code
    fn offset_valid(offset: Word) {
        if offset >= RAM_SIZE {
            panic!("Offset exceeds the number of words in our RAM");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that Op::from_mc(op.to_mc()) is the identity on `op`
    #[test]
    fn round_trip_identity() {
        let test_cases = [
            Op::NoOp,
            Op::Halt,
            Op::Beq {
                reg1: 1,
                reg2: 2,
                target: 3,
            },
            Op::Nor {
                src1: 1,
                src2: 2,
                dest: 3,
            },
            Op::Add {
                src1: 1,
                src2: 2,
                dest: 3,
            },
            Op::Jalr {
                target: 1,
                savepoint: 2,
            },
            Op::Lw {
                dest: 1,
                base: 2,
                offset: 3,
            },
            Op::Sw {
                dest: 1,
                base: 2,
                offset: 3,
            },
        ];

        for tc in test_cases {
            assert_eq!(tc, Op::from_mc(tc.to_mc()))
        }
    }

    // Ensures that the machine code type has enough space for all instructions
    #[test]
    fn mc_overflow() {
        assert!(Mc::MAX >= (1 << 4 + 3 * BITS_FOR_REGS) - 1);
        assert!(Mc::MAX >= (1 << 4 + 2 * BITS_FOR_REGS + BITS_FOR_OFFSET) - 1);
    }
}
