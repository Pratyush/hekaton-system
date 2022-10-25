use crate::instruction_set::*;

use bitfield::BitRange;

pub(crate) fn mc_opcode(machine_code: Mc) -> Opcode {
    let opcode_byte: u8 = machine_code.bit_range(OPCODE_BITLEN - 1, 0);
    match Opcode::try_from(opcode_byte) {
        Ok(oc) => oc,
        Err(()) => panic!("invalid opcode provided: {opcode_byte}"),
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
        use Opcode::*;

        match mc_opcode(machine_code) {
            Add | Nor | Beq => Op::decode_rrr(machine_code),
            Jalr => Op::decode_rr(machine_code),
            Lw | Sw => Op::decode_rrw(machine_code),
            Halt => Op::Halt,
            NoOp => Op::NoOp,
        }
    }

    // Decodes instructions that take in 3 registers, i.e., Nor, Add, and Beq
    fn decode_rrr(mc: Mc) -> Self {
        let mut cur_bit_idx = 0;

        // Structure of an RRR instruction is
        // 000...0  reg1  reg2  reg3  opcode
        // <-- MSB                   LSB -->

        let opcode = mc_opcode(mc);
        cur_bit_idx += OPCODE_BITLEN;

        let reg3 = mc.bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += REGIDX_BITLEN;

        let reg2 = mc.bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += REGIDX_BITLEN;

        let reg1 = mc.bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += REGIDX_BITLEN;

        // Check that the rest of the instruction is all 0s. This isn't strictly necessary but it
        // might help catch bugs early
        let rest: Mc = mc.bit_range(MC_BITLEN - 1, cur_bit_idx);
        assert_eq!(rest, 0);

        match opcode {
            Opcode::Add => Op::Add {
                src1: reg1,
                src2: reg2,
                dest: reg3,
            },
            Opcode::Nor => Op::Nor {
                src1: reg1,
                src2: reg2,
                dest: reg3,
            },
            Opcode::Beq => Op::Beq {
                reg1,
                reg2,
                target: reg3,
            },
            _ => panic!("decode_rrr got an opcode {:?}", opcode),
        }
    }

    // Decodes instructions that take in 2 registers
    // Jalr
    fn decode_rr(mc: Mc) -> Self {
        let mut cur_bit_idx = 0;

        // Structure of an RR instruction is
        // 000...0  reg1  reg2  opcode
        // <-- MSB              LSB -->

        let opcode = mc_opcode(mc);
        cur_bit_idx += OPCODE_BITLEN;

        let reg2 = mc.bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += REGIDX_BITLEN;

        let reg1 = mc.bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += REGIDX_BITLEN;

        // Check that the rest of the instruction is all 0s. This isn't strictly necessary but it
        // might help catch bugs early
        let rest: Mc = mc.bit_range(MC_BITLEN - 1, cur_bit_idx);
        assert_eq!(rest, 0);

        match opcode {
            Opcode::Jalr => Op::Jalr {
                target: reg1,
                savepoint: reg2,
            },
            _ => panic!("decode_rr got an opcode {:?}", opcode),
        }
    }

    // Decodes instructions that take two registers and a word, i.e., Lw, and Sw
    fn decode_rrw(mc: Mc) -> Self {
        let mut cur_bit_idx = 0;

        // Structure of an RRR instruction is
        // 000...0  reg1  reg2  word  opcode
        // <-- MSB                   LSB -->

        let opcode = mc_opcode(mc);
        cur_bit_idx += OPCODE_BITLEN;

        let word = mc.bit_range(cur_bit_idx + WORD_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += WORD_BITLEN;

        let reg2 = mc.bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += REGIDX_BITLEN;

        let reg1 = mc.bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += REGIDX_BITLEN;

        // Check that the rest of the instruction is all 0s. This isn't strictly necessary but it
        // might help catch bugs early
        let rest: Mc = mc.bit_range(MC_BITLEN - 1, cur_bit_idx);
        assert_eq!(rest, 0);

        match opcode {
            Opcode::Lw => Op::Lw {
                dest: reg1,
                base: reg2,
                offset: word,
            },
            Opcode::Sw => Op::Sw {
                dest: reg1,
                base: reg2,
                offset: word,
            },
            _ => panic!("decode_rrw got an opcode {:?}", opcode),
        }
    }

    // Converts our operation to machine code
    pub fn to_mc(&self) -> Mc {
        let opcode: u32 = self.opcode() as u32;
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
        mc += (reg2 << 4 + REGIDX_BITLEN) as Mc;
        mc += (reg1 << 4 + 2 * REGIDX_BITLEN) as Mc;
        return mc;
    }

    // Encodes instructions that take in 2 registers
    // Jalr
    fn encode_rr(reg1: RegIdx, reg2: RegIdx, op: u32) -> Mc {
        Op::regidx_valid(reg1);
        Op::regidx_valid(reg2);

        let mut mc = op as Mc;
        mc += (reg2 as Mc) << 4;
        mc += (reg1 as Mc) << 4 + REGIDX_BITLEN;
        return mc;
    }

    // Encodes instructions that take two registers and an offset
    // Lw, Sw
    fn encode_rro(reg1: RegIdx, reg2: RegIdx, offset: u32, op: u32) -> Mc {
        Op::regidx_valid(reg1);
        Op::regidx_valid(reg2);

        let mut mc = op as Mc;
        mc += (offset << 4) as Mc;
        mc += (reg2 as Mc) << 4 + WORD_BITLEN;
        mc += (reg1 as Mc) << 4 + WORD_BITLEN + REGIDX_BITLEN;
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
        assert!(Mc::MAX >= (1 << 4 + 3 * REGIDX_BITLEN) - 1);
        assert!(Mc::MAX >= (1 << 4 + 2 * REGIDX_BITLEN + WORD_BITLEN) - 1);
    }
}
