use crate::{
    constants::{MC_BITLEN, NUM_REGS, OPCODE_BITLEN, REGIDX_BITLEN, WORD_BITLEN},
    instruction_set::{Op, Opcode},
    Mc, RegIdx, Word,
};

use bitfield::{BitRange, BitRangeMut};

pub(crate) fn mc_opcode(machine_code: Mc) -> Opcode {
    let opcode_byte: u8 = machine_code.bit_range(OPCODE_BITLEN - 1, 0);
    match Opcode::try_from(opcode_byte) {
        Ok(oc) => oc,
        Err(()) => panic!("invalid opcode provided: {opcode_byte}, in {machine_code}"),
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

    /// Creates an Op out of machine code. Panics if the instruction is invalid.
    pub fn from_mc(machine_code: Mc) -> Self {
        use Opcode::*;

        match mc_opcode(machine_code) {
            Add | Or => Op::decode_rrr(machine_code),
            Cmpe | Not => Op::decode_rr(machine_code),
            Cjmp | Answer => Op::decode_r(machine_code),
            Loadw | Storew => Op::decode_rrw(machine_code),
        }
    }

    // Decodes instructions that take in 3 registers
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
            Opcode::Or => Op::Or {
                src1: reg1,
                src2: reg2,
                dest: reg3,
            },
            _ => panic!("decode_rrr got an opcode {:?}", opcode),
        }
    }

    // Decodes instructions that take in 2 registers
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
            Opcode::Cmpe => Op::Cmpe { reg1, reg2 },
            Opcode::Not => Op::Not {
                src: reg1,
                dest: reg2,
            },
            _ => panic!("decode_rr got an opcode {:?}", opcode),
        }
    }

    // Decodes instructions that take in 1 register
    fn decode_r(mc: Mc) -> Self {
        let mut cur_bit_idx = 0;

        // Structure of an RR instruction is
        // 000...0  reg1  opcode
        // <-- MSB        LSB -->

        let opcode = mc_opcode(mc);
        cur_bit_idx += OPCODE_BITLEN;

        let reg = mc.bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += REGIDX_BITLEN;

        // Check that the rest of the instruction is all 0s. This isn't strictly necessary but it
        // might help catch bugs early
        let rest: Mc = mc.bit_range(MC_BITLEN - 1, cur_bit_idx);
        assert_eq!(rest, 0);

        match opcode {
            Opcode::Cjmp => Op::Cjmp { target: reg },
            Opcode::Answer => Op::Answer { reg },
            _ => panic!("decode_r got an opcode {:?}", opcode),
        }
    }

    // Decodes instructions that take two registers and a word
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
        assert_eq!(rest, 0, "invalid left padding in instruction {mc:0x}");

        match opcode {
            Opcode::Loadw => Op::Loadw {
                dest: reg1,
                base: reg2,
                offset: word,
            },
            Opcode::Storew => Op::Storew {
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
            Op::Or { src1, src2, dest } => Op::encode_rrr(src1, src2, dest, opcode),
            Op::Not { src, dest } => Op::encode_rr(src, dest, opcode),
            Op::Loadw { dest, base, offset } => Op::encode_rrw(dest, base, offset, opcode),
            Op::Storew { dest, base, offset } => Op::encode_rrw(dest, base, offset, opcode),
            Op::Cmpe { reg1, reg2 } => Op::encode_rr(reg1, reg2, opcode),
            Op::Cjmp { target } => Op::encode_r(target, opcode),
            Op::Answer { reg } => Op::encode_r(reg, opcode),
        };
    }

    // Encodes instructions that take in 3 registers
    fn encode_rrr(reg1: RegIdx, reg2: RegIdx, reg3: RegIdx, op: u32) -> Mc {
        Op::regidx_valid(reg1);
        Op::regidx_valid(reg2);
        Op::regidx_valid(reg3);

        let mut cur_bit_idx = 0;
        let mut mc: Mc = 0;

        mc.set_bit_range(cur_bit_idx + OPCODE_BITLEN - 1, cur_bit_idx, op);
        cur_bit_idx += OPCODE_BITLEN;

        mc.set_bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx, reg3);
        cur_bit_idx += REGIDX_BITLEN;

        mc.set_bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx, reg2);
        cur_bit_idx += REGIDX_BITLEN;

        mc.set_bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx, reg1);

        return mc;
    }

    // Encodes instructions that take in 2 registers
    fn encode_rr(reg1: RegIdx, reg2: RegIdx, op: u32) -> Mc {
        Op::regidx_valid(reg1);
        Op::regidx_valid(reg2);

        let mut cur_bit_idx = 0;
        let mut mc: Mc = 0;

        mc.set_bit_range(cur_bit_idx + OPCODE_BITLEN - 1, cur_bit_idx, op);
        cur_bit_idx += OPCODE_BITLEN;

        mc.set_bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx, reg2);
        cur_bit_idx += REGIDX_BITLEN;

        mc.set_bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx, reg1);
        return mc;
    }

    // Encodes instructions that take in 1 register
    fn encode_r(reg: RegIdx, op: u32) -> Mc {
        Op::regidx_valid(reg);

        let mut cur_bit_idx = 0;
        let mut mc: Mc = 0;

        mc.set_bit_range(cur_bit_idx + OPCODE_BITLEN - 1, cur_bit_idx, op);
        cur_bit_idx += OPCODE_BITLEN;

        mc.set_bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx, reg);
        return mc;
    }

    // Encodes instructions that take two registers and a word
    fn encode_rrw(reg1: RegIdx, reg2: RegIdx, offset: Word, op: u32) -> Mc {
        Op::regidx_valid(reg1);
        Op::regidx_valid(reg2);

        let mut cur_bit_idx = 0;
        let mut mc: Mc = 0;

        mc.set_bit_range(cur_bit_idx + OPCODE_BITLEN - 1, cur_bit_idx, op);
        cur_bit_idx += OPCODE_BITLEN;

        mc.set_bit_range(cur_bit_idx + WORD_BITLEN - 1, cur_bit_idx, offset);
        cur_bit_idx += WORD_BITLEN;

        mc.set_bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx, reg2);
        cur_bit_idx += REGIDX_BITLEN;

        mc.set_bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx, reg1);
        return mc;
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
    use rand::Rng;

    fn gen_regidx<R: Rng>(mut rng: R) -> RegIdx {
        rng.gen_range(0..NUM_REGS)
    }

    // Tests that Op::from_mc(op.to_mc()) is the identity on `op`
    #[test]
    fn round_trip_identity() {
        let mut rng = rand::thread_rng();

        // Test 100 test cases of each kind of instruction
        for _ in 0..100 {
            // Make random test cases
            let test_cases = [
                Op::Answer {
                    reg: gen_regidx(&mut rng),
                },
                Op::Cmpe {
                    reg1: gen_regidx(&mut rng),
                    reg2: gen_regidx(&mut rng),
                },
                Op::Or {
                    src1: gen_regidx(&mut rng),
                    src2: gen_regidx(&mut rng),
                    dest: gen_regidx(&mut rng),
                },
                Op::Add {
                    src1: gen_regidx(&mut rng),
                    src2: gen_regidx(&mut rng),
                    dest: gen_regidx(&mut rng),
                },
                Op::Not {
                    src: gen_regidx(&mut rng),
                    dest: gen_regidx(&mut rng),
                },
                Op::Cjmp {
                    target: gen_regidx(&mut rng),
                },
                Op::Loadw {
                    dest: gen_regidx(&mut rng),
                    base: gen_regidx(&mut rng),
                    offset: rng.gen::<Word>(),
                },
                Op::Storew {
                    dest: gen_regidx(&mut rng),
                    base: gen_regidx(&mut rng),
                    offset: rng.gen::<Word>(),
                },
            ];

            // Test equality after an encode-decode round trip
            for tc in test_cases {
                assert_eq!(tc, Op::from_mc(tc.to_mc()))
            }
        }
    }

    // Ensures that the machine code type has enough space for all instructions
    #[test]
    fn mc_overflow() {
        assert!(MC_BITLEN >= OPCODE_BITLEN + 3 * REGIDX_BITLEN);
        assert!(MC_BITLEN >= OPCODE_BITLEN + 2 * REGIDX_BITLEN + WORD_BITLEN);
    }
}
