use crate::{
    constants::{MC_BITLEN, NUM_REGS, OPCODE_BITLEN, REGIDX_BITLEN, WORD_BITLEN},
    instruction_set::{ImmediateOrReg, Op, Opcode},
    Mc, RegIdx,
};

use bitfield::{Bit, BitMut, BitRange, BitRangeMut};

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
     *  | unused space | is_immediate | var1 | var2 | var3 | op |
     *
     *  Note that if our instruction does not need a variable, then we shift
     *  over the free space in the program
     *
     *  op is 5 bits long, with canonical OpCodes defined above.
     */

    /// Creates an Op out of machine code. Panics if the instruction is invalid.
    pub fn from_mc(machine_code: Mc) -> Self {
        use Opcode::*;

        // Decode the instruction. reg1 is the register (if any) that is modified, and reg2 is the
        // register (if any) that is not modified.
        let (reg1, reg2, imm_or_reg, opcode) = Self::decode(machine_code);

        match opcode {
            Add => Op::Add {
                src1: reg2,
                src2: imm_or_reg,
                dest: reg1,
            },
            Or => Op::Or {
                src1: reg2,
                src2: imm_or_reg,
                dest: reg1,
            },
            Cmpe => Op::Cmpe {
                src1: reg2,
                src2: imm_or_reg,
            },
            Not => Op::Not {
                src: imm_or_reg,
                dest: reg1,
            },
            Loadw => Op::Loadw {
                src: imm_or_reg,
                dest: reg1,
            },
            Storew => Op::Storew {
                src: reg2,
                dest: imm_or_reg,
            },
            Cjmp => Op::Cjmp { target: imm_or_reg },
            Answer => Op::Answer { src: imm_or_reg },
        }
    }

    // Decodes an instruction
    fn decode(mc: Mc) -> (RegIdx, RegIdx, ImmediateOrReg, Opcode) {
        let mut cur_bit_idx = 0;

        // Structure of an instruction is
        // 000...0  is_imm  reg1  reg2  imm_or_reg  opcode
        // <-- MSB                                 LSB -->

        let opcode = mc_opcode(mc);
        cur_bit_idx += OPCODE_BITLEN;

        let imm_or_reg_val = mc.bit_range(cur_bit_idx + WORD_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += WORD_BITLEN;

        let reg2 = mc.bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += REGIDX_BITLEN;

        let reg1 = mc.bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx);
        cur_bit_idx += REGIDX_BITLEN;

        let is_imm = mc.bit(cur_bit_idx);
        cur_bit_idx += 1;

        // Check that the rest of the instruction is all 0s. This isn't strictly necessary but it
        // might help catch bugs early
        let rest: Mc = mc.bit_range(MC_BITLEN - 1, cur_bit_idx);
        assert_eq!(rest, 0);

        // Decode the immediate-or-reg as one or the other
        let imm_or_reg = ImmediateOrReg::new(imm_or_reg_val, bool::from(is_imm));

        // Validate the register values
        Op::regidx_valid(reg1);
        Op::regidx_valid(reg2);

        (reg1, reg2, imm_or_reg, opcode)
    }

    // Converts our operation to machine code
    pub fn to_mc(&self) -> Mc {
        let opcode = self.opcode() as u32;

        match *self {
            Op::Add { src1, src2, dest } => Op::encode(dest, src1, src2, opcode),
            Op::Or { src1, src2, dest } => Op::encode(dest, src1, src2, opcode),
            Op::Not { src, dest } => Op::encode(dest, 0, src, opcode),
            Op::Loadw { src, dest } => Op::encode(dest, 0, src, opcode),
            Op::Storew { src, dest } => Op::encode(0, src, dest, opcode),
            Op::Cmpe { src1, src2 } => Op::encode(0, src1, src2, opcode),
            Op::Cjmp { target } => Op::encode(0, 0, target, opcode),
            Op::Answer { src } => Op::encode(0, 0, src, opcode),
        }
    }

    // Encodes an instruction
    fn encode(reg1: RegIdx, reg2: RegIdx, imm_or_reg: ImmediateOrReg, op: u32) -> Mc {
        let mut cur_bit_idx = 0;
        let mut mc: Mc = 0;

        // Structure of an RRI instruction is
        // 000...0  is_imm  reg1  reg2  imm_or_reg  opcode
        // <-- MSB                                 LSB -->

        mc.set_bit_range(cur_bit_idx + OPCODE_BITLEN - 1, cur_bit_idx, op);
        cur_bit_idx += OPCODE_BITLEN;

        mc.set_bit_range(
            cur_bit_idx + WORD_BITLEN - 1,
            cur_bit_idx,
            imm_or_reg.as_word(),
        );
        cur_bit_idx += WORD_BITLEN;

        mc.set_bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx, reg2);
        cur_bit_idx += REGIDX_BITLEN;

        mc.set_bit_range(cur_bit_idx + REGIDX_BITLEN - 1, cur_bit_idx, reg1);
        cur_bit_idx += REGIDX_BITLEN;

        mc.set_bit(cur_bit_idx, imm_or_reg.is_immediate());

        mc
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
    use crate::constants::WORD_BITLEN;

    use rand::Rng;

    fn gen_regidx<R: Rng>(mut rng: R) -> RegIdx {
        rng.gen_range(0..NUM_REGS)
    }

    fn gen_imm_or_regidx<R: Rng>(mut rng: R) -> ImmediateOrReg {
        let is_imm = rng.gen();
        let val = if is_imm {
            rng.gen()
        } else {
            rng.gen_range(0..NUM_REGS)
        };

        ImmediateOrReg::new(val, is_imm)
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
                    src: gen_imm_or_regidx(&mut rng),
                },
                Op::Cmpe {
                    src1: gen_regidx(&mut rng),
                    src2: gen_imm_or_regidx(&mut rng),
                },
                Op::Or {
                    src1: gen_regidx(&mut rng),
                    src2: gen_imm_or_regidx(&mut rng),
                    dest: gen_regidx(&mut rng),
                },
                Op::Add {
                    src1: gen_regidx(&mut rng),
                    src2: gen_imm_or_regidx(&mut rng),
                    dest: gen_regidx(&mut rng),
                },
                Op::Not {
                    src: gen_imm_or_regidx(&mut rng),
                    dest: gen_regidx(&mut rng),
                },
                Op::Cjmp {
                    target: gen_imm_or_regidx(&mut rng),
                },
                Op::Loadw {
                    src: gen_imm_or_regidx(&mut rng),
                    dest: gen_regidx(&mut rng),
                },
                Op::Storew {
                    src: gen_regidx(&mut rng),
                    dest: gen_imm_or_regidx(&mut rng),
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
