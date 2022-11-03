use crate::{
    instructions::{Instr, Opcode},
    register::{ImmOrRegister, RegIdx},
    word::Word,
};

use bitfield::{Bit, BitMut, BitRange, BitRangeMut};

const OPCODE_BITLEN: usize = 5;

pub(crate) fn instr_opcode(instr: u128) -> Opcode {
    let opcode_byte: u8 = instr.bit_range(OPCODE_BITLEN - 1, 0);
    match Opcode::try_from(opcode_byte) {
        Ok(oc) => oc,
        Err(_) => panic!("invalid opcode provided: {opcode_byte}, in 0x{instr:032x}"),
    }
}

impl<W: Word> Instr<W> {
    /*
     *  The machine code of an assembly command is encoded as follows.
     *  | unused space | is_immediate | var1 | var2 | var3 | op |
     *
     *  Note that if our instruction does not need a variable, then we shift
     *  over the free space in the program
     *
     *  op is 5 bits long, with canonical OpCodes defined above.
     */

    /// Creates an Op out of machine code. Panics if `bytes.len() != W::INSTR_BYTELEN` or if the
    /// instruction is invalid.
    pub fn from_bytes<const NUM_REGS: usize>(bytes: &[u8]) -> Self {
        use Opcode::*;
        assert!(bytes.len() == W::INSTR_BYTELEN);

        let instr = {
            let mut buf = [0u8; 16];
            buf[16 - bytes.len()..16].copy_from_slice(bytes);
            u128::from_be_bytes(buf)
        };

        // Decode the instruction. reg1 is the register (if any) that is modified, and reg2 is the
        // register (if any) that is not modified.
        let (reg1, reg2, imm_or_reg, opcode) = Self::decode::<NUM_REGS>(instr);

        match opcode {
            Add => Instr::Add {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            Or => Instr::Or {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            Xor => Instr::Xor {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            CmpE => Instr::CmpE {
                in1: reg2,
                in2: imm_or_reg,
            },
            Not => Instr::Not {
                in1: imm_or_reg,
                out: reg1,
            },
            LoadW => Instr::LoadW {
                in1: imm_or_reg,
                out: reg1,
            },
            StoreW => Instr::StoreW {
                in1: reg2,
                out: imm_or_reg,
            },
            Jmp => Instr::Jmp { in1: imm_or_reg },
            CJmp => Instr::CJmp { in1: imm_or_reg },
            Answer => Instr::Answer { in1: imm_or_reg },
            _ => panic!("cannot decode {:?}", opcode),
        }
    }

    // Decodes an instruction
    fn decode<const NUM_REGS: usize>(instr: u128) -> (RegIdx, RegIdx, ImmOrRegister<W>, Opcode) {
        let regidx_bitlen = f32::from(NUM_REGS as u8).log2().ceil() as usize;

        let mut cur_bit_idx = 0;

        // Structure of an instruction is
        // 000...0  is_imm  reg1  reg2  imm_or_reg  opcode
        // <-- MSB                                 LSB -->

        let opcode = instr_opcode(instr);
        cur_bit_idx += OPCODE_BITLEN;

        let imm_or_reg_val = instr.bit_range(cur_bit_idx + (W::BITLEN as usize) - 1, cur_bit_idx);
        cur_bit_idx += W::BITLEN as usize;

        let reg2 = instr.bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx);
        cur_bit_idx += regidx_bitlen;

        let reg1 = instr.bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx);
        cur_bit_idx += regidx_bitlen;

        let is_imm = instr.bit(cur_bit_idx);
        cur_bit_idx += 1;

        // Check that the rest of the instruction is all 0s. This isn't strictly necessary but it
        // might help catch bugs early
        let rest: u128 = instr.bit_range(2 * (W::BITLEN as usize) - 1, cur_bit_idx);
        assert_eq!(rest, 0);

        // Decode the immediate-or-reg as one or the other
        let imm_or_reg = ImmOrRegister::new(imm_or_reg_val, bool::from(is_imm)).unwrap();

        // Validate the register values
        Self::regidx_valid::<NUM_REGS>(reg1);
        Self::regidx_valid::<NUM_REGS>(reg2);

        (RegIdx(reg1), RegIdx(reg2), imm_or_reg, opcode)
    }

    // Converts our operation to machine code. Panics if `buf.len() != W::INSTR_BYTELEN`.
    pub fn to_bytes<const NUM_REGS: usize>(&self, out: &mut [u8]) {
        assert!(out.len() == W::INSTR_BYTELEN);

        let opcode = self.opcode() as u8;
        let reg0 = RegIdx(0);

        let instr = match *self {
            Instr::Add { in1, in2, out } => Self::encode::<NUM_REGS>(out, in1, in2, opcode),
            Instr::Or { in1, in2, out } => Self::encode::<NUM_REGS>(out, in1, in2, opcode),
            Instr::Xor { in1, in2, out } => Self::encode::<NUM_REGS>(out, in1, in2, opcode),
            Instr::Not { in1, out } => Self::encode::<NUM_REGS>(out, reg0, in1, opcode),
            Instr::LoadW { in1, out } => Self::encode::<NUM_REGS>(out, reg0, in1, opcode),
            Instr::StoreW { in1, out } => Self::encode::<NUM_REGS>(reg0, in1, out, opcode),
            Instr::CmpE { in1, in2 } => Self::encode::<NUM_REGS>(reg0, in1, in2, opcode),
            Instr::Jmp { in1 } => Self::encode::<NUM_REGS>(reg0, reg0, in1, opcode),
            Instr::CJmp { in1 } => Self::encode::<NUM_REGS>(reg0, reg0, in1, opcode),
            Instr::Answer { in1 } => Self::encode::<NUM_REGS>(reg0, reg0, in1, opcode),
            _ => todo!(),
        };

        let encoding = instr.to_be_bytes();
        out.copy_from_slice(&encoding[16 - out.len()..16]);
    }

    // Encodes an instruction
    fn encode<const NUM_REGS: usize>(
        reg1: RegIdx,
        reg2: RegIdx,
        imm_or_reg: ImmOrRegister<W>,
        opcode: u8,
    ) -> u128 {
        // Validate the register values
        Self::regidx_valid::<NUM_REGS>(reg1.0);
        Self::regidx_valid::<NUM_REGS>(reg2.0);

        let regidx_bitlen = f32::from(NUM_REGS as u8).log2().ceil() as usize;

        let mut cur_bit_idx = 0;
        let mut instr: u128 = 0;

        // Structure of an RRI instruction is
        // 000...0  is_imm  reg1  reg2  imm_or_reg  opcode
        // <-- MSB                                 LSB -->

        instr.set_bit_range(cur_bit_idx + OPCODE_BITLEN - 1, cur_bit_idx, opcode);
        cur_bit_idx += OPCODE_BITLEN;

        instr.set_bit_range(
            cur_bit_idx + (W::BITLEN as usize) - 1,
            cur_bit_idx,
            u64::from(imm_or_reg),
        );
        cur_bit_idx += W::BITLEN as usize;

        instr.set_bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx, reg2.0);
        cur_bit_idx += regidx_bitlen;

        instr.set_bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx, reg1.0);
        cur_bit_idx += regidx_bitlen;

        instr.set_bit(cur_bit_idx, imm_or_reg.is_imm());

        instr
    }

    // Panics if a Register Index overflows its allocated space in machine code
    fn regidx_valid<const NUM_REGS: usize>(regidx: u8) {
        // Note we enumerate our registers [0,...,NUM_REGS-1]
        if regidx as usize >= NUM_REGS {
            panic!("Register Index exceeds our number of registers");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register::ImmOrRegister;

    use rand::Rng;

    const NUM_REGS: usize = 16;
    type W = u32;

    fn gen_regidx<R: Rng>(mut rng: R) -> RegIdx {
        RegIdx(rng.gen_range(0..NUM_REGS) as u8)
    }

    fn gen_imm_or_regidx<R: Rng>(mut rng: R) -> ImmOrRegister<W> {
        let is_imm = rng.gen();
        if is_imm {
            ImmOrRegister::Imm(rng.gen_range(0..=W::MAX))
        } else {
            ImmOrRegister::Register(gen_regidx(&mut rng))
        }
    }

    // Tests that Instr::from_mc(op.to_mc()) is the identity on `op`
    #[test]
    fn round_trip_identity() {
        let mut rng = rand::thread_rng();

        // Test 100 test cases of each kind of instruction
        for _ in 0..100 {
            // Make random test cases
            let test_cases: &[Instr<W>] = &[
                Instr::Answer {
                    in1: gen_imm_or_regidx(&mut rng),
                },
                Instr::CmpE {
                    in1: gen_regidx(&mut rng),
                    in2: gen_imm_or_regidx(&mut rng),
                },
                Instr::Or {
                    in1: gen_regidx(&mut rng),
                    in2: gen_imm_or_regidx(&mut rng),
                    out: gen_regidx(&mut rng),
                },
                Instr::Add {
                    in1: gen_regidx(&mut rng),
                    in2: gen_imm_or_regidx(&mut rng),
                    out: gen_regidx(&mut rng),
                },
                Instr::Not {
                    in1: gen_imm_or_regidx(&mut rng),
                    out: gen_regidx(&mut rng),
                },
                Instr::CJmp {
                    in1: gen_imm_or_regidx(&mut rng),
                },
                Instr::LoadW {
                    in1: gen_imm_or_regidx(&mut rng),
                    out: gen_regidx(&mut rng),
                },
                Instr::StoreW {
                    in1: gen_regidx(&mut rng),
                    out: gen_imm_or_regidx(&mut rng),
                },
            ];

            // Test equality after an encode-decode round trip
            for tc in test_cases {
                let mut bytes = [0u8; W::INSTR_BYTELEN];
                tc.to_bytes::<NUM_REGS>(&mut bytes);
                let new_tc = Instr::<W>::from_bytes::<NUM_REGS>(&bytes);
                assert_eq!(*tc, new_tc);
            }
        }
    }
}
