use crate::{
    instructions::{Instr, Opcode},
    register::{ImmOrRegister, RegIdx},
    word::{DoubleWord, Word},
    TinyRam,
};

use bitfield::{Bit, BitMut, BitRange, BitRangeMut};

pub(crate) const OPCODE_BITLEN: usize = 5;

pub(crate) fn instr_opcode(instr: u128) -> Opcode {
    let opcode_byte: u8 = instr.bit_range(OPCODE_BITLEN - 1, 0);
    match Opcode::try_from(opcode_byte) {
        Ok(oc) => oc,
        Err(_) => panic!("invalid opcode provided: {opcode_byte}, in 0x{instr:032x}"),
    }
}

impl<T: TinyRam> Instr<T> {
    //  The machine code of an assembly command is encoded as follows.
    //  | unused space | is_immediate | var1 | var2 | var3 | op |
    //
    //  Note that if our instruction does not need a variable, then we shift
    //  over the free space in the program
    //
    //  op is 5 bits long, with canonical OpCodes defined above.

    /// Creates an Op out of machine code. Panics if `bytes.len() != W::INSTR_BYTELEN` or if the
    /// instruction is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        use Opcode::*;
        assert!(bytes.len() == T::SERIALIZED_INSTR_BYTE_LENGTH);

        let instr = {
            let mut buf = [0u8; 16];
            buf[16 - bytes.len()..16].copy_from_slice(bytes);
            u128::from_be_bytes(buf)
        };

        // Decode the instruction. reg1 is the register (if any) that is modified, and reg2 is the
        // register (if any) that is not modified.
        let (opcode, reg1, reg2, imm_or_reg) = Self::decode(instr);

        match opcode {
            And => Instr::And {
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
            Not => Instr::Not {
                in1: imm_or_reg,
                out: reg1,
            },
            Add => Instr::Add {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            Sub => Instr::Sub {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            MulL => Instr::MulL {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            UMulH => Instr::UMulH {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            SMulH => Instr::SMulH {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            UDiv => Instr::UDiv {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            UMod => Instr::UMod {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            Shl => Instr::Shl {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            Shr => Instr::Shr {
                in1: reg2,
                in2: imm_or_reg,
                out: reg1,
            },
            CmpE => Instr::CmpE {
                in1: reg2,
                in2: imm_or_reg,
            },
            CmpA => Instr::CmpA {
                in1: reg2,
                in2: imm_or_reg,
            },
            CmpAe => Instr::CmpAE {
                in1: reg2,
                in2: imm_or_reg,
            },
            CmpG => Instr::CmpG {
                in1: reg2,
                in2: imm_or_reg,
            },
            CmpGe => Instr::CmpGE {
                in1: reg2,
                in2: imm_or_reg,
            },
            Mov => Instr::Mov {
                in1: imm_or_reg,
                out: reg1,
            },
            CMov => Instr::CMov {
                in1: imm_or_reg,
                out: reg1,
            },
            Jmp => Instr::Jmp { in1: imm_or_reg },
            CJmp => Instr::CJmp { in1: imm_or_reg },
            CnJmp => Instr::CNJmp { in1: imm_or_reg },
            StoreB => Instr::StoreB {
                in1: reg2,
                out: imm_or_reg,
            },
            LoadB => Instr::LoadB {
                in1: imm_or_reg,
                out: reg1,
            },
            StoreW => Instr::StoreW {
                in1: reg2,
                out: imm_or_reg,
            },
            LoadW => Instr::LoadW {
                in1: imm_or_reg,
                out: reg1,
            },
            Read => Instr::Read {
                in1: imm_or_reg,
                out: reg1,
            },
            Answer => Instr::Answer { in1: imm_or_reg },
        }
    }

    // Decodes an instruction
    pub fn decode(instr: u128) -> (Opcode, RegIdx, RegIdx, ImmOrRegister<T>) {
        let regidx_bitlen = f32::from(T::NUM_REGS as u8).log2().ceil() as usize;

        let mut cur_bit_idx = 0;

        // Structure of an instruction is
        // 000...0  is_imm  reg1  reg2  imm_or_reg  opcode
        // <-- MSB                                 LSB -->

        let opcode = instr_opcode(instr);
        cur_bit_idx += OPCODE_BITLEN;

        let imm_or_reg_val = instr.bit_range(
            cur_bit_idx + (T::Word::BIT_LENGTH as usize) - 1,
            cur_bit_idx,
        );
        cur_bit_idx += T::Word::BIT_LENGTH as usize;

        let reg2 = instr.bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx);
        cur_bit_idx += regidx_bitlen;

        let reg1 = instr.bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx);
        cur_bit_idx += regidx_bitlen;

        let is_imm = instr.bit(cur_bit_idx);
        cur_bit_idx += 1;

        // Check that the rest of the instruction is all 0s. This isn't strictly necessary but it
        // might help catch bugs early
        let rest: u128 = instr.bit_range(2 * (T::Word::BIT_LENGTH as usize) - 1, cur_bit_idx);
        assert_eq!(rest, 0);

        // Decode the immediate-or-reg as one or the other
        let imm_or_reg = ImmOrRegister::new(imm_or_reg_val, bool::from(is_imm)).unwrap();

        // Validate the register values
        assert!(RegIdx(reg1).is_valid::<T>());
        assert!(RegIdx(reg2).is_valid::<T>());

        (opcode, RegIdx(reg1), RegIdx(reg2), imm_or_reg)
    }

    // Converts our operation to `u128`
    #[rustfmt::skip]
    pub fn to_u128(&self) -> u128 {
        let op = self.opcode() as u8;
        let rg0 = RegIdx(0);

        match *self {
            Instr::And { in1, in2, out }   => Self::encode(op, out, in1, in2),
            Instr::Or { in1, in2, out }    => Self::encode(op, out, in1, in2),
            Instr::Xor { in1, in2, out }   => Self::encode(op, out, in1, in2),
            Instr::Not { in1, out }        => Self::encode(op, out, rg0, in1),
            Instr::Add { in1, in2, out }   => Self::encode(op, out, in1, in2),
            Instr::Sub { in1, in2, out }   => Self::encode(op, out, in1, in2),
            Instr::MulL { in1, in2, out }  => Self::encode(op, out, in1, in2),
            Instr::UMulH { in1, in2, out } => Self::encode(op, out, in1, in2),
            Instr::SMulH { in1, in2, out } => Self::encode(op, out, in1, in2),
            Instr::UDiv { in1, in2, out }  => Self::encode(op, out, in1, in2),
            Instr::UMod { in1, in2, out }  => Self::encode(op, out, in1, in2),
            Instr::Shl { in1, in2, out }   => Self::encode(op, out, in1, in2),
            Instr::Shr { in1, in2, out }   => Self::encode(op, out, in1, in2),
            Instr::CmpE { in1, in2 }       => Self::encode(op, rg0, in1, in2),
            Instr::CmpA { in1, in2 }       => Self::encode(op, rg0, in1, in2),
            Instr::CmpAE { in1, in2 }      => Self::encode(op, rg0, in1, in2),
            Instr::CmpG { in1, in2 }       => Self::encode(op, rg0, in1, in2),
            Instr::CmpGE { in1, in2 }      => Self::encode(op, rg0, in1, in2),
            Instr::Mov { in1, out }        => Self::encode(op, out, rg0, in1),
            Instr::CMov { in1, out }       => Self::encode(op, out, rg0, in1),
            Instr::Jmp { in1 }             => Self::encode(op, rg0, rg0, in1),
            Instr::CJmp { in1 }            => Self::encode(op, rg0, rg0, in1),
            Instr::CNJmp { in1 }           => Self::encode(op, rg0, rg0, in1),
            Instr::StoreB { in1, out }     => Self::encode(op, rg0, in1, out),
            Instr::LoadB { in1, out }      => Self::encode(op, out, rg0, in1),
            Instr::StoreW { in1, out }     => Self::encode(op, rg0, in1, out),
            Instr::LoadW { in1, out }      => Self::encode(op, out, rg0, in1),
            Instr::Read { in1, out }       => Self::encode(op, out, rg0, in1),
            Instr::Answer { in1 }          => Self::encode(op, rg0, rg0, in1),
        }
    }

    // Converts our operation to machine code. Panics if `buf.len() != W::INSTR_BYTELEN`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_u128().to_be_bytes()[16 - T::Word::INSTR_BYTE_LENGTH..16].to_vec()
    }

    pub fn to_double_word(&self) -> DoubleWord<T::Word> {
        let bytes = self.to_bytes();
        let w0_bytes = &bytes[0..bytes.len() / 2];
        let w1_bytes = &bytes[bytes.len() / 2..];

        (
            T::Word::from_be_bytes(w0_bytes).unwrap(),
            T::Word::from_be_bytes(w1_bytes).unwrap(),
        )
    }

    // Encodes an instruction
    fn encode(opcode: u8, reg1: RegIdx, reg2: RegIdx, imm_or_reg: ImmOrRegister<T>) -> u128 {
        // Validate the register values
        assert!(reg1.is_valid::<T>());
        assert!(reg2.is_valid::<T>());

        let regidx_bitlen = f32::from(T::NUM_REGS as u8).log2().ceil() as usize;

        let mut cur_bit_idx = 0;
        let mut instr: u128 = 0;

        // Structure of an RRI instruction is
        // 000...0  is_imm  reg1  reg2  imm_or_reg  opcode
        // <-- MSB                                 LSB -->

        instr.set_bit_range(cur_bit_idx + OPCODE_BITLEN - 1, cur_bit_idx, opcode);
        cur_bit_idx += OPCODE_BITLEN;

        instr.set_bit_range(
            cur_bit_idx + (T::Word::BIT_LENGTH as usize) - 1,
            cur_bit_idx,
            u64::from(imm_or_reg),
        );
        cur_bit_idx += T::Word::BIT_LENGTH as usize;

        instr.set_bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx, reg2.0);
        cur_bit_idx += regidx_bitlen;

        instr.set_bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx, reg1.0);
        cur_bit_idx += regidx_bitlen;

        instr.set_bit(cur_bit_idx, imm_or_reg.is_imm());

        instr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that Instr::from_mc(op.to_mc()) is the identity on `op`
    #[test]
    fn encoding_round_trip() {
        fn encode_decode<T: TinyRam>() {
            let mut rng = rand::thread_rng();
            for _ in 0..200 {
                let instr = Instr::<T>::rand(&mut rng);
                let bytes = instr.to_bytes();
                let new_i = Instr::from_bytes(&bytes);
                assert_eq!(instr, new_i);
            }
        }
        crate::iter_over_tinyram_configs!(encode_decode);
    }
}
