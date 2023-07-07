use crate::{
    register::{ImmOrRegister, RegIdx},
    word::Word,
    TinyRam,
};

use bitfield::BitRangeMut;
use derivative::Derivative;
use rand::Rng;

use opcode::Opcode;

pub mod encoding;
pub mod opcode;

#[derive(Derivative)]
#[derivative(
    Debug(bound = "T: TinyRam"),
    Clone(bound = "T: TinyRam"),
    Copy(bound = "T: TinyRam"),
    PartialEq(bound = "T: TinyRam"),
    Eq(bound = "T: TinyRam")
)]
pub enum Instr<T: TinyRam> {
    // Arithmetic instructions
    And {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    Or {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    Xor {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    Not {
        in1: ImmOrRegister<T>,
        out: RegIdx,
    },
    Add {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    Sub {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    MulL {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    UMulH {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    SMulH {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    UDiv {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    UMod {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    Shl {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    Shr {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
        out: RegIdx,
    },
    // Compare instructions
    CmpE {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
    },
    CmpA {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
    },
    CmpAE {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
    },
    CmpG {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
    },
    CmpGE {
        in1: RegIdx,
        in2: ImmOrRegister<T>,
    },
    Mov {
        in1: ImmOrRegister<T>,
        out: RegIdx,
    },
    CMov {
        in1: ImmOrRegister<T>,
        out: RegIdx,
    },
    Jmp {
        in1: ImmOrRegister<T>,
    },
    CJmp {
        in1: ImmOrRegister<T>,
    },
    CNJmp {
        in1: ImmOrRegister<T>,
    },
    StoreB {
        in1: RegIdx,
        out: ImmOrRegister<T>,
    },
    LoadB {
        in1: ImmOrRegister<T>,
        out: RegIdx,
    },
    StoreW {
        in1: RegIdx,
        out: ImmOrRegister<T>,
    },
    LoadW {
        in1: ImmOrRegister<T>,
        out: RegIdx,
    },
    Read {
        in1: ImmOrRegister<T>,
        out: RegIdx,
    },
    Answer {
        in1: ImmOrRegister<T>,
    },
}

impl<T: TinyRam> Instr<T> {
    pub fn opcode(&self) -> Opcode {
        use Instr::*;
        match &self {
            And { .. } => Opcode::And,
            Or { .. } => Opcode::Or,
            Xor { .. } => Opcode::Xor,
            Not { .. } => Opcode::Not,
            Add { .. } => Opcode::Add,
            Sub { .. } => Opcode::Sub,
            MulL { .. } => Opcode::MulL,
            UMulH { .. } => Opcode::UMulH,
            SMulH { .. } => Opcode::SMulH,
            UDiv { .. } => Opcode::UDiv,
            UMod { .. } => Opcode::UMod,
            Shl { .. } => Opcode::Shl,
            Shr { .. } => Opcode::Shr,
            CmpE { .. } => Opcode::CmpE,
            CmpA { .. } => Opcode::CmpA,
            CmpAE { .. } => Opcode::CmpAe,
            CmpG { .. } => Opcode::CmpG,
            CmpGE { .. } => Opcode::CmpGe,
            Mov { .. } => Opcode::Mov,
            CMov { .. } => Opcode::CMov,
            Jmp { .. } => Opcode::Jmp,
            CJmp { .. } => Opcode::CJmp,
            CNJmp { .. } => Opcode::CnJmp,
            StoreB { .. } => Opcode::StoreB,
            LoadB { .. } => Opcode::LoadB,
            StoreW { .. } => Opcode::StoreW,
            LoadW { .. } => Opcode::LoadW,
            Read { .. } => Opcode::Read,
            Answer { .. } => Opcode::Answer,
        }
    }

    pub fn is_mem_op(&self) -> bool {
        use Instr::*;
        matches!(
            self,
            StoreB { .. } | LoadB { .. } | StoreW { .. } | LoadW { .. }
        )
    }

    pub fn is_tape_op(&self) -> bool {
        use Instr::*;
        matches!(self, Read { .. })
    }

    /// Returns a random, valid instruction. Useful for testing
    pub fn rand(mut rng: impl Rng) -> Self {
        // Structure of an instruction is
        // 000...0  is_imm  reg1  reg2  imm_or_reg  opcode
        // <-- MSB                                 LSB -->
        let regidx_bitlen = f64::from(T::NUM_REGS as u8).log2().ceil() as usize;

        let mut instr = 0u128;

        let opcode = loop {
            let val: u8 = rng.gen_range(0..32);
            // Opcodes 23, 24, 25 are invalid
            if val <= 22 || val >= 26 {
                break val;
            }
        };
        let is_imm: bool = rng.gen();
        let reg1 = rng.gen_range(0..T::NUM_REGS) as u8;
        let reg2 = rng.gen_range(0..T::NUM_REGS) as u8;
        let imm_or_reg = match is_imm {
            true => rng.gen_range(0..=T::Word::MAX.into()),
            false => rng.gen_range(0..T::NUM_REGS) as u64,
        };

        // Start encoding at the LSB
        let mut cur_bit_idx = 0;

        // Encode the opcode
        instr.set_bit_range(
            cur_bit_idx + encoding::OPCODE_BITLEN - 1,
            cur_bit_idx,
            opcode,
        );
        cur_bit_idx += encoding::OPCODE_BITLEN;
        // Encode the imm_or_reg
        instr.set_bit_range(
            cur_bit_idx + T::Word::BIT_LENGTH - 1,
            cur_bit_idx,
            imm_or_reg,
        );
        cur_bit_idx += T::Word::BIT_LENGTH;
        // Encode reg2
        instr.set_bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx, reg2);
        cur_bit_idx += regidx_bitlen;
        // Encode reg1
        instr.set_bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx, reg1);
        cur_bit_idx += regidx_bitlen;
        // Encode is_imm
        instr.set_bit_range(cur_bit_idx + 1 - 1, cur_bit_idx, is_imm as u8);
        // cur_bit_idx += 1;

        // A u128 is larger than an instruction. Use the bottom bytes as the instruction encoding
        let instr_bytes = instr.to_be_bytes();
        Instr::from_bytes(&instr_bytes[16 - T::Word::INSTR_BYTE_LENGTH..16])
    }
}
