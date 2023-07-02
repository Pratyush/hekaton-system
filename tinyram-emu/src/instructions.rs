use crate::{
    register::{ImmOrRegister, RegIdx},
    word::Word,
};

use bitfield::BitRangeMut;
use rand::Rng;
use strum::Display;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[rustfmt::skip]
#[repr(u8)]
pub enum Opcode {
    And    = 0b00000,
    Or     = 0b00001,
    Xor    = 0b00010,
    Not    = 0b00011,
    Add    = 0b00100,
    Sub    = 0b00101,
    MulL   = 0b00110,
    UMulH  = 0b00111,
    SMulH  = 0b01000,
    UDiv   = 0b01001,
    UMod   = 0b01010,
    Shl    = 0b01011,
    Shr    = 0b01100,
    CmpE   = 0b01101,
    CmpA   = 0b01110,
    CmpAe  = 0b01111,
    CmpG   = 0b10000,
    CmpGe  = 0b10001,
    Mov    = 0b10010,
    CMov   = 0b10011,
    Jmp    = 0b10100,
    CJmp   = 0b10101,
    CnJmp  = 0b10110,
    #[strum(serialize = "store.b")]
    StoreB = 0b11010,
    #[strum(serialize = "load.b")]
    LoadB  = 0b11011,
    #[strum(serialize = "store.w")]
    StoreW = 0b11100,
    #[strum(serialize = "load.w")]
    LoadW  = 0b11101,
    Read   = 0b11110,
    Answer = 0b11111,
}

pub const BYTE_TO_OPCODE: phf::Map<u8, Opcode> = phf::phf_map! {
    0b00000u8 => Opcode::And   ,
    0b00001u8 => Opcode::Or    ,
    0b00010u8 => Opcode::Xor   ,
    0b00011u8 => Opcode::Not   ,
    0b00100u8 => Opcode::Add   ,
    0b00101u8 => Opcode::Sub   ,
    0b00110u8 => Opcode::MulL  ,
    0b00111u8 => Opcode::UMulH ,
    0b01000u8 => Opcode::SMulH ,
    0b01001u8 => Opcode::UDiv  ,
    0b01010u8 => Opcode::UMod  ,
    0b01011u8 => Opcode::Shl   ,
    0b01100u8 => Opcode::Shr   ,
    0b01101u8 => Opcode::CmpE  ,
    0b01110u8 => Opcode::CmpA  ,
    0b01111u8 => Opcode::CmpAe ,
    0b10000u8 => Opcode::CmpG  ,
    0b10001u8 => Opcode::CmpGe ,
    0b10010u8 => Opcode::Mov   ,
    0b10011u8 => Opcode::CMov  ,
    0b10100u8 => Opcode::Jmp   ,
    0b10101u8 => Opcode::CJmp  ,
    0b10110u8 => Opcode::CnJmp ,
    0b11010u8 => Opcode::StoreB,
    0b11011u8 => Opcode::LoadB ,
    0b11100u8 => Opcode::StoreW,
    0b11101u8 => Opcode::LoadW ,
    0b11110u8 => Opcode::Read  ,
    0b11111u8 => Opcode::Answer,
};

pub const STR_TO_OPCODE: phf::Map<&'static str, Opcode> = phf::phf_map! {
    "and" => 	Opcode::And,
    "or" => 	Opcode::Or,
    "xor" => 	Opcode::Xor,
    "not" => 	Opcode::Not,
    "add" => 	Opcode::Add,
    "sub" => 	Opcode::Sub,
    "mull" => 	Opcode::MulL,
    "umulh" => 	Opcode::UMulH,
    "smulh" => 	Opcode::SMulH,
    "udiv" => 	Opcode::UDiv,
    "umod" => 	Opcode::UMod,
    "shl" => 	Opcode::Shl,
    "shr" => 	Opcode::Shr,
    "cmpe" => 	Opcode::CmpE,
    "cmpa" => 	Opcode::CmpA,
    "cmpae" => 	Opcode::CmpAe,
    "cmpg" => 	Opcode::CmpG,
    "cmpge" => 	Opcode::CmpGe,
    "mov" => 	Opcode::Mov,
    "cmov" => 	Opcode::CMov,
    "jmp" => 	Opcode::Jmp,
    "cjmp" => 	Opcode::CJmp,
    "cnjmp" => 	Opcode::CnJmp,
    "store.b" => 	Opcode::StoreB,
    "load.b" => 	Opcode::LoadB,
    "store.w" => 	Opcode::StoreW,
    "load.w" => 	Opcode::LoadW,
    "read" => 	Opcode::Read,
    "answer" => 	Opcode::Answer,
};

impl TryFrom<u8> for Opcode {
    type Error = ();

    fn try_from(input: u8) -> Result<Opcode, ()> {
        BYTE_TO_OPCODE.get(&input).ok_or(()).copied()
    }
}

impl TryFrom<&str> for Opcode {
    type Error = ();

    fn try_from(input: &str) -> Result<Opcode, ()> {
        STR_TO_OPCODE.get(input).ok_or(()).copied()
    }
}

impl<W: Word> From<Instr<W>> for Opcode {
    fn from(instr: Instr<W>) -> Opcode {
        instr.opcode()
    }
}

impl<W: Word> Instr<W> {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instr<W: Word> {
    // Arithmetic instructions
    And {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    Or {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    Xor {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    Not {
        in1: ImmOrRegister<W>,
        out: RegIdx,
    },
    Add {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    Sub {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    MulL {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    UMulH {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    SMulH {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    UDiv {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    UMod {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    Shl {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    Shr {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
        out: RegIdx,
    },
    // Compare instructions
    CmpE {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
    },
    CmpA {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
    },
    CmpAE {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
    },
    CmpG {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
    },
    CmpGE {
        in1: RegIdx,
        in2: ImmOrRegister<W>,
    },
    Mov {
        in1: ImmOrRegister<W>,
        out: RegIdx,
    },
    CMov {
        in1: ImmOrRegister<W>,
        out: RegIdx,
    },
    Jmp {
        in1: ImmOrRegister<W>,
    },
    CJmp {
        in1: ImmOrRegister<W>,
    },
    CNJmp {
        in1: ImmOrRegister<W>,
    },
    StoreB {
        in1: RegIdx,
        out: ImmOrRegister<W>,
    },
    LoadB {
        in1: ImmOrRegister<W>,
        out: RegIdx,
    },
    StoreW {
        in1: RegIdx,
        out: ImmOrRegister<W>,
    },
    LoadW {
        in1: ImmOrRegister<W>,
        out: RegIdx,
    },
    Read {
        in1: ImmOrRegister<W>,
        out: RegIdx,
    },
    Answer {
        in1: ImmOrRegister<W>,
    },
}

impl<W: Word> Instr<W> {
    /// Returns a random, valid instruction. Useful for testing
    pub fn rand<const NUM_REGS: usize>(mut rng: impl Rng) -> Self {
        // Structure of an instruction is
        // 000...0  is_imm  reg1  reg2  imm_or_reg  opcode
        // <-- MSB                                 LSB -->
        let regidx_bitlen = f32::from(NUM_REGS as u8).log2().ceil() as usize;

        let mut instr = 0u128;

        let opcode = loop {
            let val = rng.gen_range(0..32);
            // Opcodes 23, 24, 25 are invalid
            if val <= 22 || val >= 26 {
                break val;
            }
        };
        let is_imm: bool = rng.gen();
        let reg1 = rng.gen_range(0..NUM_REGS) as u8;
        let reg2 = rng.gen_range(0..NUM_REGS) as u8;
        let imm_or_reg = match is_imm {
            true => rng.gen_range(0..=W::MAX.into()),
            false => rng.gen_range(0..NUM_REGS) as u64,
        };

        // Start encoding at the LSB
        let mut cur_bit_idx = 0;

        // Encode the opcode
        instr.set_bit_range(
            cur_bit_idx + crate::encoding::OPCODE_BITLEN - 1,
            cur_bit_idx,
            opcode,
        );
        cur_bit_idx += crate::encoding::OPCODE_BITLEN;
        // Encode the imm_or_reg
        instr.set_bit_range(cur_bit_idx + W::BIT_LENGTH - 1, cur_bit_idx, imm_or_reg);
        cur_bit_idx += W::BIT_LENGTH;
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
        Instr::from_bytes::<NUM_REGS>(&instr_bytes[16 - W::INSTR_BYTE_LENGTH..16])
    }
}

#[cfg(test)]
mod tests {

    use super::Opcode;
    const OPCODE_ARR: [Opcode; 29] = [
        Opcode::And,
        Opcode::Or,
        Opcode::Xor,
        Opcode::Not,
        Opcode::Add,
        Opcode::Sub,
        Opcode::MulL,
        Opcode::UMulH,
        Opcode::SMulH,
        Opcode::UDiv,
        Opcode::UMod,
        Opcode::Shl,
        Opcode::Shr,
        Opcode::CmpE,
        Opcode::CmpA,
        Opcode::CmpAe,
        Opcode::CmpG,
        Opcode::CmpGe,
        Opcode::Mov,
        Opcode::CMov,
        Opcode::Jmp,
        Opcode::CJmp,
        Opcode::CnJmp,
        Opcode::StoreB,
        Opcode::LoadB,
        Opcode::StoreW,
        Opcode::LoadW,
        Opcode::Read,
        Opcode::Answer,
    ];

    #[test]
    fn check_byte_to_opcode_map() {
        use super::BYTE_TO_OPCODE;
        for opcode in OPCODE_ARR {
            assert_eq!(opcode, *BYTE_TO_OPCODE.get(&(opcode as u8)).unwrap())
        }
    }

    #[test]
    fn check_str_to_opcode_map() {
        use super::STR_TO_OPCODE;
        for opcode in OPCODE_ARR {
            assert_eq!(
                opcode,
                *STR_TO_OPCODE
                    .get(format!("{opcode}").to_lowercase().as_ref())
                    .expect(&format!("{opcode} doesn't exist in map"))
            )
        }
    }
}
