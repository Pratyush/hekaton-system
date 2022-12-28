use crate::register::{ImmOrRegister, RegIdx};
use crate::word::Word;

use bitfield::BitRangeMut;
use rand::Rng;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Opcode {
    And = 0b00000,
    Or,
    Xor,
    Not,
    Add,
    Sub,
    MulL,
    UMulH,
    SMulH,
    UDiv,
    UMod,
    Shl,
    Shr,
    CmpE,
    CmpA,
    CmpAe,
    CmpG,
    CmpGe,
    Mov,
    CMov,
    Jmp,
    CJmp,
    CnJmp,
    StoreB = 0b11010,
    LoadB,
    StoreW,
    LoadW,
    Read,
    Answer,
}

impl TryFrom<u8> for Opcode {
    type Error = ();

    fn try_from(input: u8) -> Result<Opcode, ()> {
        use Opcode::*;

        let table = [
            (And as u8, And),
            (Or as u8, Or),
            (Xor as u8, Xor),
            (Not as u8, Not),
            (Add as u8, Add),
            (Sub as u8, Sub),
            (MulL as u8, MulL),
            (UMulH as u8, UMulH),
            (SMulH as u8, SMulH),
            (UDiv as u8, UDiv),
            (UMod as u8, UMod),
            (Shl as u8, Shl),
            (Shr as u8, Shr),
            (CmpE as u8, CmpE),
            (CmpA as u8, CmpA),
            (CmpAe as u8, CmpAe),
            (CmpG as u8, CmpG),
            (CmpGe as u8, CmpGe),
            (Mov as u8, Mov),
            (CMov as u8, CMov),
            (Jmp as u8, Jmp),
            (CJmp as u8, CJmp),
            (CnJmp as u8, CnJmp),
            (StoreB as u8, StoreB),
            (LoadB as u8, LoadB),
            (StoreW as u8, StoreW),
            (LoadW as u8, LoadW),
            (Read as u8, Read),
            (Answer as u8, Answer),
        ];

        table
            .iter()
            .find_map(|(byte, var)| if input == *byte { Some(*var) } else { None })
            .ok_or(())
    }
}

impl TryFrom<&str> for Opcode {
    type Error = ();

    fn try_from(input: &str) -> Result<Opcode, ()> {
        use Opcode::*;

        let table = [
            ("and", And),
            ("or", Or),
            ("xor", Xor),
            ("not", Not),
            ("add", Add),
            ("sub", Sub),
            ("mull", MulL),
            ("umulh", UMulH),
            ("smulh", SMulH),
            ("udiv", UDiv),
            ("umod", UMod),
            ("shl", Shl),
            ("shr", Shr),
            ("cmpe", CmpE),
            ("cmpa", CmpA),
            ("cmpae", CmpAe),
            ("cmpg", CmpG),
            ("cmpge", CmpGe),
            ("mov", Mov),
            ("cmov", CMov),
            ("jmp", Jmp),
            ("cjmp", CJmp),
            ("cnjmp", CnJmp),
            ("store.b", StoreB),
            ("load.b", LoadB),
            ("store.w", StoreW),
            ("load.w", LoadW),
            ("read", Read),
            ("answer", Answer),
        ];

        table
            .iter()
            .find_map(|(s, var)| if input == *s { Some(*var) } else { None })
            .ok_or(())
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
        instr.set_bit_range(cur_bit_idx + W::BITLEN - 1, cur_bit_idx, imm_or_reg);
        cur_bit_idx += W::BITLEN;
        // Encode reg2
        instr.set_bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx, reg2);
        cur_bit_idx += regidx_bitlen;
        // Encode reg1
        instr.set_bit_range(cur_bit_idx + regidx_bitlen - 1, cur_bit_idx, reg1);
        cur_bit_idx += regidx_bitlen;
        // Encode is_imm
        instr.set_bit_range(cur_bit_idx + 1 - 1, cur_bit_idx, is_imm as u8);
        //cur_bit_idx += 1;

        // A u128 is larger than an instruction. Use the bottom bytes as the instruction encoding
        let instr_bytes = instr.to_be_bytes();
        Instr::from_bytes::<NUM_REGS>(&instr_bytes[16 - W::INSTR_BYTELEN..16])
    }
}
