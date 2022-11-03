use crate::register::{ImmOrRegister, RegIdx};
use crate::word::Word;

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
    CmpAE,
    CmpG,
    CmpGE,
    Mov,
    CMov,
    Jmp,
    CJmp,
    CNJmp,
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
            (CmpAE as u8, CmpAE),
            (CmpG as u8, CmpG),
            (CmpGE as u8, CmpGE),
            (Mov as u8, Mov),
            (CMov as u8, CMov),
            (Jmp as u8, Jmp),
            (CJmp as u8, CJmp),
            (CNJmp as u8, CNJmp),
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
            CmpAE { .. } => Opcode::CmpAE,
            CmpG { .. } => Opcode::CmpG,
            CmpGE { .. } => Opcode::CmpGE,
            Mov { .. } => Opcode::Mov,
            CMov { .. } => Opcode::CMov,
            Jmp { .. } => Opcode::Jmp,
            CJmp { .. } => Opcode::CJmp,
            CNJmp { .. } => Opcode::CNJmp,
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
