use strum::Display;

use crate::TinyRam;

use super::Instr;

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

impl<T: TinyRam> From<Instr<T>> for Opcode {
    fn from(instr: Instr<T>) -> Opcode {
        instr.opcode()
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
