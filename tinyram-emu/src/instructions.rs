use crate::register::{ImmOrRegister, RegIdx};
use crate::{
    memory::{DataMemory, ProgramMemory},
    program_state::CPUState,
    word::Word,
};

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

impl<W: Word> Instr<W> {
    /// Executes the given instruction. without necessarily updating the program counter.
    /// This method only updates the program counter if `self` is one of `Inst::Jmp`, `Inst::CJmp`, or `Inst::CNJmp`.
    fn execute<const NUM_REGS: usize>(
        &self,
        cpu_state: &mut CPUState<NUM_REGS, W>,
        memory: &mut DataMemory,
        program_memory: &mut ProgramMemory<W>,
    ) {
        match self {
            // Arithmetic instructions
            Instr::And { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 & in2;
            }
            Instr::Or { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 | in2;
            }
            Instr::Xor { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 ^ in2;
            }
            Instr::Not { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = !in1;
            }
            Instr::Add { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.carrying_add(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Instr::Sub { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, borrow) = in1.borrowing_sub(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = borrow;
            }
            Instr::MulL { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.mul_low(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Instr::UMulH { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.mul_high(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Instr::SMulH { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.signed_mul_high(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Instr::UDiv { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.checked_div(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Instr::UMod { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.checked_rem(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Instr::Shl { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.shl(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Instr::Shr { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, flag) = in1.shr(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = flag;
            }
            // Comparison instructions
            Instr::CmpE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 == in2;
            }
            Instr::CmpA { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 > in2;
            }
            Instr::CmpAE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 >= in2;
            }
            Instr::CmpG { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers).to_signed();
                let in2 = in2.value(&cpu_state.registers).to_signed();
                cpu_state.condition_flag = in1 > in2;
            }
            Instr::CmpGE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers).to_signed();
                let in2 = in2.value(&cpu_state.registers).to_signed();
                cpu_state.condition_flag = in1 >= in2;
            }
            // Move instructions
            Instr::Mov { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1;
            }
            Instr::CMov { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                if cpu_state.condition_flag {
                    cpu_state.registers[out.0 as usize] = in1;
                }
            }
            // Jump instructions
            Instr::Jmp { in1 } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.program_counter = in1;
            }
            Instr::CJmp { in1 } => {
                if cpu_state.condition_flag {
                    let in1 = in1.value(&cpu_state.registers);
                    cpu_state.program_counter = in1;
                }
            }
            Instr::CNJmp { in1 } => {
                if !cpu_state.condition_flag {
                    let in1 = in1.value(&cpu_state.registers);
                    cpu_state.program_counter = in1;
                }
            }
            _ => todo!(),
        }
    }

    /// Executes the given instruction, and updates the program counter.
    pub fn execute_and_update_pc<const NUM_REGS: usize>(
        &mut self,
        cpu_state: &mut CPUState<NUM_REGS, W>,
        memory: &mut DataMemory,
        program_memory: &mut ProgramMemory<W>,
    ) {
        let old_pc = cpu_state.program_counter;
        self.execute(cpu_state, memory, program_memory);
        if cpu_state.program_counter == old_pc {
            cpu_state
                .program_counter
                .checked_increment()
                .expect("Program counter overflow");
        }
    }
}
