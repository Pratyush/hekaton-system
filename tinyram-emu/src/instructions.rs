use crate::register::{Register, RegisterOrImm};
use crate::{
    memory::{DataMemory, ProgramMemory},
    program_state::CPUState,
    word::Word,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inst<W: Word> {
    // Arithmetic instructions
    And {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    Or {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    Xor {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    Not {
        in1: RegisterOrImm<W>,
        out: Register,
    },
    Add {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    Sub {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    MulL {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    UMulH {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    SMulH {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    UDiv {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    UMod {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    Shl {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    Shr {
        in1: Register,
        in2: RegisterOrImm<W>,
        out: Register,
    },
    // Compare instructions
    CmpE {
        in1: Register,
        in2: RegisterOrImm<W>,
    },
    CmpA {
        in1: Register,
        in2: RegisterOrImm<W>,
    },
    CmpAE {
        in1: Register,
        in2: RegisterOrImm<W>,
    },
    CmpG {
        in1: Register,
        in2: RegisterOrImm<W>,
    },
    CmpGE {
        in1: Register,
        in2: RegisterOrImm<W>,
    },
    Mov {
        in1: RegisterOrImm<W>,
        out: Register,
    },
    CMov {
        in1: RegisterOrImm<W>,
        out: Register,
    },
    Jmp {
        in1: RegisterOrImm<W>,
    },
    CJmp {
        in1: RegisterOrImm<W>,
    },
    CNJmp {
        in1: RegisterOrImm<W>,
    },
    StoreB {
        in1: Register,
        out: RegisterOrImm<W>,
    },
    LoadB {
        in1: W,
        out: Register,
    },
    StoreW {
        in1: Register,
        out: W,
    },
    LoadW {
        in1: W,
        out: Register,
    },
    Read {
        in1: W,
        out: Register,
    },
    Answer {
        in1: W,
    },
}

impl<W: Word> Inst<W> {
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
            Inst::And { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 & in2;
            }
            Inst::Or { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 | in2;
            }
            Inst::Xor { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 ^ in2;
            }
            Inst::Not { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = !in1;
            }
            Inst::Add { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.carrying_add(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Inst::Sub { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, borrow) = in1.borrowing_sub(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = borrow;
            }
            Inst::MulL { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.mul_low(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Inst::UMulH { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.mul_high(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Inst::SMulH { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.signed_mul_high(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Inst::UDiv { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.checked_div(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Inst::UMod { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.checked_rem(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Inst::Shl { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.shl(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
            }
            Inst::Shr { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, flag) = in1.shr(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = flag;
            }
            // Comparison instructions
            Inst::CmpE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 == in2;
            }
            Inst::CmpA { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 > in2;
            }
            Inst::CmpAE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 >= in2;
            }
            Inst::CmpG { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers).to_signed();
                let in2 = in2.value(&cpu_state.registers).to_signed();
                cpu_state.condition_flag = in1 > in2;
            }
            Inst::CmpGE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers).to_signed();
                let in2 = in2.value(&cpu_state.registers).to_signed();
                cpu_state.condition_flag = in1 >= in2;
            }
            // Move instructions
            Inst::Mov { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1;
            }
            Inst::CMov { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                if cpu_state.condition_flag {
                    cpu_state.registers[out.0 as usize] = in1;
                }
            }
            // Jump instructions
            Inst::Jmp { in1 } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.program_counter = in1;
            }
            Inst::CJmp { in1 } => {
                if cpu_state.condition_flag {
                    let in1 = in1.value(&cpu_state.registers);
                    cpu_state.program_counter = in1;
                }
            }
            Inst::CNJmp { in1 } => {
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
