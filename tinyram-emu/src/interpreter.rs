use crate::{
    instructions::Instr,
    memory::{DataMemory, ProgramMemory},
    program_state::CpuState,
    word::Word,
    TinyRamArch,
};

use std::collections::BTreeMap;

pub enum MemOp<W: Word> {
    StoreW { val: W, location: W },
    LoadW { val: W, location: W },
}

impl<W: Word> Instr<W> {
    /// Executes the given instruction. without necessarily updating the program counter.
    /// This method only updates the program counter if `self` is one of `Inst::Jmp`, `Inst::CJmp`, or `Inst::CNJmp`.
    fn execute<const NUM_REGS: usize>(
        &self,
        mut cpu_state: CpuState<NUM_REGS, W>,
        data_memory: &mut DataMemory<W>,
        program_memory: &mut ProgramMemory<W>,
    ) -> (CpuState<NUM_REGS, W>, Option<MemOp<W>>) {
        let mem_op = match self {
            // Arithmetic instructions
            Instr::And { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 & in2;
                None
            }
            Instr::Or { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 | in2;
                None
            }
            Instr::Xor { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 ^ in2;
                None
            }
            Instr::Not { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = !in1;
                None
            }
            Instr::Add { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.carrying_add(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            }
            Instr::Sub { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, borrow) = in1.borrowing_sub(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = borrow;
                None
            }
            Instr::MulL { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.mul_low(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            }
            Instr::UMulH { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.mul_high(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            }
            Instr::SMulH { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.signed_mul_high(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            }
            Instr::UDiv { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.checked_div(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            }
            Instr::UMod { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.checked_rem(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            }
            Instr::Shl { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.shl(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            }
            Instr::Shr { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, flag) = in1.shr(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = flag;
                None
            }
            // Comparison instructions
            Instr::CmpE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 == in2;
                None
            }
            Instr::CmpA { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 > in2;
                None
            }
            Instr::CmpAE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 >= in2;
                None
            }
            Instr::CmpG { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers).to_signed();
                let in2 = in2.value(&cpu_state.registers).to_signed();
                cpu_state.condition_flag = in1 > in2;
                None
            }
            Instr::CmpGE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers).to_signed();
                let in2 = in2.value(&cpu_state.registers).to_signed();
                cpu_state.condition_flag = in1 >= in2;
                None
            }
            // Move instructions
            Instr::Mov { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1;
                None
            }
            Instr::CMov { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                if cpu_state.condition_flag {
                    cpu_state.registers[out.0 as usize] = in1;
                }
                None
            }
            // Jump instructions
            Instr::Jmp { in1 } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.program_counter = in1;
                None
            }
            Instr::CJmp { in1 } => {
                if cpu_state.condition_flag {
                    let in1 = in1.value(&cpu_state.registers);
                    cpu_state.program_counter = in1;
                }
                None
            }
            Instr::CNJmp { in1 } => {
                if !cpu_state.condition_flag {
                    let in1 = in1.value(&cpu_state.registers);
                    cpu_state.program_counter = in1;
                }
                None
            }
            Instr::Answer { in1 } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.answer = Some(in1);
                None
            }
            _ => todo!(),
        };

        (cpu_state, mem_op)
    }

    // FIXME: This function will do the wrong thing on an assembly line like:
    //     _infinite: jmp _infinite
    /// Executes the given instruction, and updates the program counter.
    pub fn execute_and_update_pc<const NUM_REGS: usize>(
        &self,
        arch: TinyRamArch,
        cpu_state: CpuState<NUM_REGS, W>,
        data_memory: &mut DataMemory<W>,
        program_memory: &mut ProgramMemory<W>,
    ) -> (CpuState<NUM_REGS, W>, Option<MemOp<W>>) {
        let old_pc = cpu_state.program_counter;
        let (mut new_state, mem_op) = self.execute(cpu_state, data_memory, program_memory);
        if new_state.program_counter == old_pc {
            // The amount we increment the program counter depends on the architecture. In Harvard,
            // it's 1 (since program memory holds dwords). In VonNeumann it's 2 * the
            // bytelength of a word (since data memory holds bytes).
            let pc_incr_amount = match arch {
                TinyRamArch::Harvard => 1u64,
                TinyRamArch::VonNeumann => 2 * (W::BITLEN as u64) / 8,
            };

            // Try to increment the program counter
            let (new_pc, overflow) = new_state
                .program_counter
                .carrying_add(W::from_u64(pc_incr_amount).unwrap());
            // If the program counter went out of bounds, panic
            if overflow {
                panic!("program counter overflow");
            }

            // Set the new CPU state's program counter
            new_state.program_counter = new_pc;
        }

        (new_state, mem_op)
    }
}

/// Runs the given TinyRAM program and returns its output and a time-ordered transcript of all the
/// memory operations
pub fn run_program<W: Word, const NUM_REGS: usize>(
    arch: TinyRamArch,
    program: &[Instr<W>],
) -> (W, Vec<Option<MemOp<W>>>) {
    let mut mem_ops = Vec::new();
    let mut cpu_state = CpuState::<NUM_REGS, W>::default();

    // Initialize the program or data memory, depending on the arch
    let (mut data_memory, mut program_memory) = match arch {
        TinyRamArch::Harvard => {
            // For Harvard we just wrap the given instructions and that's it

            // Make sure the program is word-addressable
            assert!(program.len() < (1 << W::BITLEN));

            // Return the memory
            (DataMemory::<W>::default(), ProgramMemory(program.to_vec()))
        }
        TinyRamArch::VonNeumann => {
            // For von Neumann we're gonna have to serialize the whole program into data memory

            // Every instruction is 2 words
            let serialized_program_bytelen = program.len() * 2 * (W::BITLEN as usize / 8);
            // Make sure the program is word-addressable
            assert!(serialized_program_bytelen < (1 << W::BITLEN));

            // The memory is initialized with just the program, starting at address 0. Memory is a
            // sparse map of addr -> byte
            let serialized_program: BTreeMap<W, u8> = program
                .iter()
                .flat_map(|instr| {
                    let mut buf = vec![0u8; W::INSTR_BYTELEN];
                    instr.to_bytes::<NUM_REGS>(&mut buf);
                    buf
                })
                .enumerate()
                .map(|(i, b)| (W::from_u64(i as u64).unwrap(), b))
                .collect();

            // Return the memory
            (
                DataMemory(serialized_program),
                ProgramMemory::<W>::default(),
            )
        }
    };

    // Run the CPU until it outputs an answer
    while cpu_state.answer.is_none() {
        // Get the PC and decode the instruction there
        let instr = match arch {
            TinyRamArch::Harvard => {
                let pc = usize::try_from(cpu_state.program_counter.into())
                    .expect("program counter exceeds usize::MAX");
                *program_memory.0.get(pc).expect("illegal memory access")
            }
            TinyRamArch::VonNeumann => {
                let bytes_per_word = W::BITLEN as u64 / 8;
                let bytes_per_instr = 2 * bytes_per_word;

                // Collect 2 words of bytes starting at pc. 16 is the upper bound on the number of
                // bytes
                let pc = cpu_state.program_counter;
                let encoded_instr: Vec<u8> = (0..bytes_per_instr)
                    .map(|i| {
                        let (next_idx, overflow) = pc.carrying_add(W::from_u64(i).unwrap());
                        if overflow {
                            panic!("program counter overflow");
                        }

                        // Now get the byte
                        *data_memory.0.get(&next_idx).expect("illegal memory access")
                    })
                    .collect();

                Instr::<W>::from_bytes::<NUM_REGS>(&encoded_instr)
            }
        };

        // Run the CPU
        let (new_cpu_state, mem_op) =
            instr.execute_and_update_pc(arch, cpu_state, &mut data_memory, &mut program_memory);

        // Update the CPU state and save the mem op
        cpu_state = new_cpu_state;
        mem_ops.push(mem_op);
    }

    (cpu_state.answer.unwrap(), mem_ops)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        instructions::Instr,
        parser::assemble,
        register::{ImmOrRegister, RegIdx},
    };

    type W = u32;
    const NUM_REGS: usize = 8;

    // Test program that sums every multiple of 3 from 1 to 100. The output should be 1683.
    #[test]
    fn sum_skip3() {
        // A simple Rust program we will translate to TinyRAM assembly
        //        i is our index that ranges from 0 to 100
        //      acc is our accumulated sum, which is printed at the end
        // mul3_ctr is our mul-of-three counter
        let mut i = 0;
        let mut mul3_ctr = 0;
        let mut acc = 0u64;
        loop {
            i += 1;
            mul3_ctr += 1;
            if i == 100 {
                break;
            } else if mul3_ctr == 3 {
                acc += i;
                mul3_ctr = 0;
            }
        }
        println!("{acc}");

        // Here's the assembly code of the above program
        //     reg0 -> i
        //     reg1 -> acc
        //     reg2 -> mul3_ctr
        let skip3_code = "\
        _loop: add  r0, r0, 1     ; incr i
               add  r2, r2, 1     ; incr mul3_ctr
               cmpe r0, 100       ; if i == 100:
               cjmp _end          ;     jump to end
               cmpe r2, 3         ; else if mul3_ctr == 3:
               cjmp _acc          ;     jump to acc
               jmp  _loop         ; else jump to beginning

         _acc: add r1, r1, r0     ; Accumulate i into acc
               xor r2, r2, r2     ; Clear mul3_ctr
               jmp _loop          ; Jump back to the loop

         _end: answer r1          ; Return acc
        ";

        // Headers for the two architectures
        let hv_header = "; TinyRAM V=2.000 M=hv W=32 K=8\n";
        let vn_header = "; TinyRAM V=2.000 M=vn W=32 K=8\n";

        // Assemble the program under both architectures
        for (arch, header) in [
            (TinyRamArch::Harvard, hv_header),
            (TinyRamArch::VonNeumann, vn_header),
        ] {
            let program = [header, skip3_code].concat();
            let assembly = assemble(&program);
            let (output, _mem_trace) = run_program::<W, NUM_REGS>(arch, &assembly);

            // Check that the program outputted the correct value
            assert_eq!(output, 1683);
        }
    }
}
