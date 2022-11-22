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
        register::{ImmOrRegister, RegIdx},
    };

    type W = u32;
    const NUM_REGS: usize = 8;

    fn imm(val: u64) -> ImmOrRegister<W> {
        ImmOrRegister::new(val, true).unwrap()
    }

    // Test program that sums every multiple of 3 from 1 to 100. The output should be 1683.
    #[test]
    fn sum_skip3() {
        // A simple Rust program we will translate to TinyRAM assembly
        //        i is our index that ranges from 0 to 100
        //      acc is our accumulated sum
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

        // Here's the assembly code of the above program
        //     reg0 -> i
        //     reg1 -> acc
        //     reg2 -> mul3_ctr
        //
        // hv addr  vn addr             code
        // -------  -------  ---------------------------
        //                   ; TinyRam V=2.000 M=X W=32 K=8
        //                     (where X = hv or vn)
        //    0x00     0x00  _loop: add  reg0, reg0 1        ; incr i
        //    0x01     0x08         add  reg2, reg2 1        ; incr mul3_ctr
        //    0x02     0x10         cmpe reg0, 100           ; if i == 100:
        //    0x03     0x18         cjmp _end                ;     jump to end
        //    0x04     0x20         cmpe reg2, 3             ; else if mul3_ctr == 3:
        //    0x05     0x28         cjmp _acc                ;     jump to acc
        //    0x06     0x30         jmp  _loop               ; else jump to beginning
        //
        //    0x07     0x38   _acc: add reg1, reg1, reg0     ; Accumulate i into acc
        //    0x08     0x40         xor reg2, reg2, reg2     ; Clear mul3_ctr
        //    0x09     0x48         jmp loop                 ; Jump back to the loop
        //
        //    0x0a     0x50   _end: answer reg1              ; Return acc

        let reg0 = RegIdx(0);
        let reg1 = RegIdx(1);
        let reg2 = RegIdx(2);

        let hv_labels = (imm(0x00), imm(0x07), imm(0x0a));
        let vn_labels = (imm(0x00), imm(0x38), imm(0x50));

        for (arch, (label_loop, label_acc, label_end)) in [
            (TinyRamArch::Harvard, hv_labels),
            (TinyRamArch::VonNeumann, vn_labels),
        ] {
            let assembly = [
                Instr::Add {
                    out: reg0,
                    in1: reg0,
                    in2: imm(1),
                },
                Instr::Add {
                    out: reg2,
                    in1: reg2,
                    in2: imm(1),
                },
                Instr::CmpE {
                    in1: reg0,
                    in2: imm(100),
                },
                Instr::CJmp { in1: label_end },
                Instr::CmpE {
                    in1: reg2,
                    in2: imm(3),
                },
                Instr::CJmp { in1: label_acc },
                Instr::Jmp { in1: label_loop },
                Instr::Add {
                    out: reg1,
                    in1: reg1,
                    in2: ImmOrRegister::Register(reg0),
                },
                Instr::Xor {
                    out: reg2,
                    in1: reg2,
                    in2: ImmOrRegister::Register(reg2),
                },
                Instr::Jmp { in1: label_loop },
                Instr::Answer {
                    in1: ImmOrRegister::Register(reg1),
                },
            ];

            let (output, _mem_trace) = run_program::<W, NUM_REGS>(arch, &assembly);
            assert_eq!(u64::from(output), acc);
        }
    }
}
