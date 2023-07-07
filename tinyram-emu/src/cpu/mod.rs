use crate::{
    instructions::Instr,
    mmu::{MemOp, MemoryUnit},
    tape::{TapeOp, Tapes},
    word::Word,
    TinyRam,
};
pub use state::CpuState;

pub mod state;

pub struct Cpu<T: TinyRam> {
    /// The current state of the CPU
    pub state: CpuState<T>,
    /// The memory unit
    pub mem: MemoryUnit<T>,
    /// The input and auxiliary tapes
    pub tapes: Tapes<T>,
}

#[derive(Clone, Debug)]
pub struct TranscriptEntry<T: TinyRam> {
    /// The timestamp of this entry. This MUST be greater than 0
    pub timestamp: u64,
    /// The instruction being executed
    pub instr: Instr<T>,
    /// The memory operation corresponding to the instruction load
    pub instr_load: MemOp<T::Word>,
    /// The optional memory operation corresponding to this instruction's execution
    pub mem_op: Option<MemOp<T::Word>>,
    /// The optional tape operation corresponding to this instruction's execution
    pub tape_op: Option<TapeOp<T::Word>>,
    /// The state of the CPU after this instruction was computed
    pub cpu_after: CpuState<T>,
}

impl<T: TinyRam> Cpu<T> {
    fn initialize(
        program: &[Instr<T>],
        primary_input: Vec<T::Word>,
        aux_input: Vec<T::Word>,
    ) -> Self {
        let cpu_state = CpuState::<T>::default();

        // Initialize the program and data memory.
        let mem = MemoryUnit::initialize(&program);

        // Initialize the tapes
        let tapes = Tapes::initialize(primary_input, aux_input);

        Self {
            state: cpu_state,
            mem,
            tapes,
        }
    }

    fn run_program(mut self) -> (T::Word, Vec<TranscriptEntry<T>>) {
        let mut transcript = Vec::new();

        // Run the CPU until it outputs an answer
        let mut timestamp = 0;
        while self.state.answer.is_none() {
            // Get the PC and decode the instruction there
            let pc = self.state.program_counter;
            let instr = self.mem.get_instruction(pc);

            // Run the CPU
            let (mem_op, tape_op) = self.execute_instruction_and_update_pc(instr);

            // Register the instruction load. For transcript purposes, make sure the load is
            // word-aligned.
            let instr_load = MemOp::Load {
                val: instr.to_double_word(),
                location: pc.align_to_double_word(),
            };

            // Update the CPU state and save the transcript entry
            let cpu_after = self.state.clone();
            transcript.push(TranscriptEntry {
                timestamp,
                instr,
                instr_load,
                mem_op,
                tape_op,
                cpu_after,
            });

            timestamp += 1;
        }

        (self.state.answer.unwrap(), transcript)
    }

    /// Runs the given TinyRAM program and returns its output and a time-ordered transcript
    /// of all the memory operations
    pub fn initialize_and_run_program(
        program: &[Instr<T>],
        primary_input: Vec<T::Word>,
        aux_input: Vec<T::Word>,
    ) -> (T::Word, Vec<TranscriptEntry<T>>) {
        let cpu = Self::initialize(program, primary_input, aux_input);
        cpu.run_program()
    }

    /// Executes the given instruction, and updates the program counter accordingly.
    pub fn execute_instruction_and_update_pc(
        &mut self,
        instruction: Instr<T>,
    ) -> (Option<MemOp<T::Word>>, Option<TapeOp<T::Word>>) {
        let starting_pc = self.state.program_counter();
        let mem_op = instruction.is_mem_op().then(|| match instruction {
            Instr::StoreW { in1, out } => {
                let in1 = in1.value(&self.state.registers);
                let out = out.value(&self.state.registers);
                self.mem.store_word(out, in1)
            },

            Instr::LoadW { out, in1 } => {
                let in1 = in1.value(&self.state.registers);
                let (result, mem_op) = self.mem.load_word(in1);
                self.state.registers[out.0 as usize] = result;
                mem_op
            },
            _ => todo!("read.b and write.b not implemented yet"),
        });

        let tape_op = if let Instr::Read { in1, out } = instruction {
            let in1 = in1.value(&self.state.registers);
            // Read an element from the given tape and increment the head. The value is None if
            // the tape head is out of bounds or if the tape doesn't exist (ie if the tape
            // index is > 1)
            let tape_op = self.tapes.read_tape(in1, &mut self.state.tape_heads);

            // Set the register to the value. If it is None, set it to 0 and set the condition
            // flag to true
            self.state.registers[out.0 as usize] =
                tape_op.map(|op| op.val()).unwrap_or(T::Word::ZERO);
            self.state.condition_flag = tape_op.is_none();
            tape_op
        } else {
            None
        };

        if !instruction.is_mem_op() & !instruction.is_tape_op() {
            match instruction {
                // Arithmetic instructions
                Instr::And { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    self.state.registers[out.0 as usize] = in1 & in2;
                },

                Instr::Or { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    self.state.registers[out.0 as usize] = in1 | in2;
                },

                Instr::Xor { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    self.state.registers[out.0 as usize] = in1 ^ in2;
                },

                Instr::Not { in1, out } => {
                    let in1 = in1.value(&self.state.registers);
                    self.state.registers[out.0 as usize] = !in1;
                },

                Instr::Add { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    let (result, overflow) = in1.carrying_add(in2);
                    self.state.registers[out.0 as usize] = result;
                    self.state.condition_flag = overflow;
                },

                Instr::Sub { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    let (result, borrow) = in1.borrowing_sub(in2);
                    self.state.registers[out.0 as usize] = result;
                    self.state.condition_flag = borrow;
                },

                Instr::MulL { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    let (result, overflow) = in1.mul_low(in2);
                    self.state.registers[out.0 as usize] = result;
                    self.state.condition_flag = overflow;
                },

                Instr::UMulH { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    let (result, overflow) = in1.mul_high(in2);
                    self.state.registers[out.0 as usize] = result;
                    self.state.condition_flag = overflow;
                },

                Instr::SMulH { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    let (result, overflow) = in1.signed_mul_high(in2);
                    self.state.registers[out.0 as usize] = result;
                    self.state.condition_flag = overflow;
                },

                Instr::UDiv { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    let (result, overflow) = in1.checked_div(in2);
                    self.state.registers[out.0 as usize] = result;
                    self.state.condition_flag = overflow;
                },

                Instr::UMod { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    let (result, overflow) = in1.checked_rem(in2);
                    self.state.registers[out.0 as usize] = result;
                    self.state.condition_flag = overflow;
                },

                Instr::Shl { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    let (result, overflow) = in1.shl(in2);
                    self.state.registers[out.0 as usize] = result;
                    self.state.condition_flag = overflow;
                },

                Instr::Shr { in1, in2, out } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    let (result, flag) = in1.shr(in2);
                    self.state.registers[out.0 as usize] = result;
                    self.state.condition_flag = flag;
                },

                // Comparison instructions
                Instr::CmpE { in1, in2 } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    self.state.condition_flag = in1 == in2;
                },

                Instr::CmpA { in1, in2 } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    self.state.condition_flag = in1 > in2;
                },

                Instr::CmpAE { in1, in2 } => {
                    let in1 = in1.value(&self.state.registers);
                    let in2 = in2.value(&self.state.registers);
                    self.state.condition_flag = in1 >= in2;
                },

                Instr::CmpG { in1, in2 } => {
                    let in1 = in1.value(&self.state.registers).to_signed();
                    let in2 = in2.value(&self.state.registers).to_signed();
                    self.state.condition_flag = in1 > in2;
                },

                Instr::CmpGE { in1, in2 } => {
                    let in1 = in1.value(&self.state.registers).to_signed();
                    let in2 = in2.value(&self.state.registers).to_signed();
                    self.state.condition_flag = in1 >= in2;
                },

                // Move instructions
                Instr::Mov { in1, out } => {
                    let in1 = in1.value(&self.state.registers);
                    self.state.registers[out.0 as usize] = in1;
                },

                Instr::CMov { in1, out } => {
                    let in1 = in1.value(&self.state.registers);
                    if self.state.condition_flag {
                        self.state.registers[out.0 as usize] = in1;
                    }
                },

                // Jump instructions
                Instr::Jmp { in1 } => {
                    let in1 = in1.value(&self.state.registers);
                    self.state.program_counter = in1;
                },

                Instr::CJmp { in1 } => {
                    if self.state.condition_flag {
                        let in1 = in1.value(&self.state.registers);
                        self.state.program_counter = in1;
                    }
                },

                Instr::CNJmp { in1 } => {
                    if !self.state.condition_flag {
                        let in1 = in1.value(&self.state.registers);
                        self.state.program_counter = in1;
                    }
                },

                Instr::Answer { in1 } => {
                    let in1 = in1.value(&self.state.registers);
                    self.state.answer = Some(in1);
                },

                _ => unreachable!(),
            };
        }

        // If the program counter was not changed by the instruction (i.e., via a jmp, cjmp, or cnjmp), increment it now.
        if self.state.program_counter() == starting_pc {
            self.state.increment_pc();
        }
        (mem_op, tape_op)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parser::Parser;

    // Helper function for running TinyRAM code to completion
    fn run_code<T: TinyRam>(
        code: &str,
        primary_input: &[T::Word],
        aux_input: &[T::Word],
    ) -> T::Word {
        let program = [&T::header(), code].concat();
        let assembly = Parser::assemble::<T>(&program);
        let (prog_out, _trace) =
            Cpu::initialize_and_run_program(&assembly, primary_input.to_vec(), aux_input.to_vec());

        // Save the output
        prog_out
    }

    // Test program that sums every multiple of 3 from 1 to 100. The output should be 1683.
    #[test]
    fn sum_skip3() {
        fn test_skip3<T: TinyRam>() {
            // A simple Rust program we will translate to TinyRAM assembly
            //        i is our index that ranges from 0 to 100
            //      acc is our accumulated sum, which is printed at the end
            // mul3_ctr is our mul-of-three counter
            let zero = T::Word::ZERO;
            let one = T::Word::ONE;
            let hundred = T::Word::try_from(100u64).ok().unwrap();
            let three = T::Word::try_from(3u64).ok().unwrap();
            let mut i = zero;
            let mut mul3_ctr = zero;
            let mut acc = zero;
            loop {
                i += one;
                mul3_ctr += one;
                if i == hundred {
                    break;
                } else if mul3_ctr == three {
                    acc += i;
                    mul3_ctr = zero;
                }
            }
            let true_answer = acc;

            // Here's the assembly code of the above program
            //     reg0 -> i
            //     reg1 -> acc
            //     reg2 -> mul3_ctr
            // We also store and load registers from memory every loop
            let skip3_code = "\
            _loop: load.w r1, 600     ; acc <- RAM[600]
                load.w r0, 608     ; i <- RAM[604]
                add  r0, r0, 1     ; incr i
                add  r2, r2, 1     ; incr mul3_ctr
                cmpe r0, 100       ; if i == 100:
                cjmp _end          ;     jump to end
                cmpe r2, 3         ; else if mul3_ctr == 3:
                cjmp _acc          ;     jump to acc
                                    ; else
                store.w 608, r0    ;     i -> RAM[604]
                jmp  _loop         ;     jump to beginning

            _acc: add r1, r1, r0     ; Accumulate i into acc
                xor r2, r2, r2     ; Clear mul3_ctr
                store.w 600, r1    ; acc -> RAM[600]
                store.w 608, r0    ; i -> RAM[604]
                jmp _loop          ; Jump back to the loop

            _end: answer r1          ; Return acc
            ";

            // Run with no tapes
            let output = run_code::<T>(skip3_code, &[], &[]);
            assert_eq!(output, true_answer, "arch info: {}", T::header());
        }
        crate::iter_over_tinyram_configs!(test_skip3);
    }

    // Sums values from primary and auxiliary tape
    #[test]
    fn sum_tape() {
        fn test_sum_tape<T: TinyRam>() {
            // Sum [1, n] from primary tape, and sum 100*[1, n] from auxiliary tape. Then output the
            // sum of those sums.

            let n = 10;
            let primary_tape = (1..=n).map(T::Word::from_u64).collect::<Vec<T::Word>>();
            let aux_tape = (1..=n)
                .map(|x| T::Word::from_u64(100 * x))
                .collect::<Vec<T::Word>>();

            let code = "\
            _loop: read r0, 0     ; r0 <- primary tape
                read r1, 1     ; r1 <- aux tape
                cjmp _end      ; if read failed, jump to end
                add r2, r2, r0 ; else, r2 += r0 and r3 += r1
                add r3, r3, r1
                jmp _loop      ; goto beginning
            _end: add r4, r2, r3 ; at the end: return r2 + r3
                answer r4
            ";

            let output = run_code::<T>(code, &primary_tape, &aux_tape);
            let primary_sum = n * (n + 1) / 2;
            assert_eq!(output.into(), (primary_sum + 100 * primary_sum));
        }

        crate::iter_over_tinyram_configs!(test_sum_tape)
    }
}
