use crate::{
    instructions::Instr,
    memory::{DataMemory, ProgramMemory},
    program_state::{CpuState, Tape, TapePos},
    word::{DWord, Word},
    TinyRamArch,
};

use std::collections::BTreeMap;

use ark_ff::Field;
use rand::Rng;

/// A TinyRAM memory operation. This only deals in dwords.
///
/// NOTE: A `read` op from an invalid tape index (2 or greater) is converted to an `xor ri ri`,
/// i.e., it is not considered a memory operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemOp<W: Word> {
    /// Load a dword from RAM
    Load {
        /// The dword being loaded
        val: DWord<W>,
        /// The index the value is being loaded from
        location: W,
    },
    /// Store a dword to RAM
    Store {
        /// The dword being stored
        val: DWord<W>,
        /// The index the value is being stored to
        location: W,
    },
    /// Read a word from the primary tape
    ReadPrimary {
        /// The word being read
        val: W,
        /// The position in the tape BEFORE the value is read
        location: TapePos,
    },
    /// Read a word from the auxiliary tape
    ReadAux {
        /// The word being read
        val: W,
        /// The position in the tape BEFORE the value is read
        location: TapePos,
    },
    /// Read a word from an invalid tape. This always produces 0.
    ReadInvalid,
}

impl<W: Word> MemOp<W> {
    /// Returns a random `MemOp`. Useful for testing
    pub fn rand(mut rng: impl Rng) -> Self {
        let kind: bool = rng.gen();
        let val = (W::rand(&mut rng), W::rand(&mut rng));
        let location = W::rand(&mut rng);
        match kind {
            true => MemOp::Store { val, location },
            false => MemOp::Load { val, location },
        }
    }
}

/// The kind of memory operation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemOpKind {
    /// A memory op corresponding to `loadw` or `loadb`
    Load = 0,
    /// A memory op corresponding to `storew` or `storeb`
    Store,
    /// A memory op corresponding to `read 0`
    ReadPrimary,
    /// A memory op corresponding to `read 1`
    ReadAux,
    /// A memory op corresponding to `read X` for `X > 1`
    ReadInvalid,
}

impl<W: Word> From<&MemOp<W>> for MemOpKind {
    fn from(op: &MemOp<W>) -> Self {
        match op {
            MemOp::Load { .. } => MemOpKind::Load,
            MemOp::Store { .. } => MemOpKind::Store,
            MemOp::ReadPrimary { .. } => MemOpKind::ReadPrimary,
            MemOp::ReadAux { .. } => MemOpKind::ReadAux,
            MemOp::ReadInvalid => MemOpKind::ReadInvalid,
        }
    }
}

impl<W: Word> MemOp<W> {
    pub fn kind(&self) -> MemOpKind {
        MemOpKind::from(self)
    }

    /// Gets the dword being loaded or stored. If it's a valid tape op, then returns the word
    /// being read in the low position, and 0 in the high position. If it's an invalid tape op,
    /// then returns (0, 0)
    pub fn val(&self) -> DWord<W> {
        match self {
            MemOp::Load { val, .. } => val.clone(),
            MemOp::Store { val, .. } => val.clone(),
            MemOp::ReadPrimary { val, .. } => (val.clone(), W::ZERO),
            MemOp::ReadAux { val, .. } => (val.clone(), W::ZERO),
            MemOp::ReadInvalid => (W::ZERO, W::ZERO),
        }
    }

    pub fn is_ram_op(&self) -> bool {
        let kind = self.kind();
        kind == MemOpKind::Load || kind == MemOpKind::Store
    }

    /// Returns the location of this memory op if it's a RAM op, and the tape head position if it's
    /// a tape op. If it's an invalid tape op, i.e., `ReadInvalid`, returns 0.
    pub fn location(&self) -> u64 {
        match *self {
            MemOp::Store { location, .. } => location.into(),
            MemOp::Load { location, .. } => location.into(),
            MemOp::ReadPrimary { location, .. } => location as u64,
            MemOp::ReadAux { location, .. } => location as u64,
            MemOp::ReadInvalid => 0u64,
        }
    }

    /// Returns this memory operation, packed into the low bits of a field element. Also returns
    /// how many bits are used in the packing.
    pub fn as_ff<F: Field>(&self) -> (F, usize) {
        fn pow_two<G: Field>(n: usize) -> G {
            G::from(2u8).pow([n as u64])
        }

        // We pack this as 0000...000 val || location || kind, where location is padded to u64
        // The format doesn't really matter so long as we're consistent
        let kind = self.kind();
        let val = self.val();
        let loc = self.location();

        // Keep track of the running bitlength
        let mut bitlen = 0;
        let mut out = F::zero();

        // Pack kind into the bottom 2 bits
        out += pow_two::<F>(bitlen) * F::from(kind as u8);
        bitlen += 2;

        // Pack loc as a u64
        out += pow_two::<F>(bitlen) * F::from(loc);
        bitlen += 64;

        // val is a dword, so pack each of its words separately
        out += pow_two::<F>(bitlen) * F::from(val.0.into());
        bitlen += W::BITLEN;
        out += pow_two::<F>(bitlen) * F::from(val.1.into());
        bitlen += W::BITLEN;

        (out, bitlen)
    }
}

#[derive(Clone)]
pub struct TranscriptEntry<W: Word> {
    /// The timestamp of this entry. This MUST be greater than 0
    pub timestamp: u64,
    /// The instruction being executed
    pub instr: Instr<W>,
    /// The memory operation corresponding to the instruction load
    pub instr_load: MemOp<W>,
    /// The optional memory operation corresponding to this instruction's execution
    pub mem_op: Option<MemOp<W>>,
}

impl<W: Word> Instr<W> {
    /// Executes the given instruction. without necessarily updating the program counter.
    /// This method only updates the program counter if `self` is one of `Inst::Jmp`, `Inst::CJmp`,
    /// or `Inst::CNJmp`.
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
            },

            Instr::Or { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 | in2;
                None
            },

            Instr::Xor { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1 ^ in2;
                None
            },

            Instr::Not { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = !in1;
                None
            },

            Instr::Add { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.carrying_add(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            },

            Instr::Sub { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, borrow) = in1.borrowing_sub(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = borrow;
                None
            },

            Instr::MulL { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.mul_low(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            },

            Instr::UMulH { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.mul_high(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            },

            Instr::SMulH { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.signed_mul_high(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            },

            Instr::UDiv { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.checked_div(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            },

            Instr::UMod { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.checked_rem(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            },

            Instr::Shl { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, overflow) = in1.shl(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = overflow;
                None
            },

            Instr::Shr { in1, in2, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                let (result, flag) = in1.shr(in2);
                cpu_state.registers[out.0 as usize] = result;
                cpu_state.condition_flag = flag;
                None
            },

            // Comparison instructions
            Instr::CmpE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 == in2;
                None
            },

            Instr::CmpA { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 > in2;
                None
            },

            Instr::CmpAE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers);
                let in2 = in2.value(&cpu_state.registers);
                cpu_state.condition_flag = in1 >= in2;
                None
            },

            Instr::CmpG { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers).to_signed();
                let in2 = in2.value(&cpu_state.registers).to_signed();
                cpu_state.condition_flag = in1 > in2;
                None
            },

            Instr::CmpGE { in1, in2 } => {
                let in1 = in1.value(&cpu_state.registers).to_signed();
                let in2 = in2.value(&cpu_state.registers).to_signed();
                cpu_state.condition_flag = in1 >= in2;
                None
            },

            // Move instructions
            Instr::Mov { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.registers[out.0 as usize] = in1;
                None
            },

            Instr::CMov { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                if cpu_state.condition_flag {
                    cpu_state.registers[out.0 as usize] = in1;
                }
                None
            },

            // Jump instructions
            Instr::Jmp { in1 } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.program_counter = in1;
                None
            },

            Instr::CJmp { in1 } => {
                if cpu_state.condition_flag {
                    let in1 = in1.value(&cpu_state.registers);
                    cpu_state.program_counter = in1;
                }
                None
            },

            Instr::CNJmp { in1 } => {
                if !cpu_state.condition_flag {
                    let in1 = in1.value(&cpu_state.registers);
                    cpu_state.program_counter = in1;
                }
                None
            },

            Instr::StoreW { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                let out = out.value(&cpu_state.registers);

                // Round the byte address down to the nearest word and dword boundary
                let word_addr: u64 = out.into() - (out.into() % (W::BYTELEN as u64));
                let dword_addr = word_addr - (word_addr % (2 * W::BYTELEN as u64));
                // Determine if this word is the low or high word in the dword
                let is_high = word_addr != dword_addr;

                // Fetch a dword's worth of bytes from memory, using 0 where undefined
                let mut bytes: Vec<u8> = (dword_addr..dword_addr + 2 * W::BYTELEN as u64)
                    .map(|i| *data_memory.0.get(&W::from_u64(i).unwrap()).unwrap_or(&0))
                    .collect();
                // Overwrite whatever is being stored. Overwrite the first word if `is_high = false`.
                // Otherwise overwrite the second.
                let start = is_high as usize * W::BYTELEN;
                bytes[start..start + W::BYTELEN].copy_from_slice(&in1.to_le_bytes());

                // Now convert the little-endian encoded bytes into words
                let w0 = W::from_le_bytes(&bytes[..W::BYTELEN]).unwrap();
                let w1 = W::from_le_bytes(&bytes[W::BYTELEN..]).unwrap();

                // Update the memory
                for (i, b) in (dword_addr..dword_addr + 2 * W::BYTELEN as u64).zip(bytes.iter()) {
                    data_memory.0.insert(W::from_u64(i).unwrap(), *b);
                }

                // Construct the memory operation
                let mem_op = MemOp::Store {
                    val: (w0, w1),
                    location: out.align_to_dword(),
                };

                Some(mem_op)
            },

            Instr::LoadW { out, in1 } => {
                let in1 = in1.value(&cpu_state.registers);

                // Round the byte address down to the nearest word and dword boundary
                let word_addr: u64 = in1.into() - (in1.into() % (W::BYTELEN as u64));
                let dword_addr = word_addr - (word_addr % (2 * W::BYTELEN as u64));
                // Determine if this word is the low or high word in the dword
                let is_high = word_addr != dword_addr;

                // Fetch a dword's worth of bytes from memory, using 0 where undefined
                let bytes: Vec<u8> = (dword_addr..dword_addr + 2 * W::BYTELEN as u64)
                    .map(|i| *data_memory.0.get(&W::from_u64(i).unwrap()).unwrap_or(&0))
                    .collect();
                // Convert the little-endian encoded bytes into words
                let w0 = W::from_le_bytes(&bytes[..W::BYTELEN]).unwrap();
                let w1 = W::from_le_bytes(&bytes[W::BYTELEN..]).unwrap();
                // Construct the memory operation
                let mem_op = MemOp::Load {
                    val: (w0, w1),
                    location: in1.align_to_dword(),
                };
                // Set set the register to the first part of the dword if `is_high == false`.
                // Otherwise use the second word.
                cpu_state.registers[out.0 as usize] = if is_high { w1 } else { w0 };
                Some(mem_op)
            },

            Instr::Read { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                // Read an element from the given tape and increment the head. out_of_bounds is set
                // if the tape head has already exceeded the length of the tape, or if the tape
                // doesn't exist (i.e., the tape index is > 1).
                let (location, out_of_bounds, val) = match in1.into() {
                    0u64 => cpu_state.primary_input.pop(),
                    1u64 => cpu_state.aux_input.pop(),
                    _ => (0, true, W::ZERO),
                };

                // Set the register to the value. Set the condition flag to the out_of_bounds
                // condition described above.
                cpu_state.registers[out.0 as usize] = val;
                cpu_state.condition_flag = out_of_bounds;

                // We don't count reading from an invalid tape as a memory operation
                let mem_op = match in1.into() {
                    0u64 => Some(MemOp::ReadPrimary { val, location }),
                    1u64 => Some(MemOp::ReadAux { val, location }),
                    _ => None,
                };

                mem_op
            },

            Instr::Answer { in1 } => {
                let in1 = in1.value(&cpu_state.registers);
                cpu_state.answer = Some(in1);
                None
            },

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
    primary_input: &[W],
    aux_input: &[W],
) -> (W, Vec<TranscriptEntry<W>>) {
    let mut transcript = Vec::new();
    let mut cpu_state = CpuState::<NUM_REGS, W>::default();

    // Set the tapes
    cpu_state.primary_input = Tape::new(primary_input);
    cpu_state.aux_input = Tape::new(aux_input);

    // Initialize the program or data memory, depending on the arch
    let (mut data_memory, mut program_memory) = match arch {
        TinyRamArch::Harvard => {
            // For Harvard we just wrap the given instructions and that's it

            // Make sure the program is word-addressable
            assert!(program.len() < (1 << W::BITLEN));

            // Return the memory
            (DataMemory::<W>::default(), ProgramMemory(program.to_vec()))
        },
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
                .flat_map(Instr::to_bytes::<NUM_REGS>)
                .enumerate()
                .map(|(i, b)| (W::from_u64(i as u64).unwrap(), b))
                .collect();

            // Return the memory
            (
                DataMemory(serialized_program),
                ProgramMemory::<W>::default(),
            )
        },
    };

    // Run the CPU until it outputs an answer
    let mut timestamp = 0;
    while cpu_state.answer.is_none() {
        // Get the PC and decode the instruction there
        let (pc, instr) = match arch {
            TinyRamArch::Harvard => {
                let pc = cpu_state.program_counter;
                let pc_usize =
                    usize::try_from(pc.into()).expect("program counter exceeds usize::MAX");
                let instr = *program_memory
                    .0
                    .get(pc_usize)
                    .unwrap_or_else(|| panic!("illegal jump to 0x{:08x}", pc_usize));

                (pc, instr)
            },
            TinyRamArch::VonNeumann => {
                // Collect 2 words of bytes starting at pc. 16 is the upper bound on the number of
                // bytes
                let pc = cpu_state.program_counter.into();
                let encoded_instr: Vec<u8> = (pc..pc + W::INSTR_BYTELEN as u64)
                    .map(|i| {
                        // TODO: Check that `i` didn't overflow W::MAX
                        *data_memory
                            .0
                            .get(&W::from_u64(i).unwrap())
                            .unwrap_or_else(|| panic!("illegal jump to 0x{:08x}", pc))
                    })
                    .collect();

                let instr = Instr::<W>::from_bytes::<NUM_REGS>(&encoded_instr);
                let (new_pc, overflow) = W::carrying_add(
                    cpu_state.program_counter,
                    W::from_u64(W::INSTR_BYTELEN as u64).unwrap(),
                );
                assert!(!overflow, "pc has reached end of memory");

                (new_pc, instr)
            },
        };

        // Run the CPU
        let (new_cpu_state, mem_op) =
            instr.execute_and_update_pc(arch, cpu_state, &mut data_memory, &mut program_memory);

        // Register the instruction load. For transcript purposes, make sure the load is
        // word-aligned.
        let pc_load = MemOp::Load {
            val: instr.to_dword::<NUM_REGS>(),
            location: pc.align_to_dword(),
        };

        // Update the CPU state and save the transcript entry
        cpu_state = new_cpu_state;
        transcript.push(TranscriptEntry {
            timestamp,
            instr,
            instr_load: pc_load,
            mem_op,
        });

        timestamp += 1;
    }

    (cpu_state.answer.unwrap(), transcript)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parser::assemble;

    type W = u32;
    const NUM_REGS: usize = 8;

    // Helper function for running TinyRAM code to completion
    fn run_code(code: &str, primary_input: &[W], aux_input: &[W]) -> W {
        // Headers for the two architectures. We're gonna run the code twice, once in Harvard arch
        // and once in Von Neumann. The outputs should agree. This is fine because we don't test
        // arch-dependent code yet.
        let hv_header = "; TinyRAM V=2.000 M=hv W=32 K=8\n";
        let vn_header = "; TinyRAM V=2.000 M=vn W=32 K=8\n";

        let mut hv_output = W::ZERO;
        let mut vn_output = W::ZERO;

        // Assemble the program under both architectures
        for (arch, header, out) in [
            (TinyRamArch::Harvard, hv_header, &mut hv_output),
            (TinyRamArch::VonNeumann, vn_header, &mut vn_output),
        ] {
            let program = [header, code].concat();
            let assembly = assemble(&program);
            let (prog_out, _trace) =
                run_program::<W, NUM_REGS>(arch, &assembly, primary_input, aux_input);

            // Save the output
            *out = prog_out
        }

        // Outputs should be the same across both arches
        assert_eq!(hv_output, vn_output);

        hv_output
    }

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
        let true_answer = acc;

        // Here's the assembly code of the above program
        //     reg0 -> i
        //     reg1 -> acc
        //     reg2 -> mul3_ctr
        // We also store and load registers from memory every loop
        let skip3_code = "\
        _loop: load.w r1, 600     ; acc <- RAM[600]
               load.w r0, 604     ; i <- RAM[604]
               add  r0, r0, 1     ; incr i
               add  r2, r2, 1     ; incr mul3_ctr
               cmpe r0, 100       ; if i == 100:
               cjmp _end          ;     jump to end
               cmpe r2, 3         ; else if mul3_ctr == 3:
               cjmp _acc          ;     jump to acc
                                  ; else
               store.w 604, r0    ;     i -> RAM[604]
               jmp  _loop         ;     jump to beginning

         _acc: add r1, r1, r0     ; Accumulate i into acc
               xor r2, r2, r2     ; Clear mul3_ctr
               store.w 600, r1    ; acc -> RAM[600]
               store.w 604, r0    ; i -> RAM[604]
               jmp _loop          ; Jump back to the loop

         _end: answer r1          ; Return acc
        ";

        // Run with no tapes
        let output = run_code(skip3_code, &[], &[]);
        assert_eq!(output, true_answer as u32);
    }

    // Sums values from primary and auxiliary tape
    #[test]
    fn sum_tape() {
        // Sum [1, n] from primary tape, and sum 100*[1, n] from auxiliary tape. Then output the
        // sum of those sums.

        let n = 10;
        let primary_tape = (1..=n)
            .map(W::from_u64)
            .collect::<Result<Vec<W>, _>>()
            .unwrap();
        let aux_tape = (1..=n)
            .map(|x| W::from_u64(100 * x))
            .collect::<Result<Vec<W>, _>>()
            .unwrap();

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

        let output = run_code(code, &primary_tape, &aux_tape);
        let primary_sum = n * (n + 1) / 2;
        assert_eq!(output, (primary_sum + 100 * primary_sum) as u32);
    }
}
