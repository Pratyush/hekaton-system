use crate::{
    instructions::Instr,
    memory::{DataMemory, ProgramMemory},
    program_state::{CpuState, TapePos},
    word::{DoubleWord, Word},
    TinyRamArch,
};

use std::collections::BTreeMap;

use ark_ff::Field;
use rand::Rng;

/// A TinyRAM memory operation. This only deals in double words.
///
/// NOTE: A `read` op from an invalid tape index (2 or greater) is converted to an `xor ri ri`,
/// i.e., it is not considered a memory operation.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub enum MemOp<W: Word> {
    /// Load a double word from RAM
    Load {
        /// The double word being loaded
        val: DoubleWord<W>,
        /// The index the value is being loaded from
        location: W,
    },
    /// Store a double word to RAM
    Store {
        /// The double word being stored
        val: DoubleWord<W>,
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
    #[default]
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

    /// Gets the double word being loaded or stored. If it's a valid tape op, then returns the word
    /// being read in the low position, and 0 in the high position. If it's an invalid tape op,
    /// then returns (0, 0)
    pub fn val(&self) -> DoubleWord<W> {
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
    pub fn as_fp<F: Field>(&self) -> (F, usize) {
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

        // val is a double word, so pack each of its words separately
        out += pow_two::<F>(bitlen) * F::from(val.0.into());
        bitlen += W::BIT_LENGTH;
        out += pow_two::<F>(bitlen) * F::from(val.1.into());
        bitlen += W::BIT_LENGTH;

        (out, bitlen)
    }
}

#[derive(Clone, Debug)]
pub struct TranscriptEntry<const NUM_REGS: usize, W: Word> {
    /// The timestamp of this entry. This MUST be greater than 0
    pub timestamp: u64,
    /// The instruction being executed
    pub instr: Instr<W>,
    /// The memory operation corresponding to the instruction load
    pub instr_load: MemOp<W>,
    /// The optional memory operation corresponding to this instruction's execution
    pub mem_op: Option<MemOp<W>>,
    /// The state of the CPU after this instruction was computed
    pub cpu_after: CpuState<NUM_REGS, W>,
}

/// Contains the RAM, ROM, and tapes necessary to run a program
#[derive(Default)]
pub struct MemoryUnit<W: Word> {
    data_ram: DataMemory<W>,
    program_rom: ProgramMemory<W>,
    primary_tape: Vec<W>,
    aux_tape: Vec<W>,
}

impl<W: Word> Instr<W> {
    /// Executes the given instruction, and updates the program counter accordingly.
    pub fn execute_and_update_pc<const NUM_REGS: usize>(
        &self,
        arch: TinyRamArch,
        mut cpu_state: CpuState<NUM_REGS, W>,
        mem: &mut MemoryUnit<W>,
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

                // Round the byte address down to the nearest word and double word boundary
                let word_addr: u64 = out.into() - (out.into() % (W::BYTE_LENGTH as u64));
                let double_word_addr = word_addr - (word_addr % (2 * W::BYTE_LENGTH as u64));

                // Fetch a double word's worth of bytes from memory, using 0 where undefined
                let index_range = double_word_addr..(double_word_addr + 2 * W::BYTE_LENGTH as u64);
                let mut bytes: Vec<u8> = index_range
                    .clone()
                    .map(|i| *mem.data_ram.get(W::from_u64(i)).unwrap_or(&0))
                    .collect();

                // Determine if this word is the low or high word in the double word
                let is_high = word_addr != double_word_addr;
                // Overwrite whatever is being stored.
                // Overwrite the first word if `is_high = false`; else, overwrite the second.
                let start = (is_high as usize) * W::BYTE_LENGTH;
                bytes[start..][..W::BYTE_LENGTH].copy_from_slice(&in1.to_le_bytes());

                // Update the memory
                for (i, b) in index_range.zip(&bytes).map(|(i, b)| (W::from_u64(i), *b)) {
                    mem.data_ram.insert(i, b);
                }

                // Now convert the little-endian encoded bytes into words
                let w0 = W::from_le_bytes(&bytes[..W::BYTE_LENGTH]).unwrap();
                let w1 = W::from_le_bytes(&bytes[W::BYTE_LENGTH..]).unwrap();

                // Construct the memory operation
                let mem_op = MemOp::Store {
                    val: (w0, w1),
                    location: out.align_to_double_word(),
                };

                Some(mem_op)
            },

            Instr::LoadW { out, in1 } => {
                let in1 = in1.value(&cpu_state.registers);

                // Round the byte address down to the nearest word and double word boundary
                let word_addr: u64 = in1.into() - (in1.into() % (W::BYTE_LENGTH as u64));
                let double_word_addr = word_addr - (word_addr % (2 * W::BYTE_LENGTH as u64));

                // Fetch a double word's worth of bytes from memory, using 0 where undefined
                let index_range = double_word_addr..(double_word_addr + 2 * W::BYTE_LENGTH as u64);
                let bytes: Vec<u8> = index_range
                    .clone()
                    .map(|i| *mem.data_ram.get(W::from_u64(i)).unwrap_or(&0))
                    .collect();

                // Convert the little-endian encoded bytes into words
                let w0 = W::from_le_bytes(&bytes[..W::BYTE_LENGTH]).unwrap();
                let w1 = W::from_le_bytes(&bytes[W::BYTE_LENGTH..]).unwrap();
                // Construct the memory operation
                let mem_op = MemOp::Load {
                    val: (w0, w1),
                    location: in1.align_to_double_word(),
                };
                // Set set the register to the first part of the double word if `is_high == false`.
                // Otherwise use the second word.
                let is_high = word_addr != double_word_addr;
                cpu_state.registers[out.0 as usize] = if is_high { w1 } else { w0 };
                Some(mem_op)
            },

            Instr::Read { in1, out } => {
                let in1 = in1.value(&cpu_state.registers);
                // Read an element from the given tape and increment the head. The value is None if
                // the tape head is out of bounds or if the tape doesn't exist (ie if the tape
                // index is > 1)
                let (location, val_opt) = match in1.into() {
                    0 => {
                        let loc = cpu_state.primary_tape_pos;
                        let val = mem.primary_tape.get(loc as usize).cloned();
                        cpu_state.primary_tape_pos += 1;

                        (loc, val)
                    },
                    1 => {
                        let loc = cpu_state.aux_tape_pos;
                        let val = mem.aux_tape.get(loc as usize).cloned();
                        cpu_state.aux_tape_pos += 1;

                        (loc, val)
                    },

                    _ => (0, None),
                };

                // Set the register to the value. If it is None, set it to 0 and set the condition
                // flag to true
                let val = val_opt.unwrap_or(W::ZERO);
                cpu_state.registers[out.0 as usize] = val;
                cpu_state.condition_flag = val_opt.is_none();

                // TODO: The tape index could be a variable. We need to treat every read op as a
                // potential memory operation for consistency in ZK.
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

        if !self.is_jump() {
            // The amount we increment the program counter depends on the architecture. In Harvard,
            // it's 1 (since program memory holds double_words). In VonNeumann it's
            // 2 * bytelength of a word (since data memory holds bytes).
            let inc_amount = match arch {
                TinyRamArch::Harvard => W::ONE,
                TinyRamArch::VonNeumann => W::from_u64(2 * (W::BIT_LENGTH as u64) / 8),
            };

            // Try to increment the program counter
            cpu_state.program_counter = cpu_state
                .program_counter
                .checked_add(inc_amount)
                // If the program counter went out of bounds, panic
                .expect("program counter overflow");
        }
        (cpu_state, mem_op)
    }
}

/// Runs the given TinyRAM program and returns its output and a time-ordered transcript of all the
/// memory operations
pub fn run_program<W: Word, const NUM_REGS: usize>(
    arch: TinyRamArch,
    program: &[Instr<W>],
    primary_input: Vec<W>,
    aux_input: Vec<W>,
) -> (W, Vec<TranscriptEntry<NUM_REGS, W>>) {
    let mut transcript = Vec::new();
    let mut cpu_state = CpuState::<NUM_REGS, W>::default();

    // Initialize the program or data memory, depending on the arch
    let (data_ram, program_rom) = match arch {
        TinyRamArch::Harvard => {
            // For Harvard we just wrap the given instructions and that's it

            // Make sure the program is word-addressable
            assert!(program.len() < (1 << W::BIT_LENGTH));

            // Return the memory
            (DataMemory::<W>::default(), ProgramMemory(program.to_vec()))
        },
        TinyRamArch::VonNeumann => {
            // For von Neumann we're gonna have to serialize the whole program into data memory

            // Every instruction is 2 words
            let serialized_program_bytelen = program.len() * 2 * (W::BIT_LENGTH as usize / 8);
            // Make sure the program is word-addressable
            assert!(serialized_program_bytelen < (1 << W::BIT_LENGTH));

            // The memory is initialized with just the program, starting at address 0. Memory is a
            // sparse map of addr -> byte
            let serialized_program: BTreeMap<W, u8> = program
                .iter()
                .flat_map(Instr::to_bytes::<NUM_REGS>)
                .enumerate()
                .map(|(i, b)| (W::from_u64(i as u64), b))
                .collect();

            // Return the memory
            (
                DataMemory::new(serialized_program),
                ProgramMemory::<W>::default(),
            )
        },
    };
    // Set RAM, ROM, and tapes
    let mut mem = MemoryUnit {
        data_ram,
        program_rom,
        primary_tape: primary_input.to_vec(),
        aux_tape: aux_input.to_vec(),
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
                let instr = *mem
                    .program_rom
                    .0
                    .get(pc_usize)
                    .unwrap_or_else(|| panic!("illegal jump to 0x{:08x}", pc_usize));

                (pc, instr)
            },
            TinyRamArch::VonNeumann => {
                // Collect 2 words of bytes starting at pc. 16 is the upper bound on the number of
                // bytes
                let pc = cpu_state.program_counter;
                let pc_u64 = pc.into();
                let encoded_instr: Vec<u8> = (pc_u64..)
                    .take(W::INSTR_BYTE_LENGTH)
                    .map(W::from_u64)
                    .map(|w| {
                        // TODO: Check that `i` didn't overflow W::MAX
                        *mem.data_ram
                            .get(w)
                            .unwrap_or_else(|| panic!("illegal jump to 0x{:08x}", pc_u64))
                    })
                    .collect();

                let instr = Instr::<W>::from_bytes::<NUM_REGS>(&encoded_instr);
                (pc, instr)
            },
        };

        // Run the CPU
        let (new_cpu_state, mem_op) = instr.execute_and_update_pc(arch, cpu_state, &mut mem);

        // Register the instruction load. For transcript purposes, make sure the load is
        // word-aligned.
        let pc_load = MemOp::Load {
            val: instr.to_double_word::<NUM_REGS>(),
            location: pc.align_to_double_word(),
        };

        // Update the CPU state and save the transcript entry
        cpu_state = new_cpu_state.clone();
        transcript.push(TranscriptEntry {
            timestamp,
            instr,
            instr_load: pc_load,
            mem_op,
            cpu_after: new_cpu_state,
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
            let (prog_out, _trace) = run_program::<W, NUM_REGS>(
                arch,
                &assembly,
                primary_input.to_vec(),
                aux_input.to_vec(),
            );

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
        let primary_tape = (1..=n).map(W::from_u64).collect::<Vec<W>>();
        let aux_tape = (1..=n).map(|x| W::from_u64(100 * x)).collect::<Vec<W>>();

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
