use crate::{tape::TapeHeads, word::Word, TinyRam, TinyRamArch};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuState<T: TinyRam> {
    /// Condition flag that is set as a result of instruction exection.
    pub(super) condition_flag: bool,
    /// Program counter.
    pub(super) program_counter: T::Word,
    /// Register file.
    pub(super) registers: Box<[T::Word]>,
    /// Final result of the execution. Determined by the `answer` instruction
    pub(super) answer: Option<T::Word>,
    /// Tape heads
    pub(super) tape_heads: TapeHeads<T::Word>,
}

impl<T: TinyRam> CpuState<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, reg: usize) -> T::Word {
        self.registers[reg]
    }

    pub fn register_mut(&mut self, reg: usize) -> &mut T::Word {
        &mut self.registers[reg]
    }

    pub fn registers(&self) -> &[T::Word] {
        &self.registers
    }

    pub fn program_counter(&self) -> T::Word {
        self.program_counter
    }

    pub fn increment_pc(&mut self) {
        // The amount we increment the program counter depends on the architecture:
        // * For Harvard, it's 1 (since program memory holds double_words).
        // * For VonNeumann it's 2 * bytelength of a word (since data memory holds bytes).
        let increment_amount = match T::ARCH {
            TinyRamArch::Harvard => T::Word::ONE,
            TinyRamArch::VonNeumann => T::Word::from_u64(T::SERIALIZED_INSTR_BYTE_LENGTH as u64),
        };

        self.program_counter = self
            .program_counter
            .checked_add(increment_amount)
            .expect("Program counter overflowed");
    }
}

impl<T: TinyRam> Default for CpuState<T> {
    fn default() -> Self {
        CpuState {
            condition_flag: false,
            program_counter: T::Word::ZERO,
            registers: vec![T::Word::ZERO; T::NUM_REGS as usize].into_boxed_slice(),
            answer: None,
            tape_heads: TapeHeads::default(),
        }
    }
}
