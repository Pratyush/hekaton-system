use crate::word::Word;

pub struct CpuState<const NUM_REGS: usize, W: Word> {
    /// Condition flag that is set as a result of instruction exection.
    pub condition_flag: bool,
    /// Program counter.
    pub program_counter: W,
    /// Register file.
    pub registers: [W; NUM_REGS],
    pub primary_input: Vec<W>,
    pub aux_input: Vec<W>,
    pub answer: Option<W>,
}

impl<const NUM_REGS: usize, W: Word> Default for CpuState<NUM_REGS, W> {
    fn default() -> Self {
        let zero = W::try_from(0u64).map_err(|_| ()).unwrap();

        CpuState {
            condition_flag: false,
            program_counter: zero,
            registers: [zero; NUM_REGS],
            primary_input: Vec::new(),
            aux_input: Vec::new(),
            answer: None,
        }
    }
}
