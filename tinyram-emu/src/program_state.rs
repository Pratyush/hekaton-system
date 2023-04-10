use crate::word::Word;

use std::collections::VecDeque;

pub struct CpuState<const NUM_REGS: usize, W: Word> {
    /// Condition flag that is set as a result of instruction exection.
    pub condition_flag: bool,
    /// Program counter.
    pub program_counter: W,
    /// Register file.
    pub registers: [W; NUM_REGS],
    pub primary_input: VecDeque<W>,
    pub aux_input: VecDeque<W>,
    pub answer: Option<W>,
}

impl<const NUM_REGS: usize, W: Word> Default for CpuState<NUM_REGS, W> {
    fn default() -> Self {
        CpuState {
            condition_flag: false,
            program_counter: W::ZERO,
            registers: [W::ZERO; NUM_REGS],
            primary_input: VecDeque::new(),
            aux_input: VecDeque::new(),
            answer: None,
        }
    }
}
