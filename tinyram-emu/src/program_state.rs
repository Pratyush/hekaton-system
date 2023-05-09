use crate::word::Word;

pub(crate) type TapePos = u32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuState<const NUM_REGS: usize, W: Word> {
    /// Condition flag that is set as a result of instruction exection.
    pub condition_flag: bool,
    /// Program counter.
    pub program_counter: W,
    /// Register file.
    pub registers: [W; NUM_REGS],
    /// Final result of the execution. Determined by the `answer` instruction
    pub answer: Option<W>,
    /// Position of the primary tape head
    pub primary_tape_pos: TapePos,
    /// Position of the auxiliary tape head
    pub aux_tape_pos: TapePos,
}

impl<const NUM_REGS: usize, W: Word> Default for CpuState<NUM_REGS, W> {
    fn default() -> Self {
        CpuState {
            condition_flag: false,
            program_counter: W::ZERO,
            registers: [W::ZERO; NUM_REGS],
            answer: None,
            primary_tape_pos: 0,
            aux_tape_pos: 0,
        }
    }
}
