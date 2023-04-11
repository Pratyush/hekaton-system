use crate::word::Word;

pub(crate) type TapePos = u32;

#[derive(Default)]
pub struct Tape<W: Word> {
    pub vals: Vec<W>,
    pub pos: TapePos,
}

impl<W: Word> Tape<W> {
    /// Returns the current head index, whether the head index exceeds the length of the tape, and
    /// the tape value at that index (or 0 if out of bounds). Increments head index after
    /// calculating all this.
    pub(crate) fn pop(&mut self) -> (TapePos, bool, W) {
        let out_of_bounds = self.pos as usize >= self.vals.len();
        let val = *self.vals.get(self.pos as usize).unwrap_or(&W::ZERO);
        self.pos += 1;
        (self.pos, out_of_bounds, val)
    }
}

pub struct CpuState<const NUM_REGS: usize, W: Word> {
    /// Condition flag that is set as a result of instruction exection.
    pub condition_flag: bool,
    /// Program counter.
    pub program_counter: W,
    /// Register file.
    pub registers: [W; NUM_REGS],
    pub primary_input: Tape<W>,
    pub aux_input: Tape<W>,
    pub answer: Option<W>,
}

impl<const NUM_REGS: usize, W: Word> Default for CpuState<NUM_REGS, W> {
    fn default() -> Self {
        CpuState {
            condition_flag: false,
            program_counter: W::ZERO,
            registers: [W::ZERO; NUM_REGS],
            primary_input: Tape::default(),
            aux_input: Tape::default(),
            answer: None,
        }
    }
}
