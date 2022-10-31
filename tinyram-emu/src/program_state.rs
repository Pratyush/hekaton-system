use crate::word::Word;

pub struct CPUState<const NUM_REGS: usize, W: Word> {	
    /// Condition flag that is set as a result of instruction exection. 
    pub condition_flag: bool,
    /// Program counter.
    pub program_counter: W,
    /// Register file.
    pub registers: [W; NUM_REGS],
    pub primary_input: Vec<W>,
    pub aux_input: Vec<W>,
    pub accept: bool,
}