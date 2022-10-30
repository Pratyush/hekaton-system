use std::collections::HashMap;

use crate::{constants::NUM_REGS, Mc, RamIdx, RegIdx, Word};

/// The set of all `NUM_REGS` many registers
type Registers = Vec<Word>;

/// RAM is a sparse array
type Ram = HashMap<Word, Word>;

/// The type of a CPU memory op. It's either a load or a store
enum MemOpKind {
    Load,
    Store,
}

/// An element of the CPU's execution trace
#[derive(Copy, Clone, Eq, PartialEq)]
enum MachineStateTransition {
    LoadRam(RamIdx),
    StoreRam(RamIdx, Word),
    StoreReg(RegIdx, Word),
    StorePc(RamIdx),
    Answer(RegIdx),
}

#[derive(Default)]
struct MachineState {
    // Program counter
    pc: RamIdx,
    // Flag that's set by the `cmp*` ops
    flag: bool,
    // All the registers
    regs: Registers,
    // All the memory (von Neumann architecture)
    ram: Ram,
}

impl MachineState {
    /// Applies the transition to the current state. If this isn't a
    /// `MachineStateTransition::StorePc`, then this will also increment `pc` by `MC_BITLEN /
    /// WORD_BITLEN` (e.g., by 2 when words are `u32` and instructions are `u64`)
    fn apply_transition(&mut self, t: &MachineStateTransition) {
        unimplemented!()
    }

    /// Creates a state where the `pc` is 0, `regs` are 0, and `ram` is initialized with the given
    /// program. Each two-word machine code instruction is written in big-endian order to the
    /// beginning of the RAM.
    fn new(program: &[Mc]) -> Self {
        unimplemented!()
    }
}

/// Executes the given instruction, updating the registers and RAM. Returns a memory trace item,
/// and a `bool` indicating whether we have reached a halt instruction
fn tick(
    MachineState {
        pc,
        flag,
        regs,
        ram,
    }: &MachineState,
) -> MachineStateTransition {
    unimplemented!()
}

/// Runs the given machine code until the program halts. Returns a trace of of every step of the
/// exectuion. The last step will be a `MachineStateTransition::Answer`.
fn run_program(program: &[Mc]) -> Vec<MachineStateTransition> {
    let mut state = MachineState::new(program);
    let mut trace = Vec::new();

    // Run until we see a `MachineStateTransition::Answer`
    loop {
        // Do a tick and then apply the operation
        let trace_item = tick(&state);
        state.apply_transition(&trace_item);

        // Save the operation
        trace.push(trace_item);

        // Check if we're done
        if let MachineStateTransition::Answer(..) = trace_item {
            return trace;
        }
    }
}
