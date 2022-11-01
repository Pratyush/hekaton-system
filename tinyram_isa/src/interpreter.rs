use std::collections::HashMap;
use crate::{constants::{NUM_REGS, MC_BITLEN, WORD_BITLEN}, Mc, RamIdx, RegIdx, Word};
use bitfield::BitRange;

/// The set of all `NUM_REGS` many registers
type Registers = Vec<Word>;

/// RAM is a sparse array
type Ram = HashMap<RamIdx, Word>;

/// An element of the CPU's execution trace
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum MachineStateTransition {
    FlagSet(bool),
    RamSet(RamIdx, Word),
    RegSet(RegIdx, Word),
    PcSet(RamIdx),
    Answer(Word),
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
        match *t{
            MachineStateTransition::FlagSet(flag) => {
                self.flag = flag;
                self.inc_pc();
            },
            MachineStateTransition::RamSet(RamIdx, Word) => {
                self.ram.insert(RamIdx,Word);
                self.inc_pc();
            },
            MachineStateTransition::RegSet(RegIdx, Word) => {
                self.regs[RegIdx as usize]=Word;
                self.inc_pc();
            },
            MachineStateTransition::PcSet(RamIdx) => {
                self.pc = *self.ram.get(&RamIdx).unwrap() as RamIdx;
            },
            MachineStateTransition::Answer(Word) => (),
        }
    }

    fn inc_pc(&mut self) {
        self.pc = self.pc + (MC_BITLEN as RamIdx)/(WORD_BITLEN as RamIdx);
    }

    /// Creates a state where the `pc` is 0, `regs` are 0, and `ram` is initialized with the given
    /// program. Each multi-word machine code instruction is written in big-endian order to the
    /// beginning of the RAM.
    fn new(program: &[Mc]) -> Self {
        let mut ram:HashMap<RamIdx, Word> = HashMap::new();
        let mut ramIdx:RamIdx = 0;
        let words_per_mc:RamIdx = (MC_BITLEN as RamIdx)/(WORD_BITLEN as RamIdx);

        // Places machine code into RAM, splitting the machine code into words
        for mc in program.iter() {
            for i in 0..words_per_mc {
                let word = mc.bit_range(i as usize*MC_BITLEN,i as usize*(MC_BITLEN+1)-1);
                ram.insert(ramIdx, word);
                ramIdx=ramIdx+1;
            }
        }

        return MachineState{pc: 0, flag: false, regs: vec![0, NUM_REGS], ram};
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::instruction_set::{ImmediateOrReg, Op};

    // Test program that sums every multiple of 3 from 1 to 100. The output should be 1683.
    #[test]
    fn sum_skip3() {
        // A simple Rust program we will translate to TinyRAM assembly
        //        i is our index that ranges from 0 to 100
        //      acc is our accumulated sum
        // mul3_ctr is our mul-of-three counter
        let mut i = 0;
        let mut mul3_ctr = 0;
        let mut acc = 0;
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

        // Here's the assembly code of the above program
        //     reg0 -> i
        //     reg1 -> acc
        //     reg2 -> mul3_ctr
        //
        // addr          code
        // ----  ------------------------
        // 0x00  loop: add  reg0 reg0 1    ; incr i
        // 0x01        add  reg2 reg2 1    ; incr mul3_ctr
        // 0x02        cmpe reg0 100       ; if i == 100:
        // 0x03        cjmp end            ;     jump to end
        // 0x04        cmpe reg2 3         ; else if mul3_ctr == 3:
        // 0x05        cjmp acc            ;     jump to acc
        // 0x06        jmp  loop           ; else jump to beginning
        //
        // 0x07   acc: add reg1 reg1 reg0  ; Accumulate i into acc
        // 0x08        xor reg2 reg2 reg2  ; Clear mul3_ctr
        // 0x09        jmp loop            ; Jump back to the loop
        //
        // 0x0a   end: answer reg1         ; Return acc

        let assembly = [
            Op::Add {
                dest: 0,
                src1: 0,
                src2: ImmediateOrReg::Immediate(1),
            },
            Op::Add {
                dest: 2,
                src1: 2,
                src2: ImmediateOrReg::Immediate(1),
            },
            Op::Cmpe {
                src1: 0,
                src2: ImmediateOrReg::Immediate(100),
            },
            Op::Cjmp {
                target: ImmediateOrReg::Immediate(0x0a),
            },
            Op::Cmpe {
                src1: 2,
                src2: ImmediateOrReg::Immediate(3),
            },
            Op::Cjmp {
                target: ImmediateOrReg::Immediate(0x07),
            },
            Op::Jmp {
                target: ImmediateOrReg::Immediate(0x00),
            },
            Op::Add {
                dest: 1,
                src1: 1,
                src2: ImmediateOrReg::Reg(0),
            },
            Op::Xor {
                dest: 2,
                src1: 2,
                src2: ImmediateOrReg::Reg(2),
            },
            Op::Jmp {
                target: ImmediateOrReg::Immediate(0x00),
            },
            Op::Answer {
                src: ImmediateOrReg::Reg(1),
            },
        ];

        let machine_code: Vec<Mc> = assembly.iter().map(|op| op.to_mc()).collect();
        let transcript = run_program(&machine_code);
        let output = transcript[transcript.len() - 1];

        assert_eq!(output, MachineStateTransition::Answer(acc));
    }
}
