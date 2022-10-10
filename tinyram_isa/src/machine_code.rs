use crate::instruction_set::{Op, NUM_REGS};

// Define a canonical opcode for each operation
impl From<&Op> for u32 {
    fn from(op: &Op) -> u32 {
        match op {
            Op::Add { .. } => 0,
            Op::Nor { .. } => 1,
            Op::Lw { .. } => 2,
            Op::Sw { .. } => 3,
            Op::Beq { .. } => 4,
            Op::Jalr { .. } => 5,
            Op::Halt { .. } => 6,
            Op::NoOp { .. } => 7,
        }
    }
}

impl Op {
    /// Converts our operation to machine code
    pub fn machine_code(&self) -> u64 {
        /*
         *  The machine code of an assembly command is encoded as follows.
         *  | unused space | op | var1 | var2 | var3 |
         *
         *  op is 4 bits long while var1, var2, and var3 are ceil(lg(NUM_REGS))
         *  long.
         */
        let opcode: u32 = self.into();
        return match *self {
            Op::Add { src1, src2, dest } => Op::encode_bits(opcode, src1, src2, dest),
            Op::Nor { src1, src2, dest } => Op::encode_bits(opcode, src1, src2, dest),
            Op::Lw { dest, base, offset } => Op::encode_bits(opcode, dest, base, offset),
            Op::Sw { dest, base, offset } => Op::encode_bits(opcode, dest, base, offset),
            Op::Beq { reg1, reg2, target } => Op::encode_bits(opcode, reg1, reg2, target),
            Op::Jalr { target, savepoint } => Op::encode_bits(opcode, target, savepoint, 0),
            Op::Halt => Op::encode_bits(opcode, 0, 0, 0),
            Op::NoOp => Op::encode_bits(opcode, 0, 0, 0),
        };
    }

    // Returns information bitwise compressed together
    fn encode_bits(op: u32, var1: u32, var2: u32, var3: u32) -> u64 {
        let num_regs_dec: f64 = NUM_REGS as f64;
        let bits_for_reg: u32 = num_regs_dec.log2().ceil() as u32;
        let mut machine_code: u64 = op as u64 * (2_u64.pow(bits_for_reg * 3));
        machine_code += var1 as u64 * 2_u64.pow(bits_for_reg * 2);
        machine_code += var2 as u64 * 2_u64.pow(bits_for_reg);
        machine_code += var3 as u64;
        return machine_code;
    }
}

// Tests the machine encoding of an LW instruction
#[test]
fn lw_encoding() {
    // Let reg 0 equal RAM[1 + 128]
    let instr = Op::Lw {
        dest: 0,
        base: 1,
        offset: 128,
    };

    // We expect this to be
    //     Lw    dest  base  offset
    //     0x02  0x00  0x01  0x80
    // with some 0-padding here and there
    let encoded_instr = instr.machine_code();

    // Let's check that the bottom 32 bits is 0x80
    let bottom_32 = u32::MAX as u64;
    assert_eq!(encoded_instr & bottom_32, 0x80);
}
