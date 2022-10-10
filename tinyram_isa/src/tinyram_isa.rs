/*
 *  Assembles the TinyRAM ISA into Machine Language
 */
pub mod assembler {
    const NUM_REGS:u32 = 64;

    type Word = u32;
    type RegIdx = Word;
    type RamIdx = Word;

    pub enum Op{
        Add{src1: RegIdx, src2: RegIdx, dest: RegIdx},  // *dest = *src1 + *src2
        Nor{src1: RegIdx, src2: RegIdx, dest: RegIdx},  // *dest = ~(*src1, *src2)
        Lw{dest: RegIdx, base: RegIdx, offset: Word},   // *dest = RAM[*base+offset]   
        Sw{dest: RegIdx, base: RegIdx, offset: Word},   // RAM[*base+offset] = *src
        Beq{reg1: RegIdx, reg2: RegIdx, target: RamIdx},// if *reg1 == *reg2 
                                                        // set pc = *target
        Jalr{target: RegIdx, savepoint: RegIdx},        // Set *savepoint to pc+1,
                                                        // jump to *target
        Halt,                                           // stop all operations
        Noop,                                           // do nothing
    }

    // For a vec of assembly operations, transforms into machine code
    pub fn assembly_to_mc(assembly_program:Vec<Op>) -> Vec<u64>{
        return assembly_program.iter().map(Op::mc).collect();
    }

    impl Op {
        // Converts our operation to machine code
        pub fn mc(&self) -> u64{
            /*  
             *  The machine code of an assembly command is encoded as follows.
             *  | unused space | op | var1 | var2 | var3 |
             *
             *  op is 4 bits long while var1, var2, and var3 are ceil(lg(NUM_REGS))
             *  long.
             */
            return match *self{
                Op::Add{src1, src2, dest} => Op::encode_bits(0, src1, src2, dest),
                Op::Nor{src1, src2, dest} => Op::encode_bits(1, src1, src2, dest),
                Op::Lw{dest, base, offset} => Op::encode_bits(2, dest, base, offset),
                Op::Sw{dest, base, offset} => Op::encode_bits(3, dest, base, offset),
                Op::Beq{reg1, reg2, target} => Op::encode_bits(4, reg1, reg2, target),
                Op::Jalr{target, savepoint} => Op::encode_bits(5, target, savepoint, 0),
                Op::Halt => Op::encode_bits(6, 0, 0, 0),
                Op::Noop => Op::encode_bits(7, 0, 0, 0),
            };
        }

        // Returns information bitwise compressed together 
        fn encode_bits(op:u32, var1:u32, var2:u32, var3:u32) -> u64{
            let num_regs_dec:f64 = NUM_REGS as f64;
            let bits_for_reg:u32 = num_regs_dec.log2().ceil() as u32;
            let mut machine_code:u64 = op as u64*(2_u64.pow(bits_for_reg*3));
            machine_code += var3 as u64*2_u64.pow(bits_for_reg*2);
            machine_code += var2 as u64*2_u64.pow(bits_for_reg);
            machine_code += var1 as u64;
            return machine_code;
        }
    }
}
