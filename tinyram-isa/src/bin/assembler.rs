// Assembles the TinyRAM ISA into Machine Language
use tinyram_isa::instruction_set::*;

// For a vec of assembly operations, transforms into machine code
pub fn assembly_to_mc(assembly_program: Vec<Op>) -> Vec<u64> {
    assembly_program.iter().map(Op::to_mc).collect()
}

fn main() {
    println!("This is the assembler binary!");

    let src1 = 1;
    let src2 = 2;
    let dest = 3;
    let op1 = Op::Add { src1, src2, dest };

    let mc = op1.to_mc();

    println!("reg {src1} + reg {src2} -> reg {dest} is represented as {mc:016x}");
}
