use tinyram_isa::assembler;

fn main() {
    let op1 = assembler::Op::Add{src1:1, src2:2, dest:3};
    op1.mc();
}
