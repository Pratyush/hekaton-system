// Type overview:
//     ark_r1cs_std::bits::UInt32<F> is the "zk" representation of a u32
//     FpVar<F> is the "zk" representation of a field element

type Word<F> = UInt32<F>;
type Registers<F> = Vec<Word<F>>;
type EncodedInstruction<F> = FpVar<F>; // ~255 bits

type RegIdx<F> = FpVar<F>;
type RamIdx<F> = Word<F>;
type Pc<F> = RamIdx<F>

// Instructions:

// Let *dest = *src1 + *src2
struct InstrAdd {
    src1: RegIdx<F>,
    src2: RegIdx<F>,
    dest: RegIdx<F>,
}

// Let *dest = ~(*src1 | *src2)
struct InstrNor {
    src1: RegIdx<F>,
    src2: RegIdx<F>,
    dest: RegIdx<F>,
}

// Let *dest = RAM[*base + offset]
struct InstrLw {
    dest: RegIdx<F>,
    base: RegIdx<F>,
    offset: Word<F>,
}

// Let RAM[*base + offset] = *src
struct InstrSw {
    src: RegIdx<F>,
    base: RegIdx<F>,
    offset: Word<F>,
}

// Let pc = *target iff *reg1 == *reg2
struct InstrBeq {
    reg1: RegIdx<F>,
    reg2: RegIdx<F>,
    target: RamIdx<F>,
}

// Set *savepoint to pc+1 and jump to *target
struct InstrJalr {
    target: RegIdx<F>,
    savepoint: RegIdx<F>,
}

// Do nothing
struct InstrNoop;

// Halt computation
struct InstrHalt;

// Represents the decoded instruction and register information used to LOAD or
// STORE in a small tick. `Load` doesn't carry the thing loaded because that has
// to come from outside the CPU, from the memory.
enum SmallTickMemData<F: Field> {
    Load(RamIdx<F>),
    Store(RamIdx<F>, Word<F>),
    NoMemOp,
}

// Computes a CPU tick. Every tick can do any op, including LOAD and a STORE.
// The returned index `i` is a function of `instr`. `loaded_val` represents the
// value at the `i`, if this instruction is a LOAD. If this instruction is not a
// LOAD, the value is ignored.
//
// Returns `(new_regs, new_pc, mem_data)`, where `new_regs` is the new set of
// registers, `new_pc` is the updated program counter, and `mem_data` contains
// the decoded instruction and associated register values regarding any LOADs or
// STOREs that happened in this tick.
fn smalltick<F: Field>(
    pc: Pc<F>,
    instr: EncodedInstruction<F>,
    regs: Registers<F>,
    loaded_val: Word<F>,
) -> (Registers<F>, Pc<F>, SmallTickMemData<F>);

// TODO:
//   * Take a look at arkworks tutorials to see how ZK vars work
//   * Decide on instruction encoding scheme
//     * A RegIdx should be encoded with LOG2_NUMREGS bits
//     * A RamIdx should be encoded with LOG2_RAMSIZE bits
//     * Store things in the low bits
//   * Write the decoding procedure
//   * Implement ADD and BEQ

// High-level structure of smalltick
//   * Parse instr as an ADD. Do the add. Save to results[0]
//   * Parse instr as a BEQ. Do the beq. Save to results[1]
//   * ...
//   * let i be the instruction opcode (ADD=0, BEQ=1, ...)
//   * Return results[i] (using a mux)

// Implementation notes:
//   * Need to make sure results is "arithmetic", i.e., that it has an encoding
//     that can be multiplied by field elements, and added together. Concretely,
//     results needs to be a Vec<T> where T is a CondSelectGadget:
//     https://github.com/arkworks-rs/r1cs-std/blob/master/src/select.rs#L6
//   * In decoding, must convert Vec<Boolean<F>> into Word<F>, RegIdx<F>,
//     RamIdx<F>, etc.
//   * Optimization: if there are instructions with the same encoding (e.g., ADD
//     & NOR, or LW & SW & BEQ) then you can reuse the decodings

// Questions:
//   * Do we use offsets for jumps, or absolute addresses? Offsets probably
//     saves space, but absolute is easier to think about.
