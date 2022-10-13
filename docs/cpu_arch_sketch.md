## Traces

We need to keep track of several memory traces in our execution. We define them here for clarity.
This notation is used in the pseudocode and the diagram.

* `tr_init`: The unordered trace containing the initial memory state of our program. `tr_init` can
  be partitioned into:
    * `tr_init_accessed`: The unordered trace containing the memory values that are read (LOADed) at
      some point in the execution of the program.
    * `tr_init_nonaccessed`: The unordered trace containing the memory values that are never read in
      the execution of the program.
* `tr_exec`: The ordered trace of our program execution

# Pseudocode for the low-level circuits

```rust
// An index into RAM or ROM
type ram_idx = usize;
// Program counter
type Pc = usize;
type Instruction = Word;

/// An entry in the transcript of RAM accesses
enum TranscriptEntry {
    // If there are more ticks than memory accesses, we pad out the transcript
    Padding,

    // A real, non-padding entry
    Entry {
        // The timestamp of this entry
        t: usize,
        // LOAD or STORE
        op: enum { Load, Store },
        // Either the index being loaded from or stored to
        ram_idx: ram_idx,
        // The value being loaded or stored
        val: Word,
    },
}

/// This is the placeholder transcript entry that MUST begin the memory-ordered transcript. Indexing
/// for the real elements of the memory transcript start at t=1 and ramdix=1
const TRANSCRIPT_START = TranscriptEntry::Entry {
    t: 0,
    op: LOAD,
    ram_idx: 0,
    val: 0,
}

impl TranscriptEntry {
    /// Encodes this transcript entry as a field element for the purpose of hashing or
    /// representation as a coefficient in a polynomial
    fn to_ff(&self) -> FieldElem;

    /// Encodes this transcript entry as a field element for the purpose of hashing or
    /// representation as a coefficient in a polynomial. The `_notime` variant does not include the
    /// timestamp in the representation
    fn to_ff_notime(&self) -> FieldElem;
}

/// Represents the decoded instruction and register information used to LOAD or STORE in a small
/// tick. `Load` doesn't carry the thing loaded because that has to come from outside the CPU, from
/// the memory.
enum SmallTickMemData {
    Load(ram_idx),
    Store(ram_idx, Word),
    NoMemOp,
}

// Represents the running hash and polynomial evaluation of a transcript, i.e., `time_tr_hash =
// Hash(Hash(Hash(op1), op2), ...)` and `time_tr(X) = (X - op1)(X - op2) ...)` evaluated at some
// challenge point.
struct RunningEval {
    hash: Digest,
    polyn: FieldElem,
}

/// A committed eval is a polynomial who has been committed to and evaluated outside of the SNARK.
/// Its relevant values are its commitment (the `hash` field) and the eval `polyn`.
type CommittedEval = RunningEval;

impl RunningEval {
    /// A new RunningEval has to have a random hash initializer. This way the challenge point is
    /// hidden
    fn new(rng) -> RunningEval {
        RunningEval {
            hash: rng.gen(),
            polyn: FieldElem::ONE,
        }
    }

    /// Updates the running evals with the given field element
    fn update(&mut self, entry: FieldElem) {
        self.hash.absorb(entry);
        self.polyn *= entry;
    }
}

// Computes a CPU tick. Every tick can do any op, including LOAD and a STORE. The returned index
// `i` is a function of `instr`. `loaded_val` represents the value at the `i`, if this instruction
// is a LOAD.
//
// Returns `(new_regs, new_pc, mem_data)`, where `new_regs` is the new set of registers, `new_pc`
// is the updated program counter, and `mem_data` contains the decoded instruction and associated
// register values regarding any LOADs or STOREs that happened in this tick.
fn smalltick(
    pc: Pc<F>,
    instr: EncodedInstruction<F>,
    regs: Registers<F>,
    loaded_val: Option<Word>,
) -> (Registers, Pc, SmallTickMemData);


struct BigtickRunningEvals {
    // The time-sorted trace of our execution
    time_tr_exec: RunningEval,

    // The mem-sorted trace of our execution
    mem_tr_exec: RunningEval,

    // The unsorted trace of the initial memory that's read in our execution
    tr_init_accessed: RunningEval,
}

// Represents a transition function at time `t`, doing an optional LOAD/STORE given by `mem_op`.
// `is_first` and `is_last` indicate whether this is the first or last tick of the whole
// computation. `initmem_eval` is the evaluation of the public `p_init` polynomial representing the
// initial N memory assignments. `chal` is the Fiat-Shamir polyn eval challenge. `evals` are the
// running evaluations of the hashes and polynomial representing the time- and mem-sorted
// transcripts. `mem_tr_adj_pair` represents a pair of adjacent entries in the mem-sorted
// transcript, and since there generally are more ticks than memory accesses, the adjacent pair
// might be empty.
//
// Returns `new_regs`, `new_pc`, `new_t`, and the updated running evals
fn bigtick(
    regs: Registers,
    pc: Pc,
    chal: FieldElem,
    t: usize,
    pc_load: TranscriptEntry,
    mem_op: TranscriptEntry,
    evals: BigtickRunningEvals,
    mem_tr_adj_pair: (TranscriptEntry, TranscriptEntry),
) -> (Registers, Pc, usize, BigtickRunningEvals) {
    // Check sequentiality of pc_load and mem_op
    assert pc_load.t           == t;
    assert_if_exists mem_op.t == t + 1;
    assert pc_load.op          == LOAD;

    // Check that the instruction LOAD was at the index given
    assert pc_load.ramdix == pc;

    // Do a CPU tick
    let instr = pc_load.val;
    let loaded_word = mem_op.val or None
    let (new_regs, new_pc, mem_data) = smalltick(instr, regs, loaded_word);

    // Make sure the idx we LOADed or STOREd was indeed what the CPU wanted
    match mem_op.op {
        Some(Load)  => assert mem_data == SmallTickMemData::Load(memop.ram_idx),
        Some(Store) => assert_mem_data == SmallTickMemData::Store(memop.ram_idx, memop.val),
    }

    //
    // Now accumulate the transcript entries into the time-ordered hashes and polynomials
    //

    let mut new_evals = evals.clone();

    // There's at most 2 mem ops in a single bigtick. t just has to be monotonic, so incr by 2
    let mut new_t = t + 2;

    // Put the instruction LOAD in the time-sorted execution mem
    new_evals.time_tr_exec.update(pc_load.to_ff());

    // Put the memory operation execution mem. If this is padding, then that's fine, because
    // there's as much padding here as in the memory trace
    new_evals.time_tr_exec.update(mem_op.to_ff());

    //
    // Entirely separately from the rest of this function, we check the consistency of the given
    // adjacent entries in the mem-sorted memory transcript (if they're provided)
    //

    let (prev, cur) = mem_tr_adj_pair;

    // These asserts are taken from Figure 5 in Constant-Overhead Zero-Knowledge for RAM
    // Programs: https://eprint.iacr.org/2021/979.pdf

    // Check that this is sorted by memory idx then time
    assert
        ∨ prev.ram_idx < cur.ram_idx
        ∨ (prev.ram_idx == cur.ram_idx ∧ prev.t < cur.t);

    // Check that two adjacent LOADs on the same idx produced the same value
    assert
        ∨ prev.ram_idx != cur.ram_idx
        ∨ prev.val == cur.val
        ∨ cur.op == STORE;

    // On every tick, absorb the second entry in to the mem-sorted execution trace
    new_evals.mem_tr_exec.update(cur.to_ff());
    // If it's an initial load, also put it into tr_init_accessed
    if prev.ram_idx < cur.ram_idx && cur.op == LOAD {
        new_evals.tr_init_accessed.update(cur.to_ff_notime());
    }

    // All done

    return (
        new_regs,
        new_pc,
        new_t,
        new_evals,
    );
}
```

# Sketch of proving procedure

## Prover

Before proving, the prover first runs the full computation and saves the traces.

1. Interpret `tr_init` and `tr_init_nonaccessed` as polynomials. Commit to `tr_init(X)` and
   `tr_init_nonaccessed(X)`. Call them `com_na` and `com_init`.
2. We assume that `bigtick` will operate over chunks of the trace, rather than just single elements
   at a time. For each `bigtick`, commit to the elements of the chunk.
3. Let `com_tr` be the aggregate of all these chunk commitments. We'll define what aggregation
   scheme we use later, but think MIPP-style commitment.
4. Let `chal = H(com_init || com_na || com_tr)`
5. Do all `T / chunk_size` bigtick proofs
6. Enforce the following constraints in the aggregation phase. For each `i`, the input to the `i`-th
   instance of bigtick has:
     * `chal == chal`
     * `t == new_t` from the `i-1`th bigtick, or 0
     * `regs == new_regs` from the `i-1`th bigtick, or Default
     * `pc == new_pc` from the `i-1`th bigtick, or 0
     * `evals = new_evals` from the (`i-1`)-th bigtick, or Default
   where the Default value of a `RunningEval` has `{poly: 1, hash: rand() }`
7. Further, in aggregation, prove that the subcommitments in `com_tr` satisfy their respective
   `bigtick`s.
8. Let `final_time_tr_exec` be the `new_evals.time_tr_exec` returned by the last bigtick. Define
   `final_mem_tr_accessed` and `final_mem_tr_exec` similarly. Prove the following outside the
   circuit:
    * `final_time_tr_exec == final_mem_tr_exec`
    * `tr_init(chal) = tr_init_nonaccessed(chal) * final_mem_tr_accessed`

## Verifier

1. Receive all the commitments from the prover and compute `chal = H(com_na || com_init || com_tr)`
2. (Optional) If `tr_init` is known to the verifier, then the verifier should check that they know
   the opening to `com_init`
3. Check the aggregate proof, along with all the constraints in prover step 6.
4. Check the polynomial evals in prover step 7.
