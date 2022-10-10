# Pseudocode for the low-level circuits

```rust
// An index into RAM or ROM
type RamIdx = usize;
// Program counter
type Pc = usize;
// Instructions need to be able to STORE at least 1 Word
type Instruction = DoubleWord;

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
        ramidx: RamIdx,
        // The value being loaded or stored
        val: Word,
    },
}

/// This is the placeholder transcript entry that MUST begin the memory-ordered transcript. Indexing for
/// the real elements of the memory transcript start at t=1 and ramdix=1
const TRANSCRIPT_START = TranscriptEntry::Entry {
    t: 0,
    op: LOAD,
    ramidx: 0,
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
    Load(RamIdx),
    Store(RamIdx, Word),
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


/// Represents the running evaluations that have to get updated every bigtick
struct Evals {
    initmem_accessed: RunningEval,
    initmem_nonaccessed: CommittedEval,
    execmem: RunningEval,
}

impl Evals {
    // Computes the product of all the contained polynomials
    fn polyn(&self) -> FieldElem;

    // Computes the combination of all the contained hashes
    fn hash(&self) -> FieldElem;
}

// Represents a transition function at time `t`, doing an optional LOAD/STORE given by `mem_op`.
// `is_first` and `is_last` indicate whether this is the first or last tick of the whole
// computation. `initmem_eval` is the evaluation of the public `p_init` polynomial representing the
// initial N memory  assignments. `chal` is the Fiat-Shamir polyn eval challenge.
// `time_sorted_evals` and `mem_sorted_evals` are the running evaluations of the hashes and
// polynomial representing the time- and mem-sorted transcripts. `mem_tr_adj_pair` represents a
// pair of adjacent entries in the mem-sorted transcript, and since there generally are more ticks
// than memory accesses, the adjacent pair might be empty.
//
// Returns `new_regs`, `new_pc`, `new_t`, and the updated running evals
fn bigtick(
    regs: Registers,
    pc: Pc,
    chal: FieldElem,
    t: usize,
    pcload: TranscriptEntry,
    mem_op: TranscriptEntry,
    pexec_time: RunningEval,
    pfirst_mem: RunningEval,
    pexec_mem: RunningEval
    mem_tr_adj_pair: (TranscriptEntry, TranscriptEntry),
) -> (Registers, Pc, usize, Evals, Evals) {
    // Check sequentiality of pcload and mem_op
    assert pcload.t           == t;
    assert_if_exists mem_op.t == t + 1;
    assert pcload.op          == LOAD;

    // Check that the instruction LOAD was at the index given
    assert pcload.ramdix == pc;

    // Do a CPU tick
    let instr = pcload.val;
    let loaded_word = mem_op.val or None
    let (new_regs, new_pc, mem_data) = smalltick(instr, regs, loaded_word);

    // Make sure the idx we LOADed or STOREd was indeed what the CPU wanted
    match mem_op.op {
        Some(Load)  => assert mem_data == SmallTickMemData::Load(memop.ramidx),
        Some(Store) => assert_mem_data == SmallTickMemData::Store(memop.ramidx, memop.val),
    }

    //
    // Now accumulate the transcript entries into the time-ordered hashes and polynomials
    //

    // There's at most 2 mem ops in a single bigtick. t just has to be monotonic, so incr by 2
    let mut new_t = t + 2;

    // Put the instruction LOAD in the execution mem
    let mut new_pexec_time = pexec_time.clone();
    new_pexec_time.update(pcload.to_ff());

    // Put the memory operation execution mem. If this is padding, then that's fine, because
    // there's as much padding here as in the memory trace
    new_pexec_time.update(mem_op.to_ff());

    //
    // Entirely separately from the rest of this function, we check the consistency of the given
    // adjacent entries in the mem-sorted memory transcript (if they're provided)
    //

    let (prev, cur) = mem_tr_adj_pair;

    // These asserts are taken from Figure 5 in Constant-Overhead Zero-Knowledge for RAM
    // Programs: https://eprint.iacr.org/2021/979.pdf

    // Check that this is sorted by memory idx then time
    assert
        ∨ prev.ramidx < cur.ramidx
        ∨ (prev.ramidx == cur.ramidx ∧ prev.t < cur.t);

    // Check that two adjacent LOADs on the same idx produced the same value
    assert
        ∨ prev.ramidx != cur.ramidx
        ∨ prev.val == cur.val
        ∨ cur.op == STORE;

    // On every tick, absorb the second entry
    let mut new_pexec_mem = pexec_mem.clone();
    let mut new_pfirst_mem = pexec_mem.clone();
    new_pexec_mem.update(cur.to_ff());
    // If it's an initial load, also put it into pfirst
    if prev.ramidx < cur.ramidx && cur.op == LOAD {
        new_pfirst_mem.update(cur.to_ff_notime());
    }

    // All done

    return (
        new_regs,
        new_pc,
        new_pexec_time,
        new_pfirst_mem,
        new_pexec_mem,
    );
}
```

# Sketch of proving procedure

## Polynomial definitions:

* `pfull`: The full memory trace of our program. This consists of:
    * `pinit`: The (non-timestamped) trace resulting from LOADing all the initial memory state of
      our program. `pinit` has two factors:
        * `pnonaccessed`: The (non-timestamped) trace of LOADing all the memory values that are
          never touched in our execution of the program
        * `pfirst`: The (non-timestamped) trace of LOADing all the memory values that are touched in
          our execution of the program. Each slot is LOADed just once.
    * `pexec`: The (timestamped) trace of our program execution

## Prover

1. Commit to `pnonaccessed(X)`, `pinit(X)`. Call them `com_na` and `com_init`.
2. For each trace chunk, commit to the elements of the chunk.
3. Let `com_tr` be the aggregate of all these commitments. We'll define what aggregation scheme we use
   later, but think MIPP-style commitment.
4. Let `chal = H(com_na || com_init || com_tr)`
5. Do all `T` bigtick proofs
6. Enforce the following constraints in the aggregation phase. For each i, the input to the i-th
   instance of bigtick has:
     * `chal == chal`
     * `t == new_t` from the (i-1)-th bigtick, or 0
     * `regs == new_regs` from the (i-1)-th bigtick, or Default
     * `pc == new_pc` from the (i-1)-th bigtick, or 0
     * `pexec_time = new_pexec_time` from the (i-1)-th bigtick, or Default
        * Ditto for `pfirst_mem` and `new_pexec_mem`
   where the Default value of a `RunningEval` has `{poly: 1, hash: rand() }`
7. Further, in aggregation, prove that the subcommitments in `com_tr` satisfy their respective ticks.
8. Let `final_pexec_time` be the `new_pexec_time` running eval returned by the last bigtick. Define
   `final_pfirst_mem` and `final_pexec_mem` similarly. Prove the following outside the circuit:
    * `final_pexec_time == final_pexec_mem`
    * `pinit(chal) = pnonaccessed(chal) * final_pfirst_mem`

## Verifier

1. Receive all the commitments from the prover and compute `chal = H(com_na || com_init || com_tr)`
2. (Optional) If `pinit` is known to the verifier, then the verifier should
   check that they know the opening to `com_init`
2. Check the aggregate proof, along with all the constraints in prover step 6.
3. Check the polynomial evals in prover step 7.
