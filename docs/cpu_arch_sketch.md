## Traces

We need to keep track of several memory traces in our execution. We define them here for clarity.
This notation is used in the pseudocode and the diagram.

* `tr_rinit`: The time-unordered trace containing the initial RAM state of our program.
  `tr_rinit` can be partitioned into:
    * `tr_rinit_accessed`: The time-unordered trace containing the values that are loaded from
      RAM at some point in the execution of the program.
    * `tr_rinit_nonaccessed`: The time-unordered trace containing the values that are never
      loaded from RAM in the execution of the program.
* `tr_tinit`: The ordered trace of containing the contents of the primary (i.e., public) tape. This
  can be partitioned into:
    * `tr_tinit_accessed`: The ordered trace containing the values that are read from the
      tape at some point in the execution of the program.
    * `tr_tinit_nonaccessed` - The ordered trace contianing the values that are never read from the
      tape in the execution of the program.
* `tr_exec`: The ordered trace of our program execution

# Pseudocode for the low-level circuits

```rust
// An index into RAM or ROM. This ALWAYS refers to a byte.
type RamIdx = Word;
// An index into an input tape. This ALWAYS refers to a word.
type TapeIdx = Word;
// Program counter
type Pc = RamIdx;
type Instruction = DWord;

/// An entry in the transcript of RAM accesses
struct TranscriptEntry {
    // A flag denoting whether this is a padding entry
    is_padding: Boolean,
    // The timestamp of this entry
    t: Word,
    // The CPU interacts with memory when it does a loadw, loadb, storew, storeb or when it does a
    // read from the public or private input tapes
    op: { Load, Store, ReadPrimary, ReadAux },
    // The index being loaded from, stored to, or read from the public tape. When used as a RAM
    // index, this is line-aligned, meaning the low bits specifying individual words MUST be 0.
    idx: Word,
    // The line being loaded or stored
    line: Vec<Word>,
}

/// This is the placeholder transcript entry that MUST begin the memory-ordered transcript.
/// Indexing for the real elements of the memory transcript start at t=1 and ramdix=1
const TRANSCRIPT_START = TranscriptEntry::Entry {
    t: 0,
    op: load,
    idx: 0,
    val: 0,
};

impl TranscriptEntry {
    // Encodes this transcript entry as a field element for the purpose of hashing or
    // representation as a coefficient in a polynomial
    fn to_ff(&self) -> FieldElem;

    // Encodes this transcript entry as a field element for the purpose of hashing or
    // representation as a coefficient in a polynomial. The `_notime` variant does not include the
    // timestamp in the representation
    fn to_ff_notime(&self) -> FieldElem;

    // Extracts the byte at the given RAM index, returning it and an error flag. `err = true` iff
    // the lines of `idx` and `self.idx` are not equal, or `self.is_padding == true`.
    fn select_byte(&self, idx: RamIdx) -> (DWord, Boolean);

    // Extracts the word at the given RAM index, returning it and an error flag. Ignores the low
    // bits of `idx` denoting sub-word precision. `err = true` iff the lines of `idx` and
    // `self.idx` are not equal, or the low bits of `self.idx` denoting word precision are
    // not all 0, or `self.is_padding == true`.
    fn select_word(&self, idx: RamIdx) -> (Word, Boolean);

    // Extracts the dword starting at the given RAM index, returning it and an error flag. Ignores
    // the low bits of `idx` denoting sub-word precision. `err = true` iff the lines of `idx` and
    // `self.idx` are not equal, or the low bits of `self.idx` denoting word precision are
    // not all 0, or `self.is_padding == true`.
    fn select_dword(&self, idx: RamIdx) -> (DWord, Boolean);

    // Extracts the word from the primary input tape (of given length) at the given index (which,
    // recall, refers to words, not bytes). Returns `(word, end, err)`, where `word` is the loaded
    // word, `end` denotes that the tape had already ended and no value was read, and `err ==
    // true` iff the lines of `self.idx` and `idx` are not equal. When `end` is set, `word = 0`.
    fn read_tape(idx: TapeIdx, len: usize) -> (Word, Boolean, Boolean);
}

// Represents the running hash and polynomial evaluation of a transcript, i.e., `time_tr_hash =
// Hash(Hash(Hash(op1), op2), ...)` and `time_tr(X) = (X - op1)(X - op2) ...)` evaluated at some
// challenge point.
struct RunningEval {
    hash: Digest,
    polyn: FieldElem,
}

impl RunningEval {
    /// A new RunningEval has to have a random hash initializer. This way the challenge point is
    /// hidden
    fn new(rng: impl Rng) -> RunningEval {
        RunningEval {
            hash: rng.gen(),
            polyn: FieldElem::ONE,
        }
    }

    /// Updates the running evals with the given field element
    fn update(&mut self, entry: FieldElem, chal: FieldElem) {
        self.hash.absorb(entry);
        self.polyn *= (chal - entry);
    }
}

// Public metadata about the program we're executing
struct ProgramData {
    // Denotes whether this program runs in the VonNeumann or Harvard architecture
    arch: TinyRamArch,
    // The length of the primary tape, i.e., the size of the public input. This is necessary
    // because the executor needs to know when the tape has reached the end, and it needs to return
    // 0s and set the flag.
    primary_tape_len: usize,
    // Same idea as `primary_tape_len`
    aux_tape_len: usize,
    // The public challenge point used for all the polynomial evaluations done in the ZKP
    chal: FieldElem,
}

// The execution state of the CPU at some point in time
struct CpuState {
    // Program counter
    pc: Pc,
    // Special boolean register
    flag: Boolean,
    // The normal registers. This is a vec of words
    regs: Registers,
    // The number of words read from the primary tape
    primary_tape_idx: RamIdx,
    // The number of words read from the auxiliary tape
    aux_tape_idx: RamIdx,
}

// Computes a CPU tick. Every tick can do any op. `metadata` contains the public data about the current
// program. `instr` is the current instruction. `state` is the current CPU state. `mem_op` is the
// transcript entry corresponding to this tick's memory operation, if there is one (if not, then
// we enforce `mem_op.is_padding == true`).
//
// Returns the new CPU state
fn smalltick(
    metadata: ProgramData,
    instr: EncodedInstruction,
    state: CpuState,
    mem_op: TranscriptEntry,
) -> CpuState {
    // Store (state, err) for each possible instruction
    let all_possible_states = [(CpuState, Bool); 32];

    let pc_step_size = match metadata.arch {
        Harvard => 1,
        VonNeumann => DWORD_BYTELEN,
    };

    // Unpack the state
    let CpuState { pc, flag, regs, primary_tape_idx, aux_tape_idx } = state;

    // Parse instr as every possible instruction

    // A simple one is add
    let (dest, in1, in2) = instr.as_add();
    let word1 = in1.value(regs);
    let word2 = in2.value(regs);
    let (sum, overflow) = word1.add(word2);
    // Save the values
    let new_state = CpuState {
        pc: pc + pc_step_size,
        flag: overflow,
        regs: regs.set_val(dest, sum),
        primary_tape_idx,
        aux_tape_idx,
    }
    let err = !mem_op.is_padding;
    all_possible_results[Add as usize] = (new_state, err);

    // ...

    // Now do LoadW
    // Unpack values
    (dest, in1) = instr.as_loadw();
    let idx = in1.value(regs);
    // If mem_op isn't a load or isn't this index, this is a mismatch in the transcript vs the
    // execution. This is an error.
    let (loaded_word, err) = mem_op.select_word(idx);
    err |= mem_op.op != Load;
    // Ensure that this load isn't padding. This is the only place we have to check this, since
    // transcript_checker ensures the only padding mem ops that are allowed are loads.
    err |= mem_op.is_padding;
    // Save the new values
    let new_state = CpuState {
        pc: pc + pc_step_size,
        flag,
        regs: regs.set_val(dest, loaded_word),
        primary_tape_idx,
        aux_tape_idx,
    }
    all_possible_results[Load as usize] = (new_state, err);

    // StoreW
    // Unpack values
    (dest, in1) = instr.as_storew();
    let idx = dest.value(regs);
    let word_to_store = in1.value(regs);
    // Get the word that this operation allegedly stores and ensure that it's equal to the value in
    // the register.
    let (stored_word, mut err) = mem_op.select_word(idx);
    err |= word_to_store != stored_word;
    err |= mem_op.op != Store;
    // Save the new values. Nothing but the PC has changed
    let new_state = CpuState {
        pc: pc + pc_step_size,
        flag,
        regs,
        primary_tape_idx,
        aux_tape_idx,
    }
    all_possible_results[Store as usize] = (new_state, err);

    // Read
    // Unpack values
    (dest, in1) = instr.as_storew();
    let tape_ty = in1.value(regs);
    let mut new_primary_tape_idx = primary_tape_idx;
    let mut new_aux_tape_idx = aux_tape_idx;
    // We do different things based on the value of tape_ty. In reality, this will be a mux
    let (read_word, new_flag, err) = if tape_ty == PrimaryTape {
        // Read the word from the tape. This will error iff the mem op's index doesn't match the
        // given tape index
        let (word, flag, mut err) = mem_op.read_tape(primary_tape_idx, metadata.primary_tape_len);
        err |= mem_op.op == ReadPrimary;
        // Move the tape head
        new_primary_tape_idx += 1;
        (word, flag, err)
    } else if tape_ty == AuxTape {
        // Read the word from the tape. This will error iff the mem op's index doesn't match the
        // given tape index
        let (word, flag, err) = mem_op.read_aux_tape(aux_tape_idx, metadata.aux_tape_len);
        err |= mem_op.op == ReadAux;
        // Move the tape head
        new_aux_tape_idx += 1;
        (word, flag, err)
    } else {
        // If this is an invalid read, then the mem op better be padding. Return 0 and set the
        // flag, as per the spec.
        let err = !mem_op.is_padding;
        (0, true, err)
    };
    // Save the new values
    let new_state = CpuState {
        pc: pc + pc_step_size,
        flag: new_flag,
        regs: regs.set_val(dest, read_word),
        primary_tape_idx: new_primary_tape_idx,
        aux_tape_idx: new_aux_tape_idx,
    }
    all_possible_results[Read as usize] = (new_state, err);

    // ...

    // Select the correct set of registers etc.
    let (new_state, err) = all_possible_results.get_val(instr.opcode);
    // Ensure that this operation didn't have an error
    assert !err

    new_state
}


struct BigtickRunningEvals {
    // The time-sorted trace of our execution
    time_tr_exec: RunningEval,

    // The mem-sorted trace of our execution
    mem_tr_exec: RunningEval,

    // The unsorted trace of the initial memory that's read in our execution
    tr_rinit_accessed: RunningEval,

    // The time- (and therefore mem-) sorted trace of the public input tape
    tr_tape: RunningEval,
}

// Represents a transition function at time `t`, possibly doing a memory operation given by
// `mem_op`. `metadata` holds the public program metadata. `state` holds the current CPU state.
// `pc_load` is the load necessary to fetch the current instruction from memory. `evals` are the
// evaluations of the various polynomials we use to track RAM and tape consistency.
// `mem_tr_adj_pair` represents a pair of adjacent entries in the mem-sorted RAM transcript.
//
// Returns the next timestamp, the updated CPU state, and the updated running evals
fn bigtick(
    metadata: ProgramData,
    t: Word,
    state: CpuState,
    pc_load: TranscriptEntry,
    mem_op: TranscriptEntry,
    evals: BigtickRunningEvals,
    mem_tr_adj_pair: (TranscriptEntry, TranscriptEntry),
) -> (Word, CpuState, BigtickRunningEvals) {
    // Get the challenge point. We'll need this for polynomial evals
    let chal = metadata.chal;

    // Check sequentiality of pc_load and mem_op
    assert pc_load.t           == t;
    assert_if_exists mem_op.t  == t + 1;
    assert pc_load.op          == load;

    // Ensure that padding entries are loads. Allowing stores is a soundness issue: padding entries
    // aren't subject to the SmallTickMemData comparison below, so a store on a no-op would still
    // make it into the mem transcript and cause it to believe a real store happened.
    assert !mem_op.is_padding ∨ (mem_op.op == load);

    // Get the instruction from the PC load
    let instr = pc_load.select_dword(pc);
    // Do a CPU tick
    let (new_regs, new_pc) = smalltick(instr, regs, tape_idx, mem_op);

    //
    // Now accumulate the transcript entries into the time-ordered hashes and polynomials
    //

    let mut new_evals = evals.clone();

    // There's at most 2 mem ops in a single bigtick. t just has to be monotonic, so incr by 2
    let mut new_t = t + 2;

    // Put the instruction load in the time-sorted execution mem
    new_evals.time_tr_exec.update(pc_load.to_ff(), chal);

    match mem_op.op {
        // If the mem op reads from the public tape, record it in the tape polyn
        ReadPrimary => new_evals.tr_tape.update(mem_op.to_ff_notime(), chal),
        // If the mem op reads from the private tape, don't record anything
        ReadAux => (),
        // Otherwise, put the memory operation in the time-sorted execution mem. If this is
        // padding, then that's fine, because there's as much padding here as in the memory trace
        _ => new_evals.time_tr_exec.update(mem_op.to_ff(), chal),
    }

    //
    // Entirely separately from the rest of this function, we check the consistency of the given
    // adjacent entries in the mem-sorted memory transcript (if they're provided)
    //

    let (prev, cur) = mem_tr_adj_pair;

    // Tapes are not random-access. In our construction, we do not have to do consistency checks.
    assert
        ∧ prev.op != ReadPrimary
        ∧ prev.op != ReadAux

    // The rest of these asserts pertain just to RAM loads and stores. These asserts are taken from
    // Figure 5 in Constant-Overhead Zero-Knowledge for RAM Programs:
    // https://eprint.iacr.org/2021/979.pdf

    // Check that this is sorted by memory idx then time
    assert
        ∨ prev.idx < cur.idx
        ∨ (prev.idx == cur.idx ∧ prev.t < cur.t);

    // Check that two adjacent loads on the same idx produced the same value
    assert
        ∨ prev.idx != cur.idx
        ∨ prev.val == cur.val
        ∨ cur.op == Store;

    // On every tick, absorb the second entry in to the mem-sorted execution trace
    new_evals.mem_tr_exec.update(cur.to_ff(), chal);
    // If it's an initial load, also put it into tr_rinit_accessed
    if prev.idx < cur.idx && cur.op == load {
        new_evals.tr_rinit_accessed.update(cur.to_ff_notime(), chal);
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

1. Interpret `tr_rinit` (possibly public), `tr_rinit_nonaccessed`, `tr_tinit` (public), and
   `tr_tinit_nonaccessed` as polynomials. Commit to them, denoting them by `com_rinit`, `com_rna`,
   `com_tinit`, and `com_tna`.
2. We assume that `bigtick` will operate over chunks of the trace, rather than just single elements
   at a time. For each `bigtick`, commit to the elements of the chunk.
3. Let `com_tr` be the aggregate of all these chunk commitments. We'll define what aggregation
   scheme we use later, but think MIPP-style commitment.
4. Let `chal = H(com_rinit || com_rna || com_tinit || com_tna || com_tr)`
5. Do all `T / chunk_size` bigtick proofs
6. Enforce the following constraints in the aggregation phase. For each `i`, the input to the `i`-th
   instance of bigtick has:
     * `state == new_state` from the `i-1`th bigtick, or Default
     * `evals = new_evals` from the (`i-1`)-th bigtick, or Default
     * `metadata` is constant and equal to the publicly-known `metadata` value (notably,
       `metadata.chal == chal` from above)
   where the Default value of a `RunningEval` has `{poly: 1, hash: rand() }`
7. Further, in aggregation, prove that the subcommitments in `com_tr` satisfy their respective
   `bigtick`s.
8. Let `final_time_tr_exec` be the `new_evals.time_tr_exec` returned by the last bigtick. Define
   `final_mem_tr_accessed`, `final_mem_tr_exec`, and `final_tape_tr_accessed` similarly. Prove the
   following outside the circuit:
    * `final_time_tr_exec == final_mem_tr_exec`
    * `tr_rinit(chal) = tr_rinit_nonaccessed(chal) * final_mem_tr_accessed`
    * `tr_tinit(chal) = tr_tinit_nonaccessed(chal) * final_tape_tr_accessed`

## Verifier

1. Receive all the commitments from the prover and compute
   `chal = H(com_rinit || com_rna || com_tinit || com_tna || com_tr)`
2. The verifier should check that they know the opening to `com_tinit`, since it's public.
3. (Optional) If `tr_rinit` is known to the verifier, then the verifier should check that they know
   the opening to `com_rinit`
4. Check the aggregate proof, along with all the constraints in prover step 6.
5. Check the polynomial evals in prover step 7.
