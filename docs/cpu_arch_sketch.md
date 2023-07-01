## Transcripts

We need to keep track of several memory transcripts in our execution. We define them here for clarity.
This notation is used in the pseudocode and the diagram.

* `tr_exec`: The ordered transcript of our program execution
* `tr_dinit`: The time-unordered transcript containing the initial data memory state of our program.
  `tr_dinit` can be partitioned into:
    * `tr_dinit_accessed`: The time-unordered transcript containing the values that are loaded from
      data memory at some point in the execution of the program.
    * `tr_dinit_nonaccessed`: The time-unordered transcript containing the values that are never
      loaded from data memory in the execution of the program.
* `tr_pinit`: _Only relevant for Harvard arch._ The time-unordered transcript containing the program
  memory.
    * `tr_pinit_accessed`: The time-unordered transcript containing the values that are read from
      the program memory some point in the execution of the program.
    * `tr_pinit_nonaccessed` - The time-unordered transcript contianing the values that are never
      read from the program memory in the execution of the program.
* `tr_tinit`: The ordered transcript of containing the contents of the primary (i.e., public) tape.
  This can be partitioned into:
    * `tr_tinit_accessed`: The ordered transcript containing the values that are read from the
      tape at some point in the execution of the program.
    * `tr_tinit_nonaccessed` - The ordered transcript contianing the values that are never read from
      the tape in the execution of the program.

# Pseudocode for the low-level circuits

```rust
// An index to a byte in data memory
type RamIdx = Word;
// An index to a word on an input tape
type TapeIdx = Word;
// Program counter. In von Neumann arch, this is an index to a byte in data memory. In Harvard arch,
// it's an index to a word in program memory.
type Pc = Word;
type Instruction = DWord;

/// An entry in the transcript of RAM accesses. We load/store data at double word granularity. The
/// values `t` and `idx` both MUST start at 1, rather than 0. The 0 values are reserved for
/// placeholders.
struct TranscriptEntry {
    // A flag denoting whether this is a padding entry
    is_padding: Boolean,
    // The timestamp of this entry
    t: Word,
    // The CPU interacts with memory when it does a loadw, loadb, storew, storeb or when it does a
    // read from the public or private input tapes. LoadPrg is used exclusively in Harvard
    // architecture, and represents a load from program memory.
    op: { Load, Store, ReadPrimary, ReadAux, LoadPrg },
    // The index being loaded from, stored to, or read from the public tape. When used as a data
    // (rather than program) index, this is double word-aligned, meaning the low bits specifying
    // individual words MUST be 0. When used as a program index, no alignment is enforced.
    idx: Word,
    // The double word being loaded or stored
    double_word: DWord,
}

impl TranscriptEntry {
    // Encodes this transcript entry as a field element for the purpose of hashing or
    // representation as a coefficient in a polynomial
    fn to_ff(&self) -> FieldElem;

    // Encodes this transcript entry as a field element for the purpose of hashing or
    // representation as a coefficient in a polynomial. The `_notime` variant does not include the
    // timestamp in the representation
    fn to_ff_notime(&self) -> FieldElem;

    // Extracts the byte at the given RAM index, returning it and an error flag. `err = true` iff
    // `self.idx` and the high (non-byte-precision) bits of `idx` are not equal, or
    // `self.is_padding == true`.
    fn select_byte(&self, idx: RamIdx) -> (UInt8, Boolean);

    // Extracts the word at the given RAM index, returning it and an error flag. Ignores the low
    // bits of `idx` denoting sub-word precision. `err = true` iff `self.idx` and the high
    // (non-byte- or word-precision) bits of `idx` are not equal, or the low bits of `self.idx` are
    // not all 0, or `self.padding == true`.
    fn select_word(&self, idx: RamIdx) -> (Word, Boolean);

    // Extracts the double word at the given RAM index, returning it and an error flag. Ignores the low
    // bits of `idx` denoting sub-word precision. `err = true` iff `self.idx` and the high
    // (non-byte- or word-precision) bits of `idx` are not equal, or the low bits of `self.idx` are
    // not all 0, or `self.padding == true`.
    //
    // NOTE: This will return an `err` if it receives an `idx` that is not double word-aligned. This is
    // good, because we only allow PC to be double word-aligned
    fn select_double_word(&self, idx: RamIdx) -> (Word, Boolean);

    // Extracts the word from an input tape (of given length) at the given index (which, recall,
    // refers to words, not bytes). Returns `(word, end, err)`, where `word` is the loaded word,
    // `end` denotes that the tape had already ended and no value was read, and `err == true` iff
    // `self.idx` and the high (non-word-precision) bits of `idx` are not equal.
    fn read_tape(&self, idx: TapeIdx, len: usize) -> (Word, Boolean, Boolean);
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
    primary_tape_idx: TapeIdx,
    // The number of words read from the auxiliary tape
    aux_tape_idx: TapeIdx,
}

struct DecodedInstruction {
    reg1: UInt8,
    reg2: UInt8,
    imm_or_reg: Word,
}

// Computes the given CPU instruction. `metadata` contains the public data about the current
// program. `instr` is the current instruction. `state` is the current CPU state. `mem_op` is the
// transcript entry corresponding to this tick's memory operation, if there is one (if not, then we
// enforce `mem_op.is_padding == true`).
//
// Returns the new CPU state and a flag indicating whether a verification error occurred
fn full_exec_checker(
    metadata: ProgramData ,
    instr: EncodedInstruction,
    state: CpuState,
    mem_op: TranscriptEntry,
) -> CpuState {
    // Decode the instruction
    let (given_op, instr_args) = instr.decode();

    // Parse instr as every possible instruction. Store (state, err) for each possible instruction
    let mut all_possible_states = [(CpuState, Bool); 32];
    for op in ALL_OPCODES {
        all_possible_results[op] = exec_checker(metadata, op, instr_args, state, mem_op);
    }

    // Select the correct new state
    let (new_state, err) = all_possible_results.select(given_op);
    // Ensure that this operation ran successfully
    assert !err

    new_state
}

// Computes the CPU instruction defined by `op` and `instr_args`, where `op` is a native value that
// can be `match`ed over. `metadata` contains the public data about the current program. `instr` is
// the current instruction. `state` is the current CPU state. `mem_op` is the transcript entry
// corresponding to this tick's memory operation, if there is one (if not, then we enforce
// `mem_op.is_padding == true`).
//
// Returns the new CPU state and a flag indicating whether a verification error occurred
fn exec_checker(
    metadata: ProgramData, // Native value
    op: Opcode,            // Native value
    instr_args: InstrArgs,
    state: CpuState,
    mem_op: TranscriptEntry,
) -> CpuState {

    let pc_step_size = match metadata.arch {
        Harvard => 1,
        VonNeumann => DWORD_BYTELEN,
    };

    // Unpack the state
    let CpuState { pc, flag, regs, primary_tape_idx, aux_tape_idx } = state;

    match op {
        Add => {
            // Rename the args for clarity
            let dest = instr.reg1;
            let in1 = instr.reg2;
            let in2 = instr.imm_or_reg;

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
            (new_state, err)

        }

        CmpE => {
            // Rename the args for clarity
            let in1 = instr.reg2;
            let in2 = instr.imm_or_reg;

            let word1 = in1.value(regs);
            let word2 = in2.value(regs);
            let is_eq = word1.is_eq(word2);
            // Save the values
            let new_state = CpuState {
                pc: pc + pc_step_size,
                flag: is_eq,
                regs,
                primary_tape_idx,
                aux_tape_idx,
            }
            let err = !mem_op.is_padding;
            (new_state, err)
        }

        LoadW => {
            // Rename the args for clarity
            let dest = instr.reg1;
            let in1 = instr.imm_or_reg;

            let idx = in1.value(regs);
            // If mem_op isn't a load or isn't this index, this is a mismatch in the transcript vs
            // the execution. This is an error.
            let (loaded_word, err) = mem_op.select_word(idx);
            err |= mem_op.op != Load;
            // Ensure that this load isn't padding. This is the only place we have to check this,
            // since  transcript_checker ensures the only padding mem ops that are allowed are
            // loads.
            err |= mem_op.is_padding;
            // Return the new values
            let new_state = CpuState {
                pc: pc + pc_step_size,
                flag,
                regs: regs.set_val(dest, loaded_word),
                primary_tape_idx,
                aux_tape_idx,
            }
            all_possible_results[Load as usize] = (new_state, err);
        }

        StoreW => {
            // Rename the args for clarity
            let dest = instr.imm_or_reg;
            let in1 = instr.reg2;

            let idx = dest.value(regs);
            let word_to_store = in1.value(regs);
            // Get the word that this operation allegedly stores and ensure that it's equal to the
            // value in the register.
            let (stored_word, mut err) = mem_op.select_word(idx);
            err |= word_to_store != stored_word;
            err |= mem_op.op != Store;
            // Return the new values. Nothing but the PC has changed
            let new_state = CpuState {
                pc: pc + pc_step_size,
                flag,
                regs,
                primary_tape_idx,
                aux_tape_idx,
            }
            (new_state, err)
        }

        Read => {
            // Rename the args for clarity
            let dest = instr.reg1;
            let in1 = instr.imm_or_reg;

            // The only valid tapes are 0 (primary) and 1 (aux). If anything but the bottom bit is
            // set, then the tape is invalid and we return the default response.
            let tape_ty = in1.value(regs);
            let tape_is_valid = tape_ty.bits[1..].or().not();
            // Convert to boolean now that we have the out-of-range bit
            let tape_ty: Boolean = tape_ty[0];

            // Mux the correct tape idx and length, as well as the expected memory op type
            let tape_idx = [primary_tape_idx, aux_tape_idx].select(tape_ty);
            let tape_len = [metadata.primary_tape_len, metadata.aux_tape_len].select(tape_ty);
            let mem_op_type = [ReadPrimary, ReadAux].select(tape_ty);

            // Read the word from the tape. This will error iff the mem op's index doesn't match the
            // given tape index
            let (read_word, new_flag, mut err) = mem_op.read_tape(tape_idx, tape_len);
            err |= mem_op.op == mem_op_type;

            // Move the appropriate tape head
            let new_primary_tape_idx = primary_tape_idx + [1, 0].select(tape_ty);
            let new_aux_tape_idx = aux_tape_idx + [0, 1].select(tape_ty);

            // Define the state and err flags, assuming the tape choice was valid
            let err_tapevalid = err;
            let new_state_tapevalid = CpuState {
                pc: pc + pc_step_size,
                flag: new_flag,
                regs: regs.set_val(dest, read_word),
                primary_tape_idx: new_primary_tape_idx,
                aux_tape_idx: new_aux_tape_idx,
            }

            // Define the state and err flags assuming the tape choice was invalid. Spec says you
            // return 0, and set the flag
            let err_tapeinvalid = Boolean::FALSE;
            let new_state_tapeinvalid = CpuState {
                pc: pc + pc_step_size,
                flag: Boolean::TRUE,
                regs: regs.set_val(dest, Word::ZERO),
                primary_tape_idx: primary_tape_idx,
                aux_tape_idx: aux_tape_idx,
            };

            [
                (new_state_tapeinvalid, new_err_tapeinvalid),
                (new_state_tapevalid, err_tapevalid),
            ]
            .select(tape_is_valid)
        }
    }
}


struct RunningEvals {
    // The time-sorted transcript of our execution
    time_tr_exec: RunningEval,

    // The mem-sorted transcript of our execution
    mem_tr_exec: RunningEval,

    // The unsorted transcript of the initial memory that's read in our execution
    tr_dinit_accessed: RunningEval,

    // The time- (and therefore mem-) sorted transcript of the items in the public input tape that
    // are read in our execution
    tr_tape_accessed: RunningEval,
}

// TODO: Update transcript_checker to handle Harvard architecture. With Harvard, mem_tr_adj_seq
// would be replaced with two values:
//     mem_prog_tr_adj_pair: [TranscriptEntry; 2]
//     mem_data_tr_adj_pair: [TranscriptEntry; 2]
// The memory consistency checks would be identical, though it'd have to absorb the values into
// different polynomials.

// Represents a transition function at time `t`, possibly doing a memory operation given by
// `mem_op`. `metadata` holds the public program metadata. `state` holds the current CPU state.
// `pc_load` is the load necessary to fetch the current instruction from memory. `evals` are the
// evaluations of the various polynomials we use to track RAM and tape consistency.
// `mem_tr_adj_seq` represents a triple of adjacent entries in the mem-sorted RAM transcript.
//
// Returns the next timestamp, the updated CPU state, and the updated running evals
fn transcript_checker(
    metadata: ProgramData,
    t: Word,
    state: CpuState,
    pc_load: TranscriptEntry,
    mem_op: TranscriptEntry,
    evals: RunningEvals,
    mem_tr_adj_seq: [TranscriptEntry; 3],
) -> (Word, CpuState, RunningEvals) {
    // Get the challenge point. We'll need this for polynomial evals
    let chal = metadata.chal;

    // Check sequentiality of pc_load and mem_op
    assert pc_load.t == t;
    assert_if_exists mem_op.t == t + 1;
    assert pc_load.op == match metadata.arch {
        VonNeumann => Load,
        Harvard => LoadPrg,
    };

    // Make sure mem_op represents an operation on data memory, not program memory
    if metadata.arch == Harvard {
        assert mem_op.op != LoadPrg;
    }

    // Ensure that padding entries are loads. Allowing stores is a soundness issue: padding entries
    // aren't subject to the comparison below, so a store on a no-op would still make it into the
    // mem transcript and cause it to believe a real store happened.
    assert !mem_op.is_padding ∨ (mem_op.op == Load);

    // Get the instruction from the PC load
    let instr = pc_load.select_double_word(pc);
    // Do a CPU tick
    let (new_regs, new_pc) = full_exec_checker(instr, regs, tape_idx, mem_op);

    //
    // Now accumulate the transcript entries into the time-ordered hashes and polynomials
    //

    let mut new_evals = evals.clone();

    // There's at most 2 mem ops in a single transcript_checker. t just has to be monotonic, so incr
    // by 2
    let mut new_t = t + 2;

    // Put the instruction load in the time-sorted execution mem
    new_evals.time_tr_exec.update(pc_load.to_ff(), chal);

    match mem_op.op {
        // If the mem op reads from the public tape, record it in the tape polyn
        ReadPrimary => new_evals.tr_tape_accessed.update(mem_op.to_ff_notime(), chal),
        // If the mem op reads from the private tape, don't record anything
        ReadAux => (),
        // Otherwise, put the memory operation in the time-sorted execution transcript. If this is
        // padding, then that's fine, because there's as much padding here as in the memory
        // transcript
        _ => new_evals.time_tr_exec.update(mem_op.to_ff(), chal),
    }

    //
    // Entirely separately from the rest of this function, we check the consistency of the given
    // adjacent entries in the mem-sorted memory transcript (if they're provided).
    //

    // Check consistency of every pair of adjacent items in the memory-sorted sequence
    for (prev, cur) in mem_tr_adj_seq.windows(2) {
        // Tapes are not random-access. In our construction, we do not have to do consistency
        // checks.
        assert
            ∧ prev.op != ReadPrimary
            ∧ prev.op != ReadAux

        // In Harvard arch, program memory is separate. So we separate the mem-sorted transcript
        // into a mem-sorted data transcript followed by a mem-sorted program transcript.
        if prev.op != LoadPrg && cur.op == LoadPrg {
            // If we're transitioning to program memory, skip the rest of the checks
            continue;
        }
        // Once we're in the program memory, we can't go back to data memory. In other words, prev
        // is a program op iff cur is a program op.
        assert
            ∨ (prev.op != LoadPrg ∧ cur.op != LoadPrg)
            ∨ (prev.op == LoadPrg ∧ cur.op == LoadPrg)

        // The rest of these asserts pertain just to RAM loads and stores. These asserts are taken
        // from Figure 5 in Constant-Overhead Zero-Knowledge for RAM Programs:
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

        // On every tick, absorb the second entry in to the mem-sorted execution transcript
        new_evals.mem_tr_exec.update(cur.to_ff(), chal);
        // If it's an initial load, also put it into tr_(d/p)init_accessed
        if prev.idx < cur.idx {
            match cur.op {
            Load => new_evals.tr_dinit_accessed.update(cur.to_ff_notime(), chal),
            LoadPrg => new_evals.tr_pinit_accessed.update(cur.to_ff_notime(), chal),
        }
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

# A word on padding

We must be careful how we pad the transcripts that we feed into the prover. There are multiple
concerns here: we must pick padding that has unique timestamps, is consistent with the rest of the
transcript, and affects as few committed polynomials as possible.

A naïve solution would be to simply skip memory consistency checks for padding entries. This is
unsound, though. Suppose we don't check padding entries in the second half of `transcript_checker`.
Then there's nothing to tell whether `cur` is coherent with the rest of the transcript when `prev`
is a padding entry with no information at all. A dishonest prover could simply place a padding entry
followed by whatever load operation they wanted, and there'd be no way of proving consistency. Thus,
we mandate that _all_ entries in the mem-sorted transcript, even padding, must be consistent.

This constraint means we can't just pick padding arbitrarily. This is the process we use:

## von Neumann arch

In the von Neumann architecture, it's guaranteed that the time-ordered memory transcript is
non-empty, since there must be instruction loads. We set the time-sorted transcript as follows. At
instruction `t`, we have an instruction load `op_i`, and an optional memory op `op_m`.

* If `op_m` is `Some`, then return `[(2t+1, op_i), (2t+2, op_m)]`
* If `op_m` is `None`, then return `[(2t+1, op_i), (2t+2, op_i[is_padding=true])`

Notice we have to set `is_padding=true` when we copy `op_i` in the second case. If we don't, then
the exec checker will fail, since it's not expecting a memory operation on the non-mem-touching
instruction at `op_i`. Also note that the timestamps are doubled and incremented. This is to make
them unique so we can establish a total ordering on them (both time-major and mem-major). Finally,
notice that we add 1 to every timestamp no matter what. This is because the 0 timestamp is reserved
for the initial padding of the mem-ordered trace, which we describe now.

### Memory segments

The von Neumann has 1 random-access memory segment. But our execution transcript handles tape
accesses as well, in the form of `read` instructions. Mixing segments in the memory-sorted
transcript is clearly unsound, for the same reason that excluding consistency checks for padding is
unsound. Thus, we are forced to remove the tape `read` operations from the memory-sorted trace and
do consistency checks elsewhere.[^1]

So the length of the memory-sorted transcript can be anywhere from 2T elements (1 instruction load
plus 1 possibly padding memory op for each instruction) down to T elements (1 instruction load and 1
`read` op which gets deleted), where T is the number of total ticks.
Since the mem-sorted transcript is checked in sliding windows of size 3 with step 2, the mem-sorted
transcript needs 2T + 1 elements. This means that we will need to pad the end of the transcript with
a bunch of operations that _don't_ get absorbed into the running evals, since they do not appear in
the time-sorted transcript.

This requires a small change in design: we can happily absorb padding from the time-ordered
transcript (since it'd appear in the mem-sorted transcript), but we _cannot_ absorb padding that's
explicitly made for the mem-sorted transcript (since it doesn't appear in the time-sorted
transcript). We have two options then, 1) create two notions of padding, choosing to absorb one kind
and not the other in the memory consistency check, or 2) just do not absorb any padding in any part
of the circuit. We choose (2) for simplicity.

[^1]: As a side note, these external checks happen to be minimal, since 1) the tapes are read-only
    and read in sequence, 2) the primary tape is public knowledge, and 3) the contents of the
    witness tape can be anything the prover wants, so long as it's the right length.

### Initial element of the mem-sorted transcript

We have to make an initial padding element for the mem-sorted transcript. This is for two reasons:

1. It is mathematically necessary. The mem-sorted transcript is checked in sliding windows of size 3
   with step 2, so we need 2T + 1 elements in the mem-sorted transcript where T is the number of
   total ticks
2. Since we don't want to double count the first element in the sliding window, the consistency
   checker will only absorb the tail of the list it's given. So the first element of the mem-sorted
   trace needs to be a _consistent_ and _inconsequential_ throwaway value that does not get
   absorbed.

We are further constrained by the fact that we don't want the placeholder element to change whether
the next element is considered a first-access or not. Thus, we reserve RAM index 0 and timestamp 0
for the placeholder value, and make the initial placeholder a `load` of 0 from index 0 at time 0,
and set `padding=true`. Because nothing else uses index 0, this is essentially a no-op.
Alternatively, we can use RAM index -1 if it makes dev ergonomics easier.

### Final elements of the mem-sorted transcript

If the mem-sorted transcript is has length `L < 2T`, it will need more padding. Since the padding
does not occur in the time-sorted transcript, it cannot be absorbed. Still, it must be consistent
with the rest of the transcript. We define the padding as follows. Let `op` represent the final
element in the memory-sorted transcript prior to padding, and let `t` denote its timestamp. We note
that `op` exists (since there's at least the initial padding step above), and `op` is a RAM
operation (not a `read`, since those are explicitly deleted from the mem-sorted transcript). For
each `i = 0..2T+1-L`, we define the `i`-th padding element, appended to the end of the mem-sorted
transcript, to be `op_i = op[timestamp=(t+i), kind=load, is_padding=true]`.

One can see that this satisfies all the consistency criteria and is also not absorbed into the
running evals.

## Harvard arch

We have to use a different tactic for Harvard than what we did above. Copying `op_i` to use as a
memory operation doesn't work anymore, since `op_i` and `op_m` are in entirely different memory
segments now. So instead we do something simpler: just repeat the data memory operation from the
last tick, increment the timestamp, set `is_padding=true`, and set the op type to `Load`. That is,
if `(t, op_m)` is the previous data memory op, then we set `(t', op_m') = (t+1, op_m[type=Load,
is_padding=true])`. This would technically be consistent even without `[type=Load]`, but we need it
because padding entries must be loads. Padding entries aren't subject to checking by `exec_checker`,
so a `Store` on a no-op instruction would still end up in the mem-sorted transcript and cause it to
believe a real store happened.

### Initial element of the mem-sorted transcript

We don't have to do anything different here. Let the placeholder element be all zeros.

# Sketch of proving procedure

## Prover

Before proving, the prover first runs the full computation and saves the transcripts.

1. Interpret `tr_dinit` (possibly public), `tr_dinit_nonaccessed`, `tr_tinit` (public), and
   `tr_tinit_nonaccessed` as polynomials. Commit to them, denoting them by `com_dinit`, `com_rna`,
   `com_tinit`, and `com_tna`.
2. Compute and pad the memory-sorted transcript of the program. We feed slices of size 3 to each
   invocation of `transcript_checker`. Specifically (for consistency purposes) they're done in
   sliding windows of size 3, with a step size of 2, i.e.,
   ```
    [A B C] -> [C D E] -> [E F G]
   ```
   We commit to the elements of each slice. (NOTE: later, we will be increasing the number of
   instructions that a since `transcript_checker` processes, and hence also the number of mem-sorted
   transcript elements it will check)
3. Let `com_tr` be the aggregate of all these slice commitments. We'll define what aggregation
   scheme we use later, but think MIPP-style commitment.
4. Let `chal = H(com_dinit || com_pinit || com_rna || com_tinit || com_tna || com_tr)`
5. Do all `T / chunk_size` transcript_checker proofs
6. Enforce the following constraints in the aggregation phase. For each `i`, the input to the `i`-th
   instance of transcript_checker has:
     * `state == new_state` from the `i-1`th transcript_checker, or Default
     * `evals = new_evals` from the (`i-1`)-th transcript_checker, or Default
     * `metadata` is constant and equal to the publicly-known `metadata` value (notably,
       `metadata.chal == chal` from above)
   where the Default value of a `RunningEval` has `{poly: 1, hash: rand() }`
7. Further, in aggregation, prove that the subcommitments in `com_tr` satisfy their respective
   `transcript_checker`s.
8. Let `final_time_tr_exec` be the `new_evals.time_tr_exec` returned by the last transcript_checker.
   Define `final_mem_tr_accessed`, `final_mem_tr_exec`, and `final_tape_tr_accessed` similarly.
   Prove the following outside the circuit:
    * `final_time_tr_exec == final_mem_tr_exec`
    * `tr_dinit(chal) = tr_dinit_nonaccessed(chal) * final_mem_tr_accessed`
    * `tr_pinit(chal) = tr_pinit_nonaccessed(chal) * final_pinit_tr_accessed`
    * `tr_tinit(chal) = tr_tinit_nonaccessed(chal) * final_tape_tr_accessed`

## Verifier

1. Receive all the commitments from the prover and compute
   `chal = H(com_dinit || com_rna || com_tinit || com_tna || com_tr)`
2. The verifier should check that they know the opening to `com_tinit`, since it's public.
3. (Optional) If `tr_dinit` is known to the verifier, then the verifier should check that they know
   the opening to `com_dinit`
4. Check the aggregate proof, along with all the constraints in prover step 6.
5. Check the polynomial evals in prover step 8.
