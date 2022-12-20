use crate::{
    common::*,
    exec_checker::{exec_checker, CpuState, ExecTickMemData},
    util::log2,
    word::{DWord, DWordVar, WordVar},
};

use tinyram_emu::{word::Word, TinyRamArch};

use core::cmp::Ordering;

use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    uint32::UInt32,
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;

/// A timestamp in the memory access transcript
type Timestamp = u64;
/// A timestamp in the memory access transcript, in ZK land
type TimestampVar<F> = FpVar<F>;

// Represents the running polynomial evaluation of a transcript. E.g.,
// `time_tr_exec(X) = (X - op1)(X - op2) ...)` evaluated at some challenge point. This also
// is used for unordered evals, such as `tr_init_accessed`.
#[derive(Clone)]
struct RunningEvalVar<F: PrimeField>(FpVar<F>);

impl<F: PrimeField> Default for RunningEvalVar<F> {
    fn default() -> Self {
        RunningEvalVar(FpVar::one())
    }
}

impl<F: PrimeField> RunningEvalVar<F> {
    /// Updates the running eval with the given entry and challenge point, iff `bit` == true.
    fn conditionally_update(
        &mut self,
        bit: &Boolean<F>,
        entry: &FpVar<F>,
        chal: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // This value, when plugged into the expression below, will yield 1, thus not affecting the
        // current running eval.
        let dummy_entry = chal - FpVar::one();

        // Select either the real entry or the dummy entry
        let val_to_absorb = FpVar::conditionally_select(bit, entry, &dummy_entry)?;

        // Recall the polynoimal has factors (X - op). So to do an incremental computation, we
        // calculate `eval *= (chal - op)`.
        self.0 *= chal - val_to_absorb;

        Ok(())
    }

    /// Updates the running eval with the given entry and challenge point
    fn update(&mut self, entry: &FpVar<F>, chal: &FpVar<F>) -> Result<(), SynthesisError> {
        self.conditionally_update(&Boolean::TRUE, entry, chal)
    }
}

/// The kind of memory operation: load or store
#[derive(Clone, Copy, Debug)]
enum MemOpKind {
    /// A memory op corresponding to `loadw` or `loadb`
    Load = 0,
    /// A memory op corresponding to `storew` or `storeb`
    Store,
    /// A memory op corresponding to `read 0`
    ReadPrimary,
    /// A memory op corresponding to `read 1`
    ReadAux,
}

impl MemOpKind {
    // Returns the numerical value of this op as a field element
    fn as_fp<F: PrimeField>(&self) -> F {
        F::from(*self as u8)
    }
}

/// The kind of memory operation: load, store, read primary tape or read aux tape, in ZK land
type MemOpKindVar<F> = FpVar<F>;

/// An entry in the transcript of RAM accesses
#[derive(Clone)]
enum TranscriptEntry<W: Word> {
    /// If there are more ticks than memory accesses, we pad out the transcript
    Padding,

    /// A real, non-padding entry
    Entry {
        /// The timestamp of this entry. This MUST be greater than 0
        t: Timestamp,
        /// The operation happening
        op: MemOpKind,
        // The index being loaded from, stored to, or read from the public tape. When used as a RAM
        // index, this is dword-aligned, meaning the low bits specifying individual words MUST be 0.
        ramidx: W,
        /// The value being loaded or stored
        val: DWord<W>,
    },
}

/// This is the placeholder transcript entry that MUST begin the memory-ordered transcript. This is
/// never interpreted by the program, and its encoded values do not represent memory state.
fn transcript_starting_entry<W: Word>(
    real_transcript: &[TranscriptEntry<W>],
) -> TranscriptEntry<W> {
    // If you repeat the first item of the real transcript, it is always consistent
    real_transcript[0].clone()
}

impl<W: Word> TranscriptEntry<W> {
    /// Encodes this transcript entry as a field element for the purpose representation as a
    /// coefficient in a polynomial
    fn as_ff<F: Field>(&self) -> F {
        unimplemented!()
    }

    /// Encodes this transcript entry as a field element for the purpose of representation as a
    /// coefficient in a polynomial. The `_notime` variant does not include the timestamp in the
    /// representation (i.e., it sets `t=0`).
    fn to_ff_notime<F: Field>(&self) -> F {
        unimplemented!()
    }
}

/// An entry in the transcript of RAM accesses
pub(crate) struct TranscriptEntryVar<W: WordVar<F>, F: PrimeField> {
    /// Tells whether or not this entry is padding
    pub(crate) is_padding: Boolean<F>,
    /// The timestamp of this entry. This is at most 64 bits
    timestamp: TimestampVar<F>,
    ///
    op: MemOpKindVar<F>,
    /// Either the index being loaded from or stored to
    ram_idx: W,
    /// `ram_idx` as a field element
    ram_idx_fp: FpVar<F>,
    /// The value being loaded or stored
    val: DWordVar<W, F>,
    /// `val` as a field element
    val_fp: FpVar<F>,
}

impl<W: WordVar<F>, F: PrimeField> Default for TranscriptEntryVar<W, F> {
    fn default() -> Self {
        TranscriptEntryVar {
            is_padding: Boolean::TRUE,
            timestamp: TimestampVar::zero(),
            op: MemOpKindVar::zero(),
            ram_idx: W::zero(),
            ram_idx_fp: FpVar::zero(),
            val: DWordVar::zero(),
            val_fp: FpVar::zero(),
        }
    }
}

impl<W: WordVar<F>, F: PrimeField> TranscriptEntryVar<W, F> {
    /// Returns whether this memory operation is a load
    fn is_load(&self) -> Result<Boolean<F>, SynthesisError> {
        self.op
            .is_eq(&MemOpKindVar::Constant(MemOpKind::Load.as_fp()))
    }

    /// Returns whether this memory operation is a store
    fn is_store(&self) -> Result<Boolean<F>, SynthesisError> {
        self.op
            .is_eq(&MemOpKindVar::Constant(MemOpKind::Store.as_fp()))
    }
}

impl<W: WordVar<F>, F: PrimeField> TranscriptEntryVar<W, F> {
    /// Encodes this transcript entry as a field element. `is_init` says whether this entry is part
    /// of the initial memory or not.
    fn as_ff(&self, is_init: bool) -> Result<FpVar<F>, SynthesisError> {
        // The field element is of the form
        //     00...0 || val || ram_idx || op || timestamp || is_padding || is_init
        let mut acc = FpVar::<F>::zero();

        // First field `is_init` is in the first bit. Shift by 1.
        acc += &FpVar::Constant(F::from(is_init));
        let mut shift = 1;

        // Encode `is_padding`. Shift by 1.
        let shift_var = FpVar::<F>::Constant(F::from(1u64 << shift));
        acc += FpVar::from(self.is_padding.clone()) * shift_var;
        shift += 1;

        // Encode `timestamp` as 64 bits
        let shift_var = FpVar::<F>::Constant(F::from(1u64 << shift));
        acc += &self.timestamp * shift_var;
        shift += 64;

        // Encode `op`. Shift by 1.
        let shift_var = FpVar::<F>::Constant(F::from(1u64 << shift));
        acc += FpVar::from(self.op.clone()) * shift_var;
        shift += 1;

        // Encode `ram_idx` as 64 bits
        let shift_var = FpVar::<F>::Constant(F::from(1u64 << shift));
        acc += &self.ram_idx.as_fpvar()? * shift_var;
        shift += 64;

        // Encode `val` as 64 bits
        let shift_var = FpVar::<F>::Constant(F::from(1u64 << shift));
        acc += &self.val_fp * shift_var;

        Ok(acc)
    }

    // Extracts the byte at the given RAM index, returning it and an error flag. `err = true` iff
    // `self.idx` and the high (non-byte-precision) bits of `idx` are not equal, or
    // `self.is_padding == true`.
    fn select_byte(&self, idx: W) -> Result<(UInt8<F>, Boolean<F>), SynthesisError> {
        // Check if this is padding
        let mut err = self.is_padding.clone();

        // Do the index check. Mask out the bottom bits of idx. We just need to make sure that this
        // load is the correct dword, i.e., all but the bottom bitmask bits of idx and self.ram_idx
        // match.
        let bytes_per_word = W::BITLEN / 8;
        let bitmask_len = log2(bytes_per_word);
        let idx_high_bits = idx.as_le_bits().into_iter().skip(bitmask_len);
        for (b1, b2) in idx_high_bits.zip(self.ram_idx.as_le_bits().into_iter().skip(bitmask_len)) {
            err = err.or(&b1.is_neq(&b2)?)?;
        }

        // Now use the low bits of idx to select the correct byte from self.val
        let val_bytes = [self.val.w0.unpack(), self.val.w1.unpack()].concat();
        let out = UInt8::conditionally_select_power_of_two_vector(&idx.as_be_bits(), &val_bytes)?;

        Ok((out, err))
    }
}

/// Running evals used inside `transcript_checker`
#[derive(Clone)]
struct TranscriptCheckerEvals<F: PrimeField> {
    // The time-sorted trace of our execution
    time_tr_exec: RunningEvalVar<F>,

    // The mem-sorted trace of our execution
    mem_tr_exec: RunningEvalVar<F>,

    // The unsorted trace of the initial memory that's read in our execution
    tr_init_accessed: RunningEvalVar<F>,
}

/// This function checks the time- and mem-sorted transcripts for consistency. It also accumulates
/// both transcripts into their respective polynomial evaluations.
fn transcript_checker<const NUM_REGS: usize, W: WordVar<F>, F: PrimeField>(
    arch: TinyRamArch,
    cpu_state: &CpuState<W, F>,
    chal: &FpVar<F>,
    pc_load: &TranscriptEntryVar<W, F>,
    mem_op: &TranscriptEntryVar<W, F>,
    mem_tr_adj_pair: (&TranscriptEntryVar<W, F>, &TranscriptEntryVar<W, F>),
    evals: &TranscriptCheckerEvals<F>,
) -> Result<(CpuState<W, F>, TranscriptCheckerEvals<F>), SynthesisError> {
    // pc_load occurs at time t
    let t = &pc_load.timestamp;
    // mem_op, if defined, occurs at time t
    let t_plus_one = t + FpVar::one();

    // TODO: MUST check that mem_op.ram_idx is dword-aligned (in Harvard: check bottom bit is 0, in
    // Von Neumann: check that bottom log₂(dword_bytelen) bits are 0)

    // --------------------------------------------------------------------------------------------
    // Housekeeping of memory operations
    // --------------------------------------------------------------------------------------------

    // If mem_op is padding, it must be a LOAD. Otherwise we have a soundness issue where a STORE
    // that's technically padding is not checked in the timestep but still makes it into the mem
    // transcript. Concretely, we check
    //       ¬mem_op.is_padding
    //     ∨ mem_op.is_load()
    mem_op
        .is_padding
        .not()
        .or(&mem_op.is_load()?)?
        .enforce_equal(&Boolean::TRUE)?;

    // If mem_op is a real entry, i.e., not padding, it must have timestamp t + 1
    mem_op
        .timestamp
        .conditional_enforce_equal(&t_plus_one, &mem_op.is_padding.not())?;

    // We're gonna update our running evals
    let mut new_evals = evals.clone();

    // Put the instruction load in the time-sorted execution mem
    new_evals
        .time_tr_exec
        .update(&pc_load.as_ff(false)?, chal)?;

    // Put the memory operation execution mem. If this is padding, then that's fine, because
    // there's as much padding here as in the memory trace
    // TODO: When tape reads are implemented, the below to be muxed. mem_op might go to the tape
    // tr, the time tr, or nowhere (if it's an aux tape read)
    new_evals.time_tr_exec.update(&mem_op.as_ff(false)?, chal)?;

    // --------------------------------------------------------------------------------------------
    // Running the CPU
    // --------------------------------------------------------------------------------------------

    // Unpack the LOAD at the program counter
    let pc = &pc_load.ram_idx;
    let instr = &pc_load.val;

    // If instr is a `lw`, then it needs the value from memory
    let opt_loaded_val = &mem_op.val;

    // Run the CPU for one tick
    //let (new_pc, new_regs, exec_mem_data) = exec_checker(pc, instr, regs, opt_loaded_val);
    let new_cpu_state = exec_checker::<NUM_REGS, _, _>(arch, &mem_op, cpu_state, instr)?;

    // --------------------------------------------------------------------------------------------
    // Checking memory-sorted transcript consistency
    // --------------------------------------------------------------------------------------------

    //
    // Entirely separately from the rest of this function, we check the consistency of the given
    // adjacent entries in the mem-sorted memory transcript (if they're provided)
    //

    let (prev, cur) = mem_tr_adj_pair;

    // These asserts are taken from Figure 5 in Constant-Overhead Zero-Knowledge for RAM
    // Programs: https://eprint.iacr.org/2021/979.pdf

    // Check that this is sorted by memory idx then time. That is, check
    //       prev.ram_idx < cur.ram_idx
    //     ∨ (prev.ram_idx == cur.ram_idx ∧ prev.timestamp < cur.timestamp);
    let ram_idx_has_incrd = prev
        .ram_idx_fp
        .is_cmp(&cur.ram_idx_fp, Ordering::Less, false)?;
    let ram_idx_is_eq = prev.ram_idx.is_eq(&cur.ram_idx)?;
    let t_has_incrd = prev
        .timestamp
        .is_cmp(&cur.timestamp, Ordering::Less, false)?;
    let cond = ram_idx_has_incrd.or(&ram_idx_is_eq.and(&t_has_incrd)?)?;
    cond.enforce_equal(&Boolean::TRUE)?;

    // Check that two adjacent LOADs on the same idx produced the same value. That is, check
    //       prev.ram_idx != cur.ram_idx
    //     ∨ prev.val == cur.val
    //     ∨ cur.op == STORE;
    let ram_idx_is_neq = prev.ram_idx.is_neq(&cur.ram_idx)?;
    let val_is_eq = prev.val_fp.is_eq(&cur.val_fp)?;
    let op_is_store = cur
        .op
        .is_eq(&MemOpKindVar::Constant(MemOpKind::Store.as_fp()))?;
    let cond = ram_idx_is_neq.or(&val_is_eq)?.or(&op_is_store)?;
    cond.enforce_equal(&Boolean::TRUE)?;

    // On every tick, absorb the second entry in to the mem-sorted execution trace
    new_evals.mem_tr_exec.update(&cur.as_ff(false)?, chal)?;

    // If it's an initial load, also put it into the mem trace of initial memory that's read in our
    // execution. That is, if
    //       prev.ram_idx < cur_ram_idx
    //     ∧ cur.op == LOAD
    // then absorb cur into tr_init_accessed
    let cur_as_initmem = cur.as_ff(true)?;
    let is_new_load = {
        let op_is_load = op_is_store.not();
        ram_idx_is_eq.and(&op_is_load)?
    };
    new_evals
        .tr_init_accessed
        .conditionally_update(&is_new_load, &cur_as_initmem, chal)?;

    Ok((new_cpu_state, new_evals))
}
