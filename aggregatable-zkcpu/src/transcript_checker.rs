use crate::common::*;

use core::cmp::Ordering;

use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    uint32::UInt32,
};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// A timestamp in the memory access transcript
type Timestamp = u32;
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
    /// Updates the running eval with the given entry and challenge point
    fn update(&mut self, entry: &FpVar<F>, chal: &FpVar<F>) {
        // Recall the polynoimal has factors (X - op). So to do an incremental computation, we
        // calculate `eval *= (chal - op)`.
        self.0 *= chal - entry;
    }
}

/// The kind of memory operation: load or store
#[derive(Clone)]
enum MemOpKind {
    Load,
    Store,
}

impl MemOpKind {
    fn as_bool(&self) -> bool {
        match self {
            MemOpKind::Load => false,
            MemOpKind::Store => false,
        }
    }
}

/// The kind of memory operation: load or store, in ZK land
type MemOpKindVar<F> = Boolean<F>;

/// An entry in the transcript of RAM accesses
#[derive(Clone)]
enum TranscriptEntry {
    /// If there are more ticks than memory accesses, we pad out the transcript
    Padding,

    /// A real, non-padding entry
    Entry {
        /// The timestamp of this entry. This MUST be greater than 0
        t: Timestamp,
        /// LOAD or STORE
        op: MemOpKind,
        /// Either the index being loaded from or stored to
        ramidx: RamIdx,
        /// The value being loaded or stored
        val: Word,
    },
}

/// This is the placeholder transcript entry that MUST begin the memory-ordered transcript. This is
/// never interpreted by the program, and its encoded values do not represent memory state.
fn transcript_starting_entry(real_transcript: &[TranscriptEntry]) -> TranscriptEntry {
    // If you repeat the first item of the real transcript, it is always consistent
    real_transcript[0].clone()
}

impl TranscriptEntry {
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
struct TranscriptEntryVar<F: PrimeField> {
    /// Tells whether or not this entry is padding
    is_padding: Boolean<F>,
    /// The timestamp of this entry. This is guaranteed to be less than 32 bits.
    timestamp: TimestampVar<F>,
    /// LOAD or STORE
    op: MemOpKindVar<F>,
    /// Either the index being loaded from or stored to
    ram_idx: RamIdxVar<F>,
    /// The value being loaded or stored
    val: WordVar<F>,
}

fn uint32_to_fpvar<F: PrimeField>(x: &UInt32<F>) -> Result<FpVar<F>, SynthesisError> {
    let bits = x.to_bits_le();
    let zero = FpVar::<F>::zero();

    let mut acc = FpVar::<F>::zero();
    for (i, bit) in bits.iter().enumerate() {
        let cur_pow_2 = FpVar::Constant(F::from(1u64 << i));
        acc += FpVar::conditionally_select(&bit, &cur_pow_2, &zero)?;
    }

    Ok(acc)
}

impl<F: PrimeField> TranscriptEntryVar<F> {
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

        // Encode `timestamp`. Make sure it's 32 bits. Then shift by 32.
        let shift_var = FpVar::<F>::Constant(F::from(1u64 << shift));
        self.timestamp
            .enforce_cmp(&FpVar::Constant(F::from(u32::MAX)), Ordering::Less, true)?;
        acc += &self.timestamp * shift_var;
        shift += 32;

        // Encode `op`. Shift by 1.
        let shift_var = FpVar::<F>::Constant(F::from(1u64 << shift));
        acc += FpVar::from(self.op.clone()) * shift_var;
        shift += 1;

        // Encode `ram_idx`. Make sure it's 32 bits. Then shift by 32.
        let shift_var = FpVar::<F>::Constant(F::from(1u64 << shift));
        acc += &self.ram_idx * shift_var;
        shift += 32;

        // Encode `val`
        let shift_var = FpVar::<F>::Constant(F::from(1u64 << shift));
        acc += uint32_to_fpvar(&self.val)? * shift_var;

        Ok(acc)
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

/// Returns a value which, if absorbed into the running eval, will mutate nothing. To work, it
/// needs the challenge point.
fn dummy_running_eval_value<F: PrimeField>(chal: &FpVar<F>) -> FpVar<F> {
    // When you do an update(), it computes eval *= chal - entry. If you let entry = chal-1, then
    // you get eval *= 1, i.e., a no-op.
    chal - FpVar::one()
}

/// This function checks the time- and mem-sorted transcripts for consistency. It also accumulates
/// both transcripts into their respective polynomial evaluations.
fn transcript_checker<F: PrimeField>(
    t: &TimestampVar<F>,
    chal: &FpVar<F>,
    pc_load: &TranscriptEntryVar<F>,
    mem_op: &TranscriptEntryVar<F>,
    mem_tr_adj_pair: (&TranscriptEntryVar<F>, &TranscriptEntryVar<F>),
    evals: &TranscriptCheckerEvals<F>,
) -> Result<(), SynthesisError> {
    // pc_load occurs at time t
    let t = &pc_load.timestamp;
    // mem_op, if defined, occurs at time t
    let t_plus_one = t + FpVar::one();
    // The timestamp for the next tick is t+2
    let next_t = &t_plus_one + FpVar::one();

    // If mem_op is a real entry, i.e., not padding, it must have timestamp t + 1
    mem_op
        .timestamp
        .conditional_enforce_equal(&t_plus_one, &mem_op.is_padding.not())?;

    // We're gonna update our running evals
    let mut new_evals = evals.clone();

    // Put the instruction LOAD in the time-sorted execution mem
    new_evals.time_tr_exec.update(&pc_load.as_ff(false)?, chal);

    // Put the memory operation execution mem. If this is padding, then that's fine, because
    // there's as much padding here as in the memory trace
    new_evals.time_tr_exec.update(&mem_op.as_ff(false)?, chal);

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
    let ram_idx_has_incrd = prev.ram_idx.is_cmp(&cur.ram_idx, Ordering::Less, false)?;
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
    let val_is_eq = prev.val.is_eq(&cur.val)?;
    let op_is_store = cur
        .op
        .is_eq(&MemOpKindVar::Constant(MemOpKind::Store.as_bool()))?;
    let cond = ram_idx_is_neq.or(&val_is_eq)?.or(&op_is_store)?;
    cond.enforce_equal(&Boolean::TRUE)?;

    // On every tick, absorb the second entry in to the mem-sorted execution trace
    new_evals.mem_tr_exec.update(&cur.as_ff(false)?, chal);

    // If it's an initial load, also put it into the mem trace of initial memory that's read in our
    // execution. That is, if
    //       prev.ram_idx < cur_ram_idx
    //     ∧ cur.op == LOAD
    // then absorb cur into tr_init_accessed
    let cur_as_initmem = cur.as_ff(true)?;
    let dummy_entry = dummy_running_eval_value(chal);
    let is_new_load = {
        let op_is_load = op_is_store.not();
        ram_idx_is_eq.and(&op_is_load)?
    };
    let val_to_absorb = FpVar::conditionally_select(&is_new_load, &cur_as_initmem, &dummy_entry)?;
    new_evals.tr_init_accessed.update(&val_to_absorb, chal);

    unimplemented!()
}
