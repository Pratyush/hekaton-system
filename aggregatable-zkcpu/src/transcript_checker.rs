use crate::{
    exec_checker::{exec_checker, CpuStateVar},
    util::log2,
    word::{DWordVar, WordVar},
};

use core::{borrow::Borrow, cmp::Ordering};

use tinyram_emu::{
    interpreter::{MemOp, MemOpKind, TranscriptEntry},
    word::Word,
    ProgramMetadata,
};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    uint64::UInt64,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use rand::Rng;

/// A timestamp in the memory access transcript
type Timestamp = u64;
/// A timestamp in the memory access transcript, in ZK land
pub type TimestampVar<F> = FpVar<F>;

/// The offset to use when witnessing transcript entries. This gives us room for no-op entries at
/// the beginning. We only really need 1 padding element.
const TIMESTAMP_OFFSET: u64 = 1;

// Represents the running polynomial evaluation of a transcript. E.g.,
// `time_tr_exec(X) = (X - op1)(X - op2) ...)` evaluated at some challenge point. This also
// is used for unordered evals, such as `tr_init_accessed`.
#[derive(Clone)]
pub struct RunningEvalVar<F: PrimeField>(pub FpVar<F>);

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
        // Recall the polynoimal has factors (X - op). So to do an incremental computation, we
        // calculate `eval *= (chal - op)`. If `bit` == false, then the RHS is just 1.
        let coeff = FpVar::conditionally_select(bit, &(chal - entry), &FpVar::one())?;
        self.0 *= coeff;

        Ok(())
    }

    /// Updates the running eval with the given entry and challenge point
    fn update(&mut self, entry: &FpVar<F>, chal: &FpVar<F>) -> Result<(), SynthesisError> {
        self.conditionally_update(&Boolean::TRUE, entry, chal)
    }
}

impl<F: PrimeField> EqGadget<F> for RunningEvalVar<F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        self.0.is_eq(&other.0)
    }
}

impl<F: PrimeField> AllocVar<F, F> for RunningEvalVar<F> {
    fn new_variable<T: Borrow<F>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        FpVar::new_variable(cs, f, mode).map(RunningEvalVar)
    }
}

/// The kind of memory operation: load, store, read primary tape or read aux tape, in ZK land
pub type MemOpKindVar<F> = FpVar<F>;

/// This is the placeholder transcript entry that MUST begin the memory-ordered transcript. This is
/// never interpreted by the program, and its encoded values do not represent memory state.
fn transcript_starting_entry<W: Word>(
    real_transcript: &[TranscriptEntry<W>],
) -> TranscriptEntry<W> {
    // If you repeat the first item of the real transcript, it is always consistent
    real_transcript[0].clone()
}

impl<W: Word> ProcessedTranscriptEntry<W> {
    /// Encodes this transcript entry in the low bits of a field element for the purpose of
    /// representation as a coefficient in a polynomial. Does not include timestamp, i.e., sets
    /// `timestamp` to 0. `is_init` says whether this entry is part of the initial memory or not.
    pub(crate) fn as_ff_notime<F: PrimeField>(&self, is_init: bool) -> F {
        fn pow_two<G: PrimeField>(n: usize) -> G {
            G::from(2u8).pow([n as u64])
        }

        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp
        // The shape doesn't really matter as long as it's consistent.

        let mut shift = 0;
        let mut acc = F::zero();

        // Encode `timestamp` as 64 bits. It's all 0s here
        acc += F::zero() * pow_two::<F>(shift);
        shift += 64;

        // Encode `is_padding` as a bit
        acc += F::from(self.is_padding as u64) * pow_two::<F>(shift);
        shift += 1;

        // Encode `is_init` as a bit
        acc += F::from(is_init) * pow_two::<F>(shift);
        shift += 1;

        // Encode the memory op kind `op` as 2 bits
        acc += F::from(self.mem_op.kind() as u8) * pow_two::<F>(shift);
        shift += 2;

        // Encode `location` as a u64
        acc += F::from(self.mem_op.location()) * pow_two::<F>(shift);
        shift += 64;

        // val is a dword, so pack each of its words separately
        let val = self.mem_op.val();
        acc += F::from(val.1.into()) * pow_two::<F>(shift);
        shift += W::BITLEN;
        acc += F::from(val.0.into()) * pow_two::<F>(shift);
        shift += W::BITLEN;

        // Make sure we didn't over-pack the field element
        assert!(shift < F::MODULUS_BIT_SIZE as usize);

        acc
    }

    /// Encodes this transcript entry in the low bits of a field element for the purpose of
    /// representation as a coefficient in a polynomial. `is_init` says whether this entry is part
    /// of the initial memory or not.
    pub(crate) fn as_ff<F: PrimeField>(&self, is_init: bool) -> F {
        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp

        // Get the as_ff with timestamp 0
        let mut acc = self.as_ff_notime(is_init);

        // Add `timestamp` to the low bits
        acc += F::from(self.timestamp);

        acc
    }
}

/// This is a transcript entry with just 1 associated memory operation, and a padding flag. This is
/// easier to directly use than a [`TranscriptEntry`]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessedTranscriptEntry<W: Word> {
    /// Tells whether or not this entry is padding
    pub is_padding: bool,
    /// The timestamp of this entry. This MUST be greater than 0
    pub timestamp: Timestamp,
    /// The memory operation that occurred at this timestamp
    pub mem_op: MemOp<W>,
}

impl<W: Word> ProcessedTranscriptEntry<W> {
    /// Converts the given transcript entry (consisting of instruction load + optional mem op) into
    /// two processed entries. If there is no mem op, then a padding entry is created.
    pub(crate) fn new_pair(t: &TranscriptEntry<W>) -> [ProcessedTranscriptEntry<W>; 2] {
        // Get the instruction load. We stretch the timestamps to make every timestamp unique
        let first = ProcessedTranscriptEntry {
            is_padding: false,
            timestamp: 2 * t.timestamp + TIMESTAMP_OFFSET,
            mem_op: t.instr_load.clone(),
        };
        // The second entry is either the real memory operation, or it's a padding op that's just a
        // copy of the first instruction load. The reason it'd be a copy is because it's consistent
        // with the rest of the transcript.
        let second = match &t.mem_op {
            Some(op) => ProcessedTranscriptEntry {
                is_padding: false,
                timestamp: first.timestamp + 1,
                mem_op: op.clone(),
            },
            None => {
                let mut pad = first.clone();
                pad.is_padding = true;
                pad.timestamp = first.timestamp + 1;
                pad
            },
        };

        [first, second]
    }

    /// Returns a random `ProcessedTranscriptEntry`. Useful for testing
    pub(crate) fn rand(mut rng: impl Rng) -> Self {
        let is_padding = rng.gen();
        let timestamp = rng.gen();
        let mem_op = MemOp::rand(&mut rng);

        ProcessedTranscriptEntry {
            is_padding,
            timestamp,
            mem_op,
        }
    }

    /// Returns whether this memory operation is a `read`
    fn is_tape_op(&self) -> bool {
        match self.mem_op.kind() {
            MemOpKind::ReadPrimary | MemOpKind::ReadAux => true,
            _ => false,
        }
    }

    /// Returns whether this memory operation is a `load` or `store`
    pub(crate) fn is_ram_op(&self) -> bool {
        !self.is_tape_op()
    }
}

impl<W, WV, F> AllocVar<ProcessedTranscriptEntry<W>, F> for ProcessedTranscriptEntryVar<WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    fn new_variable<T: Borrow<ProcessedTranscriptEntry<WV::NativeWord>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let entry = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        // Witness the instruction load
        let timestamp_var = TimestampVar::new_variable(
            ns!(cs, "instr timestamp"),
            || entry.map(|e| F::from(e.timestamp)),
            mode,
        )?;
        // Witness the padding flag
        let is_padding_var =
            Boolean::new_variable(ns!(cs, "padding?"), || entry.map(|e| e.is_padding), mode)?;
        // Witness the op var
        let op = MemOpKindVar::new_variable(
            ns!(cs, "opkind"),
            || entry.map(|e| F::from(e.mem_op.kind() as u8)),
            mode,
        )?;
        // Witness the mem op RAM idx (or 0 if it's a tape op)
        let location = UInt64::new_variable(
            ns!(cs, "ram idx"),
            || entry.map(|e| e.mem_op.location()),
            mode,
        )?;
        let location_fp = location.as_fpvar()?;
        // Witness the mem op loaded/stored dword
        let val = DWordVar::new_variable(ns!(cs, "val"), || entry.map(|e| e.mem_op.val()), mode)?;
        let val_fp = val.as_fpvar()?;

        Ok(ProcessedTranscriptEntryVar {
            is_padding: is_padding_var,
            timestamp: timestamp_var,
            op,
            location,
            location_fp,
            val,
            val_fp,
        })
    }
}

/// The ZK version of `ProcessedTranscriptEntry`. It's also flattened so all the fields are right
/// here.
#[derive(Clone)]
pub struct ProcessedTranscriptEntryVar<WV: WordVar<F>, F: PrimeField> {
    /// Tells whether or not this entry is padding
    pub(crate) is_padding: Boolean<F>,
    /// The timestamp of this entry. This is at most 64 bits
    // TODO: Make sure this is 64 bits on construction
    timestamp: TimestampVar<F>,
    /// The type of memory op this is. This is determined by the discriminant of [`MemOpKind`]
    pub(crate) op: MemOpKindVar<F>,
    /// The RAM index being loaded from or stored to, or the location of the tape head
    pub(crate) location: UInt64<F>,
    /// `location` as a field element
    pub(crate) location_fp: FpVar<F>,
    /// The value being loaded or stored
    val: DWordVar<WV, F>,
    /// `val` as a field element
    val_fp: FpVar<F>,
}

impl<W, WV, F> R1CSVar<F> for ProcessedTranscriptEntryVar<WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    type Value = ProcessedTranscriptEntry<W>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.timestamp
            .cs()
            .or(self.op.cs())
            .or(self.location.cs())
            .or(self.val.w0.cs())
            .or(self.val.w1.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let is_padding = self.is_padding.value()?;
        let timestamp = {
            // Make sure the timestamp is at most a single u64
            let repr = self.timestamp.value()?.into_bigint();
            let limbs: &[u64] = repr.as_ref();
            // The number of limbs can exceed 1, but everything after the first must be 0
            assert!(limbs.iter().skip(1).all(|&x| x == 0));
            limbs[0]
        };
        // Get the discriminant of the memory op
        let op_disc = {
            let repr = self.op.value()?.into_bigint();

            // Make sure the op kind is at most one u64
            let limbs: &[u64] = repr.as_ref();
            // The number of limbs can exceed 1, but everything after the first must be 0
            assert!(limbs.iter().skip(1).all(|&x| x == 0));

            // Make sure the op kind is just 2 bits
            let disc = limbs[0];
            assert!(disc < 4);
            limbs[0] as u8
        };
        let val = self.val.value()?;
        let loc = self.location.value()?;

        // Make the mem op from the flattened values. The unwraps below are fine because if the
        // op_disc doesn't match the location type, this is a malformed value.
        let mem_op = if op_disc == MemOpKind::Load as u8 {
            MemOp::Load {
                val,
                location: W::from_u64(loc).unwrap(),
            }
        } else if op_disc == MemOpKind::Store as u8 {
            MemOp::Store {
                val,
                location: W::from_u64(loc).unwrap(),
            }
        } else {
            panic!("unexpected memop kind {op_disc}");
        };

        Ok(ProcessedTranscriptEntry {
            is_padding,
            timestamp,
            mem_op,
        })
    }
}

impl<WV: WordVar<F>, F: PrimeField> Default for ProcessedTranscriptEntryVar<WV, F> {
    fn default() -> Self {
        ProcessedTranscriptEntryVar {
            is_padding: Boolean::TRUE,
            timestamp: TimestampVar::zero(),
            op: MemOpKindVar::zero(),
            location: UInt64::zero(),
            location_fp: FpVar::zero(),
            val: DWordVar::zero(),
            val_fp: FpVar::zero(),
        }
    }
}

impl<WV: WordVar<F>, F: PrimeField> ProcessedTranscriptEntryVar<WV, F> {
    /// Returns whether this memory operation is a `load`
    fn is_load(&self) -> Result<Boolean<F>, SynthesisError> {
        self.op
            .is_eq(&MemOpKindVar::Constant(F::from(MemOpKind::Load as u8)))
    }

    /// Returns whether this memory operation is a `store`
    fn is_store(&self) -> Result<Boolean<F>, SynthesisError> {
        self.op
            .is_eq(&MemOpKindVar::Constant(F::from(MemOpKind::Store as u8)))
    }

    /// Returns whether this memory operation is a `read`
    fn is_tape_op(&self) -> Result<Boolean<F>, SynthesisError> {
        let is_primary = self
            .op
            .is_eq(&FpVar::Constant(F::from(MemOpKind::ReadPrimary as u8)))?;
        let is_aux = self
            .op
            .is_eq(&FpVar::Constant(F::from(MemOpKind::ReadAux as u8)))?;
        is_primary.or(&is_aux)
    }

    /// Returns whether this memory operation is a `load` or `store`
    fn is_ram_op(&self) -> Result<Boolean<F>, SynthesisError> {
        Ok(self.is_tape_op()?.not())
    }
}

impl<WV: WordVar<F>, F: PrimeField> ProcessedTranscriptEntryVar<WV, F> {
    fn pow_two<G: PrimeField>(n: usize) -> FpVar<G> {
        FpVar::Constant(G::from(2u8).pow([n as u64]))
    }

    /// Encodes this transcript entry as a field element, not including `timestamp` (i.e., setting
    /// `timestamp` to 0). `is_init` says whether this entry is part of the initial memory or not.
    fn as_ff_notime(&self, is_init: bool) -> Result<FpVar<F>, SynthesisError> {
        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp
        // We set timestamp to 0
        let mut acc = FpVar::<F>::zero();
        let mut shift = 0;

        // Encode `timestamp` as 64 bits. It's all 0s here
        acc += FpVar::zero() * Self::pow_two(shift);
        shift += 64;

        // Encode `is_padding` as a bit
        acc += FpVar::from(self.is_padding.clone()) * Self::pow_two(shift);
        shift += 1;

        // Encode `is_init` as a bit
        acc += FpVar::Constant(F::from(is_init)) * Self::pow_two(shift);
        shift += 1;

        // Encode the memory op kind `op` as 2 bits
        acc += FpVar::from(self.op.clone()) * Self::pow_two(shift);
        shift += 2;

        // Encode `location` as a u64
        acc += &self.location_fp * Self::pow_two(shift);
        shift += 64;

        // Encode `val` as a dword
        acc += &self.val_fp * Self::pow_two(shift);
        // shift += 2 * W::NativeWord::BITLEN;

        Ok(acc)
    }

    /// Encodes this transcript entry as a field element.`is_init` says whether this entry is part
    /// of the initial memory or not.
    fn as_ff(&self, is_init: bool) -> Result<FpVar<F>, SynthesisError> {
        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp
        let mut acc = self.as_ff_notime(is_init)?;

        // Add timestamp in the low 64 bits
        acc += &self.timestamp;

        Ok(acc)
    }

    // Extracts the word at the given RAM index, returning it and an error flag. `err = true` iff
    // `self.idx` and the high (non-byte-precision) bits of `idx` are not equal, or
    // `self.is_padding == true`.
    pub(crate) fn select_word(&self, idx: &WV) -> Result<(WV, Boolean<F>), SynthesisError> {
        // Check if this is padding
        let mut err = self.is_padding.clone();

        // Do the index check. Mask out the bottom bits of idx. We just need to make sure that this
        // load is the correct dword, i.e., all but the bottom bitmask bits of idx and self.location
        // match.
        let bytes_per_word = WV::BITLEN / 8;
        let word_bitmask_len = log2(bytes_per_word);
        let dword_bitmask_len = word_bitmask_len + 1;

        let idx_bits = idx.as_le_bits();
        let word_aligned_idx_bits = &idx_bits[word_bitmask_len..];
        let dword_aligned_idx_bits = &idx_bits[dword_bitmask_len..];

        // Check that the dword-aligned indices match
        for (b1, b2) in dword_aligned_idx_bits.iter().zip(
            self.location
                .as_le_bits()
                .into_iter()
                .skip(dword_bitmask_len),
        ) {
            err = err.or(&b1.is_neq(&b2)?)?;
        }

        // Now get the word-aligned index and use the lowest word bit to select the word
        let word_selector = &word_aligned_idx_bits[0];
        let out = WV::conditionally_select(word_selector, &self.val.w1, &self.val.w0)?;

        Ok((out, err))
    }

    /// Returns the lower word of this dword
    pub(crate) fn val_low_word(&self) -> WV {
        self.val.w0.clone()
    }
}

/// Running evals used inside `transcript_checker`
#[derive(Clone, Default)]
pub struct TranscriptCheckerEvals<F: PrimeField> {
    // The time-sorted trace of our execution
    pub time_tr_exec: F,

    // The mem-sorted trace of our execution
    pub mem_tr_exec: F,

    // The unsorted trace of the initial memory that's read in our execution
    pub tr_init_accessed: F,
}

/// ZK version of TranscriptCheckerEvals
#[derive(Clone, Default)]
pub struct TranscriptCheckerEvalsVar<F: PrimeField> {
    // The time-sorted trace of our execution
    pub time_tr_exec: RunningEvalVar<F>,

    // The mem-sorted trace of our execution
    pub mem_tr_exec: RunningEvalVar<F>,

    // The unsorted trace of the initial memory that's read in our execution
    pub tr_init_accessed: RunningEvalVar<F>,
}

impl<F: PrimeField> EqGadget<F> for TranscriptCheckerEvalsVar<F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        self.time_tr_exec
            .is_eq(&other.time_tr_exec)?
            .and(&self.mem_tr_exec.is_eq(&other.mem_tr_exec)?)?
            .and(&self.tr_init_accessed.is_eq(&other.tr_init_accessed)?)
    }
}

impl<F: PrimeField> AllocVar<TranscriptCheckerEvals<F>, F> for TranscriptCheckerEvalsVar<F> {
    fn new_variable<T: Borrow<TranscriptCheckerEvals<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let evals = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        // Allocate all the fields
        let time_tr_exec = FpVar::new_variable(
            ns!(cs, "time tr exec"),
            || evals.map(|e| F::from(e.time_tr_exec)),
            mode,
        )
        .map(RunningEvalVar)?;
        let mem_tr_exec = FpVar::new_variable(
            ns!(cs, "mem tr exec"),
            || evals.map(|e| F::from(e.mem_tr_exec)),
            mode,
        )
        .map(RunningEvalVar)?;
        let tr_init_accessed = FpVar::new_variable(
            ns!(cs, "tr init accessed"),
            || evals.map(|e| F::from(e.tr_init_accessed)),
            mode,
        )
        .map(RunningEvalVar)?;

        Ok(TranscriptCheckerEvalsVar {
            time_tr_exec,
            mem_tr_exec,
            tr_init_accessed,
        })
    }
}

/// This function checks the time- and mem-sorted transcripts for consistency. It also accumulates
/// both transcripts into their respective polynomial evaluations.
///
/// # Requires
///
/// `mem_tr_adj_seq` MUST have length 3;
pub fn transcript_checker<const NUM_REGS: usize, WV: WordVar<F>, F: PrimeField>(
    meta: ProgramMetadata,
    cpu_state: &CpuStateVar<WV, F>,
    chal: &FpVar<F>,
    instr_load: &ProcessedTranscriptEntryVar<WV, F>,
    mem_op: &ProcessedTranscriptEntryVar<WV, F>,
    mem_tr_adj_seq: &[ProcessedTranscriptEntryVar<WV, F>],
    evals: &TranscriptCheckerEvalsVar<F>,
) -> Result<(CpuStateVar<WV, F>, TranscriptCheckerEvalsVar<F>), SynthesisError> {
    assert_eq!(mem_tr_adj_seq.len(), 3);

    // pc_load occurs at time t
    let t = &instr_load.timestamp;
    // mem_op, if defined, occurs at time t
    let t_plus_one = t + FpVar::one();

    let is_padding = &mem_op.is_padding;

    // TODO: MUST check that mem_op.location is dword-aligned (in Harvard: check bottom bit is 0, in
    // Von Neumann: check that bottom log₂(dword_bytelen) bits are 0)

    // --------------------------------------------------------------------------------------------
    // Housekeeping of memory operations
    // --------------------------------------------------------------------------------------------

    // If mem_op is padding, it must be a LOAD. Otherwise we have a soundness issue where a STORE
    // that's technically padding is not checked in the timestep but still makes it into the mem
    // transcript. Concretely, we check
    //       ¬mem_op.is_padding
    //     ∨ mem_op.is_load()
    is_padding
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
        .update(&instr_load.as_ff(false)?, chal)?;

    // Put the memory operation in the correct transcript. If it's padding, don't absorb it.

    // Where the serialized memory op gets absorbed depends on the kind of memory op it is. Make
    // some mux vars.
    let is_tape_op = mem_op.is_tape_op()?;
    let is_ram_op = is_tape_op.not();

    // Absorb into the RAM transcript if it's a RAM op and not padding. Absorb into the primary
    // tape transcript if it's a primary tape op and not padding. If it's an auxiliary tape op,
    // there's no need to absorb at all.
    new_evals.time_tr_exec.conditionally_update(
        &is_ram_op.and(&is_padding.not())?,
        &mem_op.as_ff(false)?,
        chal,
    )?;
    // TODO: make primary tape transcript

    // --------------------------------------------------------------------------------------------
    // Running the CPU
    // --------------------------------------------------------------------------------------------

    // Unpack the load at the program counter
    let instr = &instr_load.val;

    // Run the CPU for one tick
    let new_cpu_state = exec_checker::<NUM_REGS, _, _>(meta, &mem_op, cpu_state, instr)?;

    // --------------------------------------------------------------------------------------------
    // Checking memory-sorted transcript consistency
    // --------------------------------------------------------------------------------------------

    // Entirely separately from the rest of this function, we check the consistency of the given
    // adjacent entries in the mem-sorted memory transcript

    // Go through the adjacent entries of the mem-sorted trace using a sliding window of size 2
    for pair in mem_tr_adj_seq.windows(2) {
        let prev = &pair[0];
        let cur = &pair[1];

        // Ensure that these are RAM and not tape operations. Tape consistency is not handled here.
        prev.is_ram_op()?.enforce_equal(&Boolean::TRUE)?;
        cur.is_ram_op()?.enforce_equal(&Boolean::TRUE)?;
        // For the same reasons as earlier in this function, ensure that, if these ops are padding,
        // they are `load` ops
        prev.is_padding
            .not()
            .or(&prev.is_load()?)?
            .enforce_equal(&Boolean::TRUE)?;
        cur.is_padding
            .not()
            .or(&prev.is_load()?)?
            .enforce_equal(&Boolean::TRUE)?;

        // These asserts are taken from Figure 5 in Constant-Overhead Zero-Knowledge for RAM
        // Programs: https://eprint.iacr.org/2021/979.pdf

        // Check that this is sorted by memory idx then time. That is, check
        //       prev.location < cur.location
        //     ∨ (prev.location == cur.location ∧ prev.timestamp < cur.timestamp);
        let loc_has_incrd = prev
            .location_fp
            .is_cmp(&cur.location_fp, Ordering::Less, false)?;
        let loc_is_eq = prev.location.is_eq(&cur.location)?;
        let t_has_incrd = prev
            .timestamp
            .is_cmp(&cur.timestamp, Ordering::Less, false)?;
        let cond = loc_has_incrd.or(&loc_is_eq.and(&t_has_incrd)?)?;
        cond.enforce_equal(&Boolean::TRUE)?;

        // Check that two adjacent LOADs on the same idx produced the same value. That is, check
        //       prev.location != cur.location
        //     ∨ prev.val == cur.val
        //     ∨ cur.op == STORE;
        let loc_is_neq = prev.location.is_neq(&cur.location)?;
        let val_is_eq = prev.val_fp.is_eq(&cur.val_fp)?;
        let op_is_store = cur.is_store()?;
        let cond = loc_is_neq.or(&val_is_eq)?.or(&op_is_store)?;
        cond.enforce_equal(&Boolean::TRUE)?;

        // On every tick, absorb all but the first entry in to the mem-sorted execution trace,
        // unless it is padding.
        new_evals.mem_tr_exec.conditionally_update(
            &cur.is_padding.not(),
            &cur.as_ff(false)?,
            chal,
        )?;

        // If it's an initial load, also put it into the mem trace of initial memory that's read in
        // our execution. That is, if
        //       prev.location < cur_location
        //     ∧ cur.op == LOAD
        // then absorb cur into tr_init_accessed.
        // We don't have to worry about whether this is padding, padding is never an initial load.
        // padding is always a repetition of the last mem op (converted to a load, if need be).
        let cur_as_initmem = cur.as_ff(true)?;
        let is_new_load = loc_is_neq.and(&cur.is_load()?)?;
        new_evals
            .tr_init_accessed
            .conditionally_update(&is_new_load, &cur_as_initmem, chal)?;
    }

    Ok((new_cpu_state, new_evals))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transcript_utils;

    use tinyram_emu::{ProgramMetadata, TinyRamArch};

    use ark_bls12_381::Fr;
    use ark_ff::{Field, UniformRand};
    use ark_r1cs_std::{alloc::AllocVar, uint32::UInt32, R1CSVar};
    use ark_relations::{ns, r1cs::ConstraintSystem};

    const NUM_REGS: usize = 16;
    type F = Fr;
    type WV = UInt32<F>;
    type W = <WV as WordVar<F>>::NativeWord;

    // Helper function that runs the given TinyRAM code through the symbolic transcript checker
    fn transcript_tester(code: &str, primary_input: &[W], aux_input: &[W]) {
        let mut rng = rand::thread_rng();
        let cs = ConstraintSystem::new_ref();

        let assembly = tinyram_emu::parser::assemble(code);

        // VonNeumann architecture, and no `read` operations.
        let meta = ProgramMetadata {
            arch: TinyRamArch::VonNeumann,
            primary_input_len: primary_input.len() as u32,
            aux_input_len: aux_input.len() as u32,
        };

        let (output, transcript) = tinyram_emu::interpreter::run_program::<W, NUM_REGS>(
            TinyRamArch::VonNeumann,
            &assembly,
            primary_input,
            aux_input,
        );

        // TODO: Put primary reads into a different transcript

        let (time_sorted_transcript, mem_sorted_transcript) =
            transcript_utils::sort_and_pad(&transcript);

        // Now witness the time- and memory-sorted transcripts
        let time_sorted_transcript_vars = time_sorted_transcript
            .iter()
            .map(|t| {
                ProcessedTranscriptEntryVar::<WV, _>::new_witness(ns!(cs, "t"), || Ok(t)).unwrap()
            })
            .collect::<Vec<_>>();
        let mem_sorted_transcript_vars = mem_sorted_transcript
            .iter()
            .map(|t| ProcessedTranscriptEntryVar::new_witness(ns!(cs, "t"), || Ok(t)).unwrap())
            .collect::<Vec<_>>();

        // Doesn't matter what the challenge value is just yet
        let chal = F::rand(&mut rng);
        let chal_var = FpVar::constant(chal);
        // Let the evals be empty
        let mut evals = TranscriptCheckerEvalsVar::default();

        // Run the CPU. Every tick takes in 2 time-sorted transcript entries, with no overlaps.
        // Also every tick takes in 3 mem-sorted transcript entries, with 1 overlap between ticks.
        let mut cpu_state = CpuStateVar::default::<NUM_REGS>();
        for (time_sorted_transcript_pair, mem_sorted_transcript_triple) in
            time_sorted_transcript_vars
                .chunks(2)
                .zip(mem_sorted_transcript_vars.windows(3).step_by(2))
        {
            // Unpack the time-sorted transcript values
            let instr_load_var = &time_sorted_transcript_pair[0];
            let mem_op_var = &time_sorted_transcript_pair[1];

            (cpu_state, evals) = transcript_checker::<NUM_REGS, _, _>(
                meta,
                &cpu_state,
                &chal_var,
                instr_load_var,
                mem_op_var,
                &mem_sorted_transcript_triple,
                &evals,
            )
            .unwrap();
        }

        // Make sure nothing errored
        if !cs.is_satisfied().unwrap() {
            panic!("unsatisfied constraint: {:?}", cs.which_is_unsatisfied());
        }

        // Check the output is set and correct
        assert!(cpu_state.answer.is_set.value().unwrap());
        assert_eq!(output, cpu_state.answer.val.value().unwrap());

        // Check that the time- and mem-sorted transcript evals are equal
        assert_eq!(evals.time_tr_exec.0.value(), evals.mem_tr_exec.0.value());
        // Also check that the native eval agrees with the ZK eval
        let t_eval: F = time_sorted_transcript
            .into_iter()
            .map(|v| {
                if v.is_padding || v.is_tape_op() {
                    F::ONE
                } else {
                    chal - v.as_ff::<F>(false)
                }
            })
            .product();
        let m_eval: F = mem_sorted_transcript
            .into_iter()
            .map(|v| {
                if v.is_padding || v.is_tape_op() {
                    F::ONE
                } else {
                    chal - v.as_ff::<F>(false)
                }
            })
            .product();
        assert_eq!(m_eval, t_eval);
        assert_eq!(t_eval, evals.time_tr_exec.0.value().unwrap());
    }

    // Tests that a simple store and load passes the transcript checker
    #[test]
    fn simple_mem() {
        transcript_tester(
            "\
        ; TinyRAM V=2.000 M=vn W=32 K=8
        add r0, r0, 10     ; let r0 = 10
        store.w 998, r0    ; Dummy store: r0 -> RAM[999]
        load.w r7, 999     ; Dummy load:  r7 <- RAM[999]
        answer r7
        ",
            &[],
            &[],
        );
    }

    // Tests that a RAM-free skip3 program passes the transcript checker
    #[test]
    fn skip3_nomem() {
        transcript_tester(
            "\
        ; TinyRAM V=2.000 M=vn W=32 K=8
        _loop: add  r0, r0, 1     ; incr i
               add  r2, r2, 1     ; incr mul3_ctr
               cmpe r0, 17        ; if i == 17:
               cjmp _end          ;     jump to end
               cmpe r2, 3         ; else if mul3_ctr == 3:
               cjmp _acc          ;     jump to acc
               jmp  _loop         ; else jump to beginning

         _acc: add r1, r1, r0     ; Accumulate i into acc
               xor r2, r2, r2     ; Clear mul3_ctr
               jmp _loop          ; Jump back to the loop

         _end: answer r1          ; Return acc
        ",
            &[],
            &[],
        );
    }

    // Tests that a RAM-heavy skip3 program passes the transcript checker
    #[test]
    fn skip3_withmem() {
        transcript_tester(
            "\
        ; TinyRAM V=2.000 M=vn W=32 K=8
        _loop: load.w r1, 600     ; acc <- RAM[600]
               load.w r0, 604     ; i <- RAM[604]
               add  r0, r0, 1     ; incr i
               add  r2, r2, 1     ; incr mul3_ctr
               cmpe r0, 17        ; if i == 17:
               cjmp _end          ;     jump to end
               cmpe r2, 3         ; else if mul3_ctr == 3:
               cjmp _acc          ;     jump to acc
                                  ; else
               store.w 604, r0    ;     i -> RAM[604]
               jmp  _loop         ;     jump to beginning

         _acc: add r1, r1, r0     ; Accumulate i into acc
               xor r2, r2, r2     ; Clear mul3_ctr
               store.w 600, r1    ; acc -> RAM[600]
               store.w 604, r0    ; i -> RAM[604]
               jmp _loop          ; Jump back to the loop

         _end: answer r1          ; Return acc
        ",
            &[],
            &[],
        );
    }

    // Tests a basic `read` workload
    #[test]
    fn sum_tape() {
        use ark_relations::r1cs::{ConstraintLayer, ConstraintTrace, TracingMode};
        use tracing_subscriber::layer::SubscriberExt;

        // First, some boilerplate that helps with debugging
        //let mut layer = ConstraintLayer::default();
        //layer.mode = TracingMode::OnlyConstraints;
        //let subscriber = tracing_subscriber::FmtSubscriber::default().with(layer);
        //let _guard = tracing::subscriber::set_default(subscriber);

        //let subscriber = tracing_subscriber::Registry::default().with(layer);
        //tracing::subscriber::set_global_default(subscriber).unwrap();

        // Sum [1, n] from primary tape, and sum 100*[1, n] from auxiliary tape. Then output the
        // sum of those sums.

        let n = 1;
        let primary_tape = (1..=n)
            .map(W::from_u64)
            .collect::<Result<Vec<W>, _>>()
            .unwrap();
        let aux_tape = (1..=n)
            .map(|x| W::from_u64(100 * x))
            .collect::<Result<Vec<W>, _>>()
            .unwrap();

        transcript_tester(
            "\
        ; TinyRAM V=2.000 M=vn W=32 K=8
        _loop: read r0, 0     ; r0 <- primary tape
               read r1, 1     ; r1 <- aux tape
               cjmp _end      ; if read failed, jump to end
               add r2, r2, r0 ; else, r2 += r0 and r3 += r1
               add r3, r3, r1
               jmp _loop      ; goto beginning
         _end: add r4, r2, r3 ; at the end: return r2 + r3
               answer r4
        ",
            &primary_tape,
            &aux_tape,
        );
    }

    // Tests that ProcessedTranscriptEntry::as_ff and ProcessedTranscriptEntryVar::as_ff agree
    #[test]
    fn ff_encoding_equality() {
        let mut rng = rand::thread_rng();
        let cs = ConstraintSystem::new_ref();

        // Make 200 random transcript entries and check that the native and ZK verisons encode to
        // the same value
        for _ in 0..200 {
            let entry = ProcessedTranscriptEntry::rand(&mut rng);
            let entry_var =
                ProcessedTranscriptEntryVar::<WV, _>::new_witness(ns!(cs, "e"), || Ok(&entry))
                    .unwrap();

            assert_eq!(
                entry.as_ff::<F>(true),
                entry_var.as_ff(true).unwrap().value().unwrap()
            );
        }
    }
}
