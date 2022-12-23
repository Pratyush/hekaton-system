use crate::{
    common::*,
    exec_checker::{exec_checker, CpuState, ExecTickMemData},
    util::log2,
    word::{DWord, DWordVar, WordVar},
};

use core::borrow::Borrow;

use tinyram_emu::{
    interpreter::{MemOp, MemOpKind, TranscriptEntry},
    word::Word,
    TinyRamArch,
};

use core::cmp::Ordering;

use ark_ff::{Field, FpParameters, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    uint32::UInt32,
    uint8::UInt8,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};

/// A timestamp in the memory access transcript
type Timestamp = u64;
/// A timestamp in the memory access transcript, in ZK land
type TimestampVar<F> = FpVar<F>;

/// The offset to use when witnessing transcript entries. This gives us room for no-op entries at
/// the beginning. We only really need 1 padding element.
const TIMESTAMP_OFFSET: u64 = 1;

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

/// The kind of memory operation: load, store, read primary tape or read aux tape, in ZK land
type MemOpKindVar<F> = FpVar<F>;

/// This is the placeholder transcript entry that MUST begin the memory-ordered transcript. This is
/// never interpreted by the program, and its encoded values do not represent memory state.
fn transcript_starting_entry<W: Word>(
    real_transcript: &[TranscriptEntry<W>],
) -> TranscriptEntry<W> {
    // If you repeat the first item of the real transcript, it is always consistent
    real_transcript[0].clone()
}

impl<W: Word> ProcessedTranscriptEntry<W> {
    fn pow_two<G: Field>(n: usize) -> G {
        G::from(2u8).pow([n as u64])
    }

    /// Encodes this transcript entry in the low bits of a field element for the purpose of
    /// representation as a coefficient in a polynomial. Returns the field element and the
    /// number of bits packed.
    fn as_ff_helper<F: Field>(&self) -> (F, usize) {
        // We pack the variables into the field element as 0...0 is_padding || mem_op || timestamp
        // The shape doesn't really matter as long as it's consistent;

        // Keep track of the running bitlength
        let mut bitlen = 0;
        let mut out = F::zero();

        // Pack the padding bit
        out += Self::pow_two::<F>(bitlen) * F::from(self.is_padding as u64);
        bitlen += 1;

        // Pack the mem op
        let (mem_op_ff, mem_op_bitlen) = self.mem_op.as_ff::<F>();
        out += Self::pow_two::<F>(bitlen) * mem_op_ff;
        bitlen += mem_op_bitlen;

        (out, bitlen)
    }

    /// Encodes this transcript entry as a field element for the purpose of representation as a
    /// coefficient in a polynomial. This includes the timstamp
    pub(crate) fn as_ff<F: PrimeField>(&self) -> F {
        // Get the field element without the timestamp
        let (mut out, mut bitlen) = self.as_ff_helper();

        // Pack the 64-bit timestamp
        out += Self::pow_two::<F>(bitlen) * F::from(self.timestamp);
        bitlen += 64;

        // Make sure we didn't over-pack the field element
        assert!(bitlen < F::Params::MODULUS_BITS as usize);

        out
    }

    /// Encodes this transcript entry as a field element for the purpose of representation as a
    /// coefficient in a polynomial. The `_notime` variant does not include the timestamp in the
    /// representation (i.e., it sets `t=0`).
    pub(crate) fn to_ff_notime<F: Field>(&self) -> F {
        // We just call the helper function, which doesn't include the timestamp
        self.as_ff_helper().0
    }
}

/// This is a transcript entry with just 1 associated memory operation, and a padding flag. This is
/// easier to directly use than a [`TranscriptEntry`]
#[derive(Clone)]
pub(crate) struct ProcessedTranscriptEntry<W: Word> {
    /// Tells whether or not this entry is padding
    is_padding: bool,
    /// The timestamp of this entry. This MUST be greater than 0
    timestamp: u64,
    /// The memory operation that occurred at this timestamp
    mem_op: MemOp<W>,
}

impl<W: Word> ProcessedTranscriptEntry<W> {
    /// Converts the given transcript entry (consisting of instruction load + optional mem op) into two processed entries. If there is no mem op, then a padding entry is created.
    fn new_pair(t: &TranscriptEntry<W>) -> [ProcessedTranscriptEntry<W>; 2] {
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
            }
        };

        [first, second]
    }
}

impl<W: WordVar<F>, F: PrimeField> AllocVar<ProcessedTranscriptEntry<W::NativeWord>, F>
    for ProcessedTranscriptEntryVar<W, F>
{
    fn new_variable<T: Borrow<ProcessedTranscriptEntry<W::NativeWord>>>(
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
        // Witness the mem op RAM idx
        let ram_idx = W::new_variable(
            ns!(cs, "ram idx"),
            || entry.map(|e| e.mem_op.location()),
            mode,
        )?;
        let ram_idx_fp = ram_idx.as_fpvar()?;
        // Witness the mem op loaded/stored dword
        let val = DWordVar::new_variable(ns!(cs, "val"), || entry.map(|e| e.mem_op.val()), mode)?;
        let val_fp = val.as_fpvar()?;

        Ok(ProcessedTranscriptEntryVar {
            is_padding: is_padding_var,
            timestamp: timestamp_var,
            op,
            ram_idx,
            ram_idx_fp,
            val,
            val_fp,
        })
    }
}

/// The ZK version of `ProcessedTranscriptEntry`. It's also flattened so all the fields are right
/// here.
#[derive(Clone)]
pub(crate) struct ProcessedTranscriptEntryVar<W: WordVar<F>, F: PrimeField> {
    /// Tells whether or not this entry is padding
    pub(crate) is_padding: Boolean<F>,
    /// The timestamp of this entry. This is at most 64 bits
    timestamp: TimestampVar<F>,
    /// The type of memory op this is. This is determined by the discriminant of [`MemOpKind`]
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

impl<W: WordVar<F>, F: PrimeField> Default for ProcessedTranscriptEntryVar<W, F> {
    fn default() -> Self {
        ProcessedTranscriptEntryVar {
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

impl<W: WordVar<F>, F: PrimeField> ProcessedTranscriptEntryVar<W, F> {
    /// Returns whether this memory operation is a load
    fn is_load(&self) -> Result<Boolean<F>, SynthesisError> {
        self.op
            .is_eq(&MemOpKindVar::Constant(F::from(MemOpKind::Load as u8)))
    }

    /// Returns whether this memory operation is a store
    fn is_store(&self) -> Result<Boolean<F>, SynthesisError> {
        self.op
            .is_eq(&MemOpKindVar::Constant(F::from(MemOpKind::Store as u8)))
    }
}

impl<W: WordVar<F>, F: PrimeField> ProcessedTranscriptEntryVar<W, F> {
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
#[derive(Clone, Default)]
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
///
/// # Requires
///
/// `mem_tr_adj_seq` MUST have length 3;
fn transcript_checker<const NUM_REGS: usize, W: WordVar<F>, F: PrimeField>(
    arch: TinyRamArch,
    cpu_state: &CpuState<W, F>,
    chal: &FpVar<F>,
    instr_load: &ProcessedTranscriptEntryVar<W, F>,
    mem_op: &ProcessedTranscriptEntryVar<W, F>,
    mem_tr_adj_seq: &[ProcessedTranscriptEntryVar<W, F>],
    evals: &TranscriptCheckerEvals<F>,
) -> Result<(CpuState<W, F>, TranscriptCheckerEvals<F>), SynthesisError> {
    assert_eq!(mem_tr_adj_seq.len(), 3);

    // pc_load occurs at time t
    let t = &instr_load.timestamp;
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
        .update(&instr_load.as_ff(false)?, chal)?;

    // Put the memory operation execution mem. If this is padding, then that's fine, because
    // there's as much padding here as in the memory trace
    // TODO: When tape reads are implemented, the below to be muxed. mem_op might go to the tape
    // tr, the time tr, or nowhere (if it's an aux tape read)
    new_evals.time_tr_exec.update(&mem_op.as_ff(false)?, chal)?;

    // --------------------------------------------------------------------------------------------
    // Running the CPU
    // --------------------------------------------------------------------------------------------

    // Unpack the load at the program counter
    let instr = &instr_load.val;

    // Run the CPU for one tick
    let new_cpu_state = exec_checker::<NUM_REGS, _, _>(arch, &mem_op, cpu_state, instr)?;

    // --------------------------------------------------------------------------------------------
    // Checking memory-sorted transcript consistency
    // --------------------------------------------------------------------------------------------

    //
    // Entirely separately from the rest of this function, we check the consistency of the given
    // adjacent entries in the mem-sorted memory transcript
    //

    // Go through the adjacent entries of the mem-sorted trace using a sliding window of size 2
    for pair in mem_tr_adj_seq.windows(2) {
        let prev = &pair[0];
        let cur = &pair[1];

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
        let op_is_store = cur.is_store()?;
        let cond = ram_idx_is_neq.or(&val_is_eq)?.or(&op_is_store)?;
        cond.enforce_equal(&Boolean::TRUE)?;

        // On every tick, absorb all but the first entry in to the mem-sorted execution trace
        new_evals.mem_tr_exec.update(&cur.as_ff(false)?, chal)?;

        // If it's an initial load, also put it into the mem trace of initial memory that's read in
        // our execution. That is, if
        //       prev.ram_idx < cur_ram_idx
        //     ∧ cur.op == LOAD
        // then absorb cur into tr_init_accessed
        let cur_as_initmem = cur.as_ff(true)?;
        let is_new_load = ram_idx_is_neq.and(&cur.is_load()?)?;
        new_evals
            .tr_init_accessed
            .conditionally_update(&is_new_load, &cur_as_initmem, chal)?;
    }

    Ok((new_cpu_state, new_evals))
}

#[cfg(test)]
mod test {
    use super::*;

    use tinyram_emu::{
        instructions::Instr,
        interpreter::TranscriptEntry,
        register::{ImmOrRegister, RegIdx},
        word::Word,
    };

    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_r1cs_std::{alloc::AllocVar, uint32::UInt32, R1CSVar};
    use ark_relations::{ns, r1cs::ConstraintSystem};
    use rand::Rng;

    const NUM_REGS: usize = 16;
    type F = Fr;
    type WV = UInt32<F>;
    type W = <WV as WordVar<F>>::NativeWord;

    // The skip3 program
    pub(crate) const SKIP3_CODE: &str = "\
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
        ";

    #[test]
    fn test_skip3() {
        let mut rng = rand::thread_rng();
        let cs = ConstraintSystem::new_ref();

        let assembly = tinyram_emu::parser::assemble(SKIP3_CODE);
        let arch = TinyRamArch::VonNeumann;

        let (output, transcript) = tinyram_emu::interpreter::run_program::<W, NUM_REGS>(
            TinyRamArch::VonNeumann,
            &assembly,
        );

        // Create the time-sorted transcript, complete with padding memory ops. This has length 2T,
        // where T is the number of CPU ticks.
        let time_sorted_transcript = transcript
            .iter()
            .flat_map(ProcessedTranscriptEntry::new_pair)
            .collect::<Vec<_>>();
        // Make the mem-sorted trace. This has length 2T + 1. The +1 is the initial padding
        let mem_sorted_transcript = {
            let mut buf = time_sorted_transcript.clone();
            // Sort by RAM index, followed by timestamp
            buf.sort_by_key(|o| (o.mem_op.location(), o.timestamp));
            // Now pad the mem-sorted transcript with an initial placeholder op. This will just
            // store the value of the true first op. We can use the timestamp 0 because we've
            // reserved it: every witnessed transcript entry has timestamp greater than 0.
            let mut initial_entry = buf.get(0).unwrap().clone();
            initial_entry.timestamp = 0;
            buf.insert(0, initial_entry);
            buf
        };

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
        let chal = FpVar::constant(F::rand(&mut rng));
        // Let the evals be empty
        let evals = TranscriptCheckerEvals::default();

        // Run the CPU
        let mut cpu_state = CpuState::default::<NUM_REGS>();
        for (i, (time_sorted_transcript_pair, mem_sorted_transcript_triple)) in
            time_sorted_transcript_vars
                .chunks(2)
                .zip(mem_sorted_transcript_vars.windows(3).step_by(2))
                .enumerate()
        {
            // Unpack the time-sorted transcript values
            let instr_load_var = &time_sorted_transcript_pair[0];
            let mem_op_var = &time_sorted_transcript_pair[1];

            println!("Iteration {i}");
            (cpu_state, _) = transcript_checker::<NUM_REGS, _, _>(
                arch,
                &cpu_state,
                &chal,
                instr_load_var,
                mem_op_var,
                &mem_sorted_transcript_triple,
                &evals,
            )
            .unwrap();
        }
        // Make sure nothing errored
        assert!(cs.is_satisfied().unwrap());

        // Check the output is set and correct
        assert!(cpu_state.answer.is_set.value().unwrap());
        assert_eq!(output, cpu_state.answer.val.value().unwrap());
    }
}
