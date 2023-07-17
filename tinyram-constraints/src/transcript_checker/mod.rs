use crate::{
    cpu::{Cpu, CpuStateVar},
    word::{DoubleWordVar, WordVar},
    TinyRamExt,
};

use core::borrow::Borrow;

use tinyram_emu::{word::Word, MemOp, MemOpKind, ProgramMetadata, ExecutionTranscriptEntry};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    cmp::CmpGadget,
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
use ark_std::log2;
use rand::Rng;

/// A timestamp in the memory access transcript
type Timestamp = u64;
/// A timestamp in the memory access transcript, in ZK land
pub type TimestampVar<F> = UInt64<F>;

/// The offset to use when witnessing transcript entries. This gives us room for no-op entries at
/// the beginning. We only really need 1 padding element.
const TIMESTAMP_OFFSET: u64 = 1;

mod processed_transcript_entry;
mod running_evaluation;
mod transcript_eval;

pub use processed_transcript_entry::*;
pub use running_evaluation::RunningEvalVar;
pub use transcript_eval::*;

/// The kind of memory operation: load, store, read primary tape or read aux tape, in ZK land
pub type MemOpKindVar<F> = FpVar<F>;

/// This function checks the time- and mem-sorted transcripts for consistency. It also accumulates
/// both transcripts into their respective polynomial evaluations.
///
/// # Requires
///
/// `mem_tr_adj_seq` MUST have length 3;
pub fn check_transcript<T: TinyRamExt>(
    meta: ProgramMetadata,
    cpu_state: &CpuStateVar<T>,
    chal: &FpVar<T::F>,
    instr_load: &MemTranscriptEntryVar<T>,
    mem_op: &MemTranscriptEntryVar<T>,
    mem_tr_adj_seq: &[MemTranscriptEntryVar<T>],
    evals: &TranscriptCheckerEvalsVar<T::F>,
) -> Result<(CpuStateVar<T>, TranscriptCheckerEvalsVar<T::F>), SynthesisError> {
    assert_eq!(mem_tr_adj_seq.len(), 3);
    let cs = cpu_state.cs();

    // pc_load occurs at time t
    let t = instr_load.timestamp.clone();
    // mem_op, if defined, occurs at time t
    let t_plus_one = TimestampVar::wrapping_add_many(&[t, TimestampVar::constant(1)])?;

    let is_padding = &mem_op.is_padding;

    // TODO: MUST check that mem_op.location is double word-aligned (in Harvard: check bottom bit is 0, in
    // Von Neumann: check that bottom log₂(double_word_bytelen) bits are 0)

    // --------------------------------------------------------------------------------------------
    // Housekeeping of memory operations
    // --------------------------------------------------------------------------------------------

    // If mem_op is padding, it must be a LOAD. Otherwise we have a soundness issue where a STORE
    // that's technically padding is not checked in the timestep but still makes it into the mem
    // transcript. Concretely, we check
    //       ¬mem_op.is_padding
    //     ∨ mem_op.is_load()
    (!is_padding | mem_op.is_load()?).enforce_equal(&Boolean::TRUE)?;

    // If mem_op is a real entry, i.e., not padding, it must have timestamp t + 1
    mem_op
        .timestamp
        .conditional_enforce_equal(&t_plus_one, &!mem_op.is_padding.clone())?;

    // We're gonna update our running evals
    let mut new_evals = evals.clone();

    // Put the instruction load in the time-sorted execution mem
    new_evals
        .time_tr_exec
        .update_with_ram_op(&instr_load, chal)?;

    // Put the memory operation in the correct transcript. If it's padding, don't absorb it.

    // Absorb into the RAM transcript. as_fp() is 0 if mem_op is padding or a tape operation.
    new_evals.time_tr_exec.update_with_ram_op(&mem_op, chal)?;
    // TODO: make primary tape transcript

    // --------------------------------------------------------------------------------------------
    // Running the CPU
    // --------------------------------------------------------------------------------------------

    // Unpack the load at the program counter
    let instr = &instr_load.val;

    // Run the CPU for one tick
    println!("Num constraints pre-exec-checker {}", cs.num_constraints());
    let new_cpu_state = check_execution::<T>(meta, &mem_op, cpu_state, instr)?;
    println!("Num constraints post-exec-checker {}", cs.num_constraints());

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
        (!&prev.is_padding | prev.is_load()?).enforce_equal(&Boolean::TRUE)?;
        (!&cur.is_padding | prev.is_load()?).enforce_equal(&Boolean::TRUE)?;

        // Check that padding never changes the memory location from the previous location. That
        // is, padding → locations are equal
        let loc_is_eq = prev.location.is_eq(&cur.location)?;
        let cond = !&cur.is_padding | &loc_is_eq;
        cond.enforce_equal(&Boolean::TRUE)?;

        // These asserts are taken from Figure 5 in Constant-Overhead Zero-Knowledge for RAM
        // Programs: https://eprint.iacr.org/2021/979.pdf

        // Check that this is sorted by memory idx then time. That is, check
        //       prev.location < cur.location
        //     ∨ (prev.location == cur.location ∧ prev.timestamp < cur.timestamp);
        let loc_has_incrd = prev.location.is_lt(&cur.location)?;
        let t_has_incrd = &prev.timestamp.is_lt(&cur.timestamp)?;
        let cond = loc_has_incrd | (&loc_is_eq & t_has_incrd);
        cond.enforce_equal(&Boolean::TRUE)?;

        // Check that two adjacent LOADs on the same idx produced the same value. That is, check
        //       prev.location != cur.location
        //     ∨ prev.val == cur.val
        //     ∨ cur.op == STORE;
        let loc_is_neq = !loc_is_eq;
        let val_is_eq = prev.val_fp.is_eq(&cur.val_fp)?;
        let op_is_store = cur.is_store()?;
        let cond = &loc_is_neq | val_is_eq | op_is_store;
        cond.enforce_equal(&Boolean::TRUE)?;

        // On every tick, absorb all but the first entry in to the mem-sorted execution trace. This
        // is absorbed as a 0 if cur is a tape op or padding.
        new_evals.mem_tr_exec.update_with_ram_op(&cur, chal)?;

        // If it's an initial load, also put it into the mem trace of initial memory that's read in
        // our execution. That is, if
        //       prev.location < cur_location
        //     ∧ cur.op == LOAD
        // then absorb cur into tr_init_accessed.
        // We don't have to worry about whether this is padding (which makes the field repr equal
        // 0), since padding is never an initial load. padding is always a repetition of the last
        // mem op (converted to a load, if need be). We also don't have to check that cur is a tape
        // op (which also makes the field repr equal 0), since that's enforced to be false above.
        let is_new_load = loc_is_neq & cur.is_load()?;
        new_evals
            .tr_init_accessed
            .conditionally_update_with_ram_op_notime(&is_new_load, &cur, chal)?;
    }

    Ok((new_cpu_state, new_evals))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transcript_utils;

    use tinyram_emu::{ProgramMetadata, TinyRamArch};

    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_poly::Polynomial;
    use ark_r1cs_std::{alloc::AllocVar, uint32::UInt32, R1CSVar};
    use ark_relations::{ns, r1cs::ConstraintSystem};

    const NUM_REGS: usize = 16;
    type F = Fr;
    type WV = UInt32<F>;
    type W = <WV as WordVar<F>>::Native;

    // Helper function that runs the given TinyRAM code through the symbolic transcript checker
    fn transcript_tester(code: &str, primary_input: Vec<W>, aux_input: Vec<W>) {
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
                MemTranscriptEntryVar::<WV, _>::new_witness(ns!(cs, "t"), || Ok(t)).unwrap()
            })
            .collect::<Vec<_>>();
        let mem_sorted_transcript_vars = mem_sorted_transcript
            .iter()
            .map(|t| MemTranscriptEntryVar::new_witness(ns!(cs, "t"), || Ok(t)).unwrap())
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

            (cpu_state, evals) = check_transcript::<NUM_REGS, _, _>(
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

        // Natively convert the transcripts to polynomials and check that the evals match each
        // other and the ones from the circuit.
        let max_deg = mem_sorted_transcript.len() - 1;
        let t_polyn = transcript_utils::ram_transcript_to_polyn(&time_sorted_transcript, max_deg);
        let m_polyn = transcript_utils::ram_transcript_to_polyn(&mem_sorted_transcript, max_deg);
        let t_eval = t_polyn.evaluate(&chal);
        let m_eval = m_polyn.evaluate(&chal);
        assert_eq!(m_eval, t_eval);
        // Check the native eval equals X * zk_eval. The extra X is because the ZK circuit ignores
        // the initial padding entry
        assert_eq!(t_eval, chal * evals.time_tr_exec.0.value().unwrap());
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
            vec![],
            vec![],
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
            vec![],
            vec![],
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
            vec![],
            vec![],
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
        let primary_tape = (1..=n).map(W::from_u64).collect();
        let aux_tape = (1..=n).map(|x| W::from_u64(100 * x)).collect();

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
            primary_tape,
            aux_tape,
        );
    }

    // Tests that ProcessedTranscriptEntry::as_fp and ProcessedTranscriptEntryVar::as_fp agree
    #[test]
    fn ff_encoding_equality() {
        let mut rng = rand::thread_rng();
        let cs = ConstraintSystem::new_ref();

        // Make 200 random transcript entries and check that the native and ZK verisons encode to
        // the same value
        for _ in 0..200 {
            let entry = MemTranscriptEntry::rand(&mut rng);
            let entry_var =
                MemTranscriptEntryVar::<WV, _>::new_witness(ns!(cs, "e"), || Ok(&entry))
                    .unwrap();

            assert_eq!(
                entry.as_fp::<F>(true),
                entry_var.as_fp(true).unwrap().value().unwrap()
            );
        }
    }
}
