use crate::{
    exec_checker::CpuStateVar,
    transcript_checker::{
        transcript_checker, ProcessedTranscriptEntry, ProcessedTranscriptEntryVar,
        TranscriptCheckerEvals, TranscriptCheckerEvalsVar,
    },
    word::WordVar,
};

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use cp_groth16::{MultiStageConstraintSynthesizer, MultiStageConstraintSystem};
use tinyram_emu::{program_state::CpuState, word::Word, ProgramMetadata};

struct TranscriptCheckerCircuit<const NUM_REGS: usize, W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    meta: ProgramMetadata,

    // Stage 0 values
    instr_load: ProcessedTranscriptEntry<W>,
    mem_op: ProcessedTranscriptEntry<W>,
    instr_load_var: ProcessedTranscriptEntryVar<WV, F>,
    mem_op_var: ProcessedTranscriptEntryVar<WV, F>,

    // Stage 1 values
    mem_tr_adj_seq: Vec<ProcessedTranscriptEntry<W>>,
    mem_tr_adj_seq_var: Vec<ProcessedTranscriptEntryVar<WV, F>>,

    // Stage 2 values
    in_evals: TranscriptCheckerEvals<F>,
    in_cpu_state: CpuState<NUM_REGS, W>,
    in_evals_var: TranscriptCheckerEvalsVar<F>,
    in_cpu_state_var: CpuStateVar<WV, F>,

    // Stage 3 values
    out_evals: TranscriptCheckerEvals<F>,
    out_cpu_state: CpuState<NUM_REGS, W>,
    out_evals_var: TranscriptCheckerEvalsVar<F>,
    out_cpu_state_var: CpuStateVar<WV, F>,

    // Stage 4 values. The challenge is last because its computation has the highest latency
    chal: F,
    chal_var: FpVar<F>,
}

impl<W, WV, F> TranscriptCheckerCircuit<16, W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    /// Commit to the time-sorted memory operations, i.e., the instr load and CPU mem op
    fn stage0(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.instr_load_var =
            ProcessedTranscriptEntryVar::new_witness(ns!(cs, "instr load"), || {
                Ok(&self.instr_load)
            })?;
        self.mem_op_var =
            ProcessedTranscriptEntryVar::new_witness(ns!(cs, "mem op"), || Ok(&self.mem_op))?;

        Ok(())
    }

    /// Commit to the mem-sorted memory operations
    fn stage1(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.mem_tr_adj_seq_var = self
            .mem_tr_adj_seq
            .iter()
            .map(|item| {
                ProcessedTranscriptEntryVar::new_witness(ns!(cs, "mem tr adj seq"), || Ok(item))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    /// Commit to the input state, i.e., the given CPU state and running polyn evals
    fn stage2(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.in_evals_var =
            TranscriptCheckerEvalsVar::new_witness(ns!(cs, "in evals"), || Ok(&self.in_evals))?;
        self.in_cpu_state_var =
            CpuStateVar::new_witness(ns!(cs, "in cpu state"), || Ok(&self.in_cpu_state))?;

        Ok(())
    }

    /// Commit to the output state, i.e., the given CPU state and running polyn evals
    fn stage3(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.out_evals_var =
            TranscriptCheckerEvalsVar::new_witness(ns!(cs, "out evals"), || Ok(&self.out_evals))?;
        self.out_cpu_state_var =
            CpuStateVar::new_witness(ns!(cs, "out cpu state"), || Ok(&self.out_cpu_state))?;

        Ok(())
    }

    /// Commit to the verifier challenge
    fn stage4(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.chal_var = FpVar::new_witness(ns!(cs, "chal"), || Ok(self.chal))?;

        Ok(())
    }

    /// Do the transcript check
    fn stage5(&mut self, _cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let (claimed_out_cpu_state, claimed_out_evals) = transcript_checker::<16, _, _>(
            self.meta,
            &self.in_cpu_state_var,
            &self.chal_var,
            &self.instr_load_var,
            &self.mem_op_var,
            &self.mem_tr_adj_seq_var,
            &self.in_evals_var,
        )?;

        claimed_out_cpu_state.enforce_equal(&self.out_cpu_state_var)?;
        claimed_out_evals.enforce_equal(&self.out_evals_var)?;

        Ok(())
    }
}

impl<W, WV, F> MultiStageConstraintSynthesizer<F> for TranscriptCheckerCircuit<16, W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    fn total_num_stages(&self) -> usize {
        6
    }

    fn generate_constraints(
        &mut self,
        stage: usize,
        cs: &mut MultiStageConstraintSystem<F>,
    ) -> Result<(), SynthesisError> {
        match stage {
            0 => cs.synthesize_with(|c| self.stage0(c)),
            1 => cs.synthesize_with(|c| self.stage1(c)),
            2 => cs.synthesize_with(|c| self.stage2(c)),
            3 => cs.synthesize_with(|c| self.stage3(c)),
            4 => cs.synthesize_with(|c| self.stage4(c)),
            5 => cs.synthesize_with(|c| self.stage5(c)),
            _ => panic!("unexpected stage stage {}", stage),
        }
    }
}
