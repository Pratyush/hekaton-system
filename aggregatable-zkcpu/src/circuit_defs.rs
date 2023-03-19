use core::{iter, marker::PhantomData};

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
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use cp_groth16::InputAllocator;
use tinyram_emu::{program_state::CpuState, word::Word, TinyRamArch};

struct CpuStateAllocator<const NUM_REGS: usize, W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    state: CpuState<NUM_REGS, W>,
    _marker: core::marker::PhantomData<(WV, F)>,
}

impl<const NUM_REGS: usize, W, WV, F> InputAllocator<F> for CpuStateAllocator<NUM_REGS, W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    type AllocatedSelf = CpuStateVar<WV, F>;

    fn alloc(&self, cs: ConstraintSystemRef<F>) -> Result<Self::AllocatedSelf, SynthesisError> {
        Self::AllocatedSelf::new_input(ns!(cs, "state"), || Ok(&self.state))
    }
}

struct TranscriptItemsAllocator<W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    instr_load: ProcessedTranscriptEntry<W>,
    mem_op: ProcessedTranscriptEntry<W>,
    mem_tr_adj_seq: Vec<ProcessedTranscriptEntry<W>>,
    _marker: PhantomData<(WV, F)>,
}

struct TranscriptItems<WV, F>
where
    F: PrimeField,
    WV: WordVar<F>,
{
    instr_load: ProcessedTranscriptEntryVar<WV, F>,
    mem_op: ProcessedTranscriptEntryVar<WV, F>,
    mem_tr_adj_seq: Vec<ProcessedTranscriptEntryVar<WV, F>>,
}

impl<W, WV, F> InputAllocator<F> for TranscriptItemsAllocator<W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    type AllocatedSelf = TranscriptItems<WV, F>;

    fn alloc(&self, cs: ConstraintSystemRef<F>) -> Result<Self::AllocatedSelf, SynthesisError> {
        // We're just allocated transcript entries. Do them all at once in a vector, and then split
        // them out again
        let mut all_entries = iter::once(&self.instr_load)
            .chain(iter::once(&self.mem_op))
            .chain(self.mem_tr_adj_seq.iter())
            .map(|item| {
                ProcessedTranscriptEntryVar::new_input(ns!(cs, "mem tr adj seq"), || Ok(item))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Destructure the vec
        let instr_load = all_entries.remove(0);
        let mem_op = all_entries.remove(0);
        let mem_tr_adj_seq = all_entries;

        Ok(Self::AllocatedSelf {
            instr_load,
            mem_op,
            mem_tr_adj_seq,
        })
    }
}

struct EvalsAllocator<F: PrimeField>(TranscriptCheckerEvals<F>);

impl<F: PrimeField> InputAllocator<F> for EvalsAllocator<F> {
    type AllocatedSelf = TranscriptCheckerEvalsVar<F>;

    fn alloc(&self, cs: ConstraintSystemRef<F>) -> Result<Self::AllocatedSelf, SynthesisError> {
        Self::AllocatedSelf::new_input(ns!(cs, "evals"), || Ok(&self.0))
    }
}

struct ChalAllocator<F: PrimeField> {
    chal: F,
}

impl<F: PrimeField> InputAllocator<F> for ChalAllocator<F> {
    type AllocatedSelf = FpVar<F>;

    fn alloc(&self, cs: ConstraintSystemRef<F>) -> Result<Self::AllocatedSelf, SynthesisError> {
        FpVar::new_input(ns!(cs, "chal"), || Ok(&self.chal))
    }
}

struct TranscriptCheckerCircuit<const NUM_REGS: usize, WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    arch: TinyRamArch,
    chal: FpVar<F>,
    ts_items: TranscriptItems<WV, F>,

    in_cpu_state: CpuStateVar<WV, F>,
    out_cpu_state: CpuStateVar<WV, F>,

    in_evals: TranscriptCheckerEvalsVar<F>,
    out_evals: TranscriptCheckerEvalsVar<F>,
}

impl<WV, F> ConstraintSynthesizer<F> for TranscriptCheckerCircuit<16, WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn generate_constraints(self, _cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let (claimed_out_cpu_state, claimed_out_evals) = transcript_checker::<16, _, _>(
            self.arch,
            &self.in_cpu_state,
            &self.chal,
            &self.ts_items.instr_load,
            &self.ts_items.mem_op,
            &self.ts_items.mem_tr_adj_seq,
            &self.in_evals,
        )?;

        claimed_out_cpu_state.enforce_equal(&self.out_cpu_state)?;
        claimed_out_evals.enforce_equal(&self.out_evals)?;

        Ok(())
    }
}
