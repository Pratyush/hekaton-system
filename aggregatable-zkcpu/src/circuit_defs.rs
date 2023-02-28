use core::{borrow::Borrow, marker::PhantomData};

use crate::{
    common::{PcVar, RegistersVar},
    exec_checker::{CpuAnswerVar, CpuStateVar},
    transcript_checker::{
        transcript_checker, MemOpKindVar, ProcessedTranscriptEntry, ProcessedTranscriptEntryVar,
        RunningEvalVar, TimestampVar, TranscriptCheckerEvals, TranscriptCheckerEvalsVar,
    },
    word::WordVar,
};

use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, bits::boolean::Boolean, fields::fp::FpVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError},
};
use tinyram_emu::{program_state::CpuState, word::Word, TinyRamArch};

// Defines a trait that can allocate public inputs/outputs in an interleaving way. For every
// input variable x with output x', this guarantees that x' is allocated immediately after x.
pub trait InOutAllocVar<V: ?Sized, F: Field>
where
    Self: Sized,
{
    fn new_inout<T: Borrow<V>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<(T, T), SynthesisError>,
    ) -> Result<(Self, Self), SynthesisError>;
}

impl<F: PrimeField> InOutAllocVar<bool, F> for Boolean<F>
where
    Self: Sized,
{
    fn new_inout<T: Borrow<bool>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<(T, T), SynthesisError>,
    ) -> Result<(Self, Self), SynthesisError> {
        let cs = cs.into().cs();

        let (in_val, out_val) = match f() {
            Ok((x, y)) => (Ok(x), Ok(y)),
            Err(e) => (Err(e.clone()), Err(e.clone())),
        };

        let in_var = Boolean::new_input(ns!(cs, "input"), || in_val)?;
        let out_var = Boolean::new_input(ns!(cs, "output"), || out_val)?;

        Ok((in_var, out_var))
    }
}
// Impl for FpVar
impl<F: PrimeField> InOutAllocVar<F, F> for FpVar<F>
where
    Self: Sized,
{
    fn new_inout<T: Borrow<F>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<(T, T), SynthesisError>,
    ) -> Result<(Self, Self), SynthesisError> {
        let cs = cs.into().cs();

        let (in_val, out_val) = match f() {
            Ok((x, y)) => (Ok(x), Ok(y)),
            Err(e) => (Err(e.clone()), Err(e.clone())),
        };

        let in_var = FpVar::new_input(ns!(cs, "input"), || in_val)?;
        let out_var = FpVar::new_input(ns!(cs, "output"), || out_val)?;

        Ok((in_var, out_var))
    }
}
// Impl for RunningEvalVar
impl<F: PrimeField> InOutAllocVar<F, F> for RunningEvalVar<F>
where
    Self: Sized,
{
    fn new_inout<T: Borrow<F>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<(T, T), SynthesisError>,
    ) -> Result<(Self, Self), SynthesisError> {
        let cs = cs.into().cs();

        let (in_val, out_val) = match f() {
            Ok((x, y)) => (Ok(x), Ok(y)),
            Err(e) => (Err(e.clone()), Err(e.clone())),
        };

        let in_var = FpVar::new_input(ns!(cs, "input"), || in_val)?;
        let out_var = FpVar::new_input(ns!(cs, "output"), || out_val)?;

        Ok((RunningEvalVar(in_var), RunningEvalVar(out_var)))
    }
}
// Impl for CpuAnswerVar
impl<F, W, WV> InOutAllocVar<Option<W>, F> for CpuAnswerVar<WV, F>
where
    Self: Sized,
    F: PrimeField,
    W: Word,
    WV: WordVar<F, NativeWord = W>,
{
    fn new_inout<T: Borrow<Option<W>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<(T, T), SynthesisError>,
    ) -> Result<(Self, Self), SynthesisError> {
        let cs = cs.into().cs();

        let (in_val, out_val) = f()?;
        let (in_val, out_val) = (in_val.borrow(), out_val.borrow());

        let in_is_set = Boolean::new_input(ns!(cs, "input is_set"), || Ok(in_val.is_some()))?;
        let out_is_set = Boolean::new_input(ns!(cs, "output is_set"), || Ok(out_val.is_some()))?;

        let in_val = WV::new_input(ns!(cs, "input val"), || Ok(in_val.unwrap_or(W::default())))?;
        let out_val = WV::new_input(
            ns!(cs, "output val"),
            || Ok(out_val.unwrap_or(W::default())),
        )?;

        let in_answer = CpuAnswerVar {
            is_set: in_is_set,
            val: in_val,
        };
        let out_answer = CpuAnswerVar {
            is_set: out_is_set,
            val: out_val,
        };

        Ok((in_answer, out_answer))
    }
}
// Impl for RegistersVar
impl<const NUM_REGS: usize, F, W, WV> InOutAllocVar<[W; NUM_REGS], F> for RegistersVar<WV>
where
    Self: Sized,
    F: PrimeField,
    W: Word,
    WV: WordVar<F, NativeWord = W>,
{
    fn new_inout<T: Borrow<[W; NUM_REGS]>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<(T, T), SynthesisError>,
    ) -> Result<(Self, Self), SynthesisError> {
        let cs = cs.into().cs();

        let (in_vals, out_vals) = f()?;
        let (in_vals, out_vals) = (in_vals.borrow(), out_vals.borrow());

        let mut in_vars = Vec::new();
        let mut out_vars = Vec::new();

        for (in_val, out_val) in in_vals.iter().zip(out_vals) {
            in_vars.push(WV::new_input(ns!(cs, "input"), || Ok(in_val))?);
            out_vars.push(WV::new_input(ns!(cs, "output"), || Ok(out_val))?);
        }

        Ok((in_vars, out_vars))
    }
}
// Impl for TranscriptCheckerEvalsVar
impl<F> InOutAllocVar<TranscriptCheckerEvals<F>, F> for TranscriptCheckerEvalsVar<F>
where
    Self: Sized,
    F: PrimeField,
{
    fn new_inout<T: Borrow<TranscriptCheckerEvals<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<(T, T), SynthesisError>,
    ) -> Result<(Self, Self), SynthesisError> {
        let cs = cs.into().cs();

        let (in_val, out_val) = f()?;
        let (in_val, out_val) = (in_val.borrow(), out_val.borrow());

        let (in_time_tr_exec, out_time_tr_exec) =
            RunningEvalVar::new_inout(ns!(cs, "time_tr"), || {
                Ok((in_val.time_tr_exec, out_val.time_tr_exec))
            })?;
        let (in_mem_tr_exec, out_mem_tr_exec) =
            RunningEvalVar::new_inout(ns!(cs, "mem_tr"), || {
                Ok((in_val.mem_tr_exec, out_val.mem_tr_exec))
            })?;
        let (in_tr_init_accessed, out_tr_init_accessed) =
            RunningEvalVar::new_inout(ns!(cs, "tr_init_accessed"), || {
                Ok((in_val.tr_init_accessed, out_val.tr_init_accessed))
            })?;

        let in_evals = TranscriptCheckerEvalsVar {
            time_tr_exec: in_time_tr_exec,
            mem_tr_exec: in_mem_tr_exec,
            tr_init_accessed: in_tr_init_accessed,
        };
        let out_evals = TranscriptCheckerEvalsVar {
            time_tr_exec: out_time_tr_exec,
            mem_tr_exec: out_mem_tr_exec,
            tr_init_accessed: out_tr_init_accessed,
        };

        Ok((in_evals, out_evals))
    }
}

// Impl for RegistersVar
impl<const NUM_REGS: usize, F, W, WV> InOutAllocVar<CpuState<NUM_REGS, W>, F> for CpuStateVar<WV, F>
where
    Self: Sized,
    F: PrimeField,
    W: Word,
    WV: WordVar<F, NativeWord = W>,
{
    fn new_inout<T: Borrow<CpuState<NUM_REGS, W>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<(T, T), SynthesisError>,
    ) -> Result<(Self, Self), SynthesisError> {
        let cs = cs.into().cs();

        let (in_state, out_state) = f()?;
        let (in_state, out_state) = (in_state.borrow(), out_state.borrow());

        let in_flag = Boolean::new_input(ns!(cs, "input flag"), || Ok(in_state.condition_flag))?;
        let out_flag = Boolean::new_input(ns!(cs, "output flag"), || Ok(out_state.condition_flag))?;

        let in_pc = PcVar::new_input(ns!(cs, "input pc"), || Ok(in_state.program_counter))?;
        let out_pc = PcVar::new_input(ns!(cs, "output pc"), || Ok(out_state.program_counter))?;

        let (in_regs, out_regs) = RegistersVar::new_inout(ns!(cs, "regs"), || {
            Ok((in_state.registers, out_state.registers))
        })?;
        let (in_answer, out_answer) = CpuAnswerVar::new_inout(ns!(cs, "answer"), || {
            Ok((in_state.answer, out_state.answer))
        })?;

        let in_state_var = CpuStateVar {
            flag: in_flag,
            pc: in_pc,
            regs: in_regs,
            answer: in_answer,
        };
        let out_state_var = CpuStateVar {
            flag: out_flag,
            pc: out_pc,
            regs: out_regs,
            answer: out_answer,
        };

        Ok((in_state_var, out_state_var))
    }
}

// Impl for MemOp
impl<F, W, WV> InOutAllocVar<ProcessedTranscriptEntry<W>, F> for ProcessedTranscriptEntryVar<WV, F>
where
    Self: Sized,
    F: PrimeField,
    W: Word,
    WV: WordVar<F, NativeWord = W> + InOutAllocVar<W, F>,
{
    fn new_inout<T: Borrow<ProcessedTranscriptEntry<W>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<(T, T), SynthesisError>,
    ) -> Result<(Self, Self), SynthesisError> {
        let cs = cs.into().cs();

        let (in_val, out_val) = f()?;
        let (in_val, out_val) = (in_val.borrow(), out_val.borrow());

        // Input/output padding
        let (in_is_padding, out_is_padding) = Boolean::new_inout(ns!(cs, "is_padding"), || {
            Ok((in_val.is_padding, out_val.is_padding))
        })?;
        // Input/output timestamp
        let (in_timestamp, out_timestamp) = TimestampVar::new_inout(ns!(cs, "timestamp"), || {
            Ok((F::from(in_val.timestamp), F::from(out_val.timestamp)))
        })?;
        // Input/output memory op kind
        let (in_opkind, out_opkind) = MemOpKindVar::new_inout(ns!(cs, "opkind"), || {
            Ok((
                F::from(in_val.mem_op.kind() as u8),
                F::from(out_val.mem_op.kind() as u8),
            ))
        })?;

        let (in_ram_idx, out_ram_idx) = WV::new_inout(ns!(cs, "ram_idx"), || {
            Ok((in_val.mem_op.location(), out_val.mem_op.location()))
        })?;

        todo!()
    }
}

/// Does a transcript check for 1 tick of the ZK TinyRAM CPU
struct MultitickCheckerCircuit<const NUM_REGS: usize, F, W, WV>
where
    F: PrimeField,
    W: Word,
    WV: WordVar<F, NativeWord = W>,
{
    arch: TinyRamArch,

    // Public values
    cpu_state_inout: (CpuState<NUM_REGS, W>, CpuState<NUM_REGS, W>),
    evals_inout: (TranscriptCheckerEvals<F>, TranscriptCheckerEvals<F>),

    chal: F,
    instr_load: ProcessedTranscriptEntry<W>,
    mem_op: ProcessedTranscriptEntry<W>,
    mem_tr_adj_seq: [ProcessedTranscriptEntry<W>; 3],
    _marker: PhantomData<WV>,
}

impl<const NUM_REGS: usize, F, W, WV> ConstraintSynthesizer<F>
    for MultitickCheckerCircuit<NUM_REGS, F, W, WV>
where
    F: PrimeField,
    W: Word,
    WV: WordVar<F, NativeWord = W>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Get the public inputs/outputs
        let (in_cpu_state, out_cpu_state) =
            CpuStateVar::<WV, _>::new_inout(ns!(cs, "cpu state"), || Ok(self.cpu_state_inout))?;
        let (in_evals, out_evals) =
            TranscriptCheckerEvalsVar::new_inout(ns!(cs, "evals"), || Ok(self.evals_inout))?;

        // Get the witnesses
        let chal_var = FpVar::new_witness(ns!(cs, "chal"), || Ok(self.chal))?;
        let instr_load_var =
            ProcessedTranscriptEntryVar::<WV, _>::new_witness(ns!(cs, "instr load"), || {
                Ok(self.instr_load)
            })?;
        let mem_op_var =
            ProcessedTranscriptEntryVar::<WV, _>::new_witness(ns!(cs, "mem op"), || {
                Ok(self.mem_op)
            })?;

        todo!()

        /*
        let (computed_cpu_state, computed_evals) = transcript_checker::<NUM_REGS, _, _>(
            self.arch,
            &in_cpu_state,
            &self.chal,
            instr_load_var,
            mem_op_var,
            &mem_sorted_transcript_triple,
            &evals,
        );
        */
    }
}
