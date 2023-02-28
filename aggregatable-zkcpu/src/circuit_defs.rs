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
