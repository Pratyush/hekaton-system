use crate::{
    portal_manager::{ProverPortalManager, SetupPortalManager},
    util::log2,
    varname_hasher, CircuitWithPortals, RomTranscriptEntry, RomTranscriptEntryVar, RunningEvals,
    RunningEvalsVar,
};

use std::{borrow::Borrow, collections::VecDeque, marker::PhantomData};

use ark_cp_groth16::{
    committer::CommitmentBuilder as G16CommitmentBuilder,
    data_structures::{Comm as G16Com, ProvingKey as G16ProvingKey},
    r1cs_to_qap::LibsnarkReduction as QAP,
    MultiStageConstraintSynthesizer, MultiStageConstraintSystem,
};

use ark_crypto_primitives::crh::{
    constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
    sha256::{digest::Digest, Sha256},
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::{boolean::Boolean, uint8::UInt8, ToBytesGadget},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

pub(crate) type MerkleRoot<C> = <C as TreeConfig>::InnerDigest;
pub(crate) type MerkleRootVar<C, F, CG> = <CG as TreeConfigGadget<C, F>>::InnerDigest;

pub use ark_crypto_primitives::merkle_tree::{
    constraints::ConfigGadget as TreeConfigGadget, Config as TreeConfig, LeafParam, TwoToOneParam,
};
pub(crate) type LeafParamVar<CG, C, F> = <<CG as TreeConfigGadget<C, F>>::LeafHash as CRHSchemeGadget<
    <C as TreeConfig>::LeafHash,
    F,
>>::ParametersVar;
pub(crate) type TwoToOneParamVar<CG, C, F> =
    <<CG as TreeConfigGadget<C, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
        <C as TreeConfig>::TwoToOneHash,
        F,
    >>::ParametersVar;

/// A leaf in the execution tree
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub(crate) struct ExecTreeLeaf<F: PrimeField> {
    // Leaf i contains the running evals AFTER having run subcircuit i
    pub evals: RunningEvals<F>,
    // Leaf i contains the last entry of the i-th addr-ordered subtrace
    pub last_subtrace_entry: RomTranscriptEntry<F>,
}

impl<F: PrimeField> ExecTreeLeaf<F> {
    /// We need to give a starting set of values to the first subcircuit. This is the padding leaf.
    /// It has empty running evals and an all-zero transcript entry
    pub(crate) fn padding() -> Self {
        ExecTreeLeaf {
            evals: RunningEvals::default(),
            last_subtrace_entry: RomTranscriptEntry::padding(),
        }
    }

    /// Serializes the leaf to bytes
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        [self.evals.to_bytes(), self.last_subtrace_entry.to_bytes()].concat()
    }
}

/// The ZK version of `Leaf`
pub(crate) struct ExecTreeLeafVar<F: PrimeField> {
    pub evals: RunningEvalsVar<F>,
    pub last_subtrace_entry: RomTranscriptEntryVar<F>,
}

/// `ExecTreeLeaf` serializes to bytes. This is the form it's in when put into the exec tree
pub(crate) type SerializedLeaf = [u8];

/// The ZK version of `SerializedLeaf`
pub(crate) type SerializedLeafVar<F> = [UInt8<F>];

impl<F: PrimeField> R1CSVar<F> for ExecTreeLeafVar<F> {
    type Value = ExecTreeLeaf<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.evals.cs().or(self.last_subtrace_entry.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(ExecTreeLeaf {
            evals: self.evals.value()?,
            last_subtrace_entry: self.last_subtrace_entry.value()?,
        })
    }
}

// Serialization here is compatible with with ExecTreeLeaf::to_bytes()
impl<F: PrimeField> ToBytesGadget<F> for ExecTreeLeafVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([self.evals.to_bytes()?, self.last_subtrace_entry.to_bytes()?].concat())
    }
}

impl<F: PrimeField> AllocVar<ExecTreeLeaf<F>, F> for ExecTreeLeafVar<F> {
    fn new_variable<T: Borrow<ExecTreeLeaf<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let leaf = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        let evals =
            RunningEvalsVar::new_variable(ns!(cs, "evals"), || leaf.map(|l| &l.evals), mode)?;
        let last_subtrace_entry = RomTranscriptEntryVar::new_variable(
            ns!(cs, "last entry"),
            || leaf.map(|l| &l.last_subtrace_entry),
            mode,
        )?;

        Ok(ExecTreeLeafVar {
            evals,
            last_subtrace_entry,
        })
    }
}
