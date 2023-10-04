use core::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use xxhash_rust::xxh3::xxh3_128;

mod eval_tree;
mod portal_manager;
//mod worker_node;
mod tree_hash_circuit;

use portal_manager::PortalManager;

pub(crate) const PADDING_VARNAME: &str = "__PADDING";

/// Hashes a portal wire name to a field element. Note: if name == PADDING_VARNAME, then this
/// outputs 0. This is a special varaible name.
pub(crate) fn varname_hasher<F: PrimeField>(name: &str) -> F {
    if name == PADDING_VARNAME {
        F::zero()
    } else {
        // Hash to u64 and convert to field elem
        F::from(xxh3_128(name.as_bytes()))
    }
}

#[derive(Clone, Default)]
pub(crate) struct RunningEvals<F: PrimeField> {
    // Stored values that are updated
    pub(crate) time_ordered_eval: F,
    pub(crate) addr_ordered_eval: F,

    // Values specific to the global polynomial. These are need by the update function. Contains
    // `(entry_chal, tr_chal)`.
    challenges: Option<(F, F)>,
}

impl<F: PrimeField> RunningEvals<F> {
    /// Updates the running evaluation of the time-ordered transcript polyn
    fn update_time_ordered(&mut self, entry: &RomTranscriptEntry<F>) {
        // Unpack challenges
        let (entry_chal, tr_chal) = self
            .challenges
            .expect("RunningEvals.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = entry.val + entry_chal * &varname_hasher(&entry.name);

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.time_ordered_eval *= tr_chal - entry_repr;
    }

    /// Updates the running evaluation of the addr-ordered transcript polyn
    fn update_addr_ordered(&mut self, entry: &RomTranscriptEntry<F>) {
        // Unpack challenges
        let (entry_chal, tr_chal) = self
            .challenges
            .expect("RunningEvals.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = entry.val + entry_chal * &varname_hasher(&entry.name);

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.addr_ordered_eval *= tr_chal - entry_repr;
    }
}

#[derive(Clone)]
pub(crate) struct RunningEvalsVar<F: PrimeField> {
    // Stored values that are updated
    time_ordered_eval: FpVar<F>,
    addr_ordered_eval: FpVar<F>,

    // Values specific to the global polynomial. These are need by the update function.
    // Specifically, this is (entry_chal, tr_chal). These are NOT inputted in the AllocVar impl
    challenges: Option<(FpVar<F>, FpVar<F>)>,
}

impl<F: PrimeField> RunningEvalsVar<F> {
    /// Updates the running evaluation of the time-ordered transcript polyn
    fn update_time_ordered(&mut self, entry: &RomTranscriptEntryVar<F>) {
        let (entry_chal, tr_chal) = self
            .challenges
            .as_ref()
            .expect("RunningEvalsVar.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = &entry.val + entry_chal * &entry.addr;

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.time_ordered_eval *= tr_chal - entry_repr;
    }

    /// Updates the running evaluation of the addr-ordered transcript polyn
    fn addr_time_ordered(&mut self, entry: &RomTranscriptEntryVar<F>) {
        let (entry_chal, tr_chal) = self
            .challenges
            .as_ref()
            .expect("RunningEvalsVar.challenges needs to be set in order to run update");

        // The single-field-element representation of a transcript entry is val + entry_chal*addr,
        // where addr is the hash of the name
        let entry_repr = &entry.val + entry_chal * &entry.addr;

        // Now add the entry to the running polynomial eval. The polynomial is Π (X - entryᵢ)
        // evaluated at X=tr_chal
        self.addr_ordered_eval *= tr_chal - entry_repr;
    }
}

impl<F: PrimeField> AllocVar<RunningEvals<F>, F> for RunningEvalsVar<F> {
    fn new_variable<T: Borrow<RunningEvals<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let evals = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        let time_ordered_eval =
            FpVar::new_variable(ns!(cs, "time"), || evals.map(|e| e.time_ordered_eval), mode)?;
        let addr_ordered_eval =
            FpVar::new_variable(ns!(cs, "addr"), || evals.map(|e| e.addr_ordered_eval), mode)?;

        Ok(RunningEvalsVar {
            time_ordered_eval,
            addr_ordered_eval,
            challenges: None,
        })
    }
}

/// An entry in the transcript of portal wire reads
#[derive(Clone, Default)]
pub struct RomTranscriptEntry<F: PrimeField> {
    name: String,
    val: F,
}

/// An entry in the transcript of portal wire reads
#[derive(Clone)]
pub(crate) struct RomTranscriptEntryVar<F: PrimeField> {
    val: FpVar<F>,
    /// The hash of the variable name
    addr: FpVar<F>,
}

impl<F: PrimeField> AllocVar<RomTranscriptEntry<F>, F> for RomTranscriptEntryVar<F> {
    fn new_variable<T: Borrow<RomTranscriptEntry<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let entry = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        // Hash the variable name into a field element
        let name_hash: Result<F, _> = entry.map(|e| e.name.as_str()).map(varname_hasher);

        let val = FpVar::new_variable(ns!(cs, "val"), || entry.map(|e| F::from(e.val)), mode)?;
        let addr = FpVar::new_variable(ns!(cs, "addr"), || name_hash, mode)?;

        Ok(RomTranscriptEntryVar { val, addr })
    }
}

/// A generic trait that any partitionable circuit has to impl
pub(crate) trait CircuitWithPortals<F: PrimeField> {
    fn num_subcircuits(&self) -> usize;

    /// Generates constraints for the subcircuit at the given index
    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError>;
}
