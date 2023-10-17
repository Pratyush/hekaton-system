use crate::{RomTranscriptEntry, RomTranscriptEntryVar, RunningEvalsVar};

use std::{cmp::Ordering, collections::HashMap};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

/// A trait for getting and setting portal wires in partitioned circuits
pub trait PortalManager<F: PrimeField> {
    /// Gets the portal wire of the given name. Panics if no such wire exists.
    fn get(&mut self, name: &str) -> Result<FpVar<F>, SynthesisError>;

    /// Sets the portal wire of the given name. Panics if the wire is already set.
    fn set(&mut self, name: String, val: &FpVar<F>) -> Result<(), SynthesisError>;
}

/// This portal manager is used by the coordinator to produce the trace
pub struct SetupPortalManager<F: PrimeField> {
    /// All the subtraces from the full run of the circuit
    pub subtraces: Vec<Vec<RomTranscriptEntry<F>>>,

    /// The address that this manager will assign to the next unseen variable name
    next_var_addr: u64,

    /// A map from variable names to their transcript entry
    var_map: HashMap<String, RomTranscriptEntry<F>>,

    cs: ConstraintSystemRef<F>,
}

impl<F: PrimeField> SetupPortalManager<F> {
    // TODO: Remove the cs input here. It's not needed bc it's given in the start_subtrace method
    pub fn new(cs: ConstraintSystemRef<F>) -> Self {
        SetupPortalManager {
            cs,
            next_var_addr: 1, // We have to start at 1 because 0 is reserved for padding
            subtraces: Vec::new(),
            var_map: HashMap::new(),
        }
    }

    /// Makes a subtrace and updates the constraint system. The constraint system needs to be
    /// updated with an empty one otherwise it gets too big and we run out of memory
    pub(crate) fn start_subtrace(&mut self, cs: ConstraintSystemRef<F>) {
        self.subtraces.push(Vec::new());
        self.cs = cs;
    }
}

impl<F: PrimeField> PortalManager<F> for SetupPortalManager<F> {
    /// Gets the value from the map, witnesses it, and adds the entry to the trace
    fn get(&mut self, name: &str) -> Result<FpVar<F>, SynthesisError> {
        // Get the transcript entry corresponding to this variable
        let entry = *self
            .var_map
            .get(name)
            .expect(&format!("cannot get portal wire '{name}'"));

        // Witness the value
        let val_var = FpVar::new_witness(ns!(self.cs, "wireval"), || Ok(entry.val))?;

        // Add the entry to the time-ordered subtrace
        self.subtraces
            .last_mut()
            .expect("must run start_subtrace() before using SetupPortalManager")
            .push(entry);

        // Return the witnessed value
        Ok(val_var)
    }

    /// Sets the value in the map and adds the entry to the trace
    fn set(&mut self, name: String, val: &FpVar<F>) -> Result<(), SynthesisError> {
        // This is ROM. You cannot overwrite values
        assert!(
            self.var_map.get(&name).is_none(),
            "cannot set portal wire more than once; wire '{name}'"
        );

        // Make a new transcript entry. Use a fresh address
        let entry = RomTranscriptEntry {
            val: val.value().unwrap(),
            addr: self.next_var_addr,
        };
        // Increment to the next unused address
        self.next_var_addr += 1;

        // Log the concrete (not ZK) entry
        self.var_map.insert(name.to_string(), entry);
        self.subtraces
            .last_mut()
            .expect("must run start_subtrace() before using SetupPortalManager")
            .push(entry);

        Ok(())
    }
}

/// This portal manager is used by a subcircuit prover. It takes the subtrace for this subcircuit as
/// well as the running evals up until this point. These values are used in the CircuitWithPortals
/// construction later.
pub(crate) struct ProverPortalManager<F: PrimeField> {
    pub time_ordered_subtrace: Vec<RomTranscriptEntryVar<F>>,
    pub addr_ordered_subtrace: Vec<RomTranscriptEntryVar<F>>,
    pub running_evals: RunningEvalsVar<F>,
    pub next_entry_idx: usize,
}

impl<F: PrimeField> PortalManager<F> for ProverPortalManager<F> {
    /// Gets the next subtrace elem, updates the running polyn evals to reflect the read op, and
    /// does one step of the name-ordered coherence check.
    fn get(&mut self, _name: &str) -> Result<FpVar<F>, SynthesisError> {
        // Get the next value
        let entry = self
            .time_ordered_subtrace
            .get(self.next_entry_idx)
            .expect("ran out of time-ordered subtrace entries");

        // TODO: Would probably be a good thing to have RomTranscriptEntry and
        // RomTranscriptEntryVar carry a copy of their variable name so you could catch errors in
        // trace ordering.

        // Update the running polyn
        self.running_evals.update_time_ordered(&entry);

        // On our other subtrace, do one step of a memory-ordering check

        // Get the next two values. Unpack both
        let RomTranscriptEntryVar {
            addr: cur_addr,
            val: cur_val,
        } = self
            .addr_ordered_subtrace
            .get(self.next_entry_idx)
            .expect("ran out of addr-ordered subtrace entries");
        let next_entry = self
            .addr_ordered_subtrace
            .get(self.next_entry_idx + 1)
            .unwrap();
        let (next_addr, next_val) = (&next_entry.addr, &next_entry.val);

        // Check cur_addr <= next_addr. In fact, next_addr is guaranteed to be cur_addr + 1 if not
        // equal.
        let is_same_addr = next_addr.is_eq(&cur_addr)?;
        let is_incrd_addr = next_addr.is_eq(&(cur_addr + FpVar::one()))?;
        is_same_addr
            .or(&is_incrd_addr)?
            .enforce_equal(&Boolean::TRUE)?;

        // Check cur_val == next_val if cur_addr == next_addr
        cur_val.conditional_enforce_equal(next_val, &is_same_addr)?;

        // Log the peeked addr-ordered entry. This means that every addr-ordered entry is logged
        // except for the initial padding entry.
        self.running_evals.update_addr_ordered(&next_entry);

        // Update the index into the trace(s)
        self.next_entry_idx += 1;

        // Return the val from the subtrace
        Ok(entry.val.clone())
    }

    /// Set is no different from get in circuit land. This does the same thing, and also enforce
    /// that `val` equals the popped subtrace value.
    fn set(&mut self, name: String, val: &FpVar<F>) -> Result<(), SynthesisError> {
        let trace_val = self.get(&name)?;
        val.enforce_equal(&trace_val)?;

        Ok(())
    }
}
