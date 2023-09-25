use crate::{varname_hasher, RomTranscriptEntry, RomTranscriptEntryVar, RunningEvalsVar};

use std::{cmp::Ordering, collections::HashMap};

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, R1CSVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

/// A trait for getting and setting portal wires in partitioned circuits
pub(crate) trait PortalManager<'a, F: PrimeField> {
    /// Gets the portal wire of the given name. Panics if no such wire exists.
    fn get(&mut self, name: &'a str) -> Result<FpVar<F>, SynthesisError>;

    /// Sets the portal wire of the given name. Panics if the wire is already set.
    fn set(&mut self, name: &'a str, val: &FpVar<F>) -> Result<(), SynthesisError>;
}

/// This portal manager is used by the coordinator to produce the trace
struct SetupPortalManager<'a, F: PrimeField> {
    pub trace: Vec<RomTranscriptEntry<'a, F>>,

    cs: ConstraintSystemRef<F>,

    // Technically not necessary, but useful for sanity checks
    map: HashMap<String, F>,
}

impl<'a, F: PrimeField> PortalManager<'a, F> for SetupPortalManager<'a, F> {
    /// Gets the value from the map, witnesses it, and adds the entry to the trace
    fn get(&mut self, name: &'a str) -> Result<FpVar<F>, SynthesisError> {
        // Get the value
        let val = *self
            .map
            .get(name)
            .expect(&format!("cannot get portal wire '{name}'"));
        // Witness the value
        let val_var = FpVar::new_witness(ns!(self.cs, "wireval"), || Ok(val))?;
        // Make the transcript entry
        self.trace.push(RomTranscriptEntry { name, val });

        // Return the witnessed value
        Ok(val_var)
    }

    /// Sets the value in the map and adds the entry to the trace
    fn set(&mut self, name: &'a str, val: &FpVar<F>) -> Result<(), SynthesisError> {
        // This is ROM. You cannot overwrite values
        assert!(
            self.map.get(name).is_none(),
            "cannot set portal wire more than once; wire '{name}'"
        );

        // Log the concrete (not ZK) entry
        self.map.insert(name.to_string(), val.value().unwrap());
        self.trace.push(RomTranscriptEntry {
            name,
            val: val.value().unwrap(),
        });

        Ok(())
    }
}

/// This portal manager is used by a subcircuit prover. It takes the subtrace for this subcircuit as
/// well as the running evals up until this point. These values are used in the CircuitWithPortals
/// construction later.
struct ProverPortalManager<F: PrimeField> {
    pub time_ordered_subtrace: Vec<RomTranscriptEntryVar<F>>,
    pub addr_ordered_subtrace: Vec<RomTranscriptEntryVar<F>>,
    pub running_evals: RunningEvalsVar<F>,
}

impl<'a, F: PrimeField> PortalManager<'a, F> for ProverPortalManager<F> {
    /// Pops off the subtrace, sanity checks that the names match, updates the running polyn
    /// evals to reflect the read op, and does one step of the name-ordered coherence check.
    fn get(&mut self, name: &str) -> Result<FpVar<F>, SynthesisError> {
        // Pop the value and sanity check the name
        let entry = self
            .time_ordered_subtrace
            .pop()
            .expect("ran out of trace elements");
        assert_eq!(entry.addr.value().unwrap(), varname_hasher(name));

        // Update the running polyn
        self.running_evals.update_time_ordered(&entry);

        // On our other subtrace, do one step of a memory-ordering check

        // Pop off a value and peek the next one. Unpack both
        let RomTranscriptEntryVar {
            addr: cur_addr,
            val: cur_val,
        } = self.addr_ordered_subtrace.pop().unwrap();
        let RomTranscriptEntryVar {
            addr: next_addr,
            val: next_val,
        } = self.addr_ordered_subtrace.first().unwrap();

        // Check cur_addr <= next_addr
        cur_addr.enforce_cmp(next_addr, Ordering::Less, true)?;
        // Check cur_val == next_val if cur_addr == next_addr
        let is_same_addr = cur_addr.is_eq(next_addr)?;
        cur_val.conditional_enforce_equal(next_val, &is_same_addr)?;

        // Return the val from the subtrace
        Ok(entry.val)
    }

    /// Set is no different from get in circuit land. This does the same thing, and also enforce
    /// that `val` equals the popped subtrace value.
    fn set(&mut self, name: &str, val: &FpVar<F>) -> Result<(), SynthesisError> {
        let trace_val = self.get(name)?;
        val.enforce_equal(&trace_val)?;

        Ok(())
    }
}
