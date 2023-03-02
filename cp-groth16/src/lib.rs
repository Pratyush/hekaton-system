use core::{marker::PhantomData, ops::Range};

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

mod data_structures;
mod generator;
mod verifier;

/// Represents a constraint system whose variables come from a number of distinct allocation
/// stages. Each allocation stage happens separately, and adds to the total instance variable
/// count.
struct MultistageConstraintSystem<F: Field> {
    cs: ConstraintSystemRef<F>,
    /// Keeps track of the instance variables. The value at element `i` is the set of instance
    /// variable indices in `self.cs` that correspond to stage `i` of allocation
    instance_var_idx_ranges: Vec<Range<usize>>,
}

impl<F: Field> Default for MultistageConstraintSystem<F> {
    fn default() -> Self {
        MultistageConstraintSystem {
            cs: ConstraintSystem::new_ref(),
            instance_var_idx_ranges: Vec::new(),
        }
    }
}

/// Defines a way for a type to allocate all its content as _instances_ or _constants_. It can
/// allocate witnesses too, but only the instances will be committed to.
trait InputAllocator<F: Field> {
    fn alloc(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError>;
}

impl<F: Field> MultistageConstraintSystem<F> {
    fn alloc_stage(&mut self, val: &dyn InputAllocator<F>) -> Result<(), SynthesisError> {
        // Mark the starting variable index (inclusive)
        let start_var_idx = self.cs.num_instance_variables();
        // Run the allocation routine
        val.alloc(self.cs.clone())?;
        // Mark the ending variable index (exclusive)
        let end_var_idx = self.cs.num_instance_variables();

        // Record the variable range. If it's empty, do nothing
        let range = Range {
            start: start_var_idx,
            end: end_var_idx,
        };
        if !range.is_empty() {
            self.instance_var_idx_ranges.push(range);
        }

        Ok(())
    }
}

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
pub struct Groth16<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> {
    _p: PhantomData<(E, QAP)>,
}
