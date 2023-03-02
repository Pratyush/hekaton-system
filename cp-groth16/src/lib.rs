use core::ops::Range;

use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

mod data_structures;
mod verifier;

/// Represents a constraint system whose variables come from a number of distinct allocation
/// stages. Each allocation stage happens separately, and adds to the total witness variable count.
struct MultistageAllocator<F: Field> {
    cs: ConstraintSystemRef<F>,
    /// Keeps track of the witness variables. The value at element `i` is the set of witness
    /// variable indices in `self.cs` that correspond to stage `i` of allocation
    wit_var_idx_ranges: Vec<Range<usize>>,
}

/// Defines a way for a type to allocate all its content as _witnesses_ or _constants_. You SHOULD
/// NOT allocate anything as a public input in this stage.
trait AllocWitnesses<F: Field> {
    fn alloc(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError>;
}

impl<F: Field> MultistageAllocator<F> {
    fn alloc_stage<A: AllocWitnesses<F>>(&mut self, val: &A) -> Result<(), SynthesisError> {
        // Mark the starting variable index (inclusive)
        let start_var_idx = self.cs.num_witness_variables();
        // Run the allocation routine
        val.alloc(self.cs.clone())?;
        // Mark the ending variable index (exclusive)
        let end_var_idx = self.cs.num_witness_variables();

        // Record the variable range. If it's empty, do nothing
        let range = Range {
            start: start_var_idx,
            end: end_var_idx,
        };
        if !range.is_empty() {
            self.wit_var_idx_ranges.push(range);
        }

        Ok(())
    }
}
