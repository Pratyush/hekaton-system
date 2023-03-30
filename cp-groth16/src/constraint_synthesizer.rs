use core::ops::Range;

use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef, ConstraintSystem};
use ark_ff::Field;

/// Represents a constraint system whose variables come from a number of distinct allocation
/// stages. Each allocation stage happens separately, and adds to the total instance variable
/// count.
/// 
/// We assume that the indexing of witness variables increases linearly. e.g. it is not the case
/// that stage 1 allocates variables 1, 2, 100, and stage 2 allocates variables 3, 4, 5.
pub struct MultiStageConstraintSystem<F: Field> {
    pub cs: ConstraintSystemRef<F>,
    /// Keeps track of the witness variables at different stages. That is
    /// `start..end = max_variable_for_stage[i]` is the range of witness variables allocated in
    /// stage `i`.
    ///
    /// Furthermore, we assume that for all `i`, `max_variable_for_stage[i].end = max_variable_for_stage[i+1].start`.
    pub variable_range_for_stage: Vec<Range<usize>>,
}

impl<F: Field> Default for MultiStageConstraintSystem<F> {
    fn default() -> Self {
        MultiStageConstraintSystem {
            cs: ConstraintSystem::new_ref(),
            variable_range_for_stage: Vec::new(),
        }
    }
}

impl<F: Field> MultiStageConstraintSystem<F> {
    /// Construct an empty constraint system.
    pub fn new() -> Self {
        Self::default()
    }

    /// Must be called by the constraint synthesizer before starting constraint synthesis
    /// for the i-th stage.
    pub fn initialize_stage(&mut self) {
        let start = self.cs.num_witness_variables();
        self.variable_range_for_stage.push(start..start);
    }

    /// Must be called by the constraint synthesizer before ending constraint synthesis
    /// for the i-th stage.
    pub fn finalize_stage(&mut self) {
        let end = self.cs.num_witness_variables();
        self.variable_range_for_stage.last().as_mut().unwrap().end = end;
    }

    /// This is the method that should be used to synthesize constraints inside `generate_constraints`.
    pub fn synthesize_with(&mut self, constraints: impl FnOnce(ConstraintSystemRef<F>) -> Result<(), SynthesisError>) -> Result<(), SynthesisError> {
        self.initialize_stage();
        constraints(self.cs.clone())?;
        self.finalize_stage();
        Ok(())
    }

    // /// Returns the witness variables allocated in stage `i`.
    // pub fn witness_variables_for_stage(&self, i: usize) -> &[F] {
    //     let range = self.variable_range_for_stage[i];
    //     &self.cs.witness_variables()[range]
    // }
    
    pub fn num_instance_variables(&self) -> usize {
        self.cs.num_instance_variables()
    }

    pub fn num_witness_variables(&self) -> usize {
        self.cs.num_witness_variables()
    }

    pub fn num_constraints(&self) -> usize {
        self.cs.num_constraints()
    }

    /// Returns the assignments to witness variables allocated in the current stage.
    pub fn current_stage_witness_assignment(&self) -> &[F] {
        let range = self.variable_range_for_stage.last().unwrap();
        &self.cs.borrow().unwrap().witness_assignment[range.clone()]
    }

    pub fn finalize(&mut self) {
        self.cs.finalize();
    }
}

/// A multi-stage constraint synthesizer that iteratively constructs 
/// a constraint system.
pub trait MultiStageConstraintSynthesizer<F: Field> {
    /// The number of stages required to construct the constraint system.
    fn total_num_stages(&self) -> usize;

    /// The current stage of the constraint system.
    fn current_stage(&self) -> usize;

    /// Generates constraints for the i-th stage.
    fn generate_constraints(&mut self, cs: MultiStageConstraintSystem<F>) -> Result<(), SynthesisError>;
}