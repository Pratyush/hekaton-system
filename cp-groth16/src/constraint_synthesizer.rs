use core::ops::Range;

use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};

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
        // self.cs.inline_all_lcs();
        let end = self.cs.num_witness_variables();
        self.variable_range_for_stage.last_mut().unwrap().end = end;
    }

    /// This is the method that should be used to synthesize constraints inside `generate_constraints`.
    pub fn synthesize_with(
        &mut self,
        constraints: impl FnOnce(ConstraintSystemRef<F>) -> Result<(), SynthesisError>,
    ) -> Result<(), SynthesisError> {
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
    pub fn current_stage_witness_assignment(&self) -> Vec<F> {
        let range = self.variable_range_for_stage.last().unwrap();
        self.cs.borrow().unwrap().witness_assignment[range.clone()].to_vec()
    }

    /// Returns the assignments to all variables.
    pub fn full_assignment(&self) -> Vec<F> {
        let mut full_assignment = self.cs.borrow().unwrap().instance_assignment.to_vec();
        full_assignment.extend_from_slice(&self.cs.borrow().unwrap().witness_assignment);
        full_assignment
    }

    pub fn finalize(&mut self) {
        self.cs.finalize();
    }

    pub fn is_satisfied(&self) -> Result<bool, SynthesisError> {
        self.cs.is_satisfied()
    }
}

/// A multi-stage constraint synthesizer that iteratively constructs
/// a constraint system.
pub trait MultiStageConstraintSynthesizer<F: Field> {
    /// The number of stages required to construct the constraint system.
    fn total_num_stages(&self) -> usize;

    /// The number of stages required to construct the constraint system.
    fn last_stage(&self) -> usize {
        self.total_num_stages() - 1
    }

    /// Generates constraints for the i-th stage.
    fn generate_constraints(
        &mut self,
        stage: usize,
        cs: &mut MultiStageConstraintSystem<F>,
    ) -> Result<(), SynthesisError>;
}
