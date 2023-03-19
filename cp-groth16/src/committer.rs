use crate::{
    data_structures::{CommittingKey, InputCom, InputComRandomness},
    InputAllocator, MultistageConstraintSystem,
};

use core::{
    marker::PhantomData,
    ops::{Deref, Range},
};

use ark_ec::{pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, AffineRepr};
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_relations::r1cs::{ConstraintSystem, SynthesisError};
use ark_std::rand::Rng;

/// A struct that sequentially runs [`InputAllocators`] and commits to the variables allocated therein
pub struct CommitmentBuilder<E, QAP>
where
    E: Pairing,
    QAP: R1CSToQAP,
{
    /// The enhanced constraint system that keeps track of public inputs
    cs: MultistageConstraintSystem<E::ScalarField>,
    /// The underlying committing key
    com_key: CommittingKey<E>,
    /// Counter keeping track of how many allocations have occured
    num_allocated: usize,
    _marker: PhantomData<QAP>,
}

impl<E, QAP> CommitmentBuilder<E, QAP>
where
    E: Pairing,
    QAP: R1CSToQAP,
{
    pub fn new(com_key: CommittingKey<E>) -> Self {
        CommitmentBuilder {
            cs: MultistageConstraintSystem::default(),
            com_key,
            num_allocated: 0,
            _marker: PhantomData,
        }
    }

    // TODO: Make a nicer way for committers to check their idea of the assignments with the actual
    // given assignments. This is important for possibly opening the commitments later.

    pub fn commit<A, R>(
        &mut self,
        rng: &mut R,
        allocator: &A,
    ) -> Result<(InputCom<E>, InputComRandomness<E>, A::AllocatedSelf), SynthesisError>
    where
        A: InputAllocator<E::ScalarField>,
        R: Rng,
    {
        // Using notation from Mirage proofs, this should compute κ₃ and π_D = [κ₃δ]₁ + [J(s)/δ']₁
        // In our case, it's not δ', but one of many etas {ηᵢ}. Pick the right η and compute the
        // commitment. This panics if we have used up all the etas, or the number of instances in a
        // given stage does not match the number of group elements in the committing key.

        // Run the allocator and save the allocated values. We pass those to the prover eventually
        let allocated_vals = self.cs.run_allocator(allocator)?;

        // Inline/outline the relevant linear combinations. This probably does nothing, but it's
        // what's done in the ordinary prover.
        self.cs.cs.finalize();
        // Get *all* the instance assignments from the underlying constraint system
        let instance_assignments = &self.cs.cs.borrow().unwrap().instance_assignment;

        // Pick out the instance values that resulted from this allocator. Also pick the associated
        // group elements for calculating the commitment. These better be the same length.

        // The below unwrap is permitted because `run_allocator` is guaranteed to add a range to
        // the list (though it may be empty)
        let latest_vars: Range<usize> = self.cs.instance_var_idx_ranges.last().unwrap().clone();
        let relevant_assignments: Vec<_> = instance_assignments[latest_vars]
            .iter()
            .cloned()
            .map(|s| s.into_bigint())
            .collect();
        let relevant_group_elems = &self
            .com_key
            .etas_abc_g1
            .get(self.num_allocated)
            .expect("no more values left in committing key");
        assert_eq!(relevant_assignments.len(), relevant_group_elems.len());

        // Compute the commitment. First compute [J(s)/ηᵢ]₁ where i is the allocation stage we're
        // in
        let committed_val = E::G1::msm_bigint(&relevant_group_elems, &relevant_assignments);
        // Now compute the blinder [κδ]₁
        let randomness = E::ScalarField::rand(rng);
        let blinder = self.com_key.delta_g1.mul_bigint(randomness.into_bigint());
        // Now sum them
        let com = committed_val + blinder;

        // Update the number of times the allocator has been run
        self.num_allocated += 1;

        // Return the commitment and the randomness
        Ok((com.into(), randomness, allocated_vals))
    }
}
