use crate::{
    data_structures::{CommittingKey, InputCom, InputComRandomness},
    InputAllocator, MultistageConstraintSystem,
};

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::Rng;

/// A struct that sequentially runs [`InputAllocators`] and commits to the variables allocated therein
pub struct CommitmentBuilder<E: Pairing> {
    cs: MultistageConstraintSystem<E::ScalarField>,
    com_key: CommittingKey<E>,
}

impl<E: Pairing> CommitmentBuilder<E> {
    pub fn new(com_key: CommittingKey<E>) -> Self {
        CommitmentBuilder {
            cs: MultistageConstraintSystem::default(),
            com_key,
        }
    }

    pub fn commit<A, R>(
        &mut self,
        rng: &mut R,
        a: &A,
    ) -> Result<(InputCom<E>, InputComRandomness<E>, A::AllocatedSelf), SynthesisError>
    where
        A: InputAllocator<E::ScalarField>,
        R: Rng,
    {
        // Using notation from Mirage proofs, this should compute κ₃ and π_D = [κ₃δ]₁ + [J(s)/δ']₁
        // In our case, it's not δ', but one of many etas {ηᵢ}. Pick the right η and compute the
        // commitment. This should return some sort of `SynthesisError` if we have already used up
        // all the etas.
        todo!()
    }
}
