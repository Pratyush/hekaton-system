use crate::{
    data_structures::{Comm, CommRandomness, Proof, ProvingKey},
    prover::Groth16,
    MultiStageConstraintSynthesizer, MultiStageConstraintSystem,
};

use core::marker::PhantomData;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_groth16::{r1cs_to_qap::R1CSToQAP, Proof as ProofWithoutComms};
use ark_relations::r1cs::{OptimizationGoal, SynthesisError};
use ark_std::rand::Rng;

/// A struct that sequentially runs [`InputAllocators`] and commits to the variables allocated therein
pub struct CommitmentBuilder<'a, C, E, QAP>
where
    C: MultiStageConstraintSynthesizer<E::ScalarField>,
    E: Pairing,
{
    /// The enhanced constraint system that keeps track of public inputs
    pub cs: MultiStageConstraintSystem<E::ScalarField>,
    /// The circuit that generates assignments for the commitment.
    pub circuit: C,
    /// The current stage.
    cur_stage: usize,
    /// The committer key that will be used to generate commitments at each step.
    pk: &'a ProvingKey<E>,
    _qap: PhantomData<QAP>,
}

impl<'a, C, E, QAP> CommitmentBuilder<'a, C, E, QAP>
where
    C: MultiStageConstraintSynthesizer<E::ScalarField>,
    E: Pairing,
    QAP: R1CSToQAP,
{
    pub fn new(circuit: C, pk: &'a ProvingKey<E>) -> Self {
        // Make a new constraint system and set the optimization goal
        let mscs = MultiStageConstraintSystem::default();
        mscs.cs.set_optimization_goal(OptimizationGoal::Constraints);

        Self {
            cs: mscs,
            circuit,
            cur_stage: 0,
            pk,
            _qap: PhantomData,
        }
    }

    // TODO: Make a nicer way for committers to check their idea of the assignments with the actual
    // given assignments. This is important for possibly opening the commitments later.

    pub fn commit(
        &mut self,
        rng: &mut impl Rng,
    ) -> Result<(Comm<E>, CommRandomness<E>), SynthesisError> {
        self.circuit
            .generate_constraints(self.cur_stage, &mut self.cs)?;

        // Inline/outline the relevant linear combinations.
        debug_assert!(self.cs.is_satisfied().unwrap());

        // Get *all* the witness assignments from the underlying constraint system
        let current_witness = self.cs.current_stage_witness_assignment();

        // Pick out the instance values that resulted from this allocator. Also pick the associated
        // group elements for calculating the commitment. These better be the same length.

        // The below unwrap is permitted because `run_allocator` is guaranteed to add a range to
        // the list (though it may be empty)
        let current_ck = &self
            .pk
            .ck
            .deltas_abc_g
            .get(self.cur_stage)
            .expect("no more values left in committing key");

        assert_eq!(current_witness.len(), current_ck.len(),);

        let randomness = E::ScalarField::rand(rng);
        // Compute the commitment.
        let commitment =
            // First compute [J(s)/ηᵢ]₁ where i is the current stage.
            E::G1::msm(current_ck, &current_witness).unwrap()
            // Then add in the randomizer
            + (self.pk.ck.last_delta_g * randomness);

        self.cur_stage += 1;

        // Return the commitment and the randomness
        Ok((commitment.into(), randomness))
    }

    pub fn prove(
        &mut self,
        comms: Vec<Comm<E>>,
        comm_rands: &[CommRandomness<E>],
        rng: &mut impl Rng,
    ) -> Result<Proof<E>, SynthesisError> {
        let ProofWithoutComms { a, b, c } =
            Groth16::<E>::prove_last_stage_with_zk(&mut self.cs, &mut self.circuit, &self.pk, rng)?;

        // Compute Σ [κᵢηᵢ] and subtract it from C
        // We use unchecked here because we don't care about if `deltas_g.len() == comm_rands.len()`
        // It actually will not be equal
        assert_eq!(self.pk.deltas_g.len(), comm_rands.len() + 1);
        let kappas_etas_g1 = E::G1::msm_unchecked(&self.pk.deltas_g, comm_rands);
        let c = (c.into_group() - kappas_etas_g1).into_affine();

        Ok(Proof { a, b, c, ds: comms })
    }
}
