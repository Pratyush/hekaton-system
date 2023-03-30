use crate::{
    data_structures::{Comm, CommRandomness, CommitterKey, Proof, ProvingKey},
    prover::Groth16,
    MultiStageConstraintSynthesizer, MultiStageConstraintSystem,
};

use core::{marker::PhantomData, ops::Range};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError,
};
use ark_std::rand::Rng;

/// A struct that sequentially runs [`InputAllocators`] and commits to the variables allocated therein
pub struct CommitmentBuilder<E: Pairing, C: MultiStageConstraintSynthesizer<E::ScalarField>, QAP> {
    /// The enhanced constraint system that keeps track of public inputs
    pub cs: MultiStageConstraintSystem<E::ScalarField>,
    /// The circuit that generates assignments for the commitment.
    pub circuit: C,
    /// The committer key that will be used to generate commitments at each step.
    ck: CommitterKey<E>,
    _qap: PhantomData<QAP>,
}

impl<E, C, QAP> CommitmentBuilder<E, C, QAP>
where
    E: Pairing,
    C: MultiStageConstraintSynthesizer<E::ScalarField>,
    QAP: R1CSToQAP,
{
    pub fn new(circuit: C, ck: CommitterKey<E>) -> Self {
        // Make a new constraint system and set the optimization goal
        let mscs = MultiStageConstraintSystem::default();
        mscs.cs.set_optimization_goal(OptimizationGoal::Constraints);

        Self {
            cs: mscs,
            circuit,
            ck,
            _qap: PhantomData,
        }
    }

    // TODO: Make a nicer way for committers to check their idea of the assignments with the actual
    // given assignments. This is important for possibly opening the commitments later.

    pub fn commit(
        &mut self,
        rng: &mut impl Rng,
    ) -> Result<(Comm<E>, CommRandomness<E>), SynthesisError> {
        self.circuit.generate_constraints(self.cs)?;

        // Inline/outline the relevant linear combinations.
        self.cs.finalize();

        // Get *all* the witness assignments from the underlying constraint system
        let current_witness = self.cs.current_stage_witness_assignment();

        // Pick out the instance values that resulted from this allocator. Also pick the associated
        // group elements for calculating the commitment. These better be the same length.

        // The below unwrap is permitted because `run_allocator` is guaranteed to add a range to
        // the list (though it may be empty)
        let current_ck = &self
            .ck
            .deltas_abc_g
            .get(self.circuit.current_stage())
            .expect("no more values left in committing key");
        assert_eq!(current_witness.len(), current_ck.len(),);

        // Compute the commitment. First compute [J(s)/ηᵢ]₁ where i is the allocation stage we're
        // in

        let randomness = E::ScalarField::rand(rng);
        let commitment =
            E::G1::msm(current_ck, current_witness).unwrap() + self.ck.last_delta_g * randomness;

        // Return the commitment and the randomness
        Ok((commitment.into(), randomness))
    }

    pub fn prove(
        &self,
        pk: &ProvingKey<E>,
        comms: Vec<Comm<E>>,
        comm_rands: &[CommRandomness<E>],
        rng: &mut impl Rng,
    ) -> Result<Proof<E>, SynthesisError>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        E: Pairing,
    {
        let ark_groth16::Proof { a, b, c } = Groth16::<E>::create_random_proof_with_reduction(
            self.cs.cs.clone(),
            circuit,
            &pk.g16_pk,
            rng,
        )?;

        // Compute Σ [κᵢηᵢ] and subtract it from C
        let kappas_etas_g1 = E::G1::msm(&pk.etas_g1, com_rands)
            .expect("incorrect number of commitment randomness vals");
        let c = (c.into_group() - &kappas_etas_g1).into_affine();

        Ok(Proof {
            a,
            b,
            c,
            ds: dbg!(coms),
        })
    }
}
