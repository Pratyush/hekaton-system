use crate::{
    coordinator::{Stage0Request, Stage1Request},
    eval_tree::{SerializedLeaf, SerializedLeafVar, TreeConfig, TreeConfigGadget},
    subcircuit_circuit::SubcircuitWithPortalsProver,
    util::{gen_merkle_params, G16Com, G16ComSeed, G16ProvingKey},
    CircuitWithPortals,
};

use std::{collections::VecDeque, marker::PhantomData};

use ark_cp_groth16::{
    committer::CommitmentBuilder as G16CommitmentBuilder, r1cs_to_qap::LibsnarkReduction as QAP,
    Proof as G16Proof,
};
use ark_ec::pairing::Pairing;
use rand::RngCore;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// The repsonse is the Groth16 commitment and seed for the requested subcircuit
#[derive(Clone)]
pub struct Stage0Response<E: Pairing> {
    pub(crate) subcircuit_idx: usize,
    pub(crate) com: G16Com<E>,
    pub(crate) com_seed: G16ComSeed,
}

/// The repsonse is the Groth16 proof for the requested subcircuit
pub struct Stage1Response<E: Pairing> {
    pub subcircuit_idx: usize,
    pub proof: G16Proof<E>,
}

/// Consumes the stage0 request and performs the necessary Groth16 commitment
pub fn process_stage0_request<C, CG, E, P, R>(
    mut rng: R,
    pk: &G16ProvingKey<E>,
    req: Stage0Request<E::ScalarField>,
) -> Stage0Response<E>
where
    C: TreeConfig<Leaf = SerializedLeaf>,
    CG: TreeConfigGadget<C, E::ScalarField, Leaf = SerializedLeafVar<E::ScalarField>>,
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField> + Clone,
    R: RngCore,
{
    // Unpack the values
    let Stage0Request {
        subcircuit_idx,
        time_ordered_subtrace,
        addr_ordered_subtrace,
    } = req;

    // Generate the merkle params
    let (leaf_params, two_to_one_params) = gen_merkle_params::<C>();

    // Commit to their stage 0 inputs (ie the subtraces), and save the commitments and RNG seeds

    // Make an empty prover
    // The number of subcircuits dictates the size of the Merkle tree. This is irrelevant
    // here because we're only running stage 0 of the circuit, which involves no tree ops.
    // Make it 2 so that we don't get underflow by accident
    let num_subcircuits = 2;
    // TODO: Make this circuit take refs. Avoid the cloning
    let mut prover = SubcircuitWithPortalsProver::<_, P, _, CG>::new(
        leaf_params,
        two_to_one_params,
        num_subcircuits,
    );

    // Fill in the correct subcircuit index and subtrace data
    prover.subcircuit_idx = subcircuit_idx;
    prover.time_ordered_subtrace = time_ordered_subtrace;
    prover.addr_ordered_subtrace = addr_ordered_subtrace;

    // Create a seed and make an RNG from it
    let com_seed = rng.gen::<G16ComSeed>();
    let mut subcircuit_rng = ChaCha12Rng::from_seed(com_seed);

    // Commit to the stage 0 values (the subtraces)
    let mut cb = G16CommitmentBuilder::<_, E, QAP>::new(prover, &pk);
    let (com, _) = cb
        .commit(&mut subcircuit_rng)
        .expect("failed to commit to subtrace");

    Stage0Response {
        subcircuit_idx,
        com,
        com_seed,
    }
}

/// Process the given stage1 request, along with all the previous messages in this execution, and
/// produces a Groth16 proof
pub fn process_stage1_request<C, CG, E, P, R>(
    mut rng: R,
    pk: &G16ProvingKey<E>,
    stage0_req: Stage0Request<E::ScalarField>,
    stage0_resp: Stage0Response<E>,
    stage1_req: Stage1Request<C, E::ScalarField, P>,
) -> Stage1Response<E>
where
    C: TreeConfig<Leaf = SerializedLeaf>,
    CG: TreeConfigGadget<C, E::ScalarField, Leaf = SerializedLeafVar<E::ScalarField>>,
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField>,
    R: RngCore,
{
    let (leaf_params, two_to_one_params) = gen_merkle_params::<C>();

    // Unpack everything we'll need
    let Stage1Request {
        subcircuit_idx,
        cur_leaf,
        next_leaf_membership,
        root,
        serialized_witnesses,
        circ_params,
    } = stage1_req;
    let (entry_chal, tr_chal) = cur_leaf.evals.challenges.unwrap();

    // Make an empty version of the large circuit and fill in just the witnesses for the
    // subcircuit we're proving now
    let mut partial_circ = P::new(&circ_params);

    partial_circ.set_serialized_witnesses(subcircuit_idx, &serialized_witnesses);

    let real_circ = SubcircuitWithPortalsProver {
        subcircuit_idx,
        circ: Some(partial_circ),
        leaf_params: leaf_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
        time_ordered_subtrace: stage0_req.time_ordered_subtrace.clone(),
        addr_ordered_subtrace: stage0_req.addr_ordered_subtrace.clone(),
        time_ordered_subtrace_var: VecDeque::new(),
        addr_ordered_subtrace_var: VecDeque::new(),
        cur_leaf,
        next_leaf_membership,
        entry_chal,
        tr_chal,
        root,
        _marker: PhantomData::<CG>,
    };

    // The commitment RNG is determined by com_seed
    let mut cb = G16CommitmentBuilder::<_, E, QAP>::new(real_circ, pk);
    let mut subcircuit_rng = {
        let com_seed = stage0_resp.com_seed.clone();
        ChaCha12Rng::from_seed(com_seed)
    };

    // Commit to the values
    // TODO: Figure out a way to save constraint systems so that we don't have to do the commitment
    // from scratch
    let (com, rand) = cb.commit(&mut subcircuit_rng).unwrap();
    assert_eq!(com, stage0_resp.com);

    let proof = cb.prove(&[com], &[rand], &mut rng).unwrap();

    Stage1Response {
        subcircuit_idx,
        proof,
    }
}
