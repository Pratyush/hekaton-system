use crate::{
    coordinator::{Stage0Request, Stage1Request},
    eval_tree::{ExecTreeParams, SerializedLeaf, SerializedLeafVar, TreeConfig, TreeConfigGadget},
    subcircuit_circuit::SubcircuitWithPortalsProver,
    util::{G16Com, G16ComKey, G16ComRandomness, G16ComSeed, G16ProvingKey},
    CircuitWithPortals,
};

use std::{collections::VecDeque, marker::PhantomData};

use ark_cp_groth16::{
    committer::CommitmentBuilder as G16CommitmentBuilder, r1cs_to_qap::LibsnarkReduction as QAP,
    Proof as G16Proof,
};
use ark_ec::pairing::Pairing;
// use ark_msm::msm::VariableBaseMSMExt;
use ark_r1cs_std::fields::fp::FpVar;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::RngCore;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// The repsonse is the Groth16 commitment and seed for the requested subcircuit
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Stage0Response<E: Pairing> {
    pub(crate) subcircuit_idx: usize,
    pub(crate) com: G16Com<E>,
    pub(crate) com_seed: G16ComSeed,
}

impl<E: Pairing> Stage0Response<E> {
    pub fn dummy() -> Self {
        Self {
            subcircuit_idx: 0,
            com: G16Com::<E>::default(),
            com_seed: G16ComSeed::default(),
        }
    }
}

/// The repsonse is the Groth16 proof for the requested subcircuit
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Stage1Response<E: Pairing> {
    pub subcircuit_idx: usize,
    pub proof: G16Proof<E>,
}

impl<E: Pairing> Stage1Response<E> {
    pub fn dummy() -> Self {
        Self {
            subcircuit_idx: 0,
            proof: G16Proof::default(),
        }
    }
}

/// Consumes the stage0 request and performs the necessary Groth16 commitment
pub fn process_stage0_request<C, CG, E, P, R>(
    mut rng: R,
    tree_params: ExecTreeParams<C>,
    g16_ck: G16ComKey<E>,
    req: Stage0Request<E::ScalarField>,
) -> Stage0Response<E>
where
    C: TreeConfig<Leaf = SerializedLeaf<E::ScalarField>>,
    CG: TreeConfigGadget<C, E::ScalarField, Leaf = SerializedLeafVar<E::ScalarField>>,
    E: Pairing,
    // E::G1: VariableBaseMSMExt,
    // E::G2: VariableBaseMSMExt,
    P: CircuitWithPortals<E::ScalarField> + Clone,
    R: RngCore,
{
    // Unpack the values
    let Stage0Request {
        subcircuit_idx,
        time_ordered_subtrace,
        addr_ordered_subtrace,
    } = req;

    // Commit to their stage 0 inputs (ie the subtraces), and save the commitments and RNG seeds

    // Make an empty prover
    // The number of subcircuits dictates the size of the Merkle tree. This is irrelevant
    // here because we're only running stage 0 of the circuit, which involves no tree ops.
    // Make it 2 so that we don't get underflow by accident
    let num_subcircuits = 2;
    // TODO: Make this circuit take refs. Avoid the cloning
    let mut prover = SubcircuitWithPortalsProver::<_, P, _, CG>::new(tree_params, num_subcircuits);

    // Fill in the correct subcircuit index and subtrace data
    prover.subcircuit_idx = subcircuit_idx;
    prover.time_ordered_subtrace = time_ordered_subtrace;
    prover.addr_ordered_subtrace = addr_ordered_subtrace;

    // Create a seed and make an RNG from it
    let com_seed = rng.gen::<G16ComSeed>();
    let mut subcircuit_rng = ChaCha12Rng::from_seed(com_seed);

    // Huge hack: we're only running the G16CommitmentBuilder for the commit() step, so we don't
    // actually need the full proving key. So we make an empty proving key where just the committer
    // key is set
    let empty_pk = G16ProvingKey {
        ck: g16_ck,

        // Rest is empty
        vk: ark_cp_groth16::data_structures::VerifyingKey {
            alpha_g: E::G1Affine::default(),
            beta_h: E::G2Affine::default(),
            gamma_h: E::G2Affine::default(),
            last_delta_h: E::G2Affine::default(),
            gamma_abc_g: Vec::new(),
            deltas_h: Vec::new(),
        },
        beta_g: E::G1Affine::default(),
        a_g: Vec::new(),
        b_g: Vec::new(),
        b_h: Vec::new(),
        h_g: Vec::new(),
        deltas_g: Vec::new(),
    };

    // Commit to the stage 0 values (the subtraces)
    let mut cb = G16CommitmentBuilder::<_, E, QAP>::new(prover, &empty_pk);
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
pub fn process_stage1_request_with_cb<C, CG, E, P, R>(
    mut rng: R,
    mut cb: G16CommitmentBuilder<SubcircuitWithPortalsProver<E::ScalarField, P, C, CG>, E, QAP>,
    com: G16Com<E>,
    rand: G16ComRandomness<E>,
    stage1_req: Stage1Request<C, E::ScalarField, P>,
) -> Stage1Response<E>
where
    C: TreeConfig<Leaf = SerializedLeaf<E::ScalarField>>,
    CG: TreeConfigGadget<C, E::ScalarField, Leaf = SerializedLeafVar<E::ScalarField>>,
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField>,
    R: RngCore,
{
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

    assert_eq!(cb.circuit.subcircuit_idx, subcircuit_idx);

    // Make an empty version of the large circuit and fill in just the witnesses for the
    // subcircuit we're proving now
    let mut underlying_circuit = P::new(&circ_params);
    underlying_circuit.set_serialized_witnesses(subcircuit_idx, &serialized_witnesses);
    cb.circuit.circ = Some(underlying_circuit);

    // Put the request values into our circuit
    cb.circuit.cur_leaf = cur_leaf;
    cb.circuit.next_leaf_membership = next_leaf_membership;
    cb.circuit.root = root;
    cb.circuit.entry_chal = entry_chal;
    cb.circuit.tr_chal = tr_chal;

    let proof = cb.prove(&[com], &[rand], &mut rng).unwrap();

    Stage1Response {
        subcircuit_idx,
        proof,
    }
}

/// Process the given stage1 request, along with all the previous messages in this execution, and
/// produces a Groth16 proof
pub fn process_stage1_request<C, CG, E, P, R>(
    mut rng: R,
    tree_params: ExecTreeParams<C>,
    pk: &G16ProvingKey<E>,
    stage0_req: Stage0Request<E::ScalarField>,
    stage0_resp: &Stage0Response<E>,
    stage1_req: Stage1Request<C, E::ScalarField, P>,
) -> Stage1Response<E>
where
    C: TreeConfig<Leaf = SerializedLeaf<E::ScalarField>>,
    CG: TreeConfigGadget<C, E::ScalarField, Leaf = SerializedLeafVar<E::ScalarField>>,
    E: Pairing,
    // E::G1: VariableBaseMSMExt,
    // E::G2: VariableBaseMSMExt,
    P: CircuitWithPortals<E::ScalarField>,
    R: RngCore,
{
    let Stage0Request {
        subcircuit_idx,
        time_ordered_subtrace,
        addr_ordered_subtrace,
        ..
    } = stage0_req;

    // We don't need a real auth path length because it'll get overwritten in
    // process_stage1_request_with_cb
    let fake_auth_path_len = 2;

    // Set all the values in the underlying circuit
    let mut circ = SubcircuitWithPortalsProver::<E::ScalarField, P, C, CG>::new(tree_params, 2);
    circ.subcircuit_idx = subcircuit_idx;
    circ.time_ordered_subtrace = time_ordered_subtrace;
    circ.addr_ordered_subtrace = addr_ordered_subtrace;

    // The commitment RNG is determined by com_seed
    let mut cb = G16CommitmentBuilder::<_, E, QAP>::new(circ, pk);
    let mut subcircuit_rng = {
        let com_seed = stage0_resp.com_seed.clone();
        ChaCha12Rng::from_seed(com_seed)
    };

    let (com, rand) = cb.commit(&mut subcircuit_rng).unwrap();
    process_stage1_request_with_cb(rng, cb, com, rand, stage1_req)
}
