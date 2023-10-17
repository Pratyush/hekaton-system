use crate::data_structures::{
    G16Com, G16ComRandomness, G16ProvingKey, Stage0Request, Stage0Response, Stage1Request,
    Stage1Response,
};

use distributed_prover::{
    eval_tree::ExecTreeParams,
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig, PoseidonTreeConfigVar as TreeConfigVar,
    },
    subcircuit_circuit::SubcircuitWithPortalsProver,
    tree_hash_circuit::MerkleTreeCircuit,
    util::QAP,
    worker::{process_stage0_request_get_cb, process_stage1_request_with_cb},
};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_cp_groth16::committer::CommitmentBuilder as G16CommitmentBuilder;
use rand::thread_rng;

type CommitterState<'a> = G16CommitmentBuilder<'a,
    SubcircuitWithPortalsProver<Fr, MerkleTreeCircuit, TreeConfig, TreeConfigVar>,
    E,
    QAP,
>;

pub struct WorkerState<'a> {
    g16_pk: &'a G16ProvingKey,
    tree_params: ExecTreeParams<TreeConfig>,
    cb: Option<CommitterState<'a>>,
    com: G16Com,
    com_rand: G16ComRandomness,
}

impl<'a> WorkerState<'a> {
    pub fn new(g16_pk: &'a G16ProvingKey) -> Self {
        let tree_params = gen_merkle_params();
        WorkerState {
            g16_pk,
            tree_params,
            cb: None,
            com: G16Com::default(),
            com_rand: G16ComRandomness::default(),
        }
    }

    pub fn stage_0(&mut self, stage0_req: &Stage0Request) -> Stage0Response {
        let mut rng = thread_rng();

        // Process the request. This returns the response and the commitment builder. Save the
        // builder as state
        let (resp, cb) = process_stage0_request_get_cb::<_, TreeConfigVar, _, MerkleTreeCircuit, _>(
            &mut rng,
            self.tree_params.clone(),
            &self.g16_pk,
            stage0_req.clone(),
        );

        self.cb = Some(cb);

        resp
    }

    pub fn stage_1(self, stage1_req: &Stage1Request) -> Stage1Response {
        let mut rng = thread_rng();

        // Use the builder to respond
        process_stage1_request_with_cb(
            &mut rng,
            self.cb.unwrap(),
            self.com,
            self.com_rand,
            stage1_req.clone(),
        );

        todo!()
    }
}
