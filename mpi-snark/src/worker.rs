use crate::data_structures::{
    G16Com, G16ComRandomness, G16ProvingKey, ProvingKeys, Stage0Request, Stage0Response,
    Stage1Request, Stage1Response,
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

type CommitterState<'a> = G16CommitmentBuilder<
    'a,
    SubcircuitWithPortalsProver<Fr, MerkleTreeCircuit, TreeConfig, TreeConfigVar>,
    E,
    QAP,
>;

pub struct WorkerState<'a> {
    g16_pks: &'a ProvingKeys,
    tree_params: ExecTreeParams<TreeConfig>,
    cb: Option<CommitterState<'a>>,
    com: G16Com,
    com_rand: G16ComRandomness,
    num_subcircuits: usize,
}

impl<'a> WorkerState<'a> {
    pub fn new(num_subcircuits: usize, g16_pks: &'a ProvingKeys) -> Self {
        let tree_params = gen_merkle_params();
        WorkerState {
            g16_pks,
            tree_params,
            cb: None,
            com: G16Com::default(),
            com_rand: G16ComRandomness::default(),
            num_subcircuits,
        }
    }

    pub fn stage_0(&mut self, stage0_req: &Stage0Request) -> Stage0Response {
        let mut rng = thread_rng();
        let subcircuit_idx = stage0_req.subcircuit_idx;
        let num_subcircuits = self.num_subcircuits;

        // We need to use the right Groth16 public key. We can figure this out based on where we
        // are in the tree
        let g16_pk = if subcircuit_idx == 0 {
            self.g16_pks.first_leaf_pk.as_ref().unwrap()
        } else if subcircuit_idx < num_subcircuits / 2 {
            self.g16_pks.second_leaf_pk.as_ref().unwrap()
        } else if subcircuit_idx == num_subcircuits - 1 {
            self.g16_pks.padding_pk.as_ref().unwrap()
        } else if subcircuit_idx == num_subcircuits - 2 {
            self.g16_pks.root_pk.as_ref().unwrap()
        } else if num_subcircuits / 2 <= subcircuit_idx && subcircuit_idx < num_subcircuits - 2 {
            self.g16_pks.parent_pk.as_ref().unwrap()
        } else {
            panic!(
                "out of range subcircuit idx: {subcircuit_idx} {}",
                num_subcircuits - 1
            );
        };

        // Process the request. This returns the response and the commitment builder. Save the
        // builder as state
        let (resp, cb) = process_stage0_request_get_cb::<_, TreeConfigVar, _, MerkleTreeCircuit, _>(
            &mut rng,
            self.tree_params.clone(),
            g16_pk,
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
        )
    }
}
