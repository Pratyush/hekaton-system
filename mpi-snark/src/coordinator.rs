use crate::data_structures::{
    AggProof, G16Proof, G16ProvingKey, ProvingKeys, Stage0RequestRef, Stage0Response,
    Stage1RequestRef, Stage1Response,
};

use distributed_prover::{
    aggregation::{AggProvingKey, SuperComCommittingKey},
    coordinator::{CoordinatorStage0State, CoordinatorStage1State, G16ProvingKeyGenerator},
    kzg::KzgComKey,
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig, PoseidonTreeConfigVar as TreeConfigVar,
    },
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
    CircuitWithPortals,
};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ec::pairing::Pairing;
use ark_std::{end_timer, start_timer};
use rand::thread_rng;

pub struct CoordinatorState {
    g16_pks: ProvingKeys,
    agg_pk: AggProvingKey<E>,
    circ_params: MerkleTreeCircuitParams,
    stage0_state: Option<CoordinatorStage0State<E, MerkleTreeCircuit>>,
    stage1_state: Option<CoordinatorStage1State<TreeConfig, E, MerkleTreeCircuit>>,
}

impl CoordinatorState {
    pub fn new(g16_pks: ProvingKeys) -> Self {
        CoordinatorState {
            circ_params: g16_pks.circ_params.clone(),
            agg_pk: generate_agg_key(&g16_pks),
            g16_pks,
            stage0_state: None,
            stage1_state: None,
        }
    }

    pub fn get_pks(&self) -> &ProvingKeys {
        &self.g16_pks
    }

    pub fn stage_0(&mut self) -> Vec<Stage0RequestRef> {
        let mut rng = thread_rng();

        let circ = MerkleTreeCircuit::rand(&mut rng, &self.circ_params);
        let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);
        let all_subcircuit_indices = (0..num_subcircuits).collect::<Vec<_>>();

        self.stage0_state = Some(CoordinatorStage0State::new::<TreeConfig>(circ));
        (0..num_subcircuits)
            .map(|idx| self.stage0_state.as_ref().unwrap().gen_request(idx))
            .collect::<Vec<_>>()
    }

    pub fn stage_1(&mut self, stage0_resps: &[Stage0Response]) -> Vec<Stage1RequestRef> {
        let tree_params = gen_merkle_params();
        let num_subcircuits = 2 * self.circ_params.num_leaves;

        // Consume the stage0 state and the responses
        self.stage1_state = Some(self.stage0_state.take().unwrap().process_stage0_responses(
            &self.agg_pk.ipp_ck,
            tree_params,
            &stage0_resps,
        ));

        (0..num_subcircuits)
            .map(|idx| self.stage1_state.as_ref().unwrap().gen_request(idx))
            .collect::<Vec<_>>()
    }

    pub fn aggregate(&mut self, stage1_resps: &[Stage1Response]) -> AggProof {
        let final_agg_state = self.stage1_state.take().unwrap().into_agg_state();
        final_agg_state.gen_agg_proof(&self.agg_pk, stage1_resps)
    }
}

/// Generates all the Groth16 proving and committing keys keys that the workers will use
pub fn generate_g16_pks(circ_params: MerkleTreeCircuitParams) -> ProvingKeys {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    // Make an empty circuit of the correct size
    let circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::new(&circ_params);
    let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);

    let generator = G16ProvingKeyGenerator::<TreeConfig, TreeConfigVar, E, _>::new(
        circ.clone(),
        tree_params.clone(),
    );

    // We don't actually have to generate every circuit proving key individually. Remember the test
    // circuit only really has 5 subcircuits: the first leaf, the root, every other leaf, every
    // other parent, and the final padding circuit. So we only have to generate 5 proving keys and
    // copy them a bunch of times.

    // Now if there are more than 4 subcircuits:

    // Generate the first leaf
    let first_leaf_pk = generator.gen_pk(&mut rng, 0);
    // Generate the second leaf
    let second_leaf_pk = generator.gen_pk(&mut rng, 1);
    // Generate the padding
    let padding_pk = generator.gen_pk(&mut rng, num_subcircuits - 1);
    // Generate the root
    let root_pk = generator.gen_pk(&mut rng, num_subcircuits - 2);
    // Generate the second to last parent
    let parent_pk = generator.gen_pk(&mut rng, num_subcircuits - 3);

    ProvingKeys {
        circ_params,
        first_leaf_pk: Some(first_leaf_pk),
        second_leaf_pk: Some(second_leaf_pk),
        padding_pk: Some(padding_pk),
        root_pk: Some(root_pk),
        parent_pk: Some(parent_pk),
    }
}

fn generate_agg_key(g16_pks: &ProvingKeys) -> AggProvingKey<E> {
    let mut rng = thread_rng();

    let num_subcircuits = 2 * g16_pks.circ_params.num_leaves;

    let other_leaf_idxs = 1..(num_subcircuits / 2);
    let parent_idxs = (num_subcircuits / 2)..(num_subcircuits - 2);

    // To generate the aggregation key, we need an efficient G16 pk fetcher. Normally this hits
    // disk, but this might take a long long time.
    let pk_fetcher = |subcircuit_idx: usize| {
        if subcircuit_idx == 0 {
            g16_pks.first_leaf_pk()
        } else if other_leaf_idxs.contains(&subcircuit_idx) {
            g16_pks.second_leaf_pk()
        } else if parent_idxs.contains(&subcircuit_idx) {
            g16_pks.parent_pk()
        } else if subcircuit_idx == num_subcircuits - 2 {
            g16_pks.root_pk()
        } else if subcircuit_idx == num_subcircuits - 1 {
            g16_pks.padding_pk()
        } else {
            panic!("unexpected subcircuit index {subcircuit_idx}")
        }
    };

    // Construct the aggregator commitment key
    let start = start_timer!(|| format!("Generating aggregation key with params {circ_params}"));
    let agg_pk = {
        // Need some intermediate keys
        let super_com_key = SuperComCommittingKey::<E>::gen(&mut rng, num_subcircuits);
        let kzg_ck = KzgComKey::gen(&mut rng, num_subcircuits);
        AggProvingKey::new(super_com_key, kzg_ck, pk_fetcher)
    };
    end_timer!(start);
    agg_pk
}
