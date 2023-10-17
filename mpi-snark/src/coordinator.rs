use ark_bls12_381::{Fr, Bls12_381};
use ark_ec::pairing::Pairing;
use ark_std::{start_timer, end_timer};
use distributed_prover::{tree_hash_circuit::{MerkleTreeCircuitParams, MerkleTreeCircuit}, poseidon_util::{gen_merkle_params, PoseidonTreeConfig, PoseidonTreeConfigVar}, CircuitWithPortals, coordinator::G16ProvingKeyGenerator, aggregation::{SuperComCommittingKey, AggProvingKey}, kzg::KzgComKey};

use crate::data_structures::{
    G16Proof, G16ProvingKey, Stage0RequestRef, Stage0Response, Stage1RequestRef, Stage1Response, ProvingKeys,
};

pub struct CoordinatorState<E: Pairing>(E::G1);

impl<E: Pairing> CoordinatorState<E> {
    pub fn new(
        num_nodes: usize,
        num_subcircuits: usize,
        num_sha_iterations: usize,
        num_portals_per_subcircuit: usize,
    ) -> Self {
        let mt_params = gen_test_circuit_params(num_subcircuits, num_sha_iterations, num_portals_per_subcircuit);

        let (g16_pks, agg_pk) = generate_g16_pks(mt_params);
        todo!()
    }

    pub fn get_pk(&self) -> G16ProvingKey {
        todo!()
    }

    pub fn stage_0(&mut self) -> Vec<Stage0RequestRef> {
        todo!()
    }

    pub fn stage_1(&mut self, responses: &[Stage0Response]) -> Vec<Stage1RequestRef> {
        todo!()
    }

    pub fn aggregate(&mut self, responses: &[Stage1Response]) -> G16Proof {
        todo!()
    }
}


// Checks the test circuit parameters and puts them in a struct
fn gen_test_circuit_params(
    num_subcircuits: usize,
    num_sha_iterations: usize,
    num_portals_per_subcircuit: usize,
) -> MerkleTreeCircuitParams {
    assert!(
        num_subcircuits.is_power_of_two(),
        "#subcircuits MUST be a power of 2"
    );
    assert!(num_subcircuits > 1, "num. of subcircuits MUST be > 1");
    assert!(
        num_sha_iterations > 0,
        "num. of SHA256 iterations per subcircuit MUST be > 0"
    );
    assert!(
        num_portals_per_subcircuit > 0,
        "num. of portal ops per subcircuit MUST be > 0"
    );

    MerkleTreeCircuitParams {
        num_leaves: num_subcircuits / 2,
        num_sha_iters_per_subcircuit: num_sha_iterations,
        num_portals_per_subcircuit,
    }
}

/// Generates all the Groth16 proving and committing keys keys that the workers will use
fn generate_g16_pks(
    circ_params: MerkleTreeCircuitParams,
) -> (ProvingKeys, AggProvingKey<Bls12_381>) {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    // Make an empty circuit of the correct size
    let circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::new(&circ_params);
    let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);

    let generator = G16ProvingKeyGenerator::<PoseidonTreeConfig, PoseidonTreeConfigVar, Bls12_381, _>::new(
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

    let pks = ProvingKeys {
        first_leaf_pk: Some(first_leaf_pk),
        second_leaf_pk: Some(second_leaf_pk),
        padding_pk: Some(padding_pk),
        root_pk: Some(root_pk),
        parent_pk: Some(parent_pk),
    };

    let other_leaf_idxs = 1..(num_subcircuits / 2);
    let parent_idxs = (num_subcircuits / 2)..(num_subcircuits - 2);

    // To generate the aggregation key, we need an efficient G16 pk fetcher. Normally this hits
    // disk, but this might take a long long time.
    let pk_fetcher = |subcircuit_idx: usize| {
        if subcircuit_idx == 0 {
            pks.first_leaf_pk()
        } else if other_leaf_idxs.contains(&subcircuit_idx) {
            pks.second_leaf_pk()
        } else if parent_idxs.contains(&subcircuit_idx) {
            pks.parent_pk()
        } else if subcircuit_idx == num_subcircuits - 2 {
            pks.root_pk()
        } else if subcircuit_idx == num_subcircuits - 1 {
            pks.padding_pk()
        } else {
            panic!("unexpected subcircuit index {subcircuit_idx}")
        }
    };

    // Construct the aggregator commitment key
    let start = start_timer!(|| format!("Generating aggregation key with params {circ_params}"));
    let agg_ck = {
        // Need some intermediate keys
        let super_com_key = SuperComCommittingKey::<Bls12_381>::gen(&mut rng, num_subcircuits);
        let kzg_ck = KzgComKey::gen(&mut rng, num_subcircuits);
        AggProvingKey::new(super_com_key, kzg_ck, pk_fetcher)
    };
    end_timer!(start);
    (pks, agg_ck)
}