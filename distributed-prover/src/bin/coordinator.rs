use distributed_prover::{
    aggregation::{AggProvingKey, SuperComCommittingKey},
    coordinator::{CoordinatorStage0State, FinalAggState, G16ProvingKeyGenerator},
    kzg::KzgComKey,
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig, PoseidonTreeConfigVar as TreeConfigVar,
    },
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
    util::{cli_filenames::*, deserialize_from_path, serialize_to_path, serialize_to_paths},
    worker::{Stage0Response, Stage1Response},
    CircuitWithPortals,
};

use std::{io, path::PathBuf};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_std::{end_timer, start_timer};
use clap::{Parser, Subcommand};
use rayon::prelude::*;

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generates the Groth16 proving keys and aggregation key  for a test circuit consisting of
    /// `n` subcircuits. Places them in coord-state-dir
    GenKeys {
        /// Directory where the Groth16 proving keys will be stored
        #[clap(short, long, value_name = "DIR")]
        g16_pk_dir: PathBuf,

        /// Directory where the coordinator's intermediate state is stored.
        #[clap(short, long, value_name = "DIR")]
        coord_state_dir: PathBuf,

        /// Test circuit param: Number of subcircuits. MUST be a power of two and greater than 1.
        #[clap(short, long, value_name = "NUM")]
        num_subcircuits: usize,

        /// Test circuit param: Number of SHA256 iterations per subcircuit. MUST be at least 1.
        #[clap(short, long, value_name = "NUM")]
        num_sha2_iters: usize,

        /// Test circuit param: Number of portal wire ops per subcircuit. MUST be at least 1.
        #[clap(short, long, value_name = "NUM")]
        num_portals: usize,
    },

    /// Begins stage0 for a random proof for a large circuit with the given parameters. This
    /// produces _worker request packages_ which are processed in parallel by worker nodes.
    StartStage0 {
        /// Directory where the coordinator's intermediate state is stored.
        #[clap(short, long, value_name = "DIR")]
        coord_state_dir: PathBuf,

        /// Directory where the worker requests are stored
        #[clap(short, long, value_name = "DIR")]
        req_dir: PathBuf,
    },

    /// Process the stage0 responses from workers and produce stage1 reqeusts
    StartStage1 {
        /// Directory where the coordinator's intermediate state is stored.
        #[clap(short, long, value_name = "DIR")]
        coord_state_dir: PathBuf,

        /// Directory where the worker requests are stored
        #[clap(short, long, value_name = "DIR")]
        req_dir: PathBuf,

        /// Directory where the worker responses are stored
        #[clap(short, long, value_name = "DIR")]
        resp_dir: PathBuf,
    },

    /// Process the stage1 responses from workers and produce a final aggregate
    EndProof {
        /// Directory where the coordinator's intermediate state is stored.
        #[clap(short, long, value_name = "DIR")]
        coord_state_dir: PathBuf,

        #[clap(short, long, value_name = "DIR")]
        resp_dir: PathBuf,
    },
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
    g16_pk_dir: &PathBuf,
    coord_state_dir: &PathBuf,
) {
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

    // First a special case: if there's just 4 subcircuits, generate them all and be done with it
    if num_subcircuits <= 4 {
        // Generate the subcircuit's G16 proving keys
        let pks = (0..num_subcircuits)
            .map(|subcircuit_idx| generator.gen_pk(&mut rng, subcircuit_idx))
            .collect::<Vec<_>>();

        // Save them and the corresponding committing key
        for (subcircuit_idx, pk) in pks.iter().enumerate() {
            serialize_to_path(pk, g16_pk_dir, G16_PK_FILENAME_PREFIX, Some(subcircuit_idx))
                .unwrap();
            // Save the corresponding committing key
            serialize_to_path(
                &pk.ck,
                g16_pk_dir,
                G16_CK_FILENAME_PREFIX,
                Some(subcircuit_idx),
            )
            .unwrap();
        }

        let pk_fetcher = move |subcircuit_idx: usize| pks[subcircuit_idx].clone();

        // Construct the aggregator commitment key
        let start =
            start_timer!(|| format!("Generating aggregation key with params {circ_params}"));
        let agg_ck = {
            // Need some intermediate keys
            let super_com_key = SuperComCommittingKey::<E>::gen(&mut rng, num_subcircuits);
            let kzg_ck = KzgComKey::gen(&mut rng, num_subcircuits);
            AggProvingKey::new(super_com_key, kzg_ck, pk_fetcher)
        };
        end_timer!(start);

        // Save the aggregator key
        println!("Writing aggregation key");
        serialize_to_path(&agg_ck, coord_state_dir, AGG_CK_FILENAME_PREFIX, None).unwrap();

        return;
    }

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

    // Now save them

    // Save the first leaf (proving key and committing key)
    println!("Writing first leaf proving key");
    serialize_to_path(&first_leaf_pk, g16_pk_dir, G16_PK_FILENAME_PREFIX, Some(0)).unwrap();
    serialize_to_path(
        &first_leaf_pk.ck,
        g16_pk_dir,
        G16_CK_FILENAME_PREFIX,
        Some(0),
    )
    .unwrap();

    // Save all the rest of the leaves
    println!("Writing leaf proving keys");
    let other_leaf_idxs = 1..(num_subcircuits / 2);
    serialize_to_paths(
        &second_leaf_pk,
        g16_pk_dir,
        G16_PK_FILENAME_PREFIX,
        other_leaf_idxs.clone(),
    )
    .unwrap();
    serialize_to_paths(
        &second_leaf_pk.ck,
        g16_pk_dir,
        G16_CK_FILENAME_PREFIX,
        other_leaf_idxs.clone(),
    )
    .unwrap();

    // Save all the parents
    println!("Writing parent proving keys");
    let parent_idxs = (num_subcircuits / 2)..(num_subcircuits - 2);
    serialize_to_paths(
        &parent_pk,
        g16_pk_dir,
        G16_PK_FILENAME_PREFIX,
        parent_idxs.clone(),
    )
    .unwrap();
    serialize_to_paths(
        &parent_pk.ck,
        g16_pk_dir,
        G16_CK_FILENAME_PREFIX,
        parent_idxs.clone(),
    )
    .unwrap();

    // Save the root
    println!("Writing root proving key");
    serialize_to_path(
        &root_pk,
        g16_pk_dir,
        G16_PK_FILENAME_PREFIX,
        Some(num_subcircuits - 2),
    )
    .unwrap();
    serialize_to_path(
        &root_pk.ck,
        g16_pk_dir,
        G16_CK_FILENAME_PREFIX,
        Some(num_subcircuits - 2),
    )
    .unwrap();

    // Save the padding
    println!("Writing padding proving key");
    serialize_to_path(
        &padding_pk,
        g16_pk_dir,
        G16_PK_FILENAME_PREFIX,
        Some(num_subcircuits - 1),
    )
    .unwrap();
    serialize_to_path(
        &padding_pk.ck,
        g16_pk_dir,
        G16_CK_FILENAME_PREFIX,
        Some(num_subcircuits - 1),
    )
    .unwrap();

    // To generate the aggregation key, we need an efficient G16 pk fetcher. Normally this hits
    // disk, but this might take a long long time.
    let pk_fetcher = move |subcircuit_idx: usize| {
        if subcircuit_idx == 0 {
            first_leaf_pk.clone()
        } else if other_leaf_idxs.contains(&subcircuit_idx) {
            second_leaf_pk.clone()
        } else if parent_idxs.contains(&subcircuit_idx) {
            parent_pk.clone()
        } else if subcircuit_idx == num_subcircuits - 2 {
            root_pk.clone()
        } else if subcircuit_idx == num_subcircuits - 1 {
            padding_pk.clone()
        } else {
            panic!("unexpected subcircuit index {subcircuit_idx}")
        }
    };

    // Construct the aggregator commitment key
    let start = start_timer!(|| format!("Generating aggregation key with params {circ_params}"));
    let agg_ck = {
        // Need some intermediate keys
        let super_com_key = SuperComCommittingKey::<E>::gen(&mut rng, num_subcircuits);
        let kzg_ck = KzgComKey::gen(&mut rng, num_subcircuits);
        AggProvingKey::new(super_com_key, kzg_ck, pk_fetcher)
    };
    end_timer!(start);

    // Save the aggregator key
    println!("Writing aggregation key");
    serialize_to_path(&agg_ck, coord_state_dir, AGG_CK_FILENAME_PREFIX, None).unwrap();
}

fn begin_stage0(worker_req_dir: &PathBuf, coord_state_dir: &PathBuf) -> io::Result<()> {
    let mut rng = rand::thread_rng();
    let stage0_timer = start_timer!(|| "Begin Stage0");

    let circ_params_timer = start_timer!(|| "Deserializing circuit parameters");
    // Get the circuit parameters determined at Groth16 PK generation
    let circ_params = deserialize_from_path::<MerkleTreeCircuitParams>(
        &coord_state_dir,
        TEST_CIRC_PARAM_FILENAME_PREFIX,
        None,
    )
    .unwrap();
    end_timer!(circ_params_timer);
    // Num subcircuits is 2× num leaves
    let num_subcircuits = 2 * circ_params.num_leaves;

    let merkle_tree_timer = start_timer!(|| format!("Sampling a random MerkleTreeCircuit with parapms {circ_params}"));
    // Make a random circuit with the given parameters
    println!("Making a random circuit");
    let circ = MerkleTreeCircuit::rand(&mut rng, &circ_params);
    end_timer!(merkle_tree_timer);

    // Make the stage0 coordinator state
    println!("Building stage0 state");
    let stage0_state = CoordinatorStage0State::<E, _>::new::<TreeConfig>(circ);

    // Sender sends stage0 requests containing the subtraces. Workers will commit to these
    let start = start_timer!(|| format!("Generating stage0 requests with params {circ_params}"));
    let reqs = (0..num_subcircuits)
        .into_par_iter()
        .map(|subcircuit_idx| stage0_state.gen_request(subcircuit_idx))
        .collect::<Vec<_>>();
    end_timer!(start);

    let write_timer = start_timer!(|| format!("Writing stage0 requests with params {circ_params}"));
    reqs.into_par_iter()
        .enumerate()
        .for_each(|(subcircuit_idx, req)| {
            serialize_to_path(
                &req,
                worker_req_dir,
                STAGE0_REQ_FILENAME_PREFIX,
                Some(subcircuit_idx),
            )
            .unwrap()
        });
    end_timer!(write_timer);

    // Save the coordinator state
    let write_timer = start_timer!(|| format!("Writing coordinator state"));
    serialize_to_path(
        &stage0_state,
        coord_state_dir,
        STAGE0_COORD_STATE_FILENAME_PREFIX,
        None,
    )?;
    end_timer!(write_timer);
    end_timer!(stage0_timer);

    Ok(())
}

fn process_stage0_resps(coord_state_dir: &PathBuf, req_dir: &PathBuf, resp_dir: &PathBuf) {
    let tree_params = gen_merkle_params();

    // Get the circuit parameters determined at Groth16 PK generation
    let circ_params = deserialize_from_path::<MerkleTreeCircuitParams>(
        &coord_state_dir,
        TEST_CIRC_PARAM_FILENAME_PREFIX,
        None,
    )
    .unwrap();
    // Num subcircuits is 2× num leaves
    let num_subcircuits = 2 * circ_params.num_leaves;

    // Deserialize the coordinator's state and the aggregation key
    let coord_state = deserialize_from_path::<CoordinatorStage0State<E, MerkleTreeCircuit>>(
        coord_state_dir,
        STAGE0_COORD_STATE_FILENAME_PREFIX,
        None,
    )
    .unwrap();
    let super_com_key = {
        let agg_ck = deserialize_from_path::<AggProvingKey<E>>(
            coord_state_dir,
            AGG_CK_FILENAME_PREFIX,
            None,
        )
        .unwrap();
        agg_ck.ipp_ck
    };

    // Collect all the repsonses into a single vec. They're tiny, so this is fine.
    let stage0_resps = (0..num_subcircuits)
        .into_par_iter()
        .map(|subcircuit_idx| {
            deserialize_from_path::<Stage0Response<E>>(
                resp_dir,
                STAGE0_RESP_FILENAME_PREFIX,
                Some(subcircuit_idx),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    // Process the responses and get a new coordinator state
    let new_coord_state =
        coord_state.process_stage0_responses(&super_com_key, tree_params, &stage0_resps);

    // Create all the stage1 requests
    let start = start_timer!(|| format!(
        "Generating stage1 requests for circuit with params {circ_params}"
    ));
    let reqs = (0..num_subcircuits)
        .into_par_iter()
        .map(|subcircuit_idx| new_coord_state.gen_request(subcircuit_idx))
        .collect::<Vec<_>>();
    end_timer!(start);

    reqs.into_par_iter()
        .enumerate()
        .for_each(|(subcircuit_idx, req)| {
            serialize_to_path(
                &req,
                req_dir,
                STAGE1_REQ_FILENAME_PREFIX,
                Some(subcircuit_idx),
            )
            .unwrap()
        });

    // Convert the coordinator state to an aggregator state and save it
    let final_agg_state = new_coord_state.into_agg_state();
    serialize_to_path(
        &final_agg_state,
        coord_state_dir,
        FINAL_AGG_STATE_FILENAME_PREFIX,
        None,
    )
    .unwrap();
}

fn process_stage1_resps(coord_state_dir: &PathBuf, resp_dir: &PathBuf) {
    // Get the circuit parameters determined at Groth16 PK generation
    let circ_params = deserialize_from_path::<MerkleTreeCircuitParams>(
        &coord_state_dir,
        TEST_CIRC_PARAM_FILENAME_PREFIX,
        None,
    )
    .unwrap();
    // Num subcircuits is 2× num leaves
    let num_subcircuits = 2 * circ_params.num_leaves;

    // Deserialize the coordinator's final state, the aggregation key
    let final_agg_state = deserialize_from_path::<FinalAggState<E>>(
        coord_state_dir,
        FINAL_AGG_STATE_FILENAME_PREFIX,
        None,
    )
    .unwrap();
    let agg_ck =
        deserialize_from_path::<AggProvingKey<E>>(coord_state_dir, AGG_CK_FILENAME_PREFIX, None)
            .unwrap();

    // Collect all the stage1 repsonses into a single vec. They're tiny (Groth16 proofs), so this
    // is fine.
    let stage1_resps = (0..num_subcircuits)
        .into_par_iter()
        .map(|subcircuit_idx| {
            deserialize_from_path::<Stage1Response<E>>(
                resp_dir,
                STAGE1_RESP_FILENAME_PREFIX,
                Some(subcircuit_idx),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    // Compute the aggregate
    let start =
        start_timer!(|| format!("Aggregating proofs for circuit with params {circ_params}"));
    let agg_proof = final_agg_state.gen_agg_proof(&agg_ck, &stage1_resps);
    end_timer!(start);
    // Save the proof
    serialize_to_path(&agg_proof, coord_state_dir, FINAL_PROOF_PREFIX, None).unwrap();
}

fn main() {
    println!("Rayon num threads: {}", rayon::current_num_threads());

    let args = Args::parse();
    let start = start_timer!(|| format!("Running coordinator"));

    match args.command {
        Command::GenKeys {
            g16_pk_dir,
            coord_state_dir,
            num_subcircuits,
            num_sha2_iters,
            num_portals,
        } => {
            // Make the circuit params and save them to disk
            let circ_params = gen_test_circuit_params(num_subcircuits, num_sha2_iters, num_portals);
            serialize_to_path(
                &circ_params,
                &coord_state_dir,
                TEST_CIRC_PARAM_FILENAME_PREFIX,
                None,
            )
            .unwrap();

            // Now run the subcommand
            generate_g16_pks(circ_params, &g16_pk_dir, &coord_state_dir);
        },

        Command::StartStage0 {
            req_dir,
            coord_state_dir,
        } => {
            begin_stage0(&req_dir, &coord_state_dir).unwrap();
        },

        Command::StartStage1 {
            resp_dir,
            coord_state_dir,
            req_dir,
        } => {
            process_stage0_resps(&coord_state_dir, &req_dir, &resp_dir);
        },

        Command::EndProof {
            coord_state_dir,
            resp_dir,
        } => {
            process_stage1_resps(&coord_state_dir, &resp_dir);
        },
    }

    end_timer!(start);
}
