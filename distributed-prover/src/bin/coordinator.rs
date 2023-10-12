use distributed_prover::{
    aggregation::{AggProvingKey, SuperComCommittingKey},
    coordinator::{
        CoordinatorStage0State, CoordinatorStage1State, FinalAggState, G16ProvingKeyGenerator,
        Stage1Request,
    },
    kzg::KzgComKey,
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig, PoseidonTreeConfigVar as TreeConfigVar,
    },
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
    util::{deserialize_from_path, serialize_to_path, G16Com, G16ComSeed, G16ProvingKey},
    worker::{process_stage0_request, process_stage1_request, Stage0Response, Stage1Response},
    CircuitWithPortals,
};

use std::{fs::File, io, path::PathBuf};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, Subcommand};
use rayon::prelude::*;

const G16_PK_FILENAME_PREFIX: &str = "g16_pk";
const AGG_CK_FILENAME_PREFIX: &str = "agg_ck";
const STAGE0_COORD_STATE_FILENAME_PREFIX: &str = "stage0_coordinator_state";
const FINAL_AGG_STATE_FILENAME_PREFIX: &str = "final_aggregator_state";
const STAGE0_REQ_FILENAME_PREFIX: &str = "stage0_req";
const STAGE0_RESP_FILENAME_PREFIX: &str = "stage0_resp";
const STAGE1_REQ_FILENAME_PREFIX: &str = "stage1_req";
const STAGE1_RESP_FILENAME_PREFIX: &str = "stage1_resp";
const FINAL_PROOF_PREFIX: &str = "agg_proof";

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generates the Groth16 proving keys for a test circuit consisting of `n` subcircuits. Places
    /// them in `OUT_DIR` with the name `g16_pk_i.bin`, where `i` is the subcircuit index.
    GenGroth16Keys {
        /// Directory where the Groth16 proving keys will be stored
        #[clap(short, long, value_name = "DIR")]
        g16_pk_dir: PathBuf,

        /// Test circuit param: Number of subcircuits. MUST be a power of two and greater than 1.
        #[clap(short, long, value_name = "NUM")]
        num_subcircuits: usize,
    },

    /// Generates an aggregation commitment key for a test circuit consisting of `n` subcircuits.
    /// Places it in `COORD_STATE_DIR/agg_ck.bin`.
    GenAggKey {
        /// Path to where the Groth16 proving keys are stored
        #[clap(short, long, value_name = "DIR")]
        g16_pk_dir: PathBuf,

        /// Path to the coordinator's state directory
        #[clap(short, long, value_name = "DIR")]
        coord_state_dir: PathBuf,

        /// Test circuit param: Number of subcircuits. MUST be a power of two and greater than 1.
        #[clap(short, long, value_name = "NUM")]
        num_subcircuits: usize,
    },

    /// Begins stage0 for a random proof for a large circuit with the given parameters. This
    /// produces _worker request packages_ which are processed in parallel by worker nodes.
    StartStage0 {
        /// Path to place the coordinator's intermediate state once all the requests are generated.
        /// This is named `coord_state.bin`.
        #[clap(short, long, value_name = "DIR")]
        coord_state_dir: PathBuf,

        /// Directory where the worker requests are stored
        #[clap(short, long, value_name = "DIR")]
        req_dir: PathBuf,

        /// Test circuit param: Number of subcircuits. MUST be a power of two and greater than 1.
        #[clap(short, long, value_name = "NUM")]
        num_subcircuits: usize,
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

        /// How many responses there are
        #[clap(short, long, value_name = "NUM")]
        num_subcircuits: usize,
    },

    /// Process the stage1 responses from workers and produce a final aggregate
    EndProof {
        /// Directory where the coordinator's intermediate state is stored.
        #[clap(short, long, value_name = "DIR")]
        coord_state_dir: PathBuf,

        #[clap(short, long, value_name = "DIR")]
        resp_dir: PathBuf,

        /// How many responses there are
        #[clap(short, long, value_name = "NUM")]
        num_subcircuits: usize,
    },
}

fn gen_circuit_params(num_subcircuits: usize) -> MerkleTreeCircuitParams {
    assert!(
        num_subcircuits.is_power_of_two(),
        "#subcircuits MUST be a power of 2"
    );
    assert!(num_subcircuits > 1, "#subcircuits MUST be > 1");

    MerkleTreeCircuitParams {
        num_leaves: num_subcircuits / 2,
        num_sha_iterations: 1,
        num_portals_per_subcircuit: 1,
    }
}

/// Generates all the Groth16 proving keys that the workers will use
fn generate_g16_pks(circ_params: MerkleTreeCircuitParams, g16_pk_dir: &PathBuf) {
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
        for subcircuit_idx in 0..num_subcircuits {
            // Generate the subcircuit's G16 proving key
            let pk = generator.gen_pk(&mut rng, subcircuit_idx);
            // Save it
            serialize_to_path(
                &pk,
                g16_pk_dir,
                G16_PK_FILENAME_PREFIX,
                Some(subcircuit_idx),
            )
            .unwrap();
        }

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

    // Save the first leaf
    serialize_to_path(&first_leaf_pk, g16_pk_dir, G16_PK_FILENAME_PREFIX, Some(0)).unwrap();

    // Save all the rest of the leaves
    for subcircuit_idx in 1..(num_subcircuits / 2) {
        serialize_to_path(
            &second_leaf_pk,
            g16_pk_dir,
            G16_PK_FILENAME_PREFIX,
            Some(subcircuit_idx),
        )
        .unwrap();
    }

    // Save all the parents
    for subcircuit_idx in (num_subcircuits / 2)..(num_subcircuits - 2) {
        serialize_to_path(
            &parent_pk,
            g16_pk_dir,
            G16_PK_FILENAME_PREFIX,
            Some(subcircuit_idx),
        )
        .unwrap();
    }

    // Save the root
    serialize_to_path(
        &root_pk,
        g16_pk_dir,
        G16_PK_FILENAME_PREFIX,
        Some(num_subcircuits - 2),
    )
    .unwrap();

    // Save the padding
    serialize_to_path(
        &padding_pk,
        g16_pk_dir,
        G16_PK_FILENAME_PREFIX,
        Some(num_subcircuits - 1),
    )
    .unwrap();
}

fn generate_agg_ck(
    circ_params: MerkleTreeCircuitParams,
    g16_pk_dir: &PathBuf,
    coord_state_dir: &PathBuf,
) {
    let mut rng = rand::thread_rng();
    let num_subcircuits = 2 * circ_params.num_leaves;

    // Create a lambda that returns the given subcircuit's Groth16 proving key
    let pk_fetcher = |subcircuit_idx| {
        deserialize_from_path(g16_pk_dir, G16_PK_FILENAME_PREFIX, Some(subcircuit_idx)).unwrap()
    };

    // Construct the aggregator commitment key
    let agg_ck = {
        // Need some intermediate keys
        let super_com_key = SuperComCommittingKey::<E>::gen(&mut rng, num_subcircuits);
        let kzg_ck = KzgComKey::gen(&mut rng, num_subcircuits);
        AggProvingKey::new(super_com_key, kzg_ck, pk_fetcher)
    };

    // Save the aggregator key
    serialize_to_path(&agg_ck, coord_state_dir, AGG_CK_FILENAME_PREFIX, None).unwrap();
}

fn begin_stage0(
    circ_params: MerkleTreeCircuitParams,
    worker_req_dir: &PathBuf,
    coord_state_dir: &PathBuf,
) -> io::Result<()> {
    let mut rng = rand::thread_rng();
    let num_subcircuits = 2 * circ_params.num_leaves;

    // Make a random circuit with teh given parameters
    let circ = MerkleTreeCircuit::rand(&mut rng, &circ_params);

    // Make the stage0 coordinator state
    let stage0_state = CoordinatorStage0State::<E, _>::new::<TreeConfig>(circ);

    // Workers receives stage0 packages containing the subtraces it will need for this run. We
    // imagine the worker saves their package to disk.
    for subcircuit_idx in 0..num_subcircuits {
        let req = stage0_state.gen_request(subcircuit_idx);
        serialize_to_path(
            &req,
            worker_req_dir,
            STAGE0_REQ_FILENAME_PREFIX,
            Some(subcircuit_idx),
        )?;
    }

    // Save the coordinator state
    serialize_to_path(
        &stage0_state,
        coord_state_dir,
        STAGE0_COORD_STATE_FILENAME_PREFIX,
        None,
    )?;

    Ok(())
}

fn process_stage0_resps(
    num_subcircuits: usize,
    coord_state_dir: &PathBuf,
    req_dir: &PathBuf,
    resp_dir: &PathBuf,
) {
    let tree_params = gen_merkle_params();

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
    for subcircuit_idx in 0..num_subcircuits {
        // Construct the request and serialize it
        let stage1_req = new_coord_state.gen_request(subcircuit_idx);
        serialize_to_path(
            &stage1_req,
            req_dir,
            STAGE1_REQ_FILENAME_PREFIX,
            Some(subcircuit_idx),
        )
        .unwrap();
    }

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

fn process_stage1_resps(num_subcircuits: usize, coord_state_dir: &PathBuf, resp_dir: &PathBuf) {
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
    let agg_proof = final_agg_state.gen_agg_proof(&agg_ck, &stage1_resps);
    // Save the proof
    serialize_to_path(&agg_proof, coord_state_dir, FINAL_PROOF_PREFIX, None).unwrap();
}

fn main() {
    let args = Args::parse();

    match args.command {
        Command::GenGroth16Keys {
            g16_pk_dir,
            num_subcircuits,
        } => {
            let circ_params = gen_circuit_params(num_subcircuits);
            generate_g16_pks(circ_params, &g16_pk_dir);
        },

        Command::GenAggKey {
            g16_pk_dir,
            coord_state_dir,
            num_subcircuits,
        } => {
            let circ_params = gen_circuit_params(num_subcircuits);
            generate_agg_ck(circ_params, &g16_pk_dir, &coord_state_dir);
        },

        Command::StartStage0 {
            req_dir,
            coord_state_dir,
            num_subcircuits,
        } => {
            let circ_params = gen_circuit_params(num_subcircuits);
            begin_stage0(circ_params, &req_dir, &coord_state_dir).unwrap();
        },

        Command::StartStage1 {
            resp_dir,
            coord_state_dir,
            req_dir,
            num_subcircuits,
        } => {
            process_stage0_resps(num_subcircuits, &coord_state_dir, &req_dir, &resp_dir);
        },

        Command::EndProof {
            coord_state_dir,
            resp_dir,
            num_subcircuits,
        } => {
            process_stage1_resps(num_subcircuits, &coord_state_dir, &resp_dir);
        },
    }
}
