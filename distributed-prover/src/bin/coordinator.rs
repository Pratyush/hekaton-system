use distributed_prover::{
    aggregation::{AggProvingKey, SuperComCommittingKey},
    coordinator::{CoordinatorStage0State, G16ProvingKeyGenerator, Stage1Request},
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
const COORD_STATE_FILENAME_PREFIX: &str = "coordinator_state";
const STAGE0_REQ_FILENAME_PREFIX: &str = "stage0_req";
const STAGE0_RESP_FILENAME_PREFIX: &str = "stage0_resp";
const STAGE1_REQ_FILENAME_PREFIX: &str = "stage1_req";

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
        /// Path to the outputted proving keys
        #[clap(short, long, value_name = "DIR")]
        out_dir: PathBuf,

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
        /// Path to place worker request packages in. These are named `stage0_req_i.bin` where `i`
        /// is the subcircuit index.
        #[clap(short, long, value_name = "DIR")]
        worker_req_dir: PathBuf,

        /// Path to place the coordinator's intermediate state once all the requests are generated.
        /// This is named `coord_state.bin`.
        #[clap(short, long, value_name = "DIR")]
        coord_state_dir: PathBuf,

        /// Test circuit param: Number of subcircuits. MUST be a power of two and greater than 1.
        #[clap(short, long, value_name = "NUM")]
        num_subcircuits: usize,
    },

    /// Process the stage0 responses from workers and produce stage1 reqeusts
    StartStage1 {
        /// Directory where the stage0 worker responses are stored
        #[clap(short, long, value_name = "DIR")]
        stage0_resp_dir: PathBuf,

        /// Directory where the coordinator's intermediate state is stored.
        #[clap(short, long, value_name = "DIR")]
        coord_state_dir: PathBuf,

        /// Path to place worker request packages in. These are named `stage0_req_i.bin` where `i`
        /// is the subcircuit index.
        #[clap(short, long, value_name = "DIR")]
        worker_req_dir: PathBuf,

        /// How many responses there are
        #[clap(short, long, value_name = "NUM")]
        num_subcircuits: usize,
    },
}

fn generate_g16_pks(circ_params: MerkleTreeCircuitParams, out_dir: &PathBuf) {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    // Make an empty circuit of the correct size
    let circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::new(&circ_params);
    let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);

    let generator = G16ProvingKeyGenerator::<TreeConfig, TreeConfigVar, E, _>::new(
        circ.clone(),
        tree_params.clone(),
    );

    // For every subcircuit...
    for subcircuit_idx in 0..num_subcircuits {
        // Generate the subcircuit's G16 proving key
        let pk = generator.gen_pk(&mut rng, subcircuit_idx);
        // Save it
        serialize_to_path(&pk, out_dir, G16_PK_FILENAME_PREFIX, Some(subcircuit_idx)).unwrap();
    }
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
        COORD_STATE_FILENAME_PREFIX,
        None,
    )?;

    Ok(())
}

fn process_stage0_resps(
    num_subcircuits: usize,
    stage0_resp_dir: &PathBuf,
    coord_state_dir: &PathBuf,
    worker_req_dir: &PathBuf,
) {
    let tree_params = gen_merkle_params();

    // Deserialize the coordinator's state and the aggregation key
    let coord_state = deserialize_from_path::<CoordinatorStage0State<E, MerkleTreeCircuit>>(
        coord_state_dir,
        COORD_STATE_FILENAME_PREFIX,
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
                stage0_resp_dir,
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
            worker_req_dir,
            STAGE1_REQ_FILENAME_PREFIX,
            Some(subcircuit_idx),
        )
        .unwrap();
    }
}

fn main() {
    let args = Args::parse();

    match args.command {
        Command::GenGroth16Keys {
            out_dir,
            num_subcircuits,
        } => {
            assert!(
                num_subcircuits.is_power_of_two(),
                "#subcircuits MUST be a power of 2"
            );
            assert!(num_subcircuits > 1, "#subcircuits MUST be > 1");

            let circ_params = MerkleTreeCircuitParams {
                num_leaves: num_subcircuits / 2,
            };
            generate_g16_pks(circ_params, &out_dir);
        },

        Command::GenAggKey {
            g16_pk_dir,
            coord_state_dir,
            num_subcircuits,
        } => {
            assert!(
                num_subcircuits.is_power_of_two(),
                "#subcircuits MUST be a power of 2"
            );
            assert!(num_subcircuits > 1, "#subcircuits MUST be > 1");

            let circ_params = MerkleTreeCircuitParams {
                num_leaves: num_subcircuits / 2,
            };
            generate_agg_ck(circ_params, &g16_pk_dir, &coord_state_dir);
        },

        Command::StartStage0 {
            worker_req_dir,
            coord_state_dir,
            num_subcircuits,
        } => {
            assert!(
                num_subcircuits.is_power_of_two(),
                "#subcircuits MUST be a power of 2"
            );
            assert!(num_subcircuits > 1, "#subcircuits MUST be > 1");

            let circ_params = MerkleTreeCircuitParams {
                num_leaves: num_subcircuits / 2,
            };
            begin_stage0(circ_params, &worker_req_dir, &coord_state_dir).unwrap();
        },

        Command::StartStage1 {
            stage0_resp_dir,
            coord_state_dir,
            worker_req_dir,
            num_subcircuits,
        } => {
            process_stage0_resps(
                num_subcircuits,
                &stage0_resp_dir,
                &coord_state_dir,
                &worker_req_dir,
            );
        },
    }
}
