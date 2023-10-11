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

const G16_PK_FILENAME_PREFIX: &str = "g16_pk";
const AGG_CK_FILENAME_PREFIX: &str = "agg_ck";
const STAGE0_REQ_FILENAME_PREFIX: &str = "stage0_req";
const STAGE0_RESP_FILENAME_PREFIX: &str = "stage0_resp";
const COORD_STATE_FILENAME_PREFIX: &str = "coordinator_state";

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

    /// Begins a proof for a large circuit with the given parameters. This produces _worker request
    /// packages_ which are processed in parallel by worker nodes.
    StartRandomProof {
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

        Command::StartRandomProof {
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
    }
}
