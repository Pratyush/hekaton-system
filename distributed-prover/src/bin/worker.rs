use distributed_prover::{
    aggregation::{AggProvingKey, SuperComCommittingKey},
    coordinator::{CoordinatorStage0State, G16ProvingKeyGenerator, Stage0Request, Stage1Request},
    kzg::KzgComKey,
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig, PoseidonTreeConfigVar as TreeConfigVar,
    },
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
    util::{deserialize_from_path, serialize_to_path, G16Com, G16ComSeed, G16ProvingKey},
    worker::{Stage0Response, Stage1Response},
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
    /// Processes the stage0 requests issued by the coordinator
    ProcessStage0Request {
        /// Directory where the Groth16 proving keys are stored
        #[clap(short, long, value_name = "DIR")]
        g16_pk_dir: PathBuf,

        /// Directory where the stage0 requests are stored
        #[clap(short, long, value_name = "DIR")]
        stage0_req_dir: PathBuf,

        /// Directory where the stage0 responses should be saved
        #[clap(short, long, value_name = "DIR")]
        out_dir: PathBuf,

        /// Which subcircuit should be proven
        #[clap(short, long, value_name = "NUM")]
        subcircuit_index: usize,
    },
}

fn process_stage0_request(
    subcircuit_idx: usize,
    g16_pk_dir: &PathBuf,
    stage0_req_dir: &PathBuf,
    out_dir: &PathBuf,
) {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    // Deserialize the appropriate proving key and request
    let g16_pk = deserialize_from_path::<G16ProvingKey<E>>(
        g16_pk_dir,
        G16_PK_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();
    let stage0_req = deserialize_from_path::<Stage0Request<Fr>>(
        stage0_req_dir,
        STAGE0_REQ_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();

    // Sanity check that the request index matches the expected index
    assert_eq!(stage0_req.subcircuit_idx, subcircuit_idx);

    // Compute the response
    let stage0_resp = distributed_prover::worker::process_stage0_request::<
        _,
        TreeConfigVar,
        _,
        MerkleTreeCircuit,
        _,
    >(&mut rng, tree_params, &g16_pk, stage0_req);

    // Save it
    serialize_to_path(
        &stage0_resp,
        out_dir,
        STAGE0_RESP_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();
}

fn main() {
    let args = Args::parse();

    match args.command {
        Command::ProcessStage0Request {
            g16_pk_dir,
            stage0_req_dir,
            out_dir,
            subcircuit_index,
        } => process_stage0_request(subcircuit_index, &g16_pk_dir, &stage0_req_dir, &out_dir),
    }
}
