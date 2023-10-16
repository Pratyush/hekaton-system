use distributed_prover::{
    coordinator::{Stage0Request, Stage1Request},
    poseidon_util::{gen_merkle_params, PoseidonTreeConfigVar as TreeConfigVar},
    tree_hash_circuit::MerkleTreeCircuit,
    util::{cli_filenames::*, deserialize_from_path, serialize_to_path, G16ComKey, G16ProvingKey},
    worker::Stage0Response,
};

use std::path::PathBuf;

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_std::{end_timer, start_timer};
use clap::{Parser, Subcommand};

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

        /// Directory where worker requests are stored
        #[clap(short, long, value_name = "DIR")]
        req_dir: PathBuf,

        /// Directory where worker responses will be stored
        #[clap(short, long, value_name = "DIR")]
        out_dir: PathBuf,

        /// Which subcircuit should be proven
        #[clap(short, long, value_name = "NUM")]
        subcircuit_index: usize,
    },

    /// Process the stage0 responses from workers and produce stage1 reqeusts
    ProcessStage1Request {
        /// Directory where the Groth16 proving keys are stored
        #[clap(short, long, value_name = "DIR")]
        g16_pk_dir: PathBuf,

        /// Directory where worker requests are stored
        #[clap(short, long, value_name = "DIR")]
        req_dir: PathBuf,

        /// Directory where stage0 worker responses are stored
        #[clap(short, long, value_name = "DIR")]
        resp_dir: PathBuf,

        /// Directory where stage1 worker responses will be stored
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
    req_dir: &PathBuf,
    out_dir: &PathBuf,
) {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    // Deserialize the appropriate committing key and request
    let start = start_timer!(|| "Deserializing g16 com key");
    let g16_ck = deserialize_from_path::<G16ComKey<E>>(
        g16_pk_dir,
        G16_CK_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();
    end_timer!(start);
    let start = start_timer!(|| "Deserializing req");
    let stage0_req = deserialize_from_path::<Stage0Request<Fr>>(
        req_dir,
        STAGE0_REQ_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();
    end_timer!(start);

    // Sanity check that the request index matches the expected index
    assert_eq!(stage0_req.subcircuit_idx, subcircuit_idx);

    // Compute the response
    let start = start_timer!(|| format!("Processing stage0 request"));
    let stage0_resp = distributed_prover::worker::process_stage0_request::<
        _,
        TreeConfigVar,
        _,
        MerkleTreeCircuit,
        _,
    >(&mut rng, tree_params, g16_ck, stage0_req);
    end_timer!(start);

    // Save it
    serialize_to_path(
        &stage0_resp,
        out_dir,
        STAGE0_RESP_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();
}

fn process_stage1_request(
    subcircuit_idx: usize,
    g16_pk_dir: &PathBuf,
    req_dir: &PathBuf,
    resp_dir: &PathBuf,
    out_dir: &PathBuf,
) {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    // Deserialize the appropriate proving key, old request, old response, and new request
    let g16_pk = deserialize_from_path::<G16ProvingKey<E>>(
        g16_pk_dir,
        G16_PK_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();
    let stage0_req = deserialize_from_path::<Stage0Request<Fr>>(
        req_dir,
        STAGE0_REQ_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();
    let stage0_resp = deserialize_from_path::<Stage0Response<E>>(
        resp_dir,
        STAGE0_RESP_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();
    let stage1_req = deserialize_from_path::<Stage1Request<_, _, MerkleTreeCircuit>>(
        req_dir,
        STAGE1_REQ_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();

    // Compute the response. This is a Groth16 proof over a potentially large circuit
    let start = start_timer!(|| format!("Processing stage1 request"));
    let stage1_resp = distributed_prover::worker::process_stage1_request::<_, TreeConfigVar, _, _, _>(
        &mut rng,
        tree_params,
        &g16_pk,
        stage0_req,
        &stage0_resp,
        stage1_req,
    );
    end_timer!(start);

    // Save it
    serialize_to_path(
        &stage1_resp,
        out_dir,
        STAGE1_RESP_FILENAME_PREFIX,
        Some(subcircuit_idx),
    )
    .unwrap();
}

fn main() {
    println!("Rayon num threads: {}", rayon::current_num_threads());

    let args = Args::parse();
    let start = start_timer!(|| format!("Running worker"));

    match args.command {
        Command::ProcessStage0Request {
            g16_pk_dir,
            req_dir,
            out_dir,
            subcircuit_index,
        } => process_stage0_request(subcircuit_index, &g16_pk_dir, &req_dir, &out_dir),

        Command::ProcessStage1Request {
            g16_pk_dir,
            req_dir,
            resp_dir,
            out_dir,
            subcircuit_index,
        } => process_stage1_request(subcircuit_index, &g16_pk_dir, &req_dir, &resp_dir, &out_dir),
    }

    end_timer!(start);
}
