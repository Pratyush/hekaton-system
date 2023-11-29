#![allow(warnings)]
use ark_std::{cfg_chunks, cfg_chunks_mut, cfg_into_iter, cfg_iter};
use distributed_prover::tree_hash_circuit::MerkleTreeCircuitParams;
use rand_chacha::ChaCha12Rng;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, Subcommand};
use mimalloc::MiMalloc;
use mpi::{
    datatype::{Partition, PartitionMut},
    topology::Process,
    Count,
};
use mpi::{request, traits::*};
use mpi_snark::{
    construct_partitioned_buffer_for_scatter, construct_partitioned_mut_buffer_for_gather,
    coordinator::{generate_g16_pks, CoordinatorState},
    data_structures::{ProvingKeys, Stage0Response, Stage1Response},
    deserialize_flattened_bytes, deserialize_from_packed_bytes, serialize_to_packed_vec,
    serialize_to_vec,
    worker::WorkerState,
    Packed,
};

use std::{
    fs::File,
    io::{Read, Write},
    num::NonZeroUsize,
    path::PathBuf,
};

#[cfg(feature = "parallel")]
use crossbeam::thread;
use itertools::Itertools;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

macro_rules! start_timer_buf {
    ($buf:ident, $msg:expr) => {{
        use std::time::Instant;

        let msg = $msg();
        let start_info = "Start:";

        println!("{:8} {}", start_info, msg);
        $buf.push(format!("{:8} {}", start_info, msg));
        (msg.to_string(), Instant::now())
    }};
}

macro_rules! end_timer_buf {
    ($buf:ident, $time:expr) => {{
        let time = $time.1;
        let final_time = time.elapsed();

        let end_info = "End:";
        let message = format!("{}", $time.0);

        println!("{:8} {} {}μs", end_info, message, final_time.as_micros());
        $buf.push(format!(
            "{:8} {} {}μs",
            end_info,
            message,
            final_time.as_micros()
        ));
    }};
}

#[derive(Parser)]
struct Args {
    /// Path to the coordinator key package
    #[clap(long, value_name = "DIR")]
    key_file: PathBuf,
}

fn main() {
    println!("Rayon num threads: {}", current_num_threads());

    let Args { key_file } = Args::parse();

    // Deserialize the proving keys
    let proving_keys = {
        let mut buf = Vec::new();
        let mut f = File::open(&key_file).expect(&format!("couldn't open file {:?}", key_file));
        let _ = f.read_to_end(&mut buf);
        ProvingKeys::deserialize_uncompressed_unchecked(&mut buf.as_slice()).unwrap()
    };
    work(proving_keys);
}

fn work(proving_keys: ProvingKeys) {
    let circ_params = proving_keys.circ_params.clone();
    let num_subcircuits = 2 * circ_params.num_leaves;

    let mut log = Vec::new();
    let very_start = start_timer_buf!(log, || format!("Node {rank}: Beginning work"));

    let start = start_timer_buf!(log, || format!("Coord: construct coordinator state"));
    let mut coordinator_state = CoordinatorState::new(proving_keys);
    end_timer_buf!(log, start);

    // Stage0 requests
    let start = start_timer_buf!(log, || format!("Coord: Generating stage0 requests"));
    let stage0_reqs = coordinator_state.stage_0();
    end_timer_buf!(log, start);

    // Stage0 responses
    // Each commitment comes with a seed so we can reconstruct the commitment in stage1
    let (stage0_resps, stage0_seeds) = cfg_iter!(stage0_reqs)
        .map(|req| {
            // Per-worker seed
            let mut seed: [u8; 32] = rand::thread_rng().gen();
            let mut rng = ChaCha12Rng::from_seed(seed);

            let start =
                start_timer_buf!(log, || format!("Worker {rank}: Processing stage0 requests"));

            // Make a new state for each worker and compute the commimtent
            let resp = WorkerState::new(num_subcircuits, &proving_keys).stage_0(&mut rng, req);

            end_timer_buf!(log, start);
            (resp, seed)
        })
        .unzip()
        .collect();

    // Stage1 requests
    let start = start_timer_buf!(log, || format!("Coord: Processing stage0 responses"));
    let stage1_reqs = coordinator_state.stage_1(&stage0_resps);
    end_timer_buf!(log, start);

    // Stage1 responses
    let stage1_resps = cfg_into_iter!(stage0_reqs)
        .zip(cfg_into_iter!(stage1_reqs))
        .zip(cfg_into_iter!(stage0_seeds))
        .map(|((req0, req1), seed)| {
            // Per-worker seed
            let mut seed: [u8; 32] = rand::thread_rng().gen();
            let mut rng = ChaCha12Rng::from_seed(seed);

            let state = WorkerState::new(num_subcircuits, &proving_keys);
            state.stage_0(&mut rng, req);
            state.stage_1(req)
        })
        .collect();

    let start = start_timer_buf!(log, || format!("Coord: Aggregating"));
    let _proof = coordinator_state.aggregate(&stage1_resps);

    end_timer_buf!(log, very_start);

    println!("Rank {rank} log: {}", log.join(";"));
}
