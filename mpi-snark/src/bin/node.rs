#![allow(warnings)]
use ark_std::{cfg_chunks, cfg_chunks_mut, cfg_into_iter, cfg_iter};
use distributed_prover::tree_hash_circuit::MerkleTreeCircuitParams;

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
    data_structures::{ProvingKeys, Stage0Request, Stage0Response, Stage1Request, Stage1Response},
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
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Setup {
        /// Test circuit param: Number of subcircuits. MUST be a power of two and greater than 1.
        #[clap(long, value_name = "NUM")]
        num_subcircuits: usize,

        /// Test circuit param: Number of SHA256 iterations per subcircuit. MUST be at least 1.
        #[clap(long, value_name = "NUM")]
        num_sha2_iters: usize,

        /// Test circuit param: Number of portal wire ops per subcircuit. MUST be at least 1.
        #[clap(long, value_name = "NUM")]
        num_portals: usize,

        /// Path for the output coordinator key package
        #[clap(long, value_name = "DIR")]
        key_out: PathBuf,
    },

    Work {
        /// Path to the coordinator key package
        #[clap(long, value_name = "DIR")]
        key_file: PathBuf,

        /// The number of workers who will do the committing and proving. Each worker has 1 core.
        #[clap(long, value_name = "NUM")]
        num_workers: usize,
    },
}

fn main() {
    println!("Rayon num threads: {}", current_num_threads());

    let args = Args::parse();

    match args.command {
        Command::Setup {
            num_subcircuits,
            num_sha2_iters,
            num_portals,
            key_out,
        } => setup(key_out, num_subcircuits, num_sha2_iters, num_portals),
        Command::Work {
            key_file,
            num_workers,
        } => {
            // Deserialize the proving keys
            let proving_keys = {
                let mut buf = Vec::new();
                let mut f =
                    File::open(&key_file).expect(&format!("couldn't open file {:?}", key_file));
                let _ = f.read_to_end(&mut buf);
                ProvingKeys::deserialize_uncompressed_unchecked(&mut buf.as_slice()).unwrap()
            };
            work(num_workers, proving_keys);
        },
    }
}

fn setup(
    key_out_path: PathBuf,
    num_subcircuits: usize,
    num_sha_iterations: usize,
    num_portals_per_subcircuit: usize,
) {
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

    let circ_params = MerkleTreeCircuitParams {
        num_leaves: num_subcircuits / 2,
        num_sha_iters_per_subcircuit: num_sha_iterations,
        num_portals_per_subcircuit,
    };

    let pks = generate_g16_pks(circ_params);

    let mut buf = Vec::new();
    pks.serialize_uncompressed(&mut buf).unwrap();

    let mut f =
        File::create(&key_out_path).expect(&format!("could not create file {:?}", key_out_path));
    f.write_all(&buf).unwrap();
}

fn work(num_workers: usize, proving_keys: ProvingKeys) {
    let (universe, _) = mpi::initialize_with_threading(mpi::Threading::Funneled).unwrap();
    let world = universe.world();
    let root_rank = 0;
    let root_process = world.process_at_rank(root_rank);
    let rank = world.rank();
    let size = world.size();

    let circ_params = proving_keys.circ_params.clone();
    let num_subcircuits = 2 * circ_params.num_leaves;

    let num_subcircuits_per_worker = num_subcircuits / num_workers;
    assert_eq!(num_subcircuits_per_worker * num_workers, num_subcircuits);

    let mut log = Vec::new();
    let very_start = start_timer_buf!(log, || format!("Node {rank}: Beginning work"));

    if rank == root_rank {
        // Initial broadcast

        let start = start_timer_buf!(log, || format!("Coord: construct coordinator state"));
        let mut coordinator_state = CoordinatorState::new(&proving_keys);
        end_timer_buf!(log, start);

        /***************************************************************************/
        /***************************************************************************/
        // Stage 0
        let start = start_timer_buf!(log, || format!("Coord: Generating stage0 requests"));
        let requests = coordinator_state.stage_0();
        let requests_chunked = requests
            .chunks(num_subcircuits_per_worker)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();
        end_timer_buf!(log, start);

        // Stage 0 scatter
        scatter_requests(&mut log, "stage0", &root_process, &requests_chunked);
        println!("Finished coordinator scatter 0");

        // Stage 0 gather
        let default_response = vec![Stage0Response::default(); num_subcircuits_per_worker];
        let responses_chunked: Vec<Vec<_>> =
            gather_responses(&mut log, "stage0", size, &root_process, default_response);
        let responses = cfg_into_iter!(responses_chunked)
            .flatten()
            .collect::<Vec<_>>();
        println!("Finished coordinator gather 0");
        /***************************************************************************/
        /***************************************************************************/

        /***************************************************************************/
        /***************************************************************************/
        // Stage 1
        let start = start_timer_buf!(log, || format!("Coord: Processing stage0 responses"));
        let requests = coordinator_state.stage_1(&responses);
        let requests_chunked = requests
            .chunks(num_subcircuits_per_worker)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();
        end_timer_buf!(log, start);

        // Stage 1 scatter
        scatter_requests(&mut log, "stage1", &root_process, &requests_chunked);
        println!("Finished coordinator scatter 1");

        // Stage 1 gather
        let default_response = vec![Stage1Response::default(); num_subcircuits_per_worker];
        let responses_chunked: Vec<Vec<_>> =
            gather_responses(&mut log, "stage1", size, &root_process, default_response);
        let responses = cfg_into_iter!(responses_chunked)
            .flatten()
            .collect::<Vec<_>>();
        println!("Finished coordinator gather 1");
        /***************************************************************************/
        /***************************************************************************/

        let start = start_timer_buf!(log, || format!("Coord: Aggregating"));
        let _proof = coordinator_state.aggregate(&responses);
        end_timer_buf!(log, start);
    } else {
        let current_num_threads = current_num_threads() - 1;
        println!(
            "Rayon num threads in worker {rank}: {}",
            current_num_threads
        );
        // Worker code
        let start = start_timer_buf!(log, || format!("Worker {rank}: Initializing worker state"));
        let mut worker_states =
            std::iter::from_fn(|| Some(WorkerState::new(num_subcircuits, &proving_keys)))
                .take(num_subcircuits_per_worker)
                .collect::<Vec<_>>();
        end_timer_buf!(log, start);

        /***************************************************************************/
        /***************************************************************************/
        // Stage 0

        // Receive Stage 0 request
        let requests: Vec<Stage0Request> =
            receive_requests(&mut log, rank, "stage0", &root_process);

        // Compute Stage 0 response
        let start = start_timer_buf!(log, || format!("Worker {rank}: Processing stage0 requests"));
        let responses = compute_responses(
            current_num_threads,
            &requests,
            &mut worker_states,
            |req, state| state.stage_0(rand::thread_rng(), &req.to_ref()),
        );
        end_timer_buf!(log, start);
        println!("Finished worker scatter 0 for rank {rank}");

        // Send Stage 0 response
        send_responses(&mut log, rank, "stage0", &root_process, &responses);
        println!("Finished worker gather 0 for rank {rank}");

        /***************************************************************************/
        /***************************************************************************/

        /***************************************************************************/
        /***************************************************************************/
        // Stage 1

        // Receive Stage 1 request
        let requests: Vec<Stage1Request> =
            receive_requests(&mut log, rank, "stage1", &root_process);

        // Compute Stage 1 response
        let start = start_timer_buf!(log, || format!("Worker {rank}: Processing stage1 request"));
        let responses = compute_responses(
            current_num_threads,
            &requests,
            worker_states,
            |req, state| state.stage_1(rand::thread_rng(), &req.to_ref()),
        );
        end_timer_buf!(log, start);
        println!("Finished worker scatter 1 for rank {rank}");

        send_responses(&mut log, rank, "stage1", &root_process, &responses);

        println!("Finished worker gather 1 for rank {rank}");
        /***************************************************************************/
        /***************************************************************************/
    }

    end_timer_buf!(log, very_start);

    println!("Rank {rank} log: {}", log.join(";"));
}

fn scatter_requests<'a, C: 'a + Communicator>(
    log: &mut Vec<String>,
    stage: &str,
    root_process: &Process<'a, C>,
    requests: &[impl CanonicalSerialize + Send],
) {
    let start = start_timer_buf!(log, || format!("Coord: Serializing {stage} requests"));
    let mut request_bytes = vec![];
    let request_bytes_buf = construct_partitioned_buffer_for_scatter!(requests, &mut request_bytes);
    end_timer_buf!(log, start);

    let counts = request_bytes_buf.counts().to_vec();
    root_process.scatter_into_root(&counts, &mut 0i32);
    let mut _recv_buf: Vec<u8> = vec![];

    let start = start_timer_buf!(log, || format!("Coord: Scattering {stage} requests"));
    root_process.scatter_varcount_into_root(&request_bytes_buf, &mut _recv_buf);
    end_timer_buf!(log, start);
}

fn receive_requests<'a, C: 'a + Communicator, T: CanonicalDeserialize>(
    log: &mut Vec<String>,
    rank: i32,
    stage: &str,
    root_process: &Process<'a, C>,
) -> T {
    let mut size = 0 as Count;
    root_process.scatter_into(&mut size);

    let start = start_timer_buf!(log, || format!(
        "Worker {rank}: Receiving scattered {stage} request of size {size}"
    ));
    let mut request_ser = vec![Packed::zero(); size as usize];
    root_process.scatter_varcount_into(&mut request_ser);
    end_timer_buf!(log, start);

    let start = start_timer_buf!(log, || format!(
        "Worker {rank}: Deserializing {stage} request"
    ));
    let ret = deserialize_from_packed_bytes(&request_ser[..]).unwrap();
    end_timer_buf!(log, start);

    ret
}

fn send_responses<'a, C: 'a + Communicator, T: CanonicalSerialize>(
    log: &mut Vec<String>,
    rank: i32,
    stage: &str,
    root_process: &Process<'a, C>,
    responses: &[T],
) {
    // Send Stage 1 response
    let start = start_timer_buf!(log, || format!(
        "Worker {rank}: Serializing {stage} {}, responses",
        responses.len(),
    ));
    let responses_bytes = serialize_to_vec(&responses);
    end_timer_buf!(log, start);

    let start = start_timer_buf!(log, || format!(
        "Worker {rank}: Gathering {stage} response, each of size {}",
        responses_bytes.len() / responses.len()
    ));
    root_process.gather_varcount_into(&responses_bytes);
    end_timer_buf!(log, start);
}

fn gather_responses<'a, C, T>(
    log: &mut Vec<String>,
    stage: &str,
    size: Count,
    root_process: &Process<'a, C>,
    default_response: T,
) -> Vec<T>
where
    C: 'a + Communicator,
    T: CanonicalSerialize + CanonicalDeserialize + Default,
{
    let mut response_bytes = vec![];
    let mut response_bytes_buf =
        construct_partitioned_mut_buffer_for_gather!(size, default_response, &mut response_bytes);
    // Root does not send anything, it only receives.
    let start = start_timer_buf!(log, || format!("Coord: Gathering {stage} responses"));
    root_process.gather_varcount_into_root(&[0u8; 0], &mut response_bytes_buf);
    end_timer_buf!(log, start);

    let start = start_timer_buf!(log, || format!("Coord: Deserializing {stage} responses"));
    let ret = deserialize_flattened_bytes!(response_bytes, default_response, T).unwrap();
    end_timer_buf!(log, start);

    ret
}

#[cfg(feature = "parallel")]
fn execute_in_pool<T: Send>(f: impl FnOnce() -> T + Send, num_threads: usize) -> T {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();
    pool.install(f)
}

#[cfg(not(feature = "parallel"))]
fn execute_in_pool<T: Send>(f: impl FnOnce() -> T + Send, num_threads: usize) -> T {
    f()
}
#[cfg(not(feature = "parallel"))]
fn execute_in_pool_with_all_threads<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    f()
}

#[cfg(feature = "parallel")]
use rayon::current_num_threads;

#[cfg(not(feature = "parallel"))]
fn current_num_threads() -> usize {
    1
}

fn pool_and_chunk_size(num_threads: usize, num_requests: usize) -> (usize, usize) {
    let pool_size = if num_threads > num_requests {
        num_threads / num_requests
    } else {
        1
    };
    let chunk_size = if num_requests >= num_threads {
        num_requests / num_threads
    } else {
        1
    };
    dbg!((pool_size, chunk_size))
}

#[cfg(feature = "parallel")]
fn compute_responses<'a, R, W, U, F>(
    num_threads: usize,
    requests: &'a [R],
    worker_states: impl IntoIterator<Item = W>,
    stage_fn: F,
) -> Vec<U>
where
    R: 'a + Send + Sync,
    W: Send + Sync,
    U: Send + Sync,
    F: Send + Sync + Fn(&'a R, W) -> U,
{
    let (pool_size, chunk_size) = pool_and_chunk_size(num_threads, requests.len());
    thread::scope(|s| {
        let mut thread_results = Vec::new();
        let chunks = worker_states.into_iter().chunks(chunk_size);
        let worker_state_chunks = chunks
            .into_iter()
            .map(|c| c.into_iter().collect::<Vec<_>>());
        for (reqs, states) in requests.chunks(chunk_size).zip(worker_state_chunks) {
            let result = s.spawn(|_| {
                reqs.into_iter()
                    .zip(states)
                    .map(|(req, state)| execute_in_pool(|| stage_fn(req, state), pool_size))
                    .collect::<Vec<_>>()
            });
            thread_results.push(result);
        }
        thread_results
            .into_iter()
            .map(|t| t.join().unwrap())
            .flatten()
            .collect::<Vec<_>>()
    })
    .unwrap()
}

#[cfg(not(feature = "parallel"))]
fn compute_responses<'a, R, W, U, F>(
    num_threads: usize,
    requests: &'a [R],
    worker_states: impl IntoIterator<Item = W>,
    stage_fn: F,
) -> Vec<U>
where
    R: 'a + Send + Sync,
    W: Send + Sync,
    U: Send + Sync,
    F: Send + Sync + Fn(&'a R, W) -> U,
{
    let (pool_size, chunk_size) = pool_and_chunk_size(current_num_threads(), requests.len());
    let mut thread_results = Vec::new();
    let chunks = worker_states.into_iter().chunks(chunk_size);
    let worker_state_chunks = chunks
        .into_iter()
        .map(|c| c.into_iter().collect::<Vec<_>>());
    for (reqs, states) in requests.chunks(chunk_size).zip(worker_state_chunks) {
        let result = reqs
            .into_iter()
            .zip(states)
            .map(|(req, state)| stage_fn(req, state))
            .collect::<Vec<_>>();
        thread_results.push(result);
    }
    thread_results.into_iter().flatten().collect::<Vec<_>>()
}
