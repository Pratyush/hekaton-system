use distributed_prover::tree_hash_circuit::MerkleTreeCircuitParams;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, Subcommand};
use mpi::traits::*;
use mpi::{
    datatype::{Partition, PartitionMut},
    topology::Process,
    Count,
};
use mpi_snark::{
    construct_partitioned_buffer_for_scatter, construct_partitioned_mut_buffer_for_gather,
    coordinator::{generate_g16_pks, CoordinatorState},
    data_structures::{ProvingKeys, Stage0Response, Stage1Response},
    deserialize_flattened_bytes, serialize_to_vec,
    worker::WorkerState,
};

use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

macro_rules! start_timer_buf {
    ($buf:ident, $msg:expr) => {{
        use std::time::Instant;

        let msg = $msg();
        let start_info = "Start:";

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

        $buf.push(format!(
            "{:8} {} {}μs",
            end_info,
            message,
            final_time.as_micros()
        ));
    }};
}

use rayon::prelude::*;

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
    println!("Rayon num threads: {}", rayon::current_num_threads());

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
        let mut coordinator_state = CoordinatorState::new(proving_keys);
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
        let responses = responses_chunked
            .into_par_iter()
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
        let responses = responses_chunked
            .into_par_iter()
            .flatten()
            .collect::<Vec<_>>();
        println!("Finished coordinator gather 1");
        /***************************************************************************/
        /***************************************************************************/

        let start = start_timer_buf!(log, || format!("Coord: Aggregating"));
        let _proof = coordinator_state.aggregate(&responses);
        end_timer_buf!(log, start);
    } else {

        println!("Rayon num threads in worker {rank}: {}", rayon::current_num_threads());
        // Worker code
        let start = start_timer_buf!(log, || format!("Worker {rank}: Initializing worker state"));
        let mut worker_states =
            std::iter::from_fn(|| Some(WorkerState::new(num_subcircuits, &proving_keys)))
                .take(num_subcircuits_per_worker)
                .par_bridge()
                .collect::<Vec<_>>();
        end_timer_buf!(log, start);

        /***************************************************************************/
        /***************************************************************************/
        // Stage 0

        // Receive Stage 0 request
        let requests: Vec<_> = receive_requests(&mut log, rank, "stage0", &root_process);

        // Compute Stage 0 response
        let start = start_timer_buf!(log, || format!("Worker {rank}: Processing stage0 requests"));
        let responses = requests
            .par_iter()
            .zip(&mut worker_states)
            .map(|(req, state)| {
                rayon::ThreadPoolBuilder::new()
                    .build()
                    .unwrap()
                    .install(||
                state.stage_0(req))
            })
            .collect::<Vec<_>>();
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
        let requests: Vec<_> = receive_requests(&mut log, rank, "stage1", &root_process);

        // Compute Stage 1 response
        let start = start_timer_buf!(log, || format!("Worker {rank}: Processing stage1 request"));
        let responses = requests
            .par_iter()
            .zip(worker_states)
            .map(|(req, state)| {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(1)
                    .build()
                    .unwrap()
                    .install(||
                state.stage_1(req))
            })
            .collect::<Vec<_>>();
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
    let mut request_bytes = vec![0u8; size as usize];
    root_process.scatter_varcount_into(&mut request_bytes);
    end_timer_buf!(log, start);

    let start = start_timer_buf!(log, || format!(
        "Worker {rank}: Deserializing {stage} request"
    ));
    let ret = T::deserialize_uncompressed_unchecked(&request_bytes[..]).unwrap();
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
