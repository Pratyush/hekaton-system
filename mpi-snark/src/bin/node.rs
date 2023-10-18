use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer};
use clap::Parser;
use mpi::traits::*;
use mpi::{
    datatype::{Partition, PartitionMut},
    topology::Process,
    Count,
};
use mpi_snark::{
    construct_partitioned_buffer_for_scatter, construct_partitioned_mut_buffer_for_gather,
    coordinator::CoordinatorState, data_structures::ProvingKeys, deserialize_flattened_bytes,
    serialize_to_vec, worker::WorkerState,
};
use rayon::prelude::*;

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

fn do_stuff(num_workers: usize, num_subcircuits: usize, num_sha2_iters: usize, num_portals: usize) {
    let universe = mpi::initialize().unwrap();
    let world = universe.world();
    let root_rank = 0;
    let root_process = world.process_at_rank(root_rank);
    let rank = world.rank();
    let size = world.size();
    assert_eq!(
        num_workers, num_subcircuits,
        "We only support num_workers == num_subcircuits"
    ); // use num_workers somewhere
    assert_eq!(
        size as usize,
        num_workers + 1,
        "We only support one core per worker (num_workers == world.size())"
    );

    let mut log = Vec::new();

    if rank == root_rank {
        // Initial broadcast

        let start = start_timer_buf!(log, || format!("Coord: Generating PKs"));
        let mut coordinator_state =
            CoordinatorState::new(size as usize, num_subcircuits, num_sha2_iters, num_portals);
        end_timer_buf!(log, start);

        let pks = coordinator_state.get_pks();
        let mut pk_bytes = serialize_to_vec(&pks);

        let start = start_timer_buf!(log, || format!("Coord: Broadcasting PKs"));
        root_process.broadcast_into(&mut (pk_bytes.len() as u64));
        root_process.broadcast_into(&mut pk_bytes);
        end_timer_buf!(log, start);

        /***************************************************************************/
        /***************************************************************************/
        // Stage 0
        let start = start_timer_buf!(log, || format!("Coord: Generating stage0 requests"));
        let requests = coordinator_state.stage_0();
        end_timer_buf!(log, start);

        // Stage 0 scatter
        scatter_requests(&mut log, "stage0", &root_process, &requests);

        // Stage 0 gather
        let responses = gather_responses(&mut log, "stage1", size, &root_process);
        /***************************************************************************/
        /***************************************************************************/

        /***************************************************************************/
        /***************************************************************************/
        // Stage 1
        let start = start_timer_buf!(log, || format!("Coord: Processing stage0 responses"));
        let requests = coordinator_state.stage_1(&responses);
        end_timer_buf!(log, start);

        // Stage 1 scatter
        scatter_requests(&mut log, "stage1", &root_process, &requests);

        // Stage 1 gather
        let responses = gather_responses(&mut log, "stage1", size, &root_process);
        /***************************************************************************/
        /***************************************************************************/

        let start = start_timer_buf!(log, || format!("Coord: Aggregating"));
        let proof = coordinator_state.aggregate(&responses);
        end_timer_buf!(log, start);
    } else {
        let mut pk_bytes_size = 0u64;
        root_process.broadcast_into(&mut pk_bytes_size);
        let start = start_timer_buf!(log, || format!(
            "Worker {rank}: Receiving PK broadcast of size {pk_bytes_size}"
        ));
        let mut pk_bytes = vec![0u8; pk_bytes_size as usize];
        root_process.broadcast_into(&mut pk_bytes);
        end_timer_buf!(log, start);
        println!("Received pk bytes of size: {}.", pk_bytes.len());

        // FIXME drop extra pk if worker will not use them.
        let start = start_timer_buf!(log, || format!("Worker {rank}: Deserializing ProvingKeys"));
        let pks = ProvingKeys::deserialize_uncompressed_unchecked(&pk_bytes[..]).unwrap();
        end_timer_buf!(log, start);
        let mut worker_state = WorkerState::new(num_subcircuits, &pks);

        /***************************************************************************/
        /***************************************************************************/
        // Stage 0

        // Receive Stage 0 request
        let request = receive_requests(&mut log, rank, "stage0", &root_process);

        // Compute Stage 0 response
        let start = start_timer_buf!(log, || format!("Worker {rank}: Processing stage0 request"));
        let response = worker_state.stage_0(&request);
        end_timer_buf!(log, start);
        println!("Finished worker scatter 0 for rank {rank}");

        // Send Stage 0 response
        let start = start_timer_buf!(log, || format!(
            "Worker {rank}: Serializing stage0 response"
        ));
        let response_bytes = serialize_to_vec(&response);
        end_timer_buf!(log, start);

        let start = start_timer_buf!(log, || format!(
            "Worker {rank}: Gathering stage0 repsonse, each of size {}",
            response_bytes.len()
        ));
        root_process.gather_varcount_into(&response_bytes);
        end_timer_buf!(log, start);
        println!("Finished worker gather 0 for rank {rank}");

        /***************************************************************************/
        /***************************************************************************/

        /***************************************************************************/
        /***************************************************************************/
        // Stage 1

        // Receive Stage 1 request
        let request = receive_requests(&mut log, rank, "stage1", &root_process);

        // Compute Stage 1 response
        let start = start_timer_buf!(log, || format!("Worker {rank}: Processing stage1 request"));
        let response = worker_state.stage_1(&request);
        end_timer_buf!(log, start);
        println!("Finished worker scatter 1 for rank {rank}");

        // Send Stage 1 response
        let start = start_timer_buf!(log, || format!(
            "Worker {rank}: Serializing stage1 response"
        ));
        let response_bytes = serialize_to_vec(&response);
        end_timer_buf!(log, start);

        let start = start_timer_buf!(log, || format!(
            "Worker {rank}: Gathering stage1 response, each of size {}",
            response_bytes.len()
        ));
        root_process.gather_varcount_into(&response_bytes);
        end_timer_buf!(log, start);

        println!("Finished worker gather 1 for rank {rank}");
        /***************************************************************************/
        /***************************************************************************/
    }

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
) -> Vec<T>
where
    C: 'a + Communicator,
    T: CanonicalSerialize + CanonicalDeserialize + Default,
{
    let mut response_bytes = vec![];
    let mut response_bytes_buf =
        construct_partitioned_mut_buffer_for_gather!(size, T, &mut response_bytes);
    // Root does not send anything, it only receives.
    let start = start_timer_buf!(log, || format!("Coord: Gathering {stage} responses"));
    root_process.gather_varcount_into_root(&[0u8; 0], &mut response_bytes_buf);
    end_timer_buf!(log, start);

    let start = start_timer_buf!(log, || format!("Coord: Deserializing {stage} responses"));
    let ret = deserialize_flattened_bytes!(response_bytes, T).unwrap();
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

#[derive(Parser)]
struct Args {
    /// The number of workers who will do the committing and proving. Each worker has 1 core.
    #[clap(long, value_name = "NUM")]
    num_workers: usize,

    /// Test circuit param: Number of subcircuits. MUST be a power of two and greater than 1.
    #[clap(long, value_name = "NUM")]
    num_subcircuits: usize,

    /// Test circuit param: Number of SHA256 iterations per subcircuit. MUST be at least 1.
    #[clap(long, value_name = "NUM")]
    num_sha2_iters: usize,

    /// Test circuit param: Number of portal wire ops per subcircuit. MUST be at least 1.
    #[clap(long, value_name = "NUM")]
    num_portals: usize,
}

fn main() {
    println!("Rayon num threads: {}", rayon::current_num_threads());

    let Args {
        num_workers,
        num_subcircuits,
        num_sha2_iters,
        num_portals,
    } = Args::parse();

    let start = start_timer!(|| format!("Running node"));

    do_stuff(num_workers, num_subcircuits, num_sha2_iters, num_portals);

    end_timer!(start);
}
