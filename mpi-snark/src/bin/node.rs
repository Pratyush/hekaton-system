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

    if rank == root_rank {
        // Initial broadcast

        let start = start_timer!(|| format!("Coord: Generating PKs"));
        let mut coordinator_state =
            CoordinatorState::new(size as usize, num_subcircuits, num_sha2_iters, num_portals);
        end_timer!(start);

        let pks = coordinator_state.get_pks();
        let mut pk_bytes = serialize_to_vec(&pks);

        let start = start_timer!(|| format!("Coord: Broadcasting PKs"));
        root_process.broadcast_into(&mut (pk_bytes.len() as u64));
        root_process.broadcast_into(&mut pk_bytes);
        end_timer!(start);

        /***************************************************************************/
        /***************************************************************************/
        // Stage 0
        let start = start_timer!(|| format!("Coord: Generating stage0 requests"));
        let requests = coordinator_state.stage_0();
        end_timer!(start);

        // Stage 0 scatter
        scatter_requests("stage0", &root_process, &requests);

        // Stage 0 gather
        let responses = gather_responses("stage1", size, &root_process);
        /***************************************************************************/
        /***************************************************************************/

        /***************************************************************************/
        /***************************************************************************/
        // Stage 1
        let start = start_timer!(|| format!("Coord: Processing stage0 responses"));
        let requests = coordinator_state.stage_1(&responses);
        end_timer!(start);

        // Stage 1 scatter
        scatter_requests("stage1", &root_process, &requests);

        // Stage 1 gather
        let responses = gather_responses("stage1", size, &root_process);
        /***************************************************************************/
        /***************************************************************************/

        let start = start_timer!(|| format!("Coord: Aggregating"));
        let proof = coordinator_state.aggregate(&responses);
        end_timer!(start);
    } else {
        let mut pk_bytes_size = 0u64;
        root_process.broadcast_into(&mut pk_bytes_size);
        let start =
            start_timer!(|| format!("Worker: Receiving PK broadcast of size {pk_bytes_size}"));
        let mut pk_bytes = vec![0u8; pk_bytes_size as usize];
        root_process.broadcast_into(&mut pk_bytes);
        end_timer!(start);
        println!("Received pk bytes of size: {}.", pk_bytes.len());

        // FIXME drop extra pk if worker will not use them.
        let start = start_timer!(|| format!("Worker: Deserializing ProvingKeys"));
        let pks = ProvingKeys::deserialize_uncompressed_unchecked(&pk_bytes[..]).unwrap();
        end_timer!(start);
        let mut worker_state = WorkerState::new(num_subcircuits, &pks);

        /***************************************************************************/
        /***************************************************************************/
        // Stage 0

        // Receive Stage 0 request
        let request = receive_requests("stage0", &root_process);

        // Compute Stage 0 response
        let start = start_timer!(|| format!("Worker: Processing stage0 request"));
        let response = worker_state.stage_0(&request);
        end_timer!(start);
        println!("Finished worker scatter 0 for rank {rank}");

        // Send Stage 0 response
        let start = start_timer!(|| format!("Worker: Serializing stage0 response"));
        let response_bytes = serialize_to_vec(&response);
        end_timer!(start);

        let start = start_timer!(|| format!("Worker: Gathering stage0 repsonse"));
        root_process.gather_varcount_into(&response_bytes);
        end_timer!(start);
        println!("Finished worker gather 0 for rank {rank}");

        /***************************************************************************/
        /***************************************************************************/

        /***************************************************************************/
        /***************************************************************************/
        // Stage 1

        // Receive Stage 1 request
        let request = receive_requests("stage1", &root_process);

        // Compute Stage 1 response
        let start = start_timer!(|| format!("Worker: Processing stage1 request"));
        let response = worker_state.stage_1(&request);
        end_timer!(start);
        println!("Finished worker scatter 1 for rank {rank}");

        // Send Stage 1 response
        let start = start_timer!(|| format!("Worker: Serializing stage1 response"));
        let response_bytes = serialize_to_vec(&response);
        end_timer!(start);

        let start = start_timer!(|| format!("Worker: Gathering stage1 response"));
        root_process.gather_varcount_into(&response_bytes);
        end_timer!(start);

        println!("Finished worker gather 1 for rank {rank}");
        /***************************************************************************/
        /***************************************************************************/
    }
}

fn scatter_requests<'a, C: 'a + Communicator>(
    name: &str,
    root_process: &Process<'a, C>,
    requests: &[impl CanonicalSerialize + Send],
) {
    let start = start_timer!(|| format!("Coord: Serializing {name} requests"));
    let mut request_bytes = vec![];
    let request_bytes_buf = construct_partitioned_buffer_for_scatter!(requests, &mut request_bytes);
    end_timer!(start);

    let counts = request_bytes_buf.counts().to_vec();
    root_process.scatter_into_root(&counts, &mut 0i32);
    let mut _recv_buf: Vec<u8> = vec![];

    let start = start_timer!(|| format!("Coord: Scattering {name} requests"));
    root_process.scatter_varcount_into_root(&request_bytes_buf, &mut _recv_buf);
    end_timer!(start);
}

fn gather_responses<'a, C, T>(name: &str, size: Count, root_process: &Process<'a, C>) -> Vec<T>
where
    C: 'a + Communicator,
    T: CanonicalSerialize + CanonicalDeserialize + Default,
{
    let mut response_bytes = vec![];
    let mut response_bytes_buf =
        construct_partitioned_mut_buffer_for_gather!(size, T, &mut response_bytes);
    // Root does not send anything, it only receives.
    let start = start_timer!(|| format!("Coord: Gathering {name} responses"));
    root_process.gather_varcount_into_root(&[0u8; 0], &mut response_bytes_buf);
    end_timer!(start);

    let start = start_timer!(|| format!("Coord: Deserializing {name} responses"));
    let ret = deserialize_flattened_bytes!(response_bytes, T).unwrap();
    end_timer!(start);

    ret
}

fn receive_requests<'a, C: 'a + Communicator, T: CanonicalDeserialize>(
    name: &str,
    root_process: &Process<'a, C>,
) -> T {
    let mut size = 0 as Count;
    root_process.scatter_into(&mut size);

    let start =
        start_timer!(|| format!("Worker: Receiving scattered {name} request of size {size}"));
    let mut request_bytes = vec![0u8; size as usize];
    root_process.scatter_varcount_into(&mut request_bytes);
    end_timer!(start);

    let start = start_timer!(|| format!("Worker: Deserializing {name} request"));
    let ret = T::deserialize_uncompressed_unchecked(&request_bytes[..]).unwrap();
    end_timer!(start);

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
