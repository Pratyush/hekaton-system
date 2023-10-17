use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer};
// use clap::Parser;
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

        let mut coordinator_state =
            CoordinatorState::new(size as usize, num_subcircuits, num_sha2_iters, num_portals);
        let pks = coordinator_state.get_pks();
        let mut pk_bytes = serialize_to_vec(&pks);
        root_process.broadcast_into(&mut (pk_bytes.len() as u64));
        root_process.broadcast_into(&mut pk_bytes);

        /***************************************************************************/
        /***************************************************************************/
        // Stage 0
        let requests = coordinator_state.stage_0();

        // Stage 0 scatter
        scatter_requests(&root_process, &requests);
        println!("Finished scatter 0");

        // Stage 0 gather
        let responses = gather_responses(size, &root_process);
        println!("Finished gather 0");
        /***************************************************************************/
        /***************************************************************************/

        /***************************************************************************/
        /***************************************************************************/
        // Stage 1
        let requests = coordinator_state.stage_1(&responses);

        // Stage 1 scatter
        scatter_requests(&root_process, &requests);
        println!("Finished scatter 1");

        // Stage 1 gather
        let responses = gather_responses(size, &root_process);
        println!("Finished gather 1");
        /***************************************************************************/
        /***************************************************************************/

        let proof = coordinator_state.aggregate(&responses);
        println!("Made proof");
    } else {
        let mut pk_bytes_size = 0u64;
        root_process.broadcast_into(&mut pk_bytes_size);
        let mut pk_bytes = vec![0u8; pk_bytes_size as usize];
        root_process.broadcast_into(&mut pk_bytes);
        println!("Received pk bytes of size: {}.", pk_bytes.len());

        // FIXME drop extra pk if worker will not use them.
        let pks = ProvingKeys::deserialize_uncompressed_unchecked(&pk_bytes[..]).unwrap();
        let mut worker_state = WorkerState::new(num_subcircuits, &pks);

        /***************************************************************************/
        /***************************************************************************/
        // Stage 0

        // Receive Stage 0 request
        let request = receive_requests(&root_process);

        // Compute Stage 0 response
        let response = worker_state.stage_0(&request);
        println!("Finished worker scatter 0 for rank {rank}");

        // Send Stage 0 response
        let response_bytes = serialize_to_vec(&response);
        root_process.gather_varcount_into(&response_bytes);
        println!("Finished worker gather 0 for rank {rank}");

        /***************************************************************************/
        /***************************************************************************/

        /***************************************************************************/
        /***************************************************************************/
        // Stage 1

        // Receive Stage 1 request
        let request = receive_requests(&root_process);

        // Compute Stage 1 response
        let response = worker_state.stage_1(&request);
        println!("Finished worker scatter 1 for rank {rank}");

        // Send Stage 1 response
        let response_bytes = serialize_to_vec(&response);
        root_process.gather_varcount_into(&response_bytes);
        println!("Finished worker gather 1 for rank {rank}");
        /***************************************************************************/
        /***************************************************************************/
    }
}

fn scatter_requests<'a, C: 'a + Communicator>(
    root_process: &Process<'a, C>,
    requests: &[impl CanonicalSerialize + Send],
) {
    let mut request_bytes = vec![];
    let request_bytes_buf = construct_partitioned_buffer_for_scatter!(requests, &mut request_bytes);
    let counts = request_bytes_buf.counts().to_vec();
    root_process.scatter_into_root(&counts, &mut 0i32);
    let mut _recv_buf: Vec<u8> = vec![];
    root_process.scatter_varcount_into_root(&request_bytes_buf, &mut _recv_buf);
}

fn gather_responses<'a, C, T>(size: Count, root_process: &Process<'a, C>) -> Vec<T>
where
    C: 'a + Communicator,
    T: CanonicalSerialize + CanonicalDeserialize + Default,
{
    let mut response_bytes = vec![];
    let mut response_bytes_buf =
        construct_partitioned_mut_buffer_for_gather!(size, T, &mut response_bytes);
    // Root does not send anything, it only receives.
    root_process.gather_varcount_into_root(&[0u8; 0], &mut response_bytes_buf);
    deserialize_flattened_bytes!(response_bytes, T).unwrap()
}

fn receive_requests<'a, C: 'a + Communicator, T: CanonicalDeserialize>(
    root_process: &Process<'a, C>,
) -> T {
    let mut size = 0 as Count;
    root_process.scatter_into(&mut size);
    let mut request_bytes = vec![0u8; size as usize];
    root_process.scatter_varcount_into(&mut request_bytes);
    T::deserialize_uncompressed_unchecked(&request_bytes[..]).unwrap()
}

// #[derive(Parser)]
// struct Args {
//     /// The number of workers who will do the committing and proving. Each worker has 1 core.
//     #[clap(short, long, value_name = "NUM")]
//     num_workers: usize,

//     /// Test circuit param: Number of subcircuits. MUST be a power of two and greater than 1.
//     #[clap(short, long, value_name = "NUM")]
//     num_subcircuits: usize,

//     /// Test circuit param: Number of SHA256 iterations per subcircuit. MUST be at least 1.
//     #[clap(short, long, value_name = "NUM")]
//     num_sha2_iters: usize,

//     /// Test circuit param: Number of portal wire ops per subcircuit. MUST be at least 1.
//     #[clap(short, long, value_name = "NUM")]
//     num_portals: usize,
// }

fn main() {
    println!("Rayon num threads: {}", rayon::current_num_threads());

    // let Args {
    //     num_workers,
    //     num_subcircuits,
    //     num_sha2_iters,
    //     num_portals,
    // } = Args::parse();

    let num_workers = 8;
    let num_subcircuits = 8;
    let num_sha2_iters = 1;
    let num_portals = 1;

    let start = start_timer!(|| format!("Running coordinator"));

    do_stuff(num_workers, num_subcircuits, num_sha2_iters, num_portals);

    end_timer!(start);
}
