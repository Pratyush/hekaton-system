use ark_bls12_381::{Bls12_381, G1Projective as G1};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpi::traits::*;
use mpi::{
    datatype::{Partition, PartitionMut},
    topology::Process,
    Count,
};
use mpi_snark::{
    construct_partitioned_buffer_for_scatter, construct_partitioned_mut_buffer_for_gather,
    coordinator::CoordinatorState, data_structures::G16ProvingKey, deserialize_flattened_bytes,
    serialize_to_vec, worker::WorkerState,
};
use rayon::prelude::*;

fn main() {
    let universe = mpi::initialize().unwrap();
    let world = universe.world();
    let root_rank = 0;
    let root_process = world.process_at_rank(root_rank);
    let rank = world.rank();
    let size = world.size();

    if rank == root_rank {
        // Initial broadcast

        let mut coordinator_state = CoordinatorState::<Bls12_381>::new(size as usize, 0, 0, 0);
        let pk = coordinator_state.get_pk();
        let mut pk_bytes = serialize_to_vec(&pk);
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
        println!("Proof: {:?}", proof)
    } else {
        let pk: G16ProvingKey = todo!();
        let mut pk_bytes = serialize_to_vec(&pk);
        root_process.broadcast_into(&mut pk_bytes);
        println!("Received pk bytes of size: {}.", pk_bytes.len());

        // FIXME drop extra pk if worker will not use them.
        let pk = G16ProvingKey::deserialize_uncompressed_unchecked(&pk_bytes[..]).unwrap();
        let mut worker_state = WorkerState::new(&pk);

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
