use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use distributed_prover::{worker::{Stage1Response, Stage0Response}, coordinator::{Stage1Request, Stage0Request}};
use mpi::{topology::Rank, datatype::UserDatatype, Count};
use mpi::traits::*;

fn main() {
    let universe = mpi::initialize().unwrap();
    let world = universe.world();
    let root_rank = 0;
    let root_process = world.process_at_rank(root_rank);
    let rank = world.rank();

    let mut pk;
    let pk_bytes;
    // If you are root, broadcast 1024.
    if rank == root_rank {
        pk_bytes = vec![0u8; 1024]; // TODO: compute actual pk bytes
        println!("Root broadcasting value of size: {}.", pk_bytes.len());
    } else {
        // Else, just initialize to nothing; you will receive
        // below.
        pk = vec![];
    }
    root_process.broadcast_into(&mut pk_bytes);
    println!("Rank {rank} received pk bytes of size: {}.", pk_bytes.len());
    println!();

    /***************************************************************/
    /********************** Broadcast finished *********************/
    /***************************************************************/

    /***************************************************************/
    /*********************** Stage 0 Scatter ***********************/
    /***************************************************************/

    let now = std::time::Instant::now();
    let size = world.size();
    // Scatter of inputs
    let stage0_req_size = Stage0Request::dummy().uncompressed_size();
    let mut stage0_request = Stage0Request::dummy();
    let mut stage0_req_bytes = vec![0u8; stage0_req_size];
    if rank == root_rank {
        let stage0_requests = vec![0u8; stage0_req_size]; // TODO: compute actual requests
        // Coordinator stageN code goes here.
        root_process.scatter_into_root(&stage0_requests, &mut stage0_req_bytes);
    } else {
        root_process.scatter_into(&mut stage0_req_bytes);
        stage0_request = Stage0Request::deserialize_uncompressed_unchecked(&stage0_req_bytes[..]);
    }
    /***************************************************************/
    /******************* Stage0 Scatter finished *******************/
    /***************************************************************/

    let now = std::time::Instant::now();
    
    /***************************************************************/
    /******************* Stage 0 Gather started ********************/
    /***************************************************************/
    let stage0_response_size = Stage0Response::dummy().uncompressed_size();
    let dummy_response_bytes = vec![0u8; stage0_response_size];
    let mut stage0_responses = vec![];
    let proof_bytes = vec![];

    if rank == root_rank {
        let mut proof_bytes = vec![0u8; stage0_response_size * size.try_into().unwrap()];
        root_process.gather_into_root(&dummy_response_bytes, &mut proof_bytes[..]);
        stage0_responses = proof_bytes
            .chunks_exact(stage0_response_size)
            .skip(1) // Skip the root's response
            .map(|bytes| Stage0Response::deserialize_uncompressed_unchecked(bytes))
            .collect::<Vec<_>>();
        println!("Root waiting for 2 seconds? {}", now.elapsed().as_secs_f64());
        println!("Root gathered sequence: {:?}.", proof_bytes);
    } else {
        // Worker stageN code goes here.
        let proof_bytes = vec![0u8; stage0_response_size];//stage0_response();
        root_process.gather_varcount_into(&proof_bytes);
        println!("Rank {rank} sent value of size {}.", stage0_response_size.len());
    }
    /***************************************************************/
    /******************** Stage0 Gather finished *******************/
    /***************************************************************/
    


    /***************************************************************/
    /*********************** Stage 1 Scatter ***********************/
    /***************************************************************/

    let now = std::time::Instant::now();
    let size = world.size();
    // Scatter of inputs
    let stage1_req_size = Stage1Request::dummy().uncompressed_size();
    let mut stage1_request = Stage1Request::dummy();
    let mut stage1_req_bytes = vec![0u8; stage1_req_size];
    if rank == root_rank {
        let stage1_requests = vec![0u8; stage1_req_size]; // TODO: compute actual requests
        // Coordinator stageN code goes here.
        root_process.scatter_into_root(&stage1_requests, &mut stage1_req_bytes);
    } else {
        root_process.scatter_into(&mut stage1_req_bytes);
        stage1_request = Stage1Request::deserialize_uncompressed_unchecked(&stage1_req_bytes[..]);
    }
    /***************************************************************/
    /******************* Stage1 Scatter finished *******************/
    /***************************************************************/

    let now = std::time::Instant::now();
    
    /***************************************************************/
    /******************* Stage 1 Gather started ********************/
    /***************************************************************/
    let stage1_response_size = Stage1Response::dummy().uncompressed_size();
    let dummy_response_bytes = vec![0u8; stage1_response_size];
    let mut stage1_responses = vec![];
    let proof_bytes = vec![];

    if rank == root_rank {
        let mut proof_bytes = vec![0u8; stage1_response_size * size.try_into().unwrap()];
        root_process.gather_into_root(&dummy_response_bytes, &mut proof_bytes[..]);
        stage1_responses = proof_bytes
            .chunks_exact(stage1_response_size)
            .skip(1) // Skip the root's response
            .map(|bytes| Stage1Response::deserialize_uncompressed_unchecked(bytes))
            .collect::<Vec<_>>();
        println!("Root waiting for 2 seconds? {}", now.elapsed().as_secs_f64());
        println!("Root gathered sequence: {:?}.", proof_bytes);
    } else {
        // Worker stageN code goes here.
        let proof_bytes = vec![0u8; stage1_response_size];//stage1_response();
        root_process.gather_varcount_into(&proof_bytes);
        println!("Rank {rank} sent value of size {}.", stage1_response_size.len());
    }
    /***************************************************************/
    /******************** Stage1 Gather finished *******************/
    /***************************************************************/
    
    // TODO: 

    if rank == root_rank {
        // TODO: aggregate.
        // Do stuff with responses
    }
}