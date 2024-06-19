use distributed_prover::{
    coordinator::G16ProvingKeyGenerator,
    poseidon_util::{gen_merkle_params, PoseidonTreeConfig, PoseidonTreeConfigVar},
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
    CircuitWithPortals,
};

use ark_bls12_381::{Bls12_381 as E, Fr};
use mimalloc::MiMalloc;
use mpi_snark::{
    coordinator::{generate_g16_pks, CoordinatorState},
    data_structures::ProvingKeys,
    worker::WorkerState,
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

fn main() {
    println!("Rayon num threads: {}", current_num_threads());
    work();
}

fn work() {
    let num_workers = 1;
    let circ_params = MerkleTreeCircuitParams {
        num_leaves: 8,
        num_sha_iters_per_subcircuit: 1,
        num_portals_per_subcircuit: 10,
    };
    let mut rng = rand::thread_rng();

    let tree_params = gen_merkle_params();

    // Make an empty circuit of the correct size
    let circ = MerkleTreeCircuit::rand(&mut rng, &circ_params);
    let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);
    let all_subcircuit_indices = (0..num_subcircuits).collect::<Vec<_>>();

    let proving_keys_vec = {
        let generator =
            G16ProvingKeyGenerator::<PoseidonTreeConfig, PoseidonTreeConfigVar, _, _>::new(
                circ.clone(),
                tree_params.clone(),
            );
        all_subcircuit_indices
            .iter()
            .map(|&i| generator.gen_pk(&mut rng, i))
            .collect::<Vec<_>>()
    };
    let circ = MerkleTreeCircuit::rand(&mut rng, &circ_params);

    let proving_keys = ProvingKeys {
        circ_params,
        first_leaf_pk: Some(proving_keys_vec[0].clone()),
        second_leaf_pk: Some(proving_keys_vec[1].clone()),
        padding_pk: Some(proving_keys_vec[num_subcircuits - 1].clone()),
        root_pk: Some(proving_keys_vec[num_subcircuits - 2].clone()),
        parent_pk: Some(proving_keys_vec[num_subcircuits - 3].clone()),
    };

    //let proving_keys = generate_g16_pks(circ_params);
    println!("Created pks");

    let circ_params = proving_keys.circ_params.clone();
    let num_subcircuits = 2 * circ_params.num_leaves;
    let current_num_threads = current_num_threads() - 1;

    let mut coordinator_state = CoordinatorState::new(&proving_keys);

    let requests = coordinator_state.stage_0();

    let mut worker_states =
        std::iter::from_fn(|| Some(WorkerState::new(num_subcircuits, &proving_keys)))
            .take(num_subcircuits)
            .collect::<Vec<_>>();

    let responses = compute_responses(
        current_num_threads,
        &requests,
        &mut worker_states,
        |req, state| state.stage_0(rand::thread_rng(), &req),
    );

    let requests = coordinator_state.stage_1(&responses);

    // Compute Stage 1 response
    let responses = compute_responses(
        current_num_threads,
        &requests,
        worker_states,
        |req, state| state.stage_1(rand::thread_rng(), &req),
    );
    println!("Finished worker scatter 1");
    println!("Finished coordinator gather 1");
    /***************************************************************************/
    /***************************************************************************/

    let _proof = coordinator_state.aggregate(&responses);
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
    requests
        .into_iter()
        .zip(worker_states.into_iter())
        .map(|(req, state)| stage_fn(req, state))
        .collect::<Vec<_>>()
}
