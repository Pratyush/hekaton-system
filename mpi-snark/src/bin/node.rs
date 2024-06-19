use ark_ip_proofs::tipa::TIPA;
use distributed_prover::{
    aggregation::AggProvingKey,
    coordinator::{CoordinatorStage0State, G16ProvingKeyGenerator, Stage1Request},
    poseidon_util::{gen_merkle_params, PoseidonTreeConfig, PoseidonTreeConfigVar},
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
    worker::{process_stage0_request, process_stage0_request_get_cb},
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

    println!("Created pks");

    let mut worker_states =
        std::iter::from_fn(|| Some(WorkerState::new(num_subcircuits, &proving_keys)))
            .take(num_subcircuits)
            .collect::<Vec<_>>();

    let stage0_state = CoordinatorStage0State::<E, _>::new::<PoseidonTreeConfig>(circ);
    let stage0_reqs = all_subcircuit_indices
        .iter()
        .map(|&idx| stage0_state.gen_request(idx).to_owned())
        .collect::<Vec<_>>();
    let stage0_resps = stage0_reqs
        .iter()
        .zip(proving_keys_vec.iter())
        .zip(worker_states.iter_mut())
        .map(|((req, pk), worker_state)| {
            let (resp, cb) = process_stage0_request_get_cb::<
                _,
                PoseidonTreeConfigVar,
                _,
                MerkleTreeCircuit,
                _,
            >(&mut rng, tree_params.clone(), &pk, req.clone());
            worker_state.cb = Some(cb);
            resp
        })
        .collect::<Vec<_>>();

    let (tipp_pk, _tipp_vk) = TIPA::<E, Sha256>::setup(num_subcircuits, &mut rng).unwrap();
    let agg_ck = AggProvingKey::new(tipp_pk.clone(), |i| &proving_keys_vec[i]);

    let stage1_state =
        stage0_state.process_stage0_responses(&tipp_pk, tree_params.clone(), &stage0_resps);

    // Compute the values needed to prove stage1 for all subcircuits
    let stage1_reqs: Vec<Stage1Request<PoseidonTreeConfig, _, _>> = all_subcircuit_indices
        .iter()
        .map(|idx| stage1_state.gen_request(*idx).to_owned())
        .collect();

    // Compute Stage 1 response
    let stage1_resps = stage1_reqs
        .into_iter()
        .zip(worker_states.into_iter())
        .map(|(req, state)| state.stage_1(rand::thread_rng(), &req.to_ref()))
        .collect::<Vec<_>>();

    println!("Finished worker scatter 1");
    println!("Finished coordinator gather 1");
    /***************************************************************************/
    /***************************************************************************/

    // Compute the aggregate proof
    let final_agg_state = stage1_state.into_agg_state();
    let _proof = final_agg_state.gen_agg_proof(&agg_ck, &stage1_resps);
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
use sha2::Sha256;

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
