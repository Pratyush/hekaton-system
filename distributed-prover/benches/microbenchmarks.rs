use distributed_prover::{
    aggregation::{AggProvingKey, SuperComCommittingKey},
    coordinator::{
        CoordinatorStage0State, FinalAggState, G16ProvingKeyGenerator, Stage0Request, Stage1Request,
    },
    kzg::KzgComKey,
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig, PoseidonTreeConfigVar as TreeConfigVar,
    },
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
    util::{cli_filenames::*, deserialize_from_path, serialize_to_path, G16ProvingKey},
    worker::{Stage0Response, Stage1Response},
    CircuitWithPortals,
};

use std::{io, path::PathBuf};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_std::{end_timer, start_timer};
use clap::{Parser, Subcommand};
use rayon::prelude::*;

use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BatchSize, BenchmarkGroup,
    BenchmarkId, Criterion,
};

// Checks the test circuit parameters and puts them in a struct
fn gen_test_circuit_params(
    num_subcircuits: usize,
    num_sha_iterations: usize,
    num_portals_per_subcircuit: usize,
) -> MerkleTreeCircuitParams {
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

    MerkleTreeCircuitParams {
        num_leaves: num_subcircuits / 2,
        num_sha_iters_per_subcircuit: num_sha_iterations,
        num_portals_per_subcircuit,
    }
}

/// Generates all the Groth16 proving and committing keys keys that the workers will use
fn generate_g16_pk(
    c: Option<&mut Criterion>,
    circ_params: &MerkleTreeCircuitParams,
) -> G16ProvingKey<E> {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    // Make an empty circuit of the correct size
    let circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::new(&circ_params);

    let generator = G16ProvingKeyGenerator::<TreeConfig, TreeConfigVar, E, _>::new(
        circ.clone(),
        tree_params.clone(),
    );

    c.map(|c| {
        c.bench_function(&format!("Coord: generating 1 G16 PK {circ_params}"), |b| {
            b.iter(|| generator.gen_pk(&mut rng, 0))
        })
    });

    let first_leaf_pk = generator.gen_pk(&mut rng, 0);

    first_leaf_pk
}

fn generate_agg_ck(
    c: Option<&mut Criterion>,
    circ_params: &MerkleTreeCircuitParams,
    pk: &G16ProvingKey<E>,
) -> AggProvingKey<E> {
    let mut rng = rand::thread_rng();
    let num_subcircuits = 2 * circ_params.num_leaves;

    // Create a lambda that returns the same proving key
    let pk_fetcher = |_subcircuit_idx| pk.clone();

    // We don't bench the SuperCom key. This is a subset of the KZG key. This will be resolved when
    // verification is resolved.
    let super_com_key = SuperComCommittingKey::<E>::gen(&mut rng, num_subcircuits);

    c.map(|c| {
        c.bench_function(&format!("Coord: generating agg ck {circ_params}"), |b| {
            b.iter(|| {
                let kzg_ck = KzgComKey::gen(&mut rng, num_subcircuits);
                AggProvingKey::new(super_com_key.clone(), kzg_ck, pk_fetcher);
            })
        })
    });

    let kzg_ck = KzgComKey::gen(&mut rng, num_subcircuits);
    AggProvingKey::new(super_com_key, kzg_ck, pk_fetcher)
}

fn begin_stage0(
    mut c: Option<&mut Criterion>,
    circ_params: &MerkleTreeCircuitParams,
) -> (
    CoordinatorStage0State<E, MerkleTreeCircuit>,
    Stage0Request<Fr>,
) {
    let mut rng = rand::thread_rng();

    // Make a random circuit with the given parameters
    let circ = MerkleTreeCircuit::rand(&mut rng, circ_params);

    // Make the stage0 coordinator state

    c.as_mut().map(|c| {
        c.bench_function(&format!("Coord: computing full trace {circ_params}"), |b| {
            b.iter(|| CoordinatorStage0State::<E, _>::new::<TreeConfig>(circ.clone()))
        })
    });

    let stage0_state = CoordinatorStage0State::<E, _>::new::<TreeConfig>(circ);

    // Sender sends stage0 requests containing the subtraces. Workers will commit to these
    c.map(|c| {
        c.bench_function(
            &format!("Coord: generating 1 stage0 req {circ_params}"),
            |b| b.iter(|| stage0_state.gen_request(0)),
        )
    });
    let req = stage0_state.gen_request(0).to_owned();

    (stage0_state, req)
}

fn process_stage0_requests(
    c: Option<&mut Criterion>,
    circ_params: &MerkleTreeCircuitParams,
    stage0_req: Stage0Request<Fr>,
    g16_pk: &G16ProvingKey<E>,
) -> Stage0Response<E> {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    // Compute the response
    c.map(|c| {
        c.bench_function(
            &format!("Worker: computing 1 stage0 resp {circ_params}"),
            |b| {
                b.iter(|| {
                    distributed_prover::worker::process_stage0_request::<
                        _,
                        TreeConfigVar,
                        _,
                        MerkleTreeCircuit,
                        _,
                    >(
                        &mut rng,
                        tree_params.clone(),
                        g16_pk.ck.clone(),
                        stage0_req.clone(),
                    )
                })
            },
        )
    });

    distributed_prover::worker::process_stage0_request::<_, TreeConfigVar, _, MerkleTreeCircuit, _>(
        &mut rng,
        tree_params,
        g16_pk.ck.clone(),
        stage0_req,
    )
}

fn process_stage0_resps(
    c: Option<&mut Criterion>,
    circ_params: &MerkleTreeCircuitParams,
    stage0_state: CoordinatorStage0State<E, MerkleTreeCircuit>,
    stage0_resp: Stage0Response<E>,
    agg_ck: AggProvingKey<E>,
) -> (
    FinalAggState<E>,
    Stage1Request<TreeConfig, Fr, MerkleTreeCircuit>,
) {
    let tree_params = gen_merkle_params();

    let num_subcircuits = 2 * circ_params.num_leaves;
    let stage0_resps = vec![stage0_resp; num_subcircuits];

    // Process the responses and get a new coordinator state
    c.map(|c| {
        c.bench_function(
            &format!("Coord: committing to stage0 resps {circ_params}"),
            |b| {
                b.iter(|| {
                    stage0_state.clone().process_stage0_responses(
                        &agg_ck.ipp_ck,
                        tree_params.clone(),
                        &stage0_resps,
                    )
                })
            },
        )
    });

    let new_coord_state =
        stage0_state.process_stage0_responses(&agg_ck.ipp_ck, tree_params, &stage0_resps);
    let req = new_coord_state.gen_request(0).to_owned();
    let final_agg_state = new_coord_state.into_agg_state();

    (final_agg_state, req)
}

fn process_stage1_requests(
    c: Option<&mut Criterion>,
    circ_params: &MerkleTreeCircuitParams,
    g16_pk: &G16ProvingKey<E>,
    stage0_req: Stage0Request<Fr>,
    stage0_resp: Stage0Response<E>,
    stage1_req: Stage1Request<TreeConfig, Fr, MerkleTreeCircuit>,
) -> Stage1Response<E> {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    // Compute the response. This is a Groth16 proof over a potentially large circuit
    c.map(|c| {
        c.bench_function(
            &format!("Worker: computing 1 stage1 resp {circ_params}"),
            |b| {
                b.iter(|| {
                    distributed_prover::worker::process_stage1_request::<_, TreeConfigVar, _, _, _>(
                        &mut rng,
                        tree_params.clone(),
                        &g16_pk,
                        stage0_req.clone(),
                        &stage0_resp,
                        stage1_req.clone(),
                    )
                })
            },
        )
    });

    distributed_prover::worker::process_stage1_request::<_, TreeConfigVar, _, _, _>(
        &mut rng,
        tree_params,
        &g16_pk,
        stage0_req,
        &stage0_resp,
        stage1_req,
    )
}

fn process_stage1_resps(
    c: Option<&mut Criterion>,
    circ_params: &MerkleTreeCircuitParams,
    final_agg_state: FinalAggState<E>,
    agg_ck: AggProvingKey<E>,
    stage1_resp: Stage1Response<E>,
) {
    let num_subcircuits = 2 * circ_params.num_leaves;

    println!("Making vec of resps");
    let stage1_resps = vec![stage1_resp; num_subcircuits];

    c.map(|c| {
        c.bench_function(&format!("Coord: agg stage1 resps {circ_params}"), |b| {
            b.iter(|| final_agg_state.gen_agg_proof(&agg_ck, &stage1_resps))
        })
    });
}

fn show_portal_constraint_tradeoff(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    /// All of these parameters produce circuits that are ~1.5M constraints. They are of the form
    /// (num_subcircuits, num_sha2_iters, num_portal_wires)
    let num_subcircuits = 256;
    let mut num_sha2_iters = 1;
    let mut num_portals = 109_462;

    let mut circ_params = gen_test_circuit_params(num_subcircuits, num_sha2_iters, num_portals);

    // Constraint conversion factor. 1 SHA2 iter is worth 3037 portal wires
    let sha2_iter_in_portals = 3037;

    // Everyone uses 16 cores
    let num_cores = 16;
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_cores)
        .build_global()
        .unwrap();

    // Go up to 37 SHA2 iters
    for _ in 0..19 {
        // Make an empty circuit of the correct size
        let circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::new(&circ_params);
        let first_leaf_pk = generate_g16_pk(Some(c), &circ_params);
        let agg_ck = generate_agg_ck(Some(c), &circ_params, &first_leaf_pk);
        let (stage0_state, stage0_req) = begin_stage0(Some(c), &circ_params);

        // For stage0, use only 1 thread
        c.bench_function(
            &format!(
                "Stage0 {}-core gen + resp [nc={},ns={}]",
                num_cores, num_subcircuits, circ_params.num_sha_iters_per_subcircuit
            ),
            |b| {
                b.iter(|| {
                    let stage0_req = stage0_state.gen_request(0).to_owned();
                    let stage0_resp = distributed_prover::worker::process_stage0_request::<
                        _,
                        TreeConfigVar,
                        _,
                        MerkleTreeCircuit,
                        _,
                    >(
                        &mut rng,
                        tree_params.clone(),
                        first_leaf_pk.ck.clone(),
                        stage0_req,
                    );
                })
            },
        );

        let stage0_resp =
            process_stage0_requests(Some(c), &circ_params, stage0_req.clone(), &first_leaf_pk);
        let (final_agg_state, stage1_req) = process_stage0_resps(
            Some(c),
            &circ_params,
            stage0_state,
            stage0_resp.clone(),
            agg_ck.clone(),
        );

        c.bench_function(
            &format!(
                "Stage1 {}-core proving [nc={},ns={}]",
                num_cores, num_subcircuits, circ_params.num_sha_iters_per_subcircuit
            ),
            |b| {
                b.iter(|| {
                    distributed_prover::worker::process_stage1_request::<_, TreeConfigVar, _, _, _>(
                        &mut rng,
                        tree_params.clone(),
                        &first_leaf_pk,
                        stage0_req.clone(),
                        &stage0_resp,
                        stage1_req.clone(),
                    )
                })
            },
        );

        // Add a sha2 iter. This adds some number of constraints to the circuit.
        circ_params.num_sha_iters_per_subcircuit += 2;
        // Subtract off the corresponding number of portals
        circ_params.num_portals_per_subcircuit -= 2 * sha2_iter_in_portals;
    }
}

fn aggregation(c: &mut Criterion) {
    // Do the same thing as the function below this one, but only benchmark the last step
    for num_subcircuits in [4, 16, 64, 256, 1024, 4096, 16384, 65536] {
        // Pick something that gives us 1.5M constraints. This does not affect our benchmark at
        // all, but may as well.
        let num_sha2_iters_per_subcirc = 1;
        let num_portals_per_subcirc = 1; //109_462;

        // Do all the setup
        let circ_params = gen_test_circuit_params(
            num_subcircuits,
            num_sha2_iters_per_subcirc,
            num_portals_per_subcirc,
        );
        let g16_pk = generate_g16_pk(None, &circ_params);
        let agg_ck = generate_agg_ck(None, &circ_params, &g16_pk);
        let (stage0_state, stage0_req) = begin_stage0(None, &circ_params);
        let stage0_resp = process_stage0_requests(None, &circ_params, stage0_req.clone(), &g16_pk);
        let (final_agg_state, stage1_req) = process_stage0_resps(
            None,
            &circ_params,
            stage0_state,
            stage0_resp.clone(),
            agg_ck.clone(),
        );
        let stage1_resp = process_stage1_requests(
            None,
            &circ_params,
            &g16_pk,
            stage0_req,
            stage0_resp,
            stage1_req,
        );

        // Now benchmark aggregation
        process_stage1_resps(Some(c), &circ_params, final_agg_state, agg_ck, stage1_resp);
    }
}

fn microbenches(c: &mut Criterion) {
    for num_subcircuits in [4] {
        for num_sha2_iters_per_subcirc in [16] {
            for num_portals_per_subcirc in [1] {
                let circ_params = gen_test_circuit_params(
                    num_subcircuits,
                    num_sha2_iters_per_subcirc,
                    num_portals_per_subcirc,
                );

                let g16_pk = generate_g16_pk(Some(c), &circ_params);
                let agg_ck = generate_agg_ck(Some(c), &circ_params, &g16_pk);
                let (stage0_state, stage0_req) = begin_stage0(Some(c), &circ_params);
                let stage0_resp =
                    process_stage0_requests(Some(c), &circ_params, stage0_req.clone(), &g16_pk);
                let (final_agg_state, stage1_req) = process_stage0_resps(
                    Some(c),
                    &circ_params,
                    stage0_state,
                    stage0_resp.clone(),
                    agg_ck.clone(),
                );
                let stage1_resp = process_stage1_requests(
                    Some(c),
                    &circ_params,
                    &g16_pk,
                    stage0_req,
                    stage0_resp,
                    stage1_req,
                );
                process_stage1_resps(Some(c), &circ_params, final_agg_state, agg_ck, stage1_resp);
            }
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();//.sample_size(20);
    targets = microbenches, aggregation, show_portal_constraint_tradeoff
);
criterion_main!(benches);
