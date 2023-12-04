use distributed_prover::{
    aggregation::{AggProvingKey, SuperComCommittingKey},
    coordinator::{
        CoordinatorStage0State, FinalAggState, G16ProvingKeyGenerator, Stage0Request, Stage1Request,
    },
    kzg::KzgComKey,
    portal_manager::{PortalManager, SetupPortalManager},
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig, PoseidonTreeConfigVar as TreeConfigVar,
    },
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
    util::{cli_filenames::*, deserialize_from_path, serialize_to_path, G16ProvingKey},
    worker::{Stage0Response, Stage1Response},
    CircuitWithPortals,
};

use std::collections::HashMap;

use ark_bls12_381::{Bls12_381 as E, Fr as F};
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

macro_rules! start_timer {
    ($msg:expr) => {{
        use std::time::Instant;

        let msg = $msg();
        let start_info = "Start:";

        println!("{:8} {}", start_info, msg);
        (msg.to_string(), Instant::now())
    }};
}

macro_rules! end_timer {
    ($time:expr) => {{
        let time = $time.1;
        let final_time = time.elapsed();

        let end_info = "End:";
        let message = format!("{}", $time.0);

        println!("{:8} {} {}μs", end_info, message, final_time.as_micros());
    }};
}

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

/// This portal manager that does the bare minimum. For use in monolithic proving
#[derive(Default)]
pub struct MonolithicPortalManager(HashMap<String, FpVar<F>>);

struct MonolithicCircuit(MerkleTreeCircuit);

impl MonolithicCircuit {
    // Make a new empty merkle tree circuit
    fn new(params: &MerkleTreeCircuitParams) -> Self {
        MonolithicCircuit(<MerkleTreeCircuit as CircuitWithPortals<F>>::new(params))
    }
}

impl PortalManager<F> for MonolithicPortalManager {
    /// Gets the value from the map, witnesses it, and adds the entry to the trace
    fn get(&mut self, name: &str) -> Result<FpVar<F>, SynthesisError> {
        Ok(self
            .0
            .get(name)
            .expect(&format!("cannot get portal wire '{name}'"))
            .clone())
    }

    /// Sets the value in the map and adds the entry to the trace
    fn set(&mut self, name: String, val: &FpVar<F>) -> Result<(), SynthesisError> {
        // This is ROM. You cannot overwrite values
        assert!(
            self.0.get(&name).is_none(),
            "cannot set portal wire more than once; wire '{name}'"
        );

        // Log the concrete (not ZK) entry
        self.0.insert(name.to_string(), val.clone());

        Ok(())
    }
}

impl ConstraintSynthesizer<F> for MonolithicCircuit {
    fn generate_constraints(mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut pm = MonolithicPortalManager::default();
        let num_subcircuits = CircuitWithPortals::<F>::num_subcircuits(&self.0);

        for subcircuit_idx in 0..num_subcircuits {
            self.0
                .generate_constraints(cs.clone(), subcircuit_idx, &mut pm)?;
        }

        println!("Monolith: Total #constraints {} [nc={}]", cs.num_constraints(), num_subcircuits);

        Ok(())
    }
}

fn main() {
    let num_sha2_iters = 33;
    let num_portals = 11_538;

    for num_subcircuits in [16, 32, 64, 128, 256].into_iter().rev() {
        for num_threads in [1, 4, 16, 64].into_iter().rev() {
            // Do all of the following in a thread pool of the appropriate size
            rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build()
                .unwrap()
                .install(|| {

                let mut rng = rand::thread_rng();
                let circ_params = gen_test_circuit_params(num_subcircuits, num_sha2_iters, num_portals);

                // Generate the CRS
                let start = start_timer!(|| {
                    format!(
                    "Monolith: Building PK [nt={num_threads},ns={num_sha2_iters},np={num_portals},nc={num_subcircuits}]"
                )
                });
                let circuit = MonolithicCircuit::new(&circ_params);
                let pk = Groth16::<E, LibsnarkReduction>::generate_random_parameters_with_reduction(
                    circuit, &mut rng,
                )
                .unwrap();
                end_timer!(start);

                // Compute the proof
                let start = start_timer!(|| {
                    format!(
                    "Monolith: Computing proof [nt={num_threads},ns={num_sha2_iters},np={num_portals},nc={num_subcircuits}]"
                )
                });
                let circuit = MonolithicCircuit::new(&circ_params);
                Groth16::<E, LibsnarkReduction>::create_random_proof_with_reduction(
                    circuit, &pk, &mut rng,
                )
                .unwrap();
                end_timer!(start);
            });
        }
    }
}
