use distributed_prover::{
    aggregation::{AggProvingKey, SuperComCommittingKey},
    coordinator::{CoordinatorStage0State, G16ProvingKeyGenerator, Stage1Request},
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig, PoseidonTreeConfigVar as TreeConfigVar,
    },
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
    util::{G16Com, G16ComSeed},
    worker::{process_stage0_request, process_stage1_request, Stage0Response, Stage1Response},
    CircuitWithPortals,
};

use std::{fs::File, io, path::PathBuf};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use clap::{Parser, Subcommand};

const PROVING_KEY_FILENAME_PREFIX: &str = "g16_pk_";

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generates the Groth16 proving keys for a test circuit consisting of `n` subcircuits. Places
    /// them in `OUT_DIR` with the name `g16_pk_i.bin`, where `i` is the number subcircuit.
    GenGroth16Keys {
        /// Path to the outputted proving keys
        #[clap(short, long, value_name = "OUT_DIR")]
        out_dir: PathBuf,

        /// Number of subcircuits. MUST be a power of two and greater than 1.
        #[clap(short, long, value_name = "NUM")]
        num_subcircuits: usize,
    },
}

fn generate_g16_pks(circ_params: MerkleTreeCircuitParams, out_dir: PathBuf) -> io::Result<()> {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    // Make an empty circuit of the correct size
    let circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::new(&circ_params);
    let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);

    let generator = G16ProvingKeyGenerator::<TreeConfig, TreeConfigVar, E, _>::new(
        circ.clone(),
        tree_params.clone(),
    );

    // For every subcircuit...
    for subcircuit_idx in 0..num_subcircuits {
        // Generate the subcircuit's G16 proving key
        let pk = generator.gen_pk(&mut rng, subcircuit_idx);

        // Construct the output filename
        let filename = format!("{}{}.bin", PROVING_KEY_FILENAME_PREFIX, subcircuit_idx);
        let out_path = out_dir.join(filename);

        // Write to file
        let mut f = File::create(out_path)?;
        pk.serialize_uncompressed(&mut f).unwrap();
    }

    Ok(())
}

fn main() {
    let args = Args::parse();

    match args.command {
        Command::GenGroth16Keys {
            out_dir,
            num_subcircuits,
        } => {
            assert!(
                num_subcircuits.is_power_of_two(),
                "#subcircuits MUST be a power of 2"
            );
            assert!(num_subcircuits > 1, "#subcircuits MUST be > 1");

            let circ_params = MerkleTreeCircuitParams {
                num_leaves: num_subcircuits / 2,
            };
            generate_g16_pks(circ_params, out_dir).unwrap();
        },
    }
}
