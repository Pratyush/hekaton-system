use clap::{Parser, Subcommand};
use std::path::PathBuf;

use ark_ff::PrimeField;
use distributed_prover::{tree_hash_circuit, CircuitWithPortals};

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generates the Groth16 proving keys for a test circuit of size `n`. Places them in `OUT_DIR`
    /// with the name `g16_pk_i.bin`, where `i` is the number subcircuit.
    GenGroth16Keys {
        /// Path to the outputted proving keys
        #[clap(short, long, value_name = "OUT_DIR")]
        out_dir: PathBuf,

        /// Number of subcircuits
        #[clap(short, long, value_name = "NUM")]
        num_subcircuits: usize,
    },
}

fn generate_g16_pks<F, P>(params: P::Parameters)
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
{
    todo!()
}

fn main() {
    let args = Args::parse();

    match args.command {
        Command::GenGroth16Keys {
            out_dir,
            num_subcircuits,
        } => println!("hi"),
    }
}
