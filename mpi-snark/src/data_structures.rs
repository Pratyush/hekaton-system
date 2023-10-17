use distributed_prover::{
    poseidon_util::PoseidonTreeConfig as TreeConfig, tree_hash_circuit::MerkleTreeCircuit,
};

use ark_bls12_381::{Bls12_381 as E, Fr};

pub type G16Proof = distributed_prover::util::G16Proof<E>;
pub type G16ProvingKey = distributed_prover::util::G16ProvingKey<E>;
pub type G16Com = distributed_prover::util::G16Com<E>;
pub type G16ComRandomness = distributed_prover::util::G16ComRandomness<E>;

pub type Stage0Request = distributed_prover::coordinator::Stage0Request<Fr>;

pub type Stage0RequestRef<'a> = distributed_prover::coordinator::Stage0RequestRef<'a, Fr>;

pub type Stage1Request =
    distributed_prover::coordinator::Stage1Request<TreeConfig, Fr, MerkleTreeCircuit>;

pub type Stage1RequestRef<'a> =
    distributed_prover::coordinator::Stage1RequestRef<'a, TreeConfig, Fr, MerkleTreeCircuit>;

pub type Stage0Response = distributed_prover::worker::Stage0Response<E>;

pub type Stage1Response = distributed_prover::worker::Stage1Response<E>;
