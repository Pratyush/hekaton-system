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


pub struct ProvingKeys {
    // First leaf circuit PK
    pub first_leaf_pk : Option<G16ProvingKey>,
    // Second leaf circuit PK
    pub second_leaf_pk : Option<G16ProvingKey>,
    // Padding circuit PK
    pub padding_pk : Option<G16ProvingKey>,
    // Root Circuit PK
    pub root_pk : Option<G16ProvingKey>,
    // Second to last parent pk
    pub parent_pk : Option<G16ProvingKey>,
}

impl ProvingKeys {
    // Generate functions to get each proving key
    pub fn first_leaf_pk(&self) -> &G16ProvingKey {
        self.first_leaf_pk.as_ref().unwrap()
    }

    pub fn second_leaf_pk(&self) -> &G16ProvingKey {
        self.second_leaf_pk.as_ref().unwrap()
    }

    pub fn padding_pk(&self) -> &G16ProvingKey {
        self.padding_pk.as_ref().unwrap()
    }

    pub fn root_pk(&self) -> &G16ProvingKey {
        self.root_pk.as_ref().unwrap()
    }

    pub fn parent_pk(&self) -> &G16ProvingKey {
        self.parent_pk.as_ref().unwrap()
    }
}