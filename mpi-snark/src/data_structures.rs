use ark_ip_proofs::tipa::Proof;
use distributed_prover::{
    poseidon_util::PoseidonTreeConfig as TreeConfig,
    tree_hash_circuit::{MerkleTreeCircuit, MerkleTreeCircuitParams},
};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Write,
};

pub type G16Proof = distributed_prover::util::G16Proof<E>;
pub type G16ProvingKey = distributed_prover::util::G16ProvingKey<E>;
pub type G16Com = distributed_prover::util::G16Com<E>;
pub type G16ComRandomness = distributed_prover::util::G16ComRandomness<E>;
pub type AggProof = Proof<E>;

pub type Stage0Request = distributed_prover::coordinator::Stage0Request<Fr>;

pub type Stage0RequestRef<'a> = distributed_prover::coordinator::Stage0RequestRef<'a, Fr>;

pub type Stage1Request =
    distributed_prover::coordinator::Stage1Request<TreeConfig, Fr, MerkleTreeCircuit>;

pub type Stage1RequestRef<'a> =
    distributed_prover::coordinator::Stage1RequestRef<'a, TreeConfig, Fr, MerkleTreeCircuit>;

pub type Stage0Response = distributed_prover::worker::Stage0Response<E>;

pub type Stage1Response = distributed_prover::worker::Stage1Response<E>;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKeys {
    // The parameters of the circuit being proved
    pub circ_params: MerkleTreeCircuitParams,
    // First leaf circuit PK
    pub first_leaf_pk: Option<G16ProvingKey>,
    // Second leaf circuit PK
    pub second_leaf_pk: Option<G16ProvingKey>,
    // Padding circuit PK
    pub padding_pk: Option<G16ProvingKey>,
    // Root Circuit PK
    pub root_pk: Option<G16ProvingKey>,
    // Second to last parent pk
    pub parent_pk: Option<G16ProvingKey>,
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

impl<'a> CanonicalSerialize for &'a ProvingKeys {
    #[inline]
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.circ_params
            .serialize_with_mode(&mut writer, compress)?;
        self.first_leaf_pk
            .serialize_with_mode(&mut writer, compress)?;
        self.second_leaf_pk
            .serialize_with_mode(&mut writer, compress)?;
        self.padding_pk.serialize_with_mode(&mut writer, compress)?;
        self.root_pk.serialize_with_mode(&mut writer, compress)?;
        self.parent_pk.serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        self.circ_params.serialized_size(compress)
            + self.first_leaf_pk.serialized_size(compress)
            + self.second_leaf_pk.serialized_size(compress)
            + self.padding_pk.serialized_size(compress)
            + self.root_pk.serialized_size(compress)
            + self.parent_pk.serialized_size(compress)
    }
}
