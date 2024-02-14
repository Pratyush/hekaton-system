use std::collections::HashMap;
use std::marker::PhantomData;
use crate::{portal_manager::{PortalManager, SetupPortalManager}, util::log2, CircuitWithPortals, RomTranscriptEntry, sparse_tree};

use ark_crypto_primitives::crh::sha256::{
    constraints::{DigestVar, Sha256Gadget},
    digest::Digest,
    Sha256,
};
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{boolean::Boolean, uint8::UInt8, ToBitsGadget},
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{random, Rng};
use crate::sparse_tree::{MerkleIndex, MerkleTreeParameters, SparseMerkleTree};
use crate::tree_hash_circuit::{calculate_root, digest_to_fpvar, left_child, MerkleTreeCircuit, MerkleTreeCircuitParams, right_child, TestLeaf};

// Very high-level it seems VerifiableKeyDirectoryCircuit takes arguments for an initial tree and final tree and some updates
// It's check that those updates actually end us up with that final tree
#[derive(Clone)]
pub struct VerifiableKeyDirectoryCircuit<P: MerkleTreeParameters> {
    pub(crate) initial_tree: SparseMerkleTree<P>,
    pub(crate) params: VerifiableKeyDirectoryCircuitParams,
    pub(crate) final_tree: SparseMerkleTree<P>,
    pub(crate) updates: Vec<(MerkleIndex, [u8; 32])>,
}

#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableKeyDirectoryCircuitParams {
    /// get parameters for the MerkleTree
    pub(crate) max_depth: u8,
    /// Number of times to iterate SHA256 at each node
    pub(crate) num_sha_iters_per_subcircuit: usize,
    /// Number of outgoing portal wires at each node
    pub(crate) num_portals_per_subcircuit: usize,
    /// Number of updates
    pub(crate) num_updates: usize,
}

impl std::fmt::Display for VerifiableKeyDirectoryCircuitParams {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "[md={}, nu={},ns={},np={}]",
            self.max_depth,
            self.num_updates,
            self.num_sha_iters_per_subcircuit,
            self.num_portals_per_subcircuit
        )
    }
}

impl<P: MerkleTreeParameters> VerifiableKeyDirectoryCircuit<P> {
    /// Makes a Merkle tree with a random set of leaves. The size is given by `params`
    pub fn rand(params: &VerifiableKeyDirectoryCircuitParams) -> Result<Self, Error> {
        // set the parameters
        let p = params.clone();
        // generate the initial tree from a random bytes
        let random_bytes = random::<[u8; 32]>();
        let initial_tree = SparseMerkleTree::new(&random_bytes, &()).unwrap();
        // define the final tree which is updates at each step too, it's also possible to clone
        let mut final_tree = SparseMerkleTree::new(&random_bytes, &()).unwrap();
        // generate a vector of updates
        let mut updates: Vec<(MerkleIndex, [u8; 32])> = Vec::new();
        // generate random elements in each iteration
        for _ in 0..params.num_updates {
            // generate random index and leaf
            let random_u64: u64 = random::<u32>() as u64;
            let random_u8_array = random::<[u8; 32]>();
            final_tree.update(random_u64, &random_u8_array).expect("TODO: panic message");
            updates.push((random_u64, random_u8_array));
        }
        // get the final tree by updates
        Ok(VerifiableKeyDirectoryCircuit {
            initial_tree,
            params: p,
            final_tree,
            updates,
        })
    }
}

/*
impl<F: PrimeField, Params: MerkleTreeParameters> CircuitWithPortals<F> for VerifiableKeyDirectoryCircuit<Params> {
    type Parameters = VerifiableKeyDirectoryCircuitParams;

    fn get_params(&self) -> VerifiableKeyDirectoryCircuitParams {
        self.params
    }

    fn get_portal_subtraces(&self) -> Vec<Vec<RomTranscriptEntry<F>>> {
        Vec::new()
        //TODO
    }

    fn num_subcircuits(&self) -> usize {
        1
        //TODO
    }

    // Make a new empty merkle tree circuit
    fn new(&params: &Self::Parameters) -> Self {
        //TODO
        Self
    }

    fn get_serialized_witnesses(&self, subcircuit_idx: usize) -> Vec<u8> {
        Vec::new()
        //TODO
    }

    fn set_serialized_witnesses(&mut self, subcircuit_idx: usize, bytes: &[u8]) {
        //TODO
    }

    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

 */

#[cfg(test)]
mod tests {
    use rand::random;
    use crate::CircuitWithPortals;
    use crate::sparse_tree::{MerkleDepth, MerkleTreeParameters};
    use crate::vkd::{VerifiableKeyDirectoryCircuit, VerifiableKeyDirectoryCircuitParams};

    #[test]
    fn test_vkd_circuit() {
        #[derive(Clone)]
        pub struct MerkleTreeTestParameters;
        impl MerkleTreeParameters for MerkleTreeTestParameters {
            const DEPTH: MerkleDepth = 63;
        }

        let vkd_params = VerifiableKeyDirectoryCircuitParams {
            max_depth: 63_u8,
            num_sha_iters_per_subcircuit: 1,
            num_portals_per_subcircuit: 1,
            num_updates: 10,
        };
        let vkd: VerifiableKeyDirectoryCircuit<MerkleTreeTestParameters> = VerifiableKeyDirectoryCircuit::rand(&vkd_params).unwrap();
        let mut initial_tree = vkd.initial_tree;
        let updates = vkd.updates;
        for i in 0..vkd_params.num_updates {
            // generate random index and leaf
            initial_tree.update(updates[i].0, &updates[i].1).expect("TODO: panic message");
        }
        assert_eq!(initial_tree.root, vkd.final_tree.root);
    }
}



