use crate::{
    portal_manager::{PortalManager, SetupPortalManager},
    sparse_tree,
    util::log2,
    CircuitWithPortals, RomTranscriptEntry,
};
use std::fmt::Display;

use crate::sparse_tree::{
    InnerHash, MerkleDepth, MerkleIndex, MerkleTreeParameters, MerkleTreePath, SparseMerkleTree,
};
use crate::sparse_tree_constraints::MerkleTreePathVar;
use crate::tree_hash_circuit::{digest_to_fpvar, left_child, right_child};
use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_crypto_primitives::crh::sha256::digest::Digest;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::UInt8;
use ark_r1cs_std::uint64::UInt64;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{alloc::AllocVar, bits::ToBitsGadget, eq::EqGadget};
use ark_relations::r1cs::ConstraintSystem;
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{random, Rng};
use sha2::Sha256;

// Very high-level it seems VerifiableKeyDirectoryCircuit takes arguments for an initial root and final root and one update
// It checks that the updates actually end us up with that final tree
#[derive(Clone)]
pub struct VerifiableKeyDirectoryCircuit<P: MerkleTreeParameters> {
    pub(crate) initial_root: InnerHash,
    pub(crate) params: VerifiableKeyDirectoryCircuitParams,
    pub(crate) final_root: InnerHash,
    pub(crate) update: Update<P>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Update<P: MerkleTreeParameters> {
    pub(crate) merkle_index: MerkleIndex,
    pub(crate) initial_leaf: [u8; 32],
    pub(crate) final_leaf: [u8; 32],
    pub(crate) path: MerkleTreePath<P>,
}

impl<P: MerkleTreeParameters> Default for Update<P> {
    fn default() -> Self {
        Update {
            merkle_index: MerkleIndex::default(),
            initial_leaf: InnerHash::default(),
            final_leaf: InnerHash::default(),
            path: MerkleTreePath::default(),
        }
    }
}

#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableKeyDirectoryCircuitParams {
    /// get parameters for the MerkleTree
    pub(crate) max_depth: u8,
    /// Number of times to iterate SHA256 at each node
    pub(crate) num_sha_iters_per_subcircuit: usize,
    /// Number of outgoing portal wires at each node
    pub(crate) num_portals_per_subcircuit: usize,
    /// Tree depth
    pub(crate) depth: MerkleDepth,
}

impl Display for VerifiableKeyDirectoryCircuitParams {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "[md={},ns={},np={}, depth={}]",
            self.max_depth,
            self.num_sha_iters_per_subcircuit,
            self.num_portals_per_subcircuit,
            self.depth
        )
    }
}

impl<P: MerkleTreeParameters> VerifiableKeyDirectoryCircuit<P> {
    pub fn rand(params: &VerifiableKeyDirectoryCircuitParams) -> Result<Self, Error> {
        // generate the initial tree from a random bytes
        let mut tree = SparseMerkleTree::new(&[0u8; 32], &()).unwrap();
        // generate an update
        let initial_leaf = random::<[u8; 32]>();
        tree.update(177, &initial_leaf).expect("panic message");
        // for some reason I like index 177
        let path = tree.lookup(177).unwrap();
        let initial_root = tree.root.clone();
        // generate the new leaf and update the tree
        let final_leaf = random::<[u8; 32]>();
        tree.update(177, &final_leaf).expect("panic message");
        // get the final tree by updates
        Ok(VerifiableKeyDirectoryCircuit {
            initial_root,
            params: params.clone(),
            final_root: tree.get_root()?,
            update: Update {
                merkle_index: 177,
                initial_leaf,
                final_leaf,
                path,
            },
        })
    }

    pub fn verify(&self) -> bool {
        let update = &self.update;
        let initial_root = self.initial_root;
        let final_root = self.final_root;
        let con1 = update
            .path
            .verify(
                &initial_root,
                &update.initial_leaf,
                update.merkle_index,
                &(),
            )
            .expect("TODO: panic message");
        let con2 = update
            .path
            .verify(&final_root, &update.final_leaf, update.merkle_index, &())
            .expect("TODO: panic message");
        con1 & con2
    }
}

impl<F: PrimeField, Params: MerkleTreeParameters> CircuitWithPortals<F>
    for VerifiableKeyDirectoryCircuit<Params>
{
    type Parameters = VerifiableKeyDirectoryCircuitParams;

    fn get_params(&self) -> VerifiableKeyDirectoryCircuitParams {
        self.params
    }

    // This produces the same portal trace as generate_constraints(0...num_circuits) would do, but
    // without having to do all the ZK SHA2 computations
    fn get_portal_subtraces(&self) -> Vec<Vec<RomTranscriptEntry<F>>> {
        Vec::new()
    }

    fn num_subcircuits(&self) -> usize {
        1
    }

    // Make a new empty VKD
    fn new(&params: &Self::Parameters) -> Self {
        VerifiableKeyDirectoryCircuit {
            initial_root: InnerHash::default(),
            params,
            final_root: InnerHash::default(),
            update: Update::default(),
        }
    }

    fn get_serialized_witnesses(&self, subcircuit_idx: usize) -> Vec<u8> {
        let mut out_buf = Vec::new();
        // The witness here is the vector of updates
        self.update.serialize_uncompressed(&mut out_buf).unwrap();
        out_buf
    }

    fn set_serialized_witnesses(&mut self, subcircuit_idx: usize, bytes: &[u8]) {
        // simply deserialize bytes into the vector of updates for the VKD instance
        let update = Update::deserialize_uncompressed_unchecked(bytes).unwrap();
        self.update = update;
    }

    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError> {
        // since we only have one circuit right now, we don't call portal manager to set/get wires
        let starting_num_constraints = cs.num_constraints();

        // add initial root and final root as public inputs
        let initial_root_var =
            DigestVar::new_input(ns!(cs, "root"), || Ok(self.initial_root.to_vec())).unwrap();
        let final_root_var =
            DigestVar::new_input(ns!(cs, "root"), || Ok(self.final_root.to_vec())).unwrap();

        // add path as private input
        let path_var =
            MerkleTreePathVar::<Params, F>::new_witness(ns!(cs, "path"), || Ok(&self.update.path))
                .unwrap();

        // add initial leaf and final leaf as private input
        let initial_leaf_var =
            Vec::<UInt8<F>>::new_witness(ns!(cs, "leaf"), || Ok(self.update.initial_leaf)).unwrap();
        let final_leaf_var =
            Vec::<UInt8<F>>::new_witness(ns!(cs, "leaf"), || Ok(self.update.final_leaf)).unwrap();

        // add merkle index as private input
        let index_var =
            UInt64::<F>::new_witness(ns!(cs, "index"), || Ok(self.update.merkle_index)).unwrap();

        // initial path is valid
        path_var
            .check_path(&initial_root_var, &initial_leaf_var, &index_var, &())
            .unwrap();
        // final path is valid
        path_var
            .check_path(&final_root_var, &final_leaf_var, &index_var, &())
            .unwrap();

        // Print out how big this circuit was
        let ending_num_constraints = cs.num_constraints();
        println!(
            "Test subcircuit {subcircuit_idx} costs {} constraints",
            ending_num_constraints - starting_num_constraints
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::portal_manager::SetupPortalManager;
    use crate::sparse_tree::{MerkleDepth, MerkleTreeParameters};
    use crate::tree_hash_circuit::MerkleTreeCircuit;
    use crate::verifiable_key_directory::{
        VerifiableKeyDirectoryCircuit, VerifiableKeyDirectoryCircuitParams,
    };
    use crate::CircuitWithPortals;
    use ark_bls12_381::{Fq, Fr};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    #[test]
    fn test_vkd_circuit() {
        #[derive(Clone)]
        pub struct MerkleTreeTestParameters;
        impl MerkleTreeParameters for MerkleTreeTestParameters {
            const DEPTH: MerkleDepth = 63;
        }

        let vkd_params = VerifiableKeyDirectoryCircuitParams {
            max_depth: 64_u8,
            num_sha_iters_per_subcircuit: 1,
            num_portals_per_subcircuit: 1,
            depth: 63,
        };
        let vkd: VerifiableKeyDirectoryCircuit<MerkleTreeTestParameters> =
            VerifiableKeyDirectoryCircuit::rand(&vkd_params).unwrap();
        assert!(vkd.verify());
    }

    #[test]
    fn test_vkd_subcircuit() {
        #[derive(Clone)]
        pub struct MerkleTreeTestParameters;
        impl MerkleTreeParameters for MerkleTreeTestParameters {
            const DEPTH: MerkleDepth = 63;
        }

        let vkd_params = VerifiableKeyDirectoryCircuitParams {
            max_depth: 64_u8,
            num_sha_iters_per_subcircuit: 1,
            num_portals_per_subcircuit: 1,
            depth: 63,
        };

        // Make a random VKD
        let mut vkd: VerifiableKeyDirectoryCircuit<MerkleTreeTestParameters> =
            VerifiableKeyDirectoryCircuit::rand(&vkd_params).unwrap();

        // Make a fresh portal manager
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut pm = SetupPortalManager::new(cs.clone());

        // Make it all one subtrace. We're not really testing this part
        pm.start_subtrace(cs.clone());

        let num_subcircuits = <VerifiableKeyDirectoryCircuit<MerkleTreeTestParameters> as CircuitWithPortals<Fr>>::num_subcircuits(&vkd);
        for subcircuit_idx in 0..num_subcircuits {
            vkd.generate_constraints(cs.clone(), subcircuit_idx, &mut pm)
                .unwrap();
        }

        assert!(cs.is_satisfied().unwrap());
    }
}
