/*use std::fmt::{Display};
use std::marker::PhantomData;
use crate::{portal_manager::{PortalManager, SetupPortalManager}, util::log2, CircuitWithPortals, RomTranscriptEntry, sparse_tree};

use ark_crypto_primitives::crh::sha256::{digest::Digest};
use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{alloc::AllocVar, bits::{ToBitsGadget}, eq::EqGadget};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::UInt8;
use ark_r1cs_std::uint64::UInt64;
use ark_relations::{ns, r1cs::{ConstraintSystemRef, SynthesisError}};
use ark_relations::r1cs::ConstraintSystem;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{random, Rng};
use crate::sparse_tree::{CompoundUpdate, hash, InnerHash, MerkleIndex, MerkleTreeParameters, MerkleTreePath, NodeType, SparseMerkleTree, TreeUpdate};
// use crate::sparse_tree_constraints::MerkleTreePathVar;
use crate::tree_hash_circuit::{digest_to_fpvar, fpvar_to_digest};


// Very high-level it seems VerifiableKeyDirectoryCircuit takes arguments for an initial root and final root and one update
// It checks that the updates actually end us up with that final tree
#[derive(Clone)]
pub struct VerifiableKeyDirectoryCircuit<P: MerkleTreeParameters> {
    pub(crate) initial_root: InnerHash,
    pub(crate) params: VerifiableKeyDirectoryCircuitParams,
    pub(crate) final_root: InnerHash,
    pub(crate) update: Vec<TreeOperation<P>>,
}

// Enum to represent different tree operations
#[derive(Clone)]
pub enum TreeOperation<P: MerkleTreeParameters> {
    Append(VkdAppendOperation<P>),
    Deepen(VkdDeepenOperation<P>),
}

// TODO: make sure path and merkle_index have the same length
/*
Overview:
    - Struct is for adding a leaf to an empty node to the tree.
    - We also need to make sure that the index provided is already empty.
    - Empty node values are part of public parameter.
 */
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct VkdAppendOperation<P: MerkleTreeParameters> {
    // It's important merkle index has two uses, one to construct a tree where we do arithmetic operation and path verification
    // where the index is treated as a vector of boolean values, since we cannot serialise BigUint instead we model it as bool vector
    pub(crate) merkle_index: Vec<bool>,
    pub(crate) leaf: [u8; 32],
    pub(crate) path: MerkleTreePath<P>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct VkdDeepenOperation<P: MerkleTreeParameters> {
    pub(crate) merkle_index: Vec<bool>,
    pub(crate) leaf: [u8; 32],
    pub(crate) path: MerkleTreePath<P>,
}


impl<P: MerkleTreeParameters> Default for VkdAppendOperation<P> {
    fn default() -> Self {
        VkdAppendOperation {
            merkle_index: Vec::default(),
            leaf: [0u8; 32],
            path: MerkleTreePath::default(),
        }
    }
}

impl<P: MerkleTreeParameters> Default for VkdDeepenOperation<P> {
    fn default() -> Self {
        VkdDeepenOperation {
            merkle_index: Vec::default(),
            leaf: [0u8; 32],
            path: MerkleTreePath::default(),
        }
    }
}


#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableKeyDirectoryCircuitParams {
    /// Number of outgoing portal wires at each node
    pub(crate) num_portals_per_subcircuit: usize,
    /// Tree depth
    pub(crate) depth: usize,
    /// Num of updates
    pub(crate) num_of_updates: usize,
    /// Chunk size
    pub(crate) chunk_size: usize,
}


impl Display for VerifiableKeyDirectoryCircuitParams {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "[cs={},np={}, depth={}, nu={}]",
            self.chunk_size,
            self.num_portals_per_subcircuit,
            self.depth,
            self.num_of_updates
        )
    }
}

impl<P: MerkleTreeParameters> VerifiableKeyDirectoryCircuit<P> {
    pub fn rand(params: &VerifiableKeyDirectoryCircuitParams) -> Result<Self, Error> {
        let mut tree = SparseMerkleTree::new(&[0u8; 32], &()).unwrap();
        let mut t = SparseMerkleTree::new(&[0u8; 32], &()).unwrap();

        let initial_root = tree.root.clone();
        // generate random updates
        let mut updates: Vec<TreeOperation<P>> = Vec::new();
        for _ in 0..params.num_of_updates {
            let leaf = random::<[u8; 32]>();
            let u = tree.update(&leaf).unwrap();
            match u {
                TreeUpdate::SimpleUpdate(s) => {
                    t.update(&leaf).expect("TODO: panic message");
                    // do the simple update for t
                    let path = tree.lookup_path(&s.index).unwrap();
                    updates.push(TreeOperation::Append(VkdAppendOperation {
                        merkle_index: s.index.to_bit_vector(),
                        leaf: <[u8; 32]>::try_from(s.leaf).unwrap(),
                        path,
                    }));
                }
                TreeUpdate::CompoundUpdate(c) => {
                    let d = c.deepen_update;

                    updates.push(TreeOperation::Deepen(VkdDeepenOperation {
                        merkle_index: d.previous_index.to_bit_vector(),
                        leaf: <[u8; 32]>::try_from(d.leaf).unwrap(),
                        path: MerkleTreePath { path: d.previous_path, _parameters: PhantomData },
                    }));

                    let s = t.simple_update(&d.update.leaf, &d.update.leaf_h, d.min_depth).expect(" ");
                    let path = t.lookup_path(&s.index).unwrap();
                    updates.push(TreeOperation::Append(VkdAppendOperation {
                        merkle_index: s.index.to_bit_vector(),
                        leaf: <[u8; 32]>::try_from(s.leaf).unwrap(),
                        path,
                    }));

                    let s = t.simple_update(&c.simple_update.leaf, &c.simple_update.leaf_h, d.min_depth).expect(" ");
                    let path = tree.lookup_path(&s.index).unwrap();
                    updates.push(TreeOperation::Append(VkdAppendOperation {
                        merkle_index: s.index.to_bit_vector(),
                        leaf: <[u8; 32]>::try_from(s.leaf).unwrap(),
                        path,
                    }));
                }
            }
        }

        // get the final tree by updates
        Ok(VerifiableKeyDirectoryCircuit {
            initial_root,
            params: params.clone(),
            final_root: tree.root.clone(),
            update: updates,
        })
    }

    pub fn verify(&self, sparse_initial_hashes: Vec<InnerHash>) -> Result<bool, Error> {
        // TODO: Throw an appropriate error
        if self.update.len() != self.params.num_of_updates {
            // return Err(Box::new(Error::LeafIndex(0)));
        }
        let mut res = true;
        // compute the final root wrt updates and check if it's equal to the supposed one
        let mut root = self.initial_root;
        for u in self.update.iter() {
            match u {
                TreeOperation::Deepen(op) => {
                    res = res & op.path.verify(&root, &op.leaf, &op.merkle_index, &(), NodeType::Leaf).unwrap();
                    println!("mf 1  {}", op.path.verify(&root, &op.leaf, &op.merkle_index, &(), NodeType::Leaf).unwrap());
                }
                TreeOperation::Append(op) => {
                    // the previous leaf is null
                    let null_leaf = sparse_initial_hashes[op.path.path.len()];
                    res = res & op.path.verify(&root, &null_leaf, &op.merkle_index, &(), NodeType::InternalNode).unwrap();
                    eprintln!("mf 2 {}", op.path.verify(&root, &null_leaf, &op.merkle_index, &(), NodeType::InternalNode).unwrap());
                    // the root is correctly updated
                    root = op.path.compute_root(&op.leaf, &op.merkle_index, &(), NodeType::Leaf).unwrap();
                }
            }
        }
        println!("{}", root == self.final_root);
        println!("{}", res);
        Ok(res & (root == self.final_root))
    }
}

/*
// TODO: assert everywhere that num_subcircuits = num_of_updates + 1
// InnerHash <====> UInt8 <==digest_to_fpvar==> FpVar
impl<F: PrimeField, Params: MerkleTreeParameters> CircuitWithPortals<F> for VerifiableKeyDirectoryCircuit<Params> {
    type Parameters = VerifiableKeyDirectoryCircuitParams;

    fn get_params(&self) -> VerifiableKeyDirectoryCircuitParams {
        self.params
    }

    // This produces the same portal trace as generate_constraints(0...num_circuits) would do, but
    // without having to do all the ZK SHA2 computations
    fn get_portal_subtraces(&self) -> SetupPortalManager<F> {
        // Make a portal manager to collect the subtraces
        let cs = ConstraintSystem::new_ref();
        let mut pm = SetupPortalManager::new(cs.clone());
        // Iterate all update subcircuits
        for (subcircuit_idx, u) in self.update.iter().enumerate() {
            pm.start_subtrace(ConstraintSystem::new_ref());
            // compute the next_root, pad it, witness it as DigestVar and convert it to FpVar
            let next_root = u.path.compute_root_from_internal_nodes(&u.final_value, u.merkle_index, &()).unwrap();
            let root_var = UInt8::new_witness_vec(ns!(cs, "next root"), &next_root).unwrap();
            let root_fpvar = digest_to_fpvar(DigestVar(root_var)).unwrap();
            // Set the value
            let _ = pm.set(format!("root {subcircuit_idx}"), &root_fpvar).unwrap();
            println!("here: root {}", subcircuit_idx);
        }
        // We don't compute any portal wires for the equality circuit
        pm
    }

    /*
        Here we have two types of circuits:
            * update circuit     ==>    These circuits on a root and an update, verify if the update is valid
                                        and output the next root

            Update circuits take indices 0 to num_of_updates - 1 and quality circuit takes index num_of_updates

            * equality circuit   ==>    This circuit check the root from the last update circuit is equal to
                                        the supposed value
        So naturally we will have num_subcircuits = num_of_updates + 1
        The indexing starts from 0 ==> first update is subcircuit 0 etc.
    */

    fn num_subcircuits(&self) -> usize {
        self.params.num_of_updates + 1
    }

    // Make a new empty VKD
    fn new(&params: &Self::Parameters) -> Self {
        VerifiableKeyDirectoryCircuit {
            initial_root: InnerHash::default(),
            params,
            final_root: InnerHash::default(),
            update: Vec::new(),
        }
    }

    fn get_serialized_witnesses(&self, subcircuit_idx: usize) -> Vec<u8> {
        let num_subcircuits = <Self as CircuitWithPortals<F>>::num_subcircuits(&self);
        let mut out_buf = Vec::new();
        // determine the type of subcircuit
        let is_update = subcircuit_idx < num_subcircuits - 1;
        let is_root = subcircuit_idx == num_subcircuits - 1;

        if is_update {
            self.update[subcircuit_idx].serialize_uncompressed(&mut out_buf).unwrap();
        }
        if is_root {
            // TODO: Is this actually a witness? It's pp! I'm a bit lost
            // TODO: One option is to return None and in set_serialized_witnesses,just ignore it
            self.final_root.serialize_uncompressed(&mut out_buf).unwrap();
        }
        // return the output buffer
        out_buf
    }

    fn set_serialized_witnesses(&mut self, subcircuit_idx: usize, bytes: &[u8]) {
        // determine the type of subcircuit
        let num_subcircuits = <Self as CircuitWithPortals<F>>::num_subcircuits(&self);
        let is_update = subcircuit_idx < num_subcircuits - 1;
        let is_root = subcircuit_idx == num_subcircuits - 1;

        // TODO: if indexing changes, make sure to correct them for the vector of updates too
        if is_update {
            let update = VkdUpdate::deserialize_uncompressed_unchecked(bytes).unwrap();
            self.update[subcircuit_idx] = update;
        }
        if is_root {
            self.final_root = InnerHash::deserialize_uncompressed_unchecked(bytes).unwrap();
        }
    }

    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError> {
        let starting_num_constraints = cs.num_constraints();
        // determine the type of subcircuit
        let num_subcircuits = <Self as CircuitWithPortals<F>>::num_subcircuits(&self);
        let is_update = subcircuit_idx < num_subcircuits - 1;
        let is_root = subcircuit_idx == num_subcircuits - 1;
        println!("{} {} {} {}", is_root, is_update, subcircuit_idx, num_subcircuits);

        if is_update {
            // get the initial root and verify the path and initial leaf
            let initial_root_fpvar: FpVar<F>;
            // if subcircuit_idx = 0, then it's a public input otherwise get if from pm
            if subcircuit_idx != 0 {
                initial_root_fpvar = pm.get(&format!("root {subcircuit_idx}"))?;
            } else {
                let root_var = UInt8::new_witness_vec(ns!(cs, "next root"), &self.initial_root).unwrap();
                initial_root_fpvar = digest_to_fpvar(DigestVar(root_var)).unwrap();
            }

            // get the current update
            let u = &self.update[subcircuit_idx];

            // add path as private input
            let path_var = MerkleTreePathVar::<Params, F>::new_witness(ns!(cs, "path"), || Ok(&u.path)).unwrap();

            // add initial value and final value as private input
            let initial_value_var = UInt8::new_witness_vec(ns!(cs, "value"), &u.initial_value).unwrap();
            let initial_value_fpvar = digest_to_fpvar(DigestVar(initial_value_var)).unwrap();
            let final_value_var = UInt8::new_witness_vec(ns!(cs, "value"), &u.final_value).unwrap();
            let final_value_fpvar = digest_to_fpvar(DigestVar(final_value_var)).unwrap();

            // add merkle index as private input
            let index_var = UInt64::<F>::new_witness(ns!(cs, "index"), || Ok(&u.merkle_index)).unwrap();

            // set the final root to the portal manager
            let final_root = u.path.compute_root_from_internal_nodes(&u.final_value, u.merkle_index, &()).unwrap();
            let root_var = UInt8::new_witness_vec(ns!(cs, "next root"), &final_root).unwrap();
            let final_root_fpvar = digest_to_fpvar(DigestVar(root_var)).unwrap();
            // TODO: get this actually right
            //let _ = pm.set(format!("root {subcircuit_idx}"), &final_root_fpvar).unwrap();

            // initial path is valid
            path_var.check_path_from_internal_node(
                &initial_root_fpvar,
                &initial_value_fpvar,
                &index_var,
                &(),
            ).unwrap();
            // final path is valid
            path_var.check_path_from_internal_node(
                &final_root_fpvar,
                &final_value_fpvar,
                &index_var,
                &(),
            ).unwrap();
        }

        if is_root {
            // get the expected_root_fpvar
            let final_root_var = UInt8::new_witness_vec(ns!(cs, "next root"), &self.final_root).unwrap();
            let final_root_fpvar = digest_to_fpvar(DigestVar(final_root_var)).unwrap();
            // get the computed_root from portal manager
            let id = subcircuit_idx - 1;
            let initial_root_fpvar = pm.get(&format!("root {id}"))?;
            // check the equality
            initial_root_fpvar.enforce_equal(&final_root_fpvar)?;
        }

        // Print out how big this circuit was
        let ending_num_constraints = cs.num_constraints();
        println!("Test subcircuit {subcircuit_idx} costs {} constraints",
                 ending_num_constraints - starting_num_constraints
        );


        Ok(())
    }
}
 */


#[cfg(test)]
mod tests {
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use rand::random;
    use ark_bls12_381::{Fq};
    use crate::CircuitWithPortals;
    use crate::portal_manager::SetupPortalManager;
    use crate::sparse_tree::{hash_inner_node, hash_leaf, MerkleIndex, MerkleTreeParameters, SparseMerkleTree};
    use crate::tree_hash_circuit::MerkleTreeCircuit;
    use crate::verifiable_key_directory::{VerifiableKeyDirectoryCircuit, VerifiableKeyDirectoryCircuitParams};

    #[test]
    fn test_vkd_circuit() {
        #[derive(Clone)]
        pub struct MerkleTreeTestParameters;
        impl MerkleTreeParameters for MerkleTreeTestParameters {
            const DEPTH: usize = 256;
            const CHUNK_SIZE: usize = 8;
        }

        let mut sparse_initial_hashes = vec![hash_leaf(&[0u8; 32]).unwrap()];
        for i in 1..=MerkleTreeTestParameters::DEPTH {
            let child_hash = sparse_initial_hashes[i - 1].clone();
            sparse_initial_hashes.push(hash_inner_node(&child_hash, &child_hash).unwrap());
        }
        sparse_initial_hashes.reverse();

        let vkd_params = VerifiableKeyDirectoryCircuitParams {
            num_portals_per_subcircuit: 1,
            depth: 256,
            num_of_updates: 256,
            chunk_size: 8,
        };
        let vkd = VerifiableKeyDirectoryCircuit::<MerkleTreeTestParameters>::rand(&vkd_params).unwrap();
        assert!(vkd.verify(sparse_initial_hashes).unwrap());
    }

    /*
        #[test]
        fn test_vkd_subcircuit() {
            #[derive(Clone)]
            pub struct MerkleTreeTestParameters;
            impl MerkleTreeParameters for MerkleTreeTestParameters {
                const DEPTH: MerkleDepth = 16;
            }

            let vkd_params = VerifiableKeyDirectoryCircuitParams {
                max_depth: 32_u8,
                num_portals_per_subcircuit: 1,
                depth: 16,
                num_of_updates: 3,
            };

            // Make a random VKD
            let mut vkd: VerifiableKeyDirectoryCircuit<MerkleTreeTestParameters> = VerifiableKeyDirectoryCircuit::rand(&vkd_params).unwrap();

            // Make a fresh portal manager
            let cs = ConstraintSystem::<Fq>::new_ref();
            let mut pm = vkd.get_portal_subtraces();

            let num_subcircuits = <VerifiableKeyDirectoryCircuit<MerkleTreeTestParameters> as CircuitWithPortals<Fr>>::num_subcircuits(&vkd);
            for subcircuit_idx in 0..num_subcircuits {
                vkd.generate_constraints(cs.clone(), subcircuit_idx, &mut pm)
                    .unwrap();
            }

            assert!(cs.is_satisfied().unwrap());
        }
     */
}


 */





