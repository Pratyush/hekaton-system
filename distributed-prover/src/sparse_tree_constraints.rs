use ark_relations::r1cs::{SynthesisError, Namespace, ConstraintSystemRef};
use ark_r1cs_std::{prelude::*, uint64::UInt64};

use ark_crypto_primitives::crh::sha256::{constraints::{DigestVar, Sha256Gadget}, digest::Digest};
use ark_ff::PrimeField;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{boolean::Boolean, uint8::UInt8, ToBitsGadget},
    eq::EqGadget,
    fields::fp::FpVar,
};


use crate::{sparse_tree::{MerkleTreeParameters, MerkleTreePath}};

use std::{borrow::Borrow, marker::PhantomData};
use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_relations::ns;
use ark_std::iterable::Iterable;
use ark_bls12_381::{Fq};
use crate::sparse_tree::{InnerHash, MerkleDepth};
use crate::tree_hash_circuit::{digest_to_fpvar, fpvar_to_digest};

#[derive(Clone)]
pub struct MerkleTreePathVar<P, F> where P: MerkleTreeParameters, F: PrimeField, {
    path: Vec<FpVar<F>>,
    _parameters: PhantomData<P>,
}

// TODO: If we'd like to support depth of more than 64, we need to have an array of UInt64 for merkle index
impl<P, F> MerkleTreePathVar<P, F>
    where
        P: MerkleTreeParameters,
        F: PrimeField,
{
    pub fn compute_root_var_from_leaf(
        &self,
        leaf: &Vec<UInt8<F>>,
        index: &UInt64<F>,
        hash_parameters: &(),
    ) -> Result<FpVar<F>, SynthesisError> {
        let mut current_hash = hash_leaf_var::<F>(
            hash_parameters,
            leaf,
        )?;
        for (i, b) in index
            .to_bits_le()
            .iter()
            .take(P::DEPTH as usize)
            .enumerate()
        {
            let lc = FpVar::conditionally_select(
                b,
                &self.path[i],
                &current_hash,
            )?;
            let rc = FpVar::conditionally_select(
                b,
                &current_hash,
                &self.path[i],
            )?;
            current_hash = hash_inner_node_var::<F>(
                hash_parameters,
                &lc,
                &rc,
            )?;
        }
        Ok(current_hash)
    }

    pub fn compute_root_var_from_internal_node(
        &self,
        internal_node: &FpVar<F>,
        index: &UInt64<F>,
        hash_parameters: &(),
    ) -> Result<FpVar<F>, SynthesisError> {
        let mut current_hash = internal_node.clone();
        for (i, b) in index
            .to_bits_le()
            .iter()
            .take(P::DEPTH as usize)
            .enumerate()
        {
            let lc = FpVar::conditionally_select(
                b,
                &self.path[i],
                &current_hash,
            )?;
            let rc = FpVar::conditionally_select(
                b,
                &current_hash,
                &self.path[i],
            )?;
            current_hash = hash_inner_node_var::<F>(
                hash_parameters,
                &lc,
                &rc,
            )?;
        }
        Ok(current_hash)
    }

    pub fn check_path_from_leaf(
        &self,
        root: &FpVar<F>,
        leaf: &Vec<UInt8<F>>,
        index: &UInt64<F>,
        hash_parameters: &(),
    ) -> Result<(), SynthesisError> {
        self.conditional_check_path_from_leaf(
            root,
            leaf,
            index,
            hash_parameters,
            &Boolean::constant(true),
        )
    }

    pub fn check_path_from_internal_node(
        &self,
        root: &FpVar<F>,
        internal_node: &FpVar<F>,
        index: &UInt64<F>,
        hash_parameters: &(),
    ) -> Result<(), SynthesisError> {
        self.conditional_check_path_from_internal_node(
            root,
            internal_node,
            index,
            hash_parameters,
            &Boolean::constant(true),
        )
    }

    pub fn conditional_check_path_from_leaf(
        &self,
        root: &FpVar<F>,
        leaf: &Vec<UInt8<F>>,
        index: &UInt64<F>,
        hash_parameters: &(),
        condition: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let computed_root = self.compute_root_var_from_leaf(
            leaf,
            index,
            hash_parameters,
        )?;
        root.conditional_enforce_equal(&computed_root, condition)
    }

    pub fn conditional_check_path_from_internal_node(
        &self,
        root: &FpVar<F>,
        internal_node: &FpVar<F>,
        index: &UInt64<F>,
        hash_parameters: &(),
        condition: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let computed_root = self.compute_root_var_from_internal_node(
            internal_node,
            index,
            hash_parameters,
        )?;
        root.conditional_enforce_equal(&computed_root, condition)
    }
}

pub fn hash_leaf_var<F>(parameters: &(), leaf: &Vec<UInt8<F>>) -> Result<FpVar<F>, SynthesisError> where F: PrimeField, {
    let mut digest = DigestVar(leaf.to_vec());
    let x = Sha256Gadget::digest(&digest.0).unwrap();
    digest_to_fpvar(x)
}

pub fn hash_inner_node_var<F>(
    parameters: &(),
    left: &FpVar<F>,
    right: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError>
    where
        F: PrimeField,
{
    // Convert the hashes back into bytes and concat them
    let left_bytes = fpvar_to_digest(left).unwrap();
    let right_bytes = fpvar_to_digest(right).unwrap();
    let contacted = [left_bytes, right_bytes]
        .concat()
        .into_iter()
        .collect::<Vec<_>>();
    // hash the result and return only the 31 first bytes
    let mut digest = DigestVar(contacted);
    let x = Sha256Gadget::digest(&digest.0).unwrap();
    digest_to_fpvar(x)
}

impl<P, F> AllocVar<MerkleTreePath<P>, F>
for MerkleTreePathVar<P, F>
    where
        P: MerkleTreeParameters,
        F: PrimeField,
{
    fn new_variable<T: Borrow<MerkleTreePath<P>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let mut vec = Vec::new();
        for value in f()?.borrow().path.iter() {
            let fp = inner_hash_to_fpvar(cs.clone(), value, mode);
            vec.push(fp?);
        }
        Ok(MerkleTreePathVar {
            path: vec,
            _parameters: PhantomData,
        })
    }
}

fn inner_hash_to_fpvar<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    digest: &InnerHash,
    mode: AllocationMode,
) -> Result<FpVar<F>, SynthesisError> {
    let fp = F::from_le_bytes_mod_order(digest);
    FpVar::new_variable(ns!(cs, "elem"), || Ok(fp), mode)
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use super::*;
    use crate::{
        sparse_tree::*,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use rand::{Rng, rngs::StdRng, SeedableRng};
    use ark_bls12_381::{Fq, Fr};

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 8;
    }

    type TestMerkleTree = SparseMerkleTree<MerkleTreeTestParameters>;

    // Parameters for Merkle Tree AVD with Poseidon hash
    #[derive(Clone)]
    pub struct PoseidonMerkleTreeTestParameters;

    impl MerkleTreeParameters for PoseidonMerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 8;
    }

    type PoseidonTestMerkleTree = SparseMerkleTree<PoseidonMerkleTreeTestParameters>;

    #[test]
    fn valid_path_constraints_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = ();
        let mut tree = TestMerkleTree::new(&[0u8; 16], &crh_parameters).unwrap();
        tree.update_leaf(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup_path(177, PoseidonMerkleTreeTestParameters::DEPTH).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate hash parameters
        let crh_parameters_var = ();

        // Allocate root
        let root_var = inner_hash_to_fpvar(cs.clone(), &tree.root, AllocationMode::Input).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(ns!(cs, "leaf"), || Ok([1_u8; 16])).unwrap();

        // Allocate index
        let index_var = UInt64::<Fq>::new_witness(ns!(cs, "index"), || Ok(177)).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::<MerkleTreeTestParameters, Fq>::new_witness(ns!(cs, "path"), || Ok(path)).unwrap();

        path_var.check_path_from_leaf(
            &root_var,
            &leaf_var,
            &index_var,
            &crh_parameters_var,
        ).unwrap();

        // hash the leaf to reach an internal node
        let internal_node = hash_leaf_var(&(), &leaf_var).unwrap();
        path_var.check_path_from_internal_node(
            &root_var,
            &internal_node,
            &index_var,
            &crh_parameters_var,
        ).unwrap();


        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn poseidon_valid_path_constraints_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        tree.update_leaf(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup_path(177, PoseidonMerkleTreeTestParameters::DEPTH).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();


        // Allocate root
        let root_var = inner_hash_to_fpvar(cs.clone(), &tree.root, AllocationMode::Input).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(ns!(cs, "leaf"), || Ok([1_u8; 16])).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(ns!(cs, "index"), || Ok(177)).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::new_witness(ns!(cs, "path"), || Ok(path)).unwrap();

        path_var.check_path_from_leaf(
            &root_var,
            &leaf_var,
            &index_var,
            &(),
        ).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn invalid_root_path_constraints_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        tree.update_leaf(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup_path(177, PoseidonMerkleTreeTestParameters::DEPTH).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate root
        let root_var = inner_hash_to_fpvar(cs.clone(), &[0_u8; 31], AllocationMode::Input).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(ns!(cs, "leaf"), || Ok([1_u8; 16].to_vec())).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(ns!(cs, "index"), || Ok(177)).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::new_witness(ns!(cs, "path"), || Ok(path)).unwrap();

        path_var.check_path_from_leaf(
            &root_var,
            &leaf_var,
            &index_var,
            &(),
        ).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn invalid_leaf_path_constraints_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        tree.update_leaf(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup_path(177, PoseidonMerkleTreeTestParameters::DEPTH).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate root
        let root_var = inner_hash_to_fpvar(cs.clone(), &tree.root, AllocationMode::Input).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(ns!(cs, "leaf"), || Ok([2_u8; 16])).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(ns!(cs, "index"), || Ok(177)).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::new_witness(ns!(cs, "path"), || Ok(path)).unwrap();

        path_var.check_path_from_leaf(
            &root_var,
            &leaf_var,
            &index_var,
            &(),
        ).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn invalid_index_path_constraints_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        tree.update_leaf(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup_path(177, PoseidonMerkleTreeTestParameters::DEPTH).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        let root_var = inner_hash_to_fpvar(cs.clone(), &tree.root, AllocationMode::Input).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(ns!(cs, "leaf"), || Ok([1_u8; 16])).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(ns!(cs, "index"), || Ok(176)).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::new_witness(ns!(cs, "path"), || Ok(path)).unwrap();

        path_var.check_path_from_leaf(
            &root_var,
            &leaf_var,
            &index_var,
            &(),
        ).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}