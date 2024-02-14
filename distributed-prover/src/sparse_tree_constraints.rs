use ark_relations::r1cs::{SynthesisError, Namespace, ConstraintSystemRef};
use ark_r1cs_std::{
    prelude::*,
    uint64::UInt64,
};

use ark_crypto_primitives::crh::sha256::{
    constraints::{DigestVar, Sha256Gadget},
    digest::Digest,
    Sha256,
};
use ark_ff::PrimeField;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{boolean::Boolean, uint8::UInt8, ToBitsGadget},
    eq::EqGadget,
    fields::fp::FpVar,
};


use crate::{
    sparse_tree::{MerkleTreeParameters, MerkleTreePath},
};

use std::{borrow::Borrow, marker::PhantomData};
use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_relations::ns;
use ark_bls12_381::{Fq, Fr};
use crate::sparse_tree::{InnerHash, MerkleDepth};
use crate::tree_hash_circuit::digest_to_fpvar;

#[derive(Clone)]
pub struct MerkleTreePathVar<P, ConstraintF>
    where
        P: MerkleTreeParameters,
        ConstraintF: PrimeField,
{
    path: Vec<DigestVar<ConstraintF>>,
    _parameters: PhantomData<P>,
}

impl<P, ConstraintF> MerkleTreePathVar<P, ConstraintF>
    where
        P: MerkleTreeParameters,
        ConstraintF: PrimeField,
{
    pub fn compute_root_var(
        &self,
        leaf: &Vec<UInt8<ConstraintF>>,
        index: &UInt64<ConstraintF>,
        hash_parameters: &(),
    ) -> Result<DigestVar<ConstraintF>, SynthesisError> {
        let mut current_hash = hash_leaf_var::<ConstraintF>(
            hash_parameters,
            leaf,
        )?;
        for (i, b) in index
            .to_bits_le()
            .iter()
            .take(P::DEPTH as usize)
            .enumerate()
        {
            let lc = DigestVar::conditionally_select(
                b,
                &self.path[i],
                &current_hash,
            )?;
            let rc = DigestVar::conditionally_select(
                b,
                &current_hash,
                &self.path[i],
            )?;
            current_hash = hash_inner_node_var::<ConstraintF>(
                hash_parameters,
                &lc,
                &rc,
            )?;
        }
        Ok(current_hash)
    }

    pub fn check_path(
        &self,
        root: &DigestVar<ConstraintF>,
        leaf: &Vec<UInt8<ConstraintF>>,
        index: &UInt64<ConstraintF>,
        hash_parameters: &(),
    ) -> Result<(), SynthesisError> {
        self.conditional_check_path(
            root,
            leaf,
            index,
            hash_parameters,
            &Boolean::constant(true),
        )
    }

    pub fn conditional_check_path(
        &self,
        root: &DigestVar<ConstraintF>,
        leaf: &Vec<UInt8<ConstraintF>>,
        index: &UInt64<ConstraintF>,
        hash_parameters: &(),
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let computed_root = self.compute_root_var(
            leaf,
            index,
            hash_parameters,
        )?;
        root.conditional_enforce_equal(&computed_root, condition)
    }
}

pub fn hash_leaf_var<ConstraintF>(
    parameters: &(),
    leaf: &Vec<UInt8<ConstraintF>>,
) -> Result<DigestVar<ConstraintF>, SynthesisError>
    where
        ConstraintF: PrimeField,
{
    let mut digest = DigestVar(leaf.to_vec());
    Ok(Sha256Gadget::digest(&digest.0)?)
}

pub fn hash_inner_node_var<ConstraintF>(
    parameters: &(),
    left: &DigestVar<ConstraintF>,
    right: &DigestVar<ConstraintF>,
) -> Result<DigestVar<ConstraintF>, SynthesisError>
    where
        ConstraintF: PrimeField,
{
    // Convert the hashes back into bytes and concat them
    let left_bytes = left
        .0.clone()
        .into_iter()
        .collect::<Vec<_>>();
    let right_bytes = right
        .0.clone()
        .into_iter()
        .collect::<Vec<_>>();
    let contacted = [left_bytes, right_bytes].concat();
    let mut digest = DigestVar(contacted);
    Ok(Sha256Gadget::digest(&digest.0)?)
}

impl<P, ConstraintF> AllocVar<MerkleTreePath<P>, ConstraintF>
for MerkleTreePathVar<P, ConstraintF>
    where
        P: MerkleTreeParameters,
        ConstraintF: PrimeField,
{
    fn new_variable<T: Borrow<MerkleTreePath<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let f_out = f()?;
        let cs = ns.cs();
        let mut res = Vec::new();
        for (i, _) in f_out.borrow().path.iter().enumerate() {
            res.push(DigestVar::new_variable(cs.clone(), || Ok(f_out.borrow().path[i].to_vec()), mode).unwrap());
        }
        Ok(MerkleTreePathVar {
            path: res,
            _parameters: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
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
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate hash parameters
        let crh_parameters_var = ();

        // Allocate root
        let root_var = DigestVar::new_input(
            ns!(cs, "root"),
            || Ok(tree.root.to_vec()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(
            ns!(cs, "leaf"),
            || Ok([1_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(
            ns!(cs, "index"),
            || Ok(177),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::<MerkleTreeTestParameters, Fq>::new_witness(
            ns!(cs, "path"),
            || Ok(path),
        )
            .unwrap();

        path_var
            .check_path(
                &root_var,
                &leaf_var,
                &index_var,
                &crh_parameters_var,
            )
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn poseidon_valid_path_constraints_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();


        // Allocate root
        let root_var = DigestVar::new_input(
            ns!(cs, "root"),
            || Ok(tree.root.to_vec()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(
            ns!(cs, "leaf"),
            || Ok([1_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(
            ns!(cs, "index"),
            || Ok(177),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::new_witness(
            ns!(cs, "path"),
            || Ok(path),
        )
            .unwrap();

        path_var
            .check_path(
                &root_var,
                &leaf_var,
                &index_var,
                &(),
            )
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn invalid_root_path_constraints_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate root
        let root_var = DigestVar::new_input(
            ns!(cs, "root"),
            || Ok(InnerHash::default().to_vec()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(
            ns!(cs, "leaf"),
            || Ok([1_u8; 16].to_vec()),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(
            ark_relations::ns!(cs, "index"),
            || Ok(177),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::new_witness(
            ns!(cs, "path"),
            || Ok(path),
        )
            .unwrap();

        path_var
            .check_path(
                &root_var,
                &leaf_var,
                &index_var,
                &(),
            )
            .unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn invalid_leaf_path_constraints_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate root
        let root_var = DigestVar::new_input(
            ns!(cs, "root"),
            || Ok(tree.root.to_vec()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(
            ns!(cs, "leaf"),
            || Ok([2_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(
            ns!(cs, "index"),
            || Ok(177),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::new_witness(
            ns!(cs, "path"),
            || Ok(path),
        )
            .unwrap();

        path_var
            .check_path(
                &root_var,
                &leaf_var,
                &index_var,
                &(),
            )
            .unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn invalid_index_path_constraints_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate root
        let root_var = DigestVar::new_input(
            ns!(cs, "root"),
            || Ok(tree.root.to_vec()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(
            ns!(cs, "leaf"),
            || Ok([1_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(
            ns!(cs, "index"),
            || Ok(176),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::new_witness(
            ns!(cs, "path"),
            || Ok(path),
        )
            .unwrap();

        path_var
            .check_path(
                &root_var,
                &leaf_var,
                &index_var,
                &(),
            )
            .unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}