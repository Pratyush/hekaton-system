use std::{collections::HashMap, error::Error as ErrorTrait, fmt, marker::PhantomData};

use ark_crypto_primitives::crh::sha256::{digest::Digest, Sha256};
use ark_crypto_primitives::crh::TwoToOneCRHScheme;
use ark_crypto_primitives::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// Most of the code is borrowed from https://github.com/nirvantyagi/versa/blob/master/crypto_primitives/src/sparse_merkle_tree/mod.rs
// We don't use Pederson instead we use SHA256, our InnerHash is 31 bytes instead of 32 and outputs of contraints
// is Fp instead of Digest ==> output/input of hashes are Fp
pub type MerkleDepth = u8;
pub type MerkleIndex = u64;

pub const MAX_DEPTH: u8 = 64;

pub type InnerHash = [u8; 31];

pub trait MerkleTreeParameters {
    const DEPTH: MerkleDepth;
    fn is_valid() -> Result<bool, Error> {
        if Self::DEPTH < 1 || Self::DEPTH > MAX_DEPTH {
            return Err(Box::new(MerkleTreeError::TreeDepth(Self::DEPTH)));
        }
        Ok(true)
    }
}

#[derive(Clone)]
pub struct SparseMerkleTree<P: MerkleTreeParameters> {
    pub(crate) tree: HashMap<(MerkleDepth, MerkleIndex), InnerHash>,
    pub root: InnerHash,
    pub(crate) sparse_initial_hashes: Vec<InnerHash>,
    pub hash_parameters: (),
    _parameters: PhantomData<P>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleTreePath<P: MerkleTreeParameters> {
    pub path: Vec<InnerHash>,
    // pretty smart to avoid multi-thread problems ==> https://stackoverflow.com/questions/50200197/how-do-i-share-a-struct-containing-a-phantom-pointer-among-threads
    pub _parameters: PhantomData<fn() -> P>,
}

impl<P: MerkleTreeParameters> Clone for MerkleTreePath<P> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            _parameters: PhantomData,
        }
    }
}

impl<P: MerkleTreeParameters> Default for MerkleTreePath<P> {
    fn default() -> Self {
        Self {
            path: vec![InnerHash::default(); P::DEPTH as usize],
            _parameters: PhantomData,
        }
    }
}

impl<P: MerkleTreeParameters> Default for SparseMerkleTree<P> {
    fn default() -> Self {
        SparseMerkleTree::new(&[0u8; 16], &()).unwrap()
    }
}


impl<P: MerkleTreeParameters> SparseMerkleTree<P> {
    pub fn new(
        initial_leaf_value: &[u8],
        hash_parameters: &(),
    ) -> Result<Self, Error> {
        // Compute initial hashes for each depth of tree
        let mut sparse_initial_hashes =
            vec![hash_leaf(initial_leaf_value)?];
        for i in 1..=(P::DEPTH as usize) {
            let child_hash = sparse_initial_hashes[i - 1].clone();
            sparse_initial_hashes.push(hash_inner_node(
                &child_hash,
                &child_hash,
            )?);
        }
        sparse_initial_hashes.reverse();

        Ok(SparseMerkleTree {
            tree: HashMap::new(),
            root: sparse_initial_hashes[0].clone(),
            sparse_initial_hashes,
            hash_parameters: (),
            _parameters: PhantomData,
        })
    }

    // for updating leafs, the leaf is hashes first and the rest is similar to internal nodes
    pub fn update_leaf(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error> {
        if index >= 1_u64 << (P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }

        let mut i = index;
        self.tree.insert(
            (P::DEPTH, i),
            hash_leaf(leaf_value)?,
        );

        for d in (0..P::DEPTH).rev() {
            i >>= 1;
            let lc_i = i << 1;
            let rc_i = lc_i + 1;
            let lc_hash = self.lookup_internal_node(lc_i, d + 1).unwrap();
            let rc_hash = self.lookup_internal_node(rc_i, d + 1).unwrap();
            self.tree.insert(
                (d, i),
                hash_inner_node(&lc_hash, &rc_hash)?,
            );
        }
        self.root = self.tree.get(&(0, 0)).expect("root lookup failed").clone();
        Ok(())
    }

    pub fn update_internal_node(&mut self, index: MerkleIndex, internal_value: &InnerHash) -> Result<(), Error> {
        if index >= 1_u64 << (P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }

        let mut i = index;
        self.tree.insert(
            (P::DEPTH, i),
            *internal_value,
        );

        for d in (0..P::DEPTH).rev() {
            i >>= 1;
            let lc_i = i << 1;
            let rc_i = lc_i + 1;
            let lc_hash = self.lookup_internal_node(lc_i, d + 1).unwrap();
            let rc_hash = self.lookup_internal_node(rc_i, d + 1).unwrap();
            self.tree.insert(
                (d, i),
                hash_inner_node(&lc_hash, &rc_hash)?,
            );
        }
        self.root = self.tree.get(&(0, 0)).expect("root lookup failed").clone();
        Ok(())
    }


    // In the normal case, depth = P::Depth
    pub fn lookup_path(&self, index: MerkleIndex, depth: MerkleDepth) -> Result<MerkleTreePath<P>, Error> {
        if index >= 1_u64 << (depth as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
        let mut path = Vec::new();

        let mut i = index;
        for d in (1..=depth).rev() {
            let sibling_hash = self.lookup_internal_node(i ^ 1, d).unwrap();
            path.push(sibling_hash);
            i >>= 1;
        }
        Ok(MerkleTreePath {
            path,
            _parameters: PhantomData,
        })
    }

    pub fn lookup_internal_node(&self, index: MerkleIndex, depth: MerkleDepth) -> Result<InnerHash, Error> {
        let res = match self.tree.get(&(depth, index)) {
            Some(h) => h.clone(),
            None => self.sparse_initial_hashes[depth as usize].clone(),
        };
        Ok(res)
    }


    pub fn get_root(&self) -> Result<InnerHash, Error> {
        Ok(self.root)
    }
}

impl<P: MerkleTreeParameters> MerkleTreePath<P> {
    //  this function computes the root given the path and leaf, so it firsts hashes the leaf and then
    // computes the root, and it always assumes that length of path is equal to the depth of tree
    pub fn compute_root_from_leaf(
        &self,
        leaf: &[u8],
        index: MerkleIndex,
        hash_parameters: &(),
    ) -> Result<InnerHash, Error> {
        // checking index is not out of bound
        if index >= 1_u64 << (P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
        // checking length of path is equal to the depth of the tree
        if self.path.len() != P::DEPTH as usize {
            return Err(Box::new(MerkleTreeError::TreeDepth(self.path.len() as u8)));
        }

        let mut i = index;
        let mut current_hash = hash_leaf(leaf)?;
        for sibling_hash in self.path.iter() {
            current_hash = match i % 2 {
                0 => hash_inner_node(&current_hash, sibling_hash)?,
                1 => hash_inner_node(sibling_hash, &current_hash)?,
                _ => unreachable!(),
            };
            i >>= 1;
        }
        Ok(current_hash)
    }

    // this one takes a path of arbitrary length and an internal node and computes the root
    pub fn compute_root_from_internal_nodes(
        &self,
        internal_node: &InnerHash,
        index: MerkleIndex,
        hash_parameters: &(),
    ) -> Result<InnerHash, Error> {
        // out of bound error
        if index >= 1_u64 << (P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
        let mut i = index;
        // don't hash the internal node just clone it!
        let mut current_hash = internal_node.clone();
        for sibling_hash in self.path.iter() {
            current_hash = match i % 2 {
                0 => hash_inner_node(&current_hash, sibling_hash)?,
                1 => hash_inner_node(sibling_hash, &current_hash)?,
                _ => unreachable!(),
            };
            i >>= 1;
        }
        Ok(current_hash)
    }

    pub fn verify_leaf(
        &self,
        root: &InnerHash,
        leaf: &[u8],
        index: MerkleIndex,
        hash_parameters: &(),
    ) -> Result<bool, Error> {
        Ok(self.compute_root_from_leaf(leaf, index, hash_parameters)? == *root)
    }

    pub fn verify_internal_node(
        &self,
        root: &InnerHash,
        internal_node: &InnerHash,
        index: MerkleIndex,
        hash_parameters: &(),
    ) -> Result<bool, Error> {
        Ok(self.compute_root_from_internal_nodes(&internal_node, index, hash_parameters)? == *root)
    }
}

pub fn hash_leaf(
    leaf: &[u8],
) -> Result<InnerHash, Error> {
    let mut digest = leaf;
    // defining binding is needed because of the Rust's crap
    let binding = Sha256::digest(&digest);
    digest = &*binding;
    digest = &digest[0..31];
    Ok(InnerHash::try_from(digest).unwrap())
}

pub fn hash_inner_node(
    left: &InnerHash,
    right: &InnerHash,
) -> Result<InnerHash, Error> {
    let digest = Sha256::evaluate(&(), *left, *right).expect("TODO: panic message");
    let a: [u8; 32] = digest.try_into().unwrap();
    Ok(InnerHash::try_from(&a[0..31]).unwrap())
}


#[derive(Debug)]
pub enum MerkleTreeError {
    TreeDepth(MerkleDepth),
    LeafIndex(MerkleIndex),
}

impl ErrorTrait for MerkleTreeError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for MerkleTreeError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            MerkleTreeError::TreeDepth(h) => format!("tree depth is invalid: {}", h),
            MerkleTreeError::LeafIndex(i) => format!("leaf index is invalid: {}", i),
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 8;
    }

    pub struct MerkleTreeTinyTestParameters;

    impl MerkleTreeParameters for MerkleTreeTinyTestParameters {
        const DEPTH: MerkleDepth = 1;
    }

    type TestMerkleTree = SparseMerkleTree<MerkleTreeTestParameters>;
    type TinyTestMerkleTree = SparseMerkleTree<MerkleTreeTinyTestParameters>;

    #[test]
    fn initialize_test() {
        let tree = TinyTestMerkleTree::new(&[0u8; 16], &()).unwrap();
        let leaf_hash = hash_leaf(&[0u8; 16]).unwrap();
        let root_hash = hash_inner_node(&leaf_hash, &leaf_hash).unwrap();
        assert_eq!(tree.root, root_hash);
    }

    #[test]
    fn lookup_test() {
        let tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        let leaf = tree.lookup_internal_node(20, 7).unwrap();
        let path = tree.lookup_path(20, 7).unwrap();
        let p = path.compute_root_from_internal_nodes(&leaf, 20, &()).unwrap();
        assert_eq!(p, tree.root);
    }

    #[test]
    fn update_and_verify_test() {
        let rng = StdRng::seed_from_u64(0u64);
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        let proof_0 = tree.lookup_path(0, MerkleTreeTestParameters::DEPTH).unwrap();
        let proof_177 = tree.lookup_path(177, MerkleTreeTestParameters::DEPTH).unwrap();
        let proof_255 = tree.lookup_path(255, MerkleTreeTestParameters::DEPTH).unwrap();
        let proof_256 = tree.lookup_path(256, MerkleTreeTestParameters::DEPTH);
        assert!(proof_0.verify_leaf(&tree.root, &[0u8; 16], 0, &()).unwrap());
        assert!(proof_177.verify_leaf(&tree.root, &[0u8; 16], 177, &()).unwrap());
        assert!(proof_255.verify_leaf(&tree.root, &[0u8; 16], 255, &()).unwrap());
        assert!(proof_256.is_err());
        assert!(tree.update_leaf(177, &[1_u8; 16]).is_ok());
        assert!(proof_177.verify_leaf(&tree.root, &[1u8; 16], 177, &()).unwrap());
        assert!(!proof_177.verify_leaf(&tree.root, &[0u8; 16], 177, &()).unwrap());
        assert!(!proof_177.verify_leaf(&tree.root, &[1u8; 16], 0, &()).unwrap());
        assert!(!proof_0.verify_leaf(&tree.root, &[0u8; 16], 0, &()).unwrap());
        let updated_proof_0 = tree.lookup_path(0, MerkleTreeTestParameters::DEPTH).unwrap();
        assert!(updated_proof_0.verify_leaf(&tree.root, &[0u8; 16], 0, &()).unwrap());
    }
}