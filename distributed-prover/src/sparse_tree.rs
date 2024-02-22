use std::{
    collections::HashMap,
    error::Error as ErrorTrait,
    fmt,
    marker::PhantomData,
};

use ark_crypto_primitives::crh::sha256::{

    digest::Digest,
    Sha256,
};
use ark_crypto_primitives::crh::TwoToOneCRHScheme;
use ark_crypto_primitives::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// Most of the code is borrowed from https://github.com/nirvantyagi/versa/blob/master/crypto_primitives/src/sparse_merkle_tree/mod.rs
// We don't use Pederson instead we use SHA256
pub type MerkleDepth = u8;
pub type MerkleIndex = u64;
pub const MAX_DEPTH: u8 = 64;

pub type InnerHash = [u8; 32];


// TODO: Add const hash parameters
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
            sparse_initial_hashes: sparse_initial_hashes,
            hash_parameters: (),
            _parameters: PhantomData,
        })
    }

    pub fn update(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error> {
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
            let lc_hash = match self.tree.get(&(d + 1, lc_i)) {
                Some(h) => h.clone(),
                None => self.sparse_initial_hashes[(d + 1) as usize].clone(),
            };
            let rc_hash = match self.tree.get(&(d + 1, rc_i)) {
                Some(h) => h.clone(),
                None => self.sparse_initial_hashes[(d + 1) as usize].clone(),
            };
            self.tree.insert(
                (d, i),
                hash_inner_node(&lc_hash, &rc_hash)?,
            );
        }
        self.root = self.tree.get(&(0, 0)).expect("root lookup failed").clone();
        Ok(())
    }

    pub fn lookup(&self, index: MerkleIndex) -> Result<MerkleTreePath<P>, Error> {
        if index >= 1_u64 << (P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
        let mut path = Vec::new();

        let mut i = index;
        for d in (1..=P::DEPTH).rev() {
            let sibling_hash = match self.tree.get(&(d, i ^ 1)) {
                Some(h) => h.clone(),
                None => self.sparse_initial_hashes[d as usize].clone(),
            };
            path.push(sibling_hash);
            i >>= 1;
        }
        Ok(MerkleTreePath {
            path,
            _parameters: PhantomData,
        })
    }

    pub fn get_root(&self) -> Result<InnerHash, Error> {
        Ok(self.root)
    }
}

impl<P: MerkleTreeParameters> MerkleTreePath<P> {
    pub fn compute_root(
        &self,
        leaf: &[u8],
        index: MerkleIndex,
        hash_parameters: &(),
    ) -> Result<InnerHash, Error> {
        if index >= 1_u64 << (P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
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

    pub fn verify(
        &self,
        root: &InnerHash,
        leaf: &[u8],
        index: MerkleIndex,
        hash_parameters: &(),
    ) -> Result<bool, Error> {
        Ok(self.compute_root(leaf, index, hash_parameters)? == *root)
    }
}

pub fn hash_leaf(
    leaf: &[u8],
) -> Result<InnerHash, Error> {
    let mut digest = leaf;
    // defining binding is needed because of the Rust's crap
    let binding = Sha256::digest(&digest);
    digest = &*binding;

    Ok(InnerHash::try_from(digest).unwrap())
}

pub fn hash_inner_node(
    left: &InnerHash,
    right: &InnerHash,
) -> Result<InnerHash, Error> {
    let digest = Sha256::evaluate(&(), *left, *right).expect("TODO: panic message");
    Ok(InnerHash::try_from(digest).unwrap())
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
    fn update_and_verify_test() {
        let rng = StdRng::seed_from_u64(0u64);
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        let proof_0 = tree.lookup(0).unwrap();
        let proof_177 = tree.lookup(177).unwrap();
        let proof_255 = tree.lookup(255).unwrap();
        let proof_256 = tree.lookup(256);
        assert!(proof_0
            .verify(&tree.root, &[0u8; 16], 0, &())
            .unwrap());
        assert!(proof_177
            .verify(&tree.root, &[0u8; 16], 177, &())
            .unwrap());
        assert!(proof_255
            .verify(&tree.root, &[0u8; 16], 255, &())
            .unwrap());
        assert!(proof_256.is_err());
        assert!(tree.update(177, &[1_u8; 16]).is_ok());
        assert!(proof_177
            .verify(&tree.root, &[1u8; 16], 177, &())
            .unwrap());
        assert!(!proof_177
            .verify(&tree.root, &[0u8; 16], 177, &())
            .unwrap());
        assert!(!proof_177
            .verify(&tree.root, &[1u8; 16], 0, &())
            .unwrap());
        assert!(!proof_0
            .verify(&tree.root, &[0u8; 16], 0, &())
            .unwrap());
        let updated_proof_0 = tree.lookup(0).unwrap();
        assert!(updated_proof_0
            .verify(&tree.root, &[0u8; 16], 0, &())
            .unwrap());
    }
}