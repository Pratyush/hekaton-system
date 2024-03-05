use std::{collections::HashMap, error::Error as ErrorTrait, fmt, marker::PhantomData};
use std::fmt::{Display, Formatter};
use std::ops::ShrAssign;

use ark_crypto_primitives::crh::sha256::{digest::Digest, Sha256};
use ark_crypto_primitives::crh::TwoToOneCRHScheme;
use ark_crypto_primitives::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint;
use num_traits::{Zero, One, ToBytes};

// We model the array of the path as n BigUint and view it as a stream of bytes that it's meaningful for "depth" bits
#[derive(Eq, Hash, PartialEq, Clone, Debug, Default)]
pub struct MerkleIndex {
    pub index: BigUint,
    pub depth: usize,
}

impl MerkleIndex {
    // This bit vector is used by path verification function
    pub fn to_bit_vector(&self) -> Vec<bool> {
        let mut res = Vec::new();
        let depth = self.depth;
        let mut index = self.index.clone();
        for _d in (0..depth).rev() {
            if is_even(&index) {
                res.push(true);
            } else {
                res.push(false);
            }
            index = &index >> 1;
        }
        return res;
    }
}

// We use SHA256, our InnerHash is 31 bytes instead of 32 and outputs of constraints is Fp instead of Digest ==> output/input of hashes are Fp
pub type InnerHash = [u8; 31];

pub trait MerkleTreeParameters {
    const DEPTH: usize;
    const CHUNK_SIZE: usize;
    const BYTE_SIZE: usize = Self::CHUNK_SIZE / 8;
    const NUM_OF_CHUNKS: usize = Self::DEPTH / Self::CHUNK_SIZE;
    fn is_valid() -> Result<bool, Error> {
        if Self::DEPTH != 256 || Self::CHUNK_SIZE & 8 != 0 {
            return Err(Box::new(MerkleTreeError::InvalidParameter));
        }
        Ok(true)
    }
}

#[derive(Clone)]
pub struct SparseMerkleTree<P: MerkleTreeParameters> {
    pub tree: HashMap<MerkleIndex, InnerHash>,
    pub leaves: HashMap<MerkleIndex, Vec<u8>>,
    pub root: InnerHash,
    pub sparse_initial_hashes: Vec<InnerHash>,
    pub hash_parameters: (),
    _parameters: PhantomData<P>,
}

pub enum TreeUpdate {
    SimpleUpdate(SimpleUpdate),
    ShiftUpdate(ShiftUpdate),
}

pub struct SimpleUpdate {
    pub leaf: Vec<u8>,
}

#[derive(Debug)]
pub struct ShiftUpdate {
    pub leaf: Vec<u8>,
    pub shift_leaf: Vec<u8>,
    pub shift_leaf_previous_index: MerkleIndex,
    // TODO: to be removed
}

impl<P: MerkleTreeParameters> Display for SparseMerkleTree<P> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "(leaves: {:?})", self.leaves.keys())
    }
}

impl<P: MerkleTreeParameters> Default for SparseMerkleTree<P> {
    fn default() -> Self {
        SparseMerkleTree::new(&[0u8; 16], &()).unwrap()
    }
}

impl<P: MerkleTreeParameters> SparseMerkleTree<P> {
    pub fn new(initial_leaf_value: &[u8], hash_parameters: &()) -> Result<Self, Error> {
        // Compute initial hashes for each depth of tree
        let mut sparse_initial_hashes = vec![hash_leaf(initial_leaf_value)?];
        for i in 1..=(P::DEPTH as usize) {
            let child_hash = sparse_initial_hashes[i - 1].clone();
            sparse_initial_hashes.push(hash_inner_node(&child_hash, &child_hash)?);
        }
        sparse_initial_hashes.reverse();

        Ok(SparseMerkleTree {
            tree: HashMap::new(),
            root: sparse_initial_hashes[0].clone(),
            leaves: HashMap::new(),
            hash_parameters: (),
            sparse_initial_hashes,
            _parameters: PhantomData,
        })
    }

    /*
    Function Overview:
        - This function inserts a leaf into the tree based on a given MerkleIndex.
        - It is typically called as a subroutine of the simple_update and shift_update function.
        - In sparse trees, when there's a leaf on the way, the leaf movement is handled by the update functions.
        - Takes a node_type argument, which can be either Leaf or InternalNode:
           - Leaf: The initial value is hashed.
           - InternalNode: The value is treated as an internal node and cast to InnerHash.
        - Provides flexibility in handling different node types during tree updates.
     */
    pub fn insert(&mut self, mut index: MerkleIndex, value: &[u8], node_type: NodeType) -> Result<(), Error> {
        let mut i = &mut index.index;
        // set the hash, based on node type, if it's already from internal nodes just output itself, else hash the given leaf
        let node_hash = match node_type {
            NodeType::InternalNode => InnerHash::try_from(value).unwrap(),
            NodeType::Leaf => hash_leaf(value)?,
        };
        // insert the node inside the tree
        self.tree.insert(MerkleIndex { index: i.clone(), depth: index.depth }, node_hash);

        for d in (0..index.depth).rev() {
            let _ = &i.shr_assign(1);
            let lc_i = &*i << 1;
            let rc_i = &lc_i + 1_u8;
            let lc_hash = self.lookup_internal_node(lc_i, (d + 1)).unwrap();
            let rc_hash = self.lookup_internal_node(rc_i, (d + 1)).unwrap();
            let temp = MerkleIndex { index: i.clone(), depth: d };
            self.tree.insert(
                temp.clone(),
                hash_inner_node(&(lc_hash.0), &(rc_hash.0))?,
            );
        }
        let temp = MerkleIndex { index: BigUint::zero(), depth: 0 };
        self.root = self.tree.get(&temp).expect("root lookup failed").clone();
        Ok(())
    }

    /* Function Overview:
        - Used for updating the tree, distinguishing between cases:
            - Shift Case: Some leaf needs to move.
            - Simple Case: No leaf movement required.
        - Specifically designed for leaves; does not take an index or path as parameters.
        - Computes the path internally for leaf updates.
        - Provides a clear separation between shift and simple cases during tree updates.
     */
    pub fn update(&mut self, leaf: &[u8]) -> Result<TreeUpdate, Error> {
        let leaf_h = hash(leaf).unwrap();
        let is_shift = self.is_there_shift_leaf(leaf_h.as_slice()).unwrap();
        return if is_shift {
            let shift_leaf = self.get_shift_leaf(leaf_h.as_slice()).unwrap();
            let shift_leaf_h = hash(shift_leaf.0.as_slice()).unwrap();
            let u = self.shift_update(leaf, leaf_h.as_slice(), shift_leaf.0.as_slice(), shift_leaf_h.as_slice(), shift_leaf.1).unwrap();
            Ok(TreeUpdate::ShiftUpdate(u))
        } else {
            let leaf_h = hash(leaf).unwrap();
            let u = self.simple_update(leaf, leaf_h.as_slice()).unwrap();
            Ok(TreeUpdate::SimpleUpdate(u))
        };
    }

    pub fn shift_update(&mut self, leaf: &[u8], leaf_h: &[u8], shift_leaf: &[u8], shift_leaf_h: &[u8], shift_leaf_index: MerkleIndex) -> Result<ShiftUpdate, Error> {
        if leaf_h.len() != 32 || shift_leaf_h.len() != 32 {
            return Err(Box::new(MerkleTreeError::InvalidHashSize));
        }
        // remove previous leaf
        self.leaves.remove(&shift_leaf_index);
        // get the new indexes for them
        let (ind1, ind2) = self.get_indexes_for_two_leaves(leaf_h, shift_leaf_h).unwrap();
        // It's of great importance to first shift the s-leaf and then append the new leaf
        self.insert(ind2.clone(), shift_leaf, NodeType::Leaf).expect("Insertion Error");
        self.insert(ind1.clone(), leaf, NodeType::Leaf).expect("Insertion Error");
        // add the new leaves
        self.leaves.insert(ind1.clone(), leaf.to_vec());
        self.leaves.insert(ind2.clone(), shift_leaf.to_vec());
        Ok(ShiftUpdate {
            leaf: leaf.to_vec(),
            shift_leaf: shift_leaf.to_vec(),
            shift_leaf_previous_index: shift_leaf_index,
        })
    }

    pub fn simple_update(&mut self, leaf: &[u8], leaf_h: &[u8]) -> Result<SimpleUpdate, Error> {
        if leaf_h.len() != 32 {
            return Err(Box::new(MerkleTreeError::InvalidHashSize));
        }
        if self.lookup_internal_node(BigUint::from_bytes_le(&leaf_h), P::DEPTH).unwrap().1 {
            return Err(Box::new(MerkleTreeError::FullTree));
        }
        for d in (1..P::NUM_OF_CHUNKS).rev() {
            let i = BigUint::from_bytes_le(&leaf_h[0..d * P::BYTE_SIZE]);
            let depth = P::CHUNK_SIZE * d;
            let is_full = self.lookup_internal_node(i.clone(), depth).unwrap().1;
            if is_full {
                // check if contains a leaf or it's just full
                let is_leaf = match self.leaves.get(&MerkleIndex { index: i, depth }) {
                    Some(_h) => true,
                    None => false,
                };
                if is_leaf {
                    return Err(Box::new(MerkleTreeError::NotSimpleUpdate));
                } else {
                    let i = BigUint::from_bytes_le(&leaf_h[0..(d + 1) * P::BYTE_SIZE]);
                    let depth = P::CHUNK_SIZE * (d + 1);
                    let index = MerkleIndex { index: i, depth };
                    self.insert(index.clone(), leaf, NodeType::Leaf).expect("Insertion Error");
                    self.leaves.insert(index.clone(), leaf.to_vec());
                    return Ok(SimpleUpdate { leaf: leaf.to_vec() });
                }
            }
        }
        let index = MerkleIndex { index: BigUint::from_bytes_le(&leaf_h[0.. P::BYTE_SIZE]), depth: P::CHUNK_SIZE };
        self.insert(index.clone(), leaf, NodeType::Leaf).expect("Insertion Error");
        self.leaves.insert(index.clone(), leaf.to_vec());
        Ok(SimpleUpdate { leaf: leaf.to_vec() })
    }

    pub fn lookup_internal_node(&self, index: BigUint, depth: usize) -> Result<(InnerHash, bool), Error> {
        let res = match self.tree.get(&MerkleIndex { index, depth: depth as usize }) {
            Some(h) => (h.clone(), true),
            None => (self.sparse_initial_hashes[depth as usize].clone(), false),
        };
        Ok(res)
    }

    pub fn lookup_path(&self, index: &MerkleIndex) -> Result<MerkleTreePath<P>, Error> {
        let mut path = Vec::new();
        let mut i = index.index.clone();
        for d in (1..=index.depth).rev() {
            let sibling_hash = self.lookup_internal_node(&i ^ BigUint::one(), d).unwrap().0;
            path.push(sibling_hash);
            i = i >> 1;
        }
        Ok(MerkleTreePath {
            path,
            _parameters: PhantomData,
        })
    }


    /* Function Overview:
        - Takes two leaves as input and determines:
            - The first depth common to both leaves.
            - The new indexes to which these two leaves need to be moved.
     */
    pub fn get_indexes_for_two_leaves(&self, leaf_h1: &[u8], leaf_h2: &[u8]) -> Result<(MerkleIndex, MerkleIndex), Error> {
        if leaf_h1.len() != 32 || leaf_h2.len() != 32 {
            return Err(Box::new(MerkleTreeError::InvalidHashSize));
        }
        for i in 0..P::NUM_OF_CHUNKS {
            if leaf_h1[0..P::BYTE_SIZE * (i + 1)] == leaf_h2[0..P::BYTE_SIZE * (i + 1)] {
                continue;
            }
            let i1 = BigUint::from_bytes_le(&leaf_h1[0..P::BYTE_SIZE * (i + 1)]);
            let i2 = BigUint::from_bytes_le(&leaf_h2[0..P::BYTE_SIZE * (i + 1)]);
            let ind1 = MerkleIndex { index: i1, depth: P::CHUNK_SIZE * (i + 1) };
            let ind2 = MerkleIndex { index: i2, depth: P::CHUNK_SIZE * (i + 1) };
            return Ok((ind1, ind2));
        }
        return Err(Box::new(MerkleTreeError::SHA256Collision));
    }

    /*
     Function Overview:
        - This function determines whether there's a leaf to be moved after adding a new leaf
        - Start from the bottom of the tree
        - Check the first full node encountered
        - If the node contains a leaf, a shift is required
        - If the node is empty, no shift is needed
    */
    pub fn is_there_shift_leaf(&self, leaf_h: &[u8]) -> Result<bool, Error> {
        if leaf_h.len() != 32 {
            return Err(Box::new(MerkleTreeError::InvalidHashSize));
        }
        for d in (1..=P::NUM_OF_CHUNKS).rev() {
            let index = BigUint::from_bytes_le(&leaf_h[0..d * P::BYTE_SIZE]);
            let depth = P::CHUNK_SIZE * d;
            let is_full = self.lookup_internal_node(index.clone(), depth).unwrap().1;
            if is_full {
                // check if contains a leaf or it's just full
                let is_leaf = match self.leaves.get(&MerkleIndex { index, depth }) {
                    Some(_h) => true,
                    None => false,
                };
                return Ok(is_leaf);
            }
        }
        Ok(false)
    }

    // This function takes a leaf and outputs the leaf on the way of this leaf that needs to be moved
    pub fn get_shift_leaf(&self, leaf_h: &[u8]) -> Result<(Vec<u8>, MerkleIndex), Error> {
        if !self.is_there_shift_leaf(leaf_h).unwrap() {
            return Err(Box::new(MerkleTreeError::NoShiftLeaf));
        }
        if leaf_h.len() != 32 {
            return Err(Box::new(MerkleTreeError::InvalidHashSize));
        }
        for i in (1..=P::NUM_OF_CHUNKS).rev() {
            // get the biginteger from the first i * 8 bytes
            let i1 = BigUint::from_bytes_le(&leaf_h[0..i * P::BYTE_SIZE]);
            let d = P::CHUNK_SIZE * i;
            let is_full = self.lookup_internal_node(i1, d).unwrap().1;
            if is_full {
                // retrieve the leaf on the way
                let i2 = BigUint::from_bytes_le(&leaf_h[0..i * P::BYTE_SIZE]);
                let merkle_index = MerkleIndex { index: i2, depth: P::CHUNK_SIZE * i };
                let shift_leaf = match self.leaves.get(&merkle_index) {
                    Some(h) => h.clone(),
                    None => Vec::new(),
                };
                return Ok((shift_leaf, merkle_index));
            }
        }
        return Err(Box::new(MerkleTreeError::NoShiftLeaf));
    }

    // TODO: this might be buggy but hasn't been used yet
    // This function returns index where a new leaf has to be inserted its hash
    pub fn get_index_from_hash(&self, leaf_h: &[u8]) -> Result<MerkleIndex, Error> {
        if leaf_h.len() != 32 {
            return Err(Box::new(MerkleTreeError::InvalidHashSize));
        }
        // Important: we start from the bottom of the tree not top!
        for i in (1..=P::NUM_OF_CHUNKS).rev() {
            // get the biginteger from the first i * 8 bytes
            let i1 = BigUint::from_bytes_le(&leaf_h[0..i * P::BYTE_SIZE]);
            let is_full = self.lookup_internal_node(i1, P::CHUNK_SIZE * i).unwrap().1;
            if is_full {
                // retrieve the leaf
                let i2 = BigUint::from_bytes_le(&leaf_h[0..i * P::BYTE_SIZE]);
                return Ok(MerkleIndex { index: i2, depth: P::CHUNK_SIZE * i });
            }
        }
        return Err(Box::new(MerkleTreeError::LeafNotFound));
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
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

// TODO: get a sub_path
impl<P: MerkleTreeParameters> Default for MerkleTreePath<P> {
    fn default() -> Self {
        Self {
            path: vec![InnerHash::default(); P::DEPTH],
            _parameters: PhantomData,
        }
    }
}

impl<P: MerkleTreeParameters> MerkleTreePath<P> {
    pub fn compute_root(&self, value: &[u8], index: &Vec<bool>, hash_parameters: &(), node_type: NodeType) -> Result<InnerHash, Error> {
        let mut current_hash = match node_type {
            NodeType::InternalNode => InnerHash::try_from(value).unwrap(),
            NodeType::Leaf => hash_leaf(value)?,
        };
        for (i, sibling_hash) in self.path.iter().enumerate() {
            current_hash = match index[i] {
                true => hash_inner_node(&current_hash, sibling_hash)?,
                false => hash_inner_node(sibling_hash, &current_hash)?,
            };
        }
        Ok(current_hash)
    }

    pub fn verify(
        &self,
        root: &InnerHash,
        value: &[u8],
        index: &Vec<bool>,
        hash_parameters: &(),
        node_type: NodeType,
    ) -> Result<bool, Error> {
        Ok(self.compute_root(value, index, hash_parameters, node_type)? == *root)
    }
}

pub enum NodeType {
    Leaf,
    InternalNode,
}

pub fn hash_leaf(leaf: &[u8]) -> Result<InnerHash, Error> {
    let binding = hash(leaf).unwrap();
    let mut digest = binding.as_slice();
    digest = &digest[0..31];
    Ok(InnerHash::try_from(digest).unwrap())
}

pub fn hash_inner_node(left: &InnerHash, right: &InnerHash) -> Result<InnerHash, Error> {
    let digest = Sha256::evaluate(&(), *left, *right).expect("SHA256 evaluation error");
    let a: [u8; 32] = digest.try_into().unwrap();
    Ok(InnerHash::try_from(&a[0..31]).unwrap())
}

pub fn hash(value: &[u8]) -> Result<Vec<u8>, Error> {
    let binding = Sha256::digest(value);
    let digest = binding.as_slice();
    let result: Vec<u8> = digest.into();
    Ok(result)
}

pub fn is_even(number: &BigUint) -> bool {
    number % 2_u8 == BigUint::zero()
}


#[derive(Debug)]
pub enum MerkleTreeError {
    TreeDepth(usize),
    LeafIndex(MerkleIndex),
    FullTree,
    InvalidHashSize,
    LeafNotFound,
    SHA256Collision,
    InvalidDepthInsertion,
    NoShiftLeaf,
    InvalidParameter,
    NotSimpleUpdate,
}

impl ErrorTrait for MerkleTreeError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl Display for MerkleTreeError {
    fn fmt(self: &Self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            MerkleTreeError::TreeDepth(h) => format!("tree depth is invalid: {}", h),
            MerkleTreeError::LeafIndex(i) => format!("leaf index is invalid: {:?}", i),
            MerkleTreeError::FullTree => "tree already full (recurring leaf)".to_string(),
            MerkleTreeError::InvalidHashSize => "invalid hash size".to_string(),
            MerkleTreeError::LeafNotFound => "leaf not found".to_string(),
            MerkleTreeError::SHA256Collision => "sha256 collision".to_string(),
            MerkleTreeError::InvalidDepthInsertion => "invalid depth insertion".to_string(),
            MerkleTreeError::NoShiftLeaf => "no shift leaf found".to_string(),
            MerkleTreeError::InvalidParameter => "invalid parameters".to_string(),
            MerkleTreeError::NotSimpleUpdate => "not simple update".to_string(),
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn get_simple_index(leaf_h: &[u8]) -> Result<MerkleIndex, Error> {
        if leaf_h.len() != 32 {
            return Err(Box::new(MerkleTreeError::InvalidHashSize));
        }
        let i = BigUint::from_bytes_le(&leaf_h[0..MerkleTreeTestParameters::BYTE_SIZE]);
        Ok(MerkleIndex { index: i, depth: MerkleTreeTestParameters::CHUNK_SIZE })
    }

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: usize = 256;
        const CHUNK_SIZE: usize = 8;
    }


    type TestMerkleTree = SparseMerkleTree<MerkleTreeTestParameters>;

    #[test]
    fn initialize_test() {
        // test correctness of hashes
        let leaf_leaf = [0_u8; 32];
        let left_hash = hash_leaf(&leaf_leaf).unwrap();
        let right_leaf = [0_u8; 32];
        let right_hash = hash_leaf(&right_leaf).unwrap();
        let mut result = Vec::from(left_hash);
        result.extend_from_slice(&right_hash);
        let concatenation = result.as_slice();
        let h1 = hash_inner_node(&left_hash, &right_hash).unwrap();
        let h2 = hash_leaf(concatenation).unwrap();
        assert_eq!(h1, h2);
        // test parity function
        assert!(is_even(&BigUint::zero()));
        assert!(!is_even(&BigUint::one()));
    }

    #[test]
    fn insert_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        let leaf = [1_u8; 32];
        let mut index = get_simple_index(&leaf).unwrap();
        // update the tree
        tree.insert(index.clone(), &leaf, NodeType::Leaf).expect("insertion error");
        let path = tree.lookup_path(&index).unwrap();
        assert!(path.verify(&tree.root, &leaf, &index.to_bit_vector(), &(), NodeType::Leaf).expect("path verification error"));

        let leaf = [9_u8; 32];
        let mut index = get_simple_index(&leaf).unwrap();
        // update the tree
        tree.insert(index.clone(), &leaf, NodeType::Leaf).expect("insertion error");
        let path = tree.lookup_path(&index).unwrap();
        assert!(path.verify(&tree.root, &leaf, &index.to_bit_vector(), &(), NodeType::Leaf).expect("path verification error"));

        let leaf = [10_u8; 32];
        let h = hash_leaf(&leaf).unwrap();
        let mut index = get_simple_index(&leaf).unwrap();
        // update the tree
        tree.insert(index.clone(), &leaf, NodeType::Leaf).expect("insertion error");
        let path = tree.lookup_path(&index).unwrap();
        assert!(path.verify(&tree.root, &h, &index.to_bit_vector(), &(), NodeType::InternalNode).expect("path verification error"));
    }

    #[test]
    fn shift_leaf_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        let leaf = [0u8; 32];
        let leaf_h1: [u8; 32] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let leaf_h2: [u8; 32] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let index1 = get_simple_index(&leaf_h1).unwrap();
        let index2 = get_simple_index(&leaf_h2).unwrap();
        let (ind1, ind2) = tree.get_indexes_for_two_leaves(&leaf_h1, &leaf_h2).unwrap();
        assert_eq!(index1.depth, MerkleTreeTestParameters::CHUNK_SIZE);
        assert_eq!(ind1.depth, ind2.depth);
        assert_eq!(ind2.depth, 72);
        let b = tree.is_there_shift_leaf(&leaf_h1).unwrap();
        assert!(!b);
        tree.simple_update(&leaf, &leaf_h1).expect("TODO: panic message");
        // tree.insert(index1, &leaf, NodeType::Leaf).expect("insertion error");
        let b = tree.is_there_shift_leaf(&leaf_h2).unwrap();
        assert!(b);
    }

    #[test]
    fn shift_leaf_test2() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        let leaf1 = [0u8; 32];
        let leaf2 = [1u8; 32];
        let leaf3 = [2u8; 32];
        let leaf4 = [3u8; 32];
        let  leaf_h1: [u8; 32] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let leaf_h2: [u8; 32] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let leaf_h3: [u8; 32] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8,
            1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let leaf_h4: [u8; 32] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8,
            1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8,
            1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8];
        tree.simple_update(&leaf1, &leaf_h1).expect("simple update error");
        println!("{}", tree);
        let l1 = tree.get_shift_leaf(&leaf_h2).unwrap();
        assert_eq!(l1.0.as_slice(), leaf1.as_slice());
        tree.shift_update(&leaf2, &leaf_h2, &leaf1, &leaf_h1, l1.1).expect("shift update error");
        assert!(tree.is_there_shift_leaf(&leaf_h2).unwrap());
        println!("{}", tree);
        let l2 = tree.get_shift_leaf(&leaf_h3).unwrap();
        assert_eq!(l2.0.as_slice(), leaf2.as_slice());
        tree.shift_update(&leaf3, &leaf_h3, &leaf2, &leaf_h2, l2.1).expect("shift update error");
        assert!(tree.is_there_shift_leaf(&leaf_h3).unwrap());
        println!("{}", tree);
        let l3 = tree.get_shift_leaf(&leaf_h3).unwrap();
        assert_eq!(l3.0.as_slice(), leaf3.as_slice());
        tree.shift_update(&leaf4, &leaf_h4, &leaf3, &leaf_h3, l3.1).expect("shift update error");
        assert!(tree.is_there_shift_leaf(&leaf_h4).unwrap());
        println!("{}", tree);
    }

    #[test]
    fn same_leaf_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        let leaf_h: [u8; 32] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let t = tree.get_indexes_for_two_leaves(&leaf_h, &leaf_h);
        assert!(t.is_err());
    }

    #[test]
    fn update_tree_test2() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        for i in 0..100 {
            let j = i as i32;
            let leaf = j.to_le_bytes();
            tree.update(&leaf).expect("TODO: panic message");
            let leaf_h = hash(&leaf).unwrap();
            let index = tree.get_index_from_hash(leaf_h.as_slice()).unwrap();
            let path = tree.lookup_path(&index).unwrap();
            assert!(path.verify(&tree.root, &leaf, &index.to_bit_vector(), &(), NodeType::Leaf).unwrap());
        }
    }

    #[test]
    fn null_leaf_test() {
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        let leaf = [3u8; 32];
        let leaf_h = hash(&leaf).unwrap();
        let index = get_simple_index(leaf_h.as_slice()).unwrap();
        let x = tree.lookup_internal_node(index.index.clone(), index.depth).unwrap().0;
        let path = tree.lookup_path(&index).unwrap();
        assert!(path.verify(&tree.root, &x, &index.to_bit_vector(), &(), NodeType::InternalNode).unwrap());
    }

    #[test]
    fn update_result_test() {
        // simple update
        let mut tree = TestMerkleTree::new(&[0u8; 16], &()).unwrap();
        let leaf = [3u8; 32];
        let leaf_h = hash(&leaf).unwrap();
        let u = tree.update(&leaf).unwrap();
        match u {
            TreeUpdate::ShiftUpdate(op) => {
                assert_eq!(1, 2);
            }
            TreeUpdate::SimpleUpdate(op) => {
                assert_eq!(op.leaf, leaf.to_vec());
            }
        }
        // shift update
        let leaf1 = [0u8; 32];
        let leaf2 = [1u8; 32];
        let leaf_h1: [u8; 32] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let leaf_h2: [u8; 32] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        tree.simple_update(&leaf, &leaf_h1).expect("TODO: panic message");
        let previous_index = tree.get_index_from_hash(&leaf_h1).unwrap();
        let u = tree.shift_update(&leaf2, &leaf_h2, &leaf1, &leaf_h1, previous_index.clone()).unwrap();
        assert_eq!(u.shift_leaf_previous_index, previous_index.clone());
        assert_eq!(u.leaf, leaf2.to_vec());
        assert_eq!(u.shift_leaf, leaf1.to_vec());
    }
}

