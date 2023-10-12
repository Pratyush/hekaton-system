use crate::{portal_manager::PortalManager, util::log2, CircuitWithPortals};

use ark_crypto_primitives::crh::sha256::{
    constraints::{DigestVar, Sha256Gadget},
    digest::Digest,
    Sha256,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{boolean::Boolean, uint8::UInt8, ToBitsGadget},
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;

pub(crate) type TestLeaf = [u8; 64];
const EMPTY_LEAF: TestLeaf = [0u8; 64];

type InnerHash = [u8; 31];

/// Truncates the SHA256 hash to 31 bytes, converts to bits (each byte to little-endian), and
/// interprets the resulting bitstring as a little-endian-encoded field element
pub(crate) fn digest_to_fpvar<F: PrimeField>(
    digest: DigestVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let bits = digest
        .0
        .into_iter()
        .take(31)
        .flat_map(|byte| byte.to_bits_le().unwrap())
        .collect::<Vec<_>>();
    Boolean::le_bits_to_fp_var(&bits)
}

/// Converts a field element back into the truncated digest that created it
fn fpvar_to_digest<F: PrimeField>(f: FpVar<F>) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let bytes = f
        .to_bits_le()?
        .chunks(8)
        .take(31)
        .map(UInt8::from_bits_le)
        .collect::<Vec<_>>();
    Ok(bytes)
}

/// Takes a digest as public input to the circuit
fn input_digest<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    digest: InnerHash,
) -> Result<FpVar<F>, SynthesisError> {
    // TODO: Make this an actual public input, not just a witness
    let fp = F::from_le_bytes_mod_order(&digest);
    FpVar::new_witness(ns!(cs, "elem"), || Ok(fp))
}

/// The tree thas to be evaluated level-by-level. So we need to be able to map a subcircuit idx to
/// a node in the tree in a specific order
fn subcircuit_idx_to_node_idx(subcircuit_idx: usize, num_leaves: usize) -> u32 {
    let mut i = 0;

    // Create all the node_idxs in order. Stop when i == subcircuit_idx
    for level in 0..=level(root_idx(num_leaves)) {
        // Every index at level l is of the form 0X011...1 where there are l trailing ones
        let upper_half_size = log2(num_leaves) as u32 - level;
        let trailing_ones = (1 << level) - 1;

        for upper_half in 0..(1 << upper_half_size) {
            let node_idx = (upper_half << (level + 1)) + trailing_ones;

            if i == subcircuit_idx {
                return node_idx;
            } else {
                i += 1;
            }
        }
    }

    panic!("invalid subcircuit idx {subcircuit_idx} for a tree of {num_leaves} leaves");
}

#[derive(Clone)]
pub struct MerkleTreeCircuit {
    pub(crate) leaves: Vec<TestLeaf>,
    pub(crate) root_hash: InnerHash,
    pub(crate) params: MerkleTreeCircuitParams,
}

/// Parameters that define the Merkle tree. For now this is just size
// TODO: for benchmarking make a variable number of SHA2 iterations, variable # portal wires,
// variable # witnesses, etc.
#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleTreeCircuitParams {
    /// Number of leaves in this Merkle tree
    pub num_leaves: usize,
    /// Number of times to iterate SHA256 at each node
    pub num_sha_iterations: usize,
    /// Number of outgoing portal wires at each node
    pub num_portals_per_subcircuit: usize,
}

impl MerkleTreeCircuit {
    /// Makes a Merkle tree with a random set of leaves. The size is given by `params`
    pub fn rand(mut rng: impl Rng, &params: &MerkleTreeCircuitParams) -> Self {
        let mut leaves = vec![EMPTY_LEAF; params.num_leaves];
        leaves.iter_mut().for_each(|l| rng.fill(l));
        let root_hash = calculate_root(&leaves, params);
        MerkleTreeCircuit {
            leaves,
            root_hash,
            params,
        }
    }
}

impl MerkleTreeCircuit {
    /// Helper function. Runs SHA256 over the input `self.num_sha_iterations` many times, and
    /// interprets the final hash as a field element
    fn iterated_sha256<F: PrimeField>(
        &self,
        input: &[UInt8<F>],
    ) -> Result<FpVar<F>, SynthesisError> {
        // Set the initial digest to the input
        let mut digest = DigestVar(input.to_vec());
        // Iteratively apply SHA256 to the digest
        for _ in 0..self.params.num_sha_iterations {
            digest = Sha256Gadget::digest(&digest.0)?;
        }

        // Convert the final digest to a field element
        digest_to_fpvar(digest)
    }
}

impl<F: PrimeField> CircuitWithPortals<F> for MerkleTreeCircuit {
    type Parameters = MerkleTreeCircuitParams;

    fn num_subcircuits(&self) -> usize {
        // A tree has 2l - 1 nodes where l is the number of leaves. We pad with 1 extra circuit to
        // get to a power of two
        2 * self.leaves.len()
    }

    fn get_params(&self) -> MerkleTreeCircuitParams {
        self.params
    }

    // Make a new empty merkle tree circuit
    fn new(&params: &Self::Parameters) -> Self {
        assert!(
            params.num_sha_iterations > 0,
            "cannot have 0 SHA256 iterations in test circuit"
        );

        let leaves = vec![EMPTY_LEAF; params.num_leaves];
        // Set the default root hash
        let root_hash = InnerHash::default();

        MerkleTreeCircuit {
            leaves,
            root_hash,
            params,
        }
    }

    fn get_serialized_witnesses(&self, subcircuit_idx: usize) -> Vec<u8> {
        let num_leaves = self.leaves.len();
        let num_subcircuits = <Self as CircuitWithPortals<F>>::num_subcircuits(&self);
        let mut out_buf = Vec::new();

        // If this is a padding circuit, return nothing
        if subcircuit_idx == num_subcircuits - 1 {
            return Vec::with_capacity(0);
        }

        // The witnesses for subcircuit i is either a leaf value (in the case this is a leaf) or a
        // root hash (if this is the root)

        // The subcircuit ordering is level by level. Pick the right node idx
        let node_idx = subcircuit_idx_to_node_idx(subcircuit_idx, num_leaves);

        let is_leaf = level(node_idx) == 0;
        let is_root = root_idx(num_leaves) == node_idx;

        // If this is a leaf, return the serialized leaf val
        if is_leaf {
            // Which number leaf is it
            let leaf_idx = (node_idx / 2) as usize;
            let leaf = self.leaves.get(leaf_idx).unwrap();
            leaf.serialize_uncompressed(&mut out_buf).unwrap();
        } else if is_root {
            self.root_hash.serialize_uncompressed(&mut out_buf).unwrap();
        }

        out_buf
    }

    fn set_serialized_witnesses(&mut self, subcircuit_idx: usize, bytes: &[u8]) {
        let num_leaves = self.leaves.len();
        let num_subcircuits = <Self as CircuitWithPortals<F>>::num_subcircuits(&self);

        // If this is a padding circuit, do nothing
        if subcircuit_idx == num_subcircuits - 1 {
            return;
        }

        // The witnesses for subcircuit i is either a leaf value (in the case this is a leaf) or a
        // root hash (if this is the root)

        // The subcircuit ordering is level by level. Pick the right node idx
        let node_idx = subcircuit_idx_to_node_idx(subcircuit_idx, num_leaves);

        let is_leaf = level(node_idx) == 0;
        let is_root = root_idx(num_leaves) == node_idx;

        // If this is a leaf, return the serialized leaf val
        if is_leaf {
            // Which number leaf is it
            let leaf_idx = (node_idx / 2) as usize;
            let leaf = TestLeaf::deserialize_uncompressed_unchecked(bytes).unwrap();
            self.leaves[leaf_idx] = leaf;
        } else if is_root {
            self.root_hash = InnerHash::deserialize_uncompressed_unchecked(bytes).unwrap();
        }
    }

    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError> {
        let starting_num_constraints = cs.num_constraints();

        // Special padding subcircuit. If it's the last subcircuit, do nothing. This pads us out to
        // a power of two
        if subcircuit_idx == <Self as CircuitWithPortals<F>>::num_subcircuits(&self) - 1 {
            return Ok(());
        }

        let num_leaves = self.leaves.len();

        // The subcircuit ordering is level by level. Pick the right node idx
        let node_idx = subcircuit_idx_to_node_idx(subcircuit_idx, num_leaves);

        let is_leaf = level(node_idx) == 0;
        let is_root = root_idx(num_leaves) == node_idx;

        if is_leaf {
            // Which number leaf is it
            let leaf_idx = (node_idx / 2) as usize;

            // Witness the leaf
            let leaf_var = UInt8::new_witness_vec(ns!(cs, "leaf"), &self.leaves[leaf_idx])?;

            // Compute the leaf hash and store it in the portal manager
            let leaf_hash = self.iterated_sha256(&leaf_var)?;
            pm.set(format!("node {node_idx} hash"), &leaf_hash)?;
        } else {
            // This is a non-root parent node. Get the left and right hashes
            let left = left_child(node_idx);
            let right = right_child(node_idx);
            let left_child_hash = pm.get(&format!("node {left} hash"))?;
            let right_child_hash = pm.get(&format!("node {right} hash"))?;

            // Convert the hashes back into bytes and concat them
            let left_bytes = fpvar_to_digest(left_child_hash)?;
            let right_bytes = fpvar_to_digest(right_child_hash)?;
            let concatted_bytes = [left_bytes, right_bytes].concat();

            // Compute the parent hash and store it in the portal manager
            let parent_hash = self.iterated_sha256(&concatted_bytes)?;
            pm.set(format!("node {node_idx} hash"), &parent_hash)?;

            // Finally, if this is the root, verify that the parent hash equals the public hash
            // value
            if is_root {
                let expected_root_hash = input_digest(cs.clone(), self.root_hash)?;
                parent_hash.enforce_equal(&expected_root_hash)?;
            }
        }

        // Print out how big this circuit was
        let ending_num_constraints = cs.num_constraints();
        let ty = if is_leaf {
            "leaf"
        } else if is_root {
            "root"
        } else {
            "parent"
        };
        println!(
            "Test subcircuit {subcircuit_idx} of type {ty} costs {} constraints",
            ending_num_constraints - starting_num_constraints
        );

        Ok(())
    }
}

// Calculates the Merkle tree root in the same way as is calculated above. That is, truncating each
// hash to 31 bytes, and computing parents as H(left || right).
pub(crate) fn calculate_root(leaves: &[TestLeaf], params: MerkleTreeCircuitParams) -> InnerHash {
    // A helper function
    let iterated_sha256 = |input: &[u8]| {
        let mut digest = input.to_vec();
        for _ in 0..params.num_sha_iterations {
            digest = Sha256::digest(&digest).to_vec();
        }

        // Output the final digest
        let mut outbuf = [0u8; 32];
        outbuf.copy_from_slice(&digest);
        outbuf
    };

    // Compute all the leaf digests
    let mut cur_level = leaves
        .iter()
        .map(|leaf| iterated_sha256(leaf))
        .collect::<Vec<_>>();

    // Compute all the parents level by level until there's only 1 element left (the root)
    let mut next_level = Vec::new();
    while cur_level.len() > 1 {
        for siblings in cur_level.chunks(2) {
            let left = siblings[0];
            let right = siblings[1];
            let parent = iterated_sha256(&[&left[..31], &right[..31]].concat());
            next_level.push(parent)
        }

        cur_level = next_level.clone();
        next_level.clear();
    }

    let mut root = [0u8; 31];
    root.copy_from_slice(&cur_level[0][..31]);
    root
}

/******** TREE MATH ********/

// We use a mapping of subcircuit idx to tree node as follows. Stolen from the MLS spec
//
//                              X
//                              |
//                    .---------+---------.
//                   /                     \
//                  X                       X
//                  |                       |
//              .---+---.               .---+---.
//             /         \             /         \
//            X           X           X           X
//           / \         / \         / \         / \
//          /   \       /   \       /   \       /   \
//         X     X     X     X     X     X     X     X
//
//   Node: 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14

// The level of an internal node is how "odd" it is, i.e., how many trailing ones it has in its
// binary representation
fn level(node: u32) -> u32 {
    node.trailing_ones()
}

pub(crate) fn left_child(node: u32) -> u32 {
    let k = level(node);
    assert_ne!(k, 0, "cannot compute the child of a level-0 node");

    node ^ (0x01 << (k - 1))
}

pub(crate) fn right_child(node: u32) -> u32 {
    let k = level(node);
    assert_ne!(k, 0, "cannot compute the child of a level-0 node");

    node ^ (0x03 << (k - 1))
}

/// The number of internal nodes necessary to represent a tree with `num_leaves` leaves.
fn num_internal_nodes(num_leaves: usize) -> usize {
    if num_leaves < 2 {
        0
    } else {
        2 * (num_leaves - 1) + 1
    }
}

fn root_idx(num_leaves: usize) -> u32 {
    let w = num_internal_nodes(num_leaves);
    (1 << log2(w)) - 1
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{portal_manager::SetupPortalManager, CircuitWithPortals};
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{rand::Rng, test_rng};

    // Digests truncated to 31 bytes and stored as portal wires. When we get the portal wire, we
    // have to unpack back into bytes. This test checks that the structure is preserved
    // preserves their structure.
    #[test]
    fn test_digest_fpvar_roundtrip() {
        let mut rng = test_rng();
        let cs = ConstraintSystemRef::<Fr>::new(ConstraintSystem::default());

        for _ in 0..10 {
            // Pick a random digest
            let digest: [u8; 32] = rng.gen();
            let digest_var = DigestVar(UInt8::new_input_vec(ns!(cs, "digest"), &digest).unwrap());

            // Convert to an FpVar. This truncates to 31 bytes
            let fp = digest_to_fpvar(digest_var.clone()).unwrap();

            // Convert back into a digest
            let digest_again = fpvar_to_digest(fp).unwrap();

            // Check that the resulting value equals the original truncated digest
            digest_again.enforce_equal(&digest_var.0[..31]).unwrap();
            assert!(cs.is_satisfied().unwrap());
        }
    }

    /// Tests that the circuit's Merkle root matches the one computed natively
    #[test]
    fn test_merkle_tree_correctness() {
        let mut rng = test_rng();
        let circ_params = MerkleTreeCircuitParams {
            num_leaves: 16,
            num_sha_iterations: 2,
            num_portals_per_subcircuit: 1,
        };

        // Make a random Merkle tree
        let mut circ = MerkleTreeCircuit::rand(&mut rng, &circ_params);

        // Make a fresh portal manager
        let cs = ConstraintSystemRef::<Fr>::new(ConstraintSystem::default());
        let mut pm = SetupPortalManager::new(cs.clone());
        // Make it all one subtrace. We're not really testing this part
        pm.start_subtrace();

        let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);
        for subcircuit_idx in 0..num_subcircuits {
            circ.generate_constraints(cs.clone(), subcircuit_idx, &mut pm)
                .unwrap();
        }

        assert!(cs.is_satisfied().unwrap());
    }
}
