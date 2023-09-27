use crate::{portal_manager::PortalManager, CircuitWithPortals};

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

type TestLeaf = [u8; 32];
type InnerHash = [u8; 31];

struct MerkleTreeCircuit {
    leaves: Vec<TestLeaf>,
    root_hash: InnerHash,
}

/// Truncates the SHA256 hash to 31 bytes, converts to bits (each byte to little-endian), and
/// interprets the resulting bitstring as a little-endian-encoded field element
fn digest_to_fpvar<F: PrimeField>(digest: DigestVar<F>) -> Result<FpVar<F>, SynthesisError> {
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
    let bits = digest
        .into_iter()
        .flat_map(u8_le_bits)
        .map(|bit| Boolean::new_witness(ns!(cs, "bit"), || Ok(bit)))
        .collect::<Result<Vec<_>, _>>()?;
    Boolean::le_bits_to_fp_var(&bits)
}

impl<F: PrimeField> CircuitWithPortals<F> for MerkleTreeCircuit {
    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError> {
        let node_idx = subcircuit_idx as u32;

        let is_leaf = level(node_idx) == 0;
        let is_root = root_idx(self.leaves.len()) == node_idx;

        if is_leaf {
            // Every leaf idx is even
            let leaf_idx = (node_idx / 2) as usize;

            // Witness the leaf
            let leaf_var = UInt8::new_witness_vec(ns!(cs, "leaf"), &self.leaves[leaf_idx])?;

            // Compute the leaf hash and store it in the portal manager
            let leaf_hash = {
                let mut hasher = Sha256Gadget::default();
                hasher.update(&leaf_var)?;
                let digest = hasher.finalize()?;
                digest_to_fpvar(digest)?
            };
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
            let parent_hash = {
                let mut hasher = Sha256Gadget::default();
                hasher.update(&concatted_bytes)?;
                let digest = hasher.finalize()?;
                digest_to_fpvar(digest)?
            };
            pm.set(format!("node {node_idx} hash"), &parent_hash)?;

            // Finally, if this is the root, verify that the parent hash equals the public hash
            // value
            if is_root {
                let expected_root_hash = input_digest(cs.clone(), self.root_hash)?;
                parent_hash.enforce_equal(&expected_root_hash)?;
            }
        }

        Ok(())
    }
}

// Calculates the Merkle tree root in the same way as is calculated above. That is, truncating each
// hash to 31 bytes, and computing parents as H(left || right).
pub(crate) fn calculate_root(leaves: &[TestLeaf]) -> InnerHash {
    // Compute all the leaf digests
    let mut cur_level = leaves.iter().map(Sha256::digest).collect::<Vec<_>>();

    // Compute all the parents level by level until there's only 1 element left (the root)
    let mut next_level = Vec::new();
    while cur_level.len() > 1 {
        for siblings in cur_level.chunks(2) {
            let left = siblings[0];
            let right = siblings[1];
            let parent = Sha256::digest([&left[..31], &right[..31]].concat());
            next_level.push(parent)
        }

        cur_level = next_level.clone();
        next_level.clear();
    }

    let mut root = [0u8; 31];
    root.copy_from_slice(&cur_level[0][..31]);
    root
}

/// Converts a u8 to its little-endian bit representation
fn u8_le_bits(x: u8) -> [bool; 8] {
    [
        x & 0b00000001 != 0,
        x & 0b00000010 != 0,
        x & 0b00000100 != 0,
        x & 0b00001000 != 0,
        x & 0b00010000 != 0,
        x & 0b00100000 != 0,
        x & 0b01000000 != 0,
        x & 0b10000000 != 0,
    ]
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

fn log2(x: usize) -> usize {
    // We set log2(0) == 0
    if x == 0 {
        0
    } else {
        let mut k = 0;
        while (x >> k) > 0 {
            k += 1;
        }
        k - 1
    }
}

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
    use crate::portal_manager::SetupPortalManager;
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
        let num_leaves = 16;

        // Make a Merkle tree with a random set of leaves
        let mut leaves = vec![TestLeaf::default(); num_leaves];
        leaves.iter_mut().for_each(|l| rng.fill(l));
        let root_hash = calculate_root(&leaves);
        let mut circ = MerkleTreeCircuit { leaves, root_hash };

        // Make a fresh portal manager
        let cs = ConstraintSystemRef::<Fr>::new(ConstraintSystem::default());
        let mut pm = SetupPortalManager::new(cs.clone());

        // Evaluate the tree level by level. Parents need the values of their children before they
        // can run.
        for level in 0..=level(root_idx(num_leaves)) {
            // Every index at level l is of the form 0X011...1 where there are l trailing ones
            let upper_half_size = log2(num_leaves) as u32 - level;
            let trailing_ones = (1 << level) - 1;

            for upper_half in 0..(1 << upper_half_size) {
                let subcircuit_idx = (upper_half << (level + 1)) + trailing_ones;

                circ.generate_constraints(cs.clone(), subcircuit_idx, &mut pm)
                    .unwrap();
            }
        }

        assert!(cs.is_satisfied().unwrap());
    }
}
