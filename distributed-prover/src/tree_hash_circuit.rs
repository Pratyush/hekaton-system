use crate::{portal_manager::PortalManager, CircuitWithPortals};

use ark_crypto_primitives::crh::sha256::constraints::{DigestVar, Sha256Gadget};
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

type TestLeaf = [u8; 31];
type Digest = [u8; 31];

struct MerkleTreeCircuit {
    leaves: Vec<TestLeaf>,
    root_hash: Digest,
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

/// Takes a digest as public input to the circuit
fn input_digest<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    digest: Digest,
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
            let left_bytes = left_child_hash
                .to_bits_le()?
                .chunks(8)
                .map(UInt8::from_bits_le)
                .collect::<Vec<_>>();
            let right_bytes = right_child_hash
                .to_bits_le()?
                .chunks(8)
                .map(UInt8::from_bits_le)
                .collect::<Vec<_>>();
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

// TREE MATH //

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

    #[test]
    fn test_merkle_tree_runs() {
        let mut rng = test_rng();
        // Make a random set of leaves
        let mut leaves = vec![TestLeaf::default(); 16];
        leaves.iter_mut().for_each(|l| rng.fill(l));

        let mut circ = MerkleTreeCircuit {
            leaves,
            root_hash: Digest::default(),
        };
        let cs = ConstraintSystemRef::<Fr>::new(ConstraintSystem::default());
        let mut pm = SetupPortalManager::new(cs.clone());
        let subcircuit_idx = 0;
        circ.generate_constraints(cs, subcircuit_idx, &mut pm)
            .unwrap();
    }
}
