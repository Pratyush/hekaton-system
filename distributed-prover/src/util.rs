use crate::eval_tree::{
    ExecTreeLeaf, LeafParam, MerkleRoot, SerializedLeaf, SerializedLeafVar, TreeConfig,
    TwoToOneParam,
};

use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

pub use ark_cp_groth16::data_structures::{Comm as G16Com, ProvingKey as G16ProvingKey};

/// A seed used for the RNG in stage 0 commitments. Each worker saves this and redoes the
/// commitment once it's asked to do stage 1
pub type G16ComSeed = [u8; 32];

const MERKLE_HASH_PARAMS_SEED: &'static [u8; 32] = b"horizontal-snark-hash-param-seed";

pub(crate) fn gen_merkle_params<C>() -> (LeafParam<C>, TwoToOneParam<C>)
where
    C: TreeConfig,
{
    let mut rng = ChaCha12Rng::from_seed(*MERKLE_HASH_PARAMS_SEED);
    (
        <C::LeafHash as CRHScheme>::setup(&mut rng).unwrap(),
        <C::TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap(),
    )
}

pub(crate) fn log2(x: usize) -> usize {
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
