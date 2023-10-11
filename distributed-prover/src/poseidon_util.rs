use crate::eval_tree::{ExecTreeParams, SerializedLeaf, SerializedLeafVar};

use ark_bls12_381::Fr;
use ark_crypto_primitives::{
    crh::{
        constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
        poseidon, CRHScheme, TwoToOneCRHScheme,
    },
    merkle_tree::{
        constraints::ConfigGadget as TreeConfigGadget, Config as TreeConfig,
        IdentityDigestConverter,
    },
    sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonDefaultConfigEntry},
};
use ark_ff::PrimeField;

// Define all the leaf and two-to-one hashes for Poseidon
pub type LeafH = poseidon::CRH<Fr>;
pub type LeafHG = poseidon::constraints::CRHGadget<Fr>;
pub type CompressH = poseidon::TwoToOneCRH<Fr>;
pub type CompressHG = poseidon::constraints::TwoToOneCRHGadget<Fr>;

// Define the structs necessary to make a Merkle tree over the Poseidon hash

#[derive(Clone)]
pub struct PoseidonTreeConfig;
impl TreeConfig for PoseidonTreeConfig {
    type Leaf = SerializedLeaf<Fr>;

    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;

    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<Self::LeafDigest>;
    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;
}

pub struct PoseidonTreeConfigVar;
impl TreeConfigGadget<PoseidonTreeConfig, Fr> for PoseidonTreeConfigVar {
    type Leaf = SerializedLeafVar<Fr>;

    type LeafDigest = <LeafHG as CRHSchemeGadget<LeafH, Fr>>::OutputVar;
    type LeafInnerConverter = IdentityDigestConverter<Self::LeafDigest>;
    type InnerDigest = <CompressHG as TwoToOneCRHSchemeGadget<CompressH, Fr>>::OutputVar;
    type LeafHash = LeafHG;
    type TwoToOneHash = CompressHG;
}

// Generates Poseidon params for BLS12-381. This is copied from
//     https://github.com/arkworks-rs/crypto-primitives/blob/54b3ac24b8943fbd984863558c749997e96ff399/src/sponge/poseidon/traits.rs#L69
// and
//     https://github.com/arkworks-rs/crypto-primitives/blob/54b3ac24b8943fbd984863558c749997e96ff399/src/sponge/test.rs
fn gen_poseidon_params(rate: usize, optimized_for_weights: bool) -> PoseidonConfig<Fr> {
    let params_set = if !optimized_for_weights {
        [
            PoseidonDefaultConfigEntry::new(2, 17, 8, 31, 0),
            PoseidonDefaultConfigEntry::new(3, 5, 8, 56, 0),
            PoseidonDefaultConfigEntry::new(4, 5, 8, 56, 0),
            PoseidonDefaultConfigEntry::new(5, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(6, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(7, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(8, 5, 8, 57, 0),
        ]
    } else {
        [
            PoseidonDefaultConfigEntry::new(2, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(3, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(4, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(5, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(6, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(7, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(8, 257, 8, 13, 0),
        ]
    };

    for param in params_set.iter() {
        if param.rate == rate {
            let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
                Fr::MODULUS_BIT_SIZE as u64,
                rate,
                param.full_rounds as u64,
                param.partial_rounds as u64,
                param.skip_matrices as u64,
            );

            return PoseidonConfig {
                full_rounds: param.full_rounds,
                partial_rounds: param.partial_rounds,
                alpha: param.alpha as u64,
                ark,
                mds,
                rate: param.rate,
                capacity: 1,
            };
        }
    }

    panic!("could not generate poseidon params");
}

/// Returns leaf and two-to-one params for a Poseidon Merkle tree
pub fn gen_merkle_params() -> ExecTreeParams<PoseidonTreeConfig> {
    ExecTreeParams {
        leaf_params: gen_poseidon_params(3, false),
        two_to_one_params: gen_poseidon_params(2, false),
    }
}
