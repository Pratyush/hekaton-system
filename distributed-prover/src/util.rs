use crate::eval_tree::{
    ExecTreeLeaf, LeafParam, MerkleRoot, SerializedLeaf, SerializedLeafVar, TreeConfig,
    TwoToOneParam,
};

use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

pub use ark_cp_groth16::data_structures::{
    Comm as G16Com, Proof as G16Proof, ProvingKey as G16ProvingKey,
};
pub use merlin::Transcript as ProtoTranscript;

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

// Convenience functions for generateing Fiat-Shamir challenges
pub(crate) trait TranscriptProtocol {
    /// Appends a CanonicalSerialize-able element to the transcript. Panics on serialization error.
    fn append_serializable<S>(&mut self, label: &'static [u8], val: &S)
    where
        S: CanonicalSerialize + ?Sized;

    /// Produces a pseudorandom field element from the current transcript
    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F;
}

impl TranscriptProtocol for ProtoTranscript {
    /// Appends a CanonicalSerialize-able element to the transcript. Panics on serialization error.
    fn append_serializable<S>(&mut self, label: &'static [u8], val: &S)
    where
        S: CanonicalSerialize + ?Sized,
    {
        // Serialize the input and give it to the transcript
        let mut buf = Vec::new();
        val.serialize_uncompressed(&mut buf)
            .expect("serialization error in transcript");
        self.append_message(label, &buf);
    }

    /// Produces a pseudorandom field element from the current transcript
    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F {
        // Fill a buf with random bytes
        let mut buf = <<ChaCha12Rng as SeedableRng>::Seed as Default>::default();
        self.challenge_bytes(label, &mut buf);

        // Use the buf to make an RNG. Then use that RNG to generate a field element
        let mut rng = ChaCha12Rng::from_seed(buf);
        F::rand(&mut rng)
    }
}
