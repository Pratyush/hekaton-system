use crate::eval_tree::{
    ExecTreeLeaf, LeafParam, MerkleRoot, SerializedLeaf, SerializedLeafVar, TreeConfig,
    TwoToOneParam,
};

use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::{fs::File, io, path::PathBuf};

pub use ark_cp_groth16::data_structures::{
    Comm as G16Com, CommitterKey as G16ComKey, Proof as G16Proof, ProvingKey as G16ProvingKey,
};
pub use merlin::Transcript as ProtoTranscript;

/// A seed used for the RNG in stage 0 commitments. Each worker saves this and redoes the
/// commitment once it's asked to do stage 1
pub type G16ComSeed = [u8; 32];

const MERKLE_HASH_PARAMS_SEED: &'static [u8; 32] = b"horizontal-snark-hash-param-seed";

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

// Helpers for the binaries

pub mod cli_filenames {
    pub const G16_PK_FILENAME_PREFIX: &str = "g16_pk";
    pub const G16_CK_FILENAME_PREFIX: &str = "g16_ck";
    pub const AGG_CK_FILENAME_PREFIX: &str = "agg_ck";
    pub const STAGE0_REQ_FILENAME_PREFIX: &str = "stage0_req";
    pub const STAGE0_RESP_FILENAME_PREFIX: &str = "stage0_resp";
    pub const STAGE1_REQ_FILENAME_PREFIX: &str = "stage1_req";
    pub const STAGE1_RESP_FILENAME_PREFIX: &str = "stage1_resp";
    pub const TEST_CIRC_PARAM_FILENAME_PREFIX: &str = "test_circ_params";
    pub const STAGE0_COORD_STATE_FILENAME_PREFIX: &str = "stage0_coordinator_state";
    pub const FINAL_AGG_STATE_FILENAME_PREFIX: &str = "final_aggregator_state";
    pub const FINAL_PROOF_PREFIX: &str = "agg_proof";
}

/// Serializes the given value to "DIR/FILENAMEPREFIX_INDEX". The "_INDEX" part is ommitted if no
/// index is given.
pub fn serialize_to_path<T: CanonicalSerialize>(
    val: &T,
    dir: &PathBuf,
    filename_prefix: &str,
    index: Option<usize>,
) -> io::Result<()> {
    let idx_str = if let Some(i) = index {
        format!("_{i}")
    } else {
        "".to_string()
    };
    let filename = format!("{}{}.bin", filename_prefix, idx_str);

    let file_path = dir.join(filename);

    let mut f = File::create(file_path)?;
    val.serialize_uncompressed(&mut f).unwrap();

    Ok(())
}

/// Deserializes "DIR/FILENAMEPREFIX_INDEX" to the given type. The "_INDEX" part is ommitted if no
/// index is given.
pub fn deserialize_from_path<T: CanonicalDeserialize>(
    dir: &PathBuf,
    filename_prefix: &str,
    index: Option<usize>,
) -> io::Result<T> {
    let idx_str = if let Some(i) = index {
        format!("_{i}")
    } else {
        "".to_string()
    };
    let filename = format!("{}{}.bin", filename_prefix, idx_str);

    let file_path = dir.join(filename);
    let mut f = File::open(&file_path).expect(&format!("couldn't open file {:?}", file_path));
    Ok(T::deserialize_uncompressed_unchecked(&mut f).unwrap())
}
