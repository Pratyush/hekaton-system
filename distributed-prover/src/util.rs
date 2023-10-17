use std::{
    io,
    // fs::File,
    // io::{self, Read, Write},
    // os,
    path::PathBuf,
};

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use rayon::prelude::*;

pub use ark_cp_groth16::{
    committer::CommitmentBuilder as G16CommitmentBuilder,
    data_structures::{
        Comm as G16Com, CommRandomness as G16ComRandomness, CommitterKey as G16ComKey,
        Proof as G16Proof, ProvingKey as G16ProvingKey,
    },
    r1cs_to_qap::LibsnarkReduction as QAP,
};
pub use merlin::Transcript as ProtoTranscript;

/// A seed used for the RNG in stage 0 commitments. Each worker saves this and redoes the
/// commitment once it's asked to do stage 1
pub type G16ComSeed = [u8; 32];

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
    // let idx_str = if let Some(i) = index {
    //     format!("_{i}")
    // } else {
    //     "".to_string()
    // };
    // let filename = format!("{}{}.bin", filename_prefix, idx_str);

    // let file_path = dir.join(filename);

    // let start0 = start_timer!(|| "Serializing value");
    // let mut buf = Vec::new();
    // val.serialize_uncompressed(&mut buf).unwrap();
    // end_timer!(start0);

    // let start1 = start_timer!(|| format!("Writing to file {:?}", file_path));
    // let mut f = File::create(file_path)?;
    // f.write_all(&buf)?;
    // end_timer!(start1);

    Ok(())
}

/// Serializes the given value to "DIR/FILENAMEPREFIX_INDEX1", "DIR/FILENAMEPREFIX_INDEX2", etc..
/// The "_INDEX" part is ommitted if no index is given.
pub fn serialize_to_paths<T: CanonicalSerialize>(
    val: &T,
    dir: &PathBuf,
    filename_prefix: &str,
    indices: core::ops::Range<usize>,
) -> io::Result<()> {
    // let start0 = start_timer!(|| "Serializing value");
    // let mut buf = Vec::new();
    // val.serialize_uncompressed(&mut buf).unwrap();
    // end_timer!(start0);

    // // Write the first file for real
    // let first_file_path = {
    //     let first_idx = indices.start;
    //     let filename = format!("{filename_prefix}_{first_idx}.bin");
    //     dir.join(filename)
    // };
    // let start1 = start_timer!(|| format!("Writing to file {:?}", first_file_path));
    // let mut f = File::create(&first_file_path)?;
    // f.write_all(&buf)?;
    // end_timer!(start1);

    // // For all the remaining files, just make symlinks to the first file
    // let start2 = start_timer!(|| format!("Symlinking {} times", indices.len()));
    // indices
    //     .into_par_iter()
    //     .skip(1)
    //     .map(|i| {
    //         let filename = format!("{filename_prefix}_{i}.bin");
    //         let new_file_path = dir.join(filename);

    //         os::unix::fs::symlink(&first_file_path, &new_file_path)
    //     })
    //     .collect::<io::Result<()>>()?;
    // end_timer!(start2);

    Ok(())
}

/// Deserializes "DIR/FILENAMEPREFIX_INDEX" to the given type. The "_INDEX" part is ommitted if no
/// index is given.
pub fn deserialize_from_path<T: CanonicalDeserialize>(
    dir: &PathBuf,
    filename_prefix: &str,
    index: Option<usize>,
) -> io::Result<T> {
    // let idx_str = if let Some(i) = index {
    //     format!("_{i}")
    // } else {
    //     "".to_string()
    // };
    // let filename = format!("{}{}.bin", filename_prefix, idx_str);

    // let file_path = dir.join(filename);
    // let mut buf = Vec::new();
    // let start0 = start_timer!(|| format!("Reading from file {:?}", file_path));
    // let mut f = File::open(&file_path).expect(&format!("couldn't open file {:?}", file_path));
    // let _ = f.read_to_end(&mut buf)?;
    // end_timer!(start0);

    // let start1 = start_timer!(|| "Deserializing value");
    // let val = T::deserialize_uncompressed_unchecked(buf.as_slice()).unwrap();
    // end_timer!(start1);

    // Ok(val)
    todo!()
}
