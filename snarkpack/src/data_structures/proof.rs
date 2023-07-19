use ark_ec::pairing::{Pairing, PairingOutput};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize 
};
use std::io::{Read, Write};

use crate::Error;
use crate::{
    mmt::data_structures::MMTProof,
    commitment::Commitment,
    srs,
};

/// AggregateProof contains all elements to verify n aggregated Groth16 proofs
/// using inner pairing product arguments. This proof can be created by any
/// party in possession of valid Groth16 proofs.
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct AggregationProof<E: Pairing> {
    /// Commitment to A and B using the pair commitment scheme needed to verify
    /// TIPP relation.
    pub com_ab: Commitment<E>,
    /// Commitment to C since we use it only in MIPP
    pub com_c: Commitment<E>,
    /// $A^r * B = Z$ is the left side of the aggregated Groth16 equation
    pub ip_ab: PairingOutput<E>,
    /// $C^r$ is used on the right side of the aggregated Groth16 equation
    pub agg_c: E::G1Affine,
    /// The TIPP and MIPP proofs
    pub mmt_proof: MMTProof<E>,
}

impl<E: Pairing> PartialEq for AggregationProof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.com_ab == other.com_ab
            && self.com_c == other.com_c
            && self.ip_ab == other.ip_ab
            && self.agg_c == other.agg_c
            && self.mmt_proof == other.mmt_proof
    }
}

impl<E: Pairing> AggregationProof<E> {
    /// Performs some high level checks on the length of vectors and others to
    /// make sure all items in the proofs are consistent with each other.
    pub fn parsing_check(&self) -> Result<(), Error> {
        let gipa = &self.mmt_proof.gipa;
        // 1. Check length of the proofs
        if gipa.num_proofs < 2 || gipa.num_proofs as usize > srs::MAX_SRS_SIZE {
            return Err(Error::InvalidProof(
                "Proof length out of bounds".to_string(),
            ));
        }
        // 2. Check if it's a power of two
        if !gipa.num_proofs.is_power_of_two() {
            return Err(Error::InvalidProof(
                "Proof length not a power of two".to_string(),
            ));
        }
        // 3. Check all vectors are of the same length and of the correct length
        let ref_len = (gipa.num_proofs as f32).log2().ceil() as usize;
        let all_same = ref_len == gipa.comms_ab.len()
            && ref_len == gipa.comms_c.len()
            && ref_len == gipa.z_ab.len()
            && ref_len == gipa.z_c.len();
        if !all_same {
            return Err(Error::InvalidProof(
                "Proof vectors unequal sizes".to_string(),
            ));
        }
        Ok(())
    }

    /// Writes the aggregate proof to the given destination. This method is for
    /// high level protocol to use it as a library. If you want to use within
    /// another arkwork protocol, you can use the underlying implementation of
    /// `CanonicalSerialize`.
    pub fn write(&self, out: impl Write) -> Result<(), Error> {
        self.serialize_compressed(out)
            .map_err(|e| Error::Serialization(e))
    }

    /// Reads the aggregate proof to the given destination. This method is for
    /// high level protocol to use it as a library. If you want to use within
    /// another arkwork protocol, you can use the underlying implementation of
    /// `CanonicalSerialize`.
    pub fn read(source: impl Read) -> Result<Self, Error> {
        Self::deserialize_compressed(source).map_err(|e| Error::Serialization(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;

    use crate::{commitment::Commitment, mmt::data_structures::GipaProof, kzg::EvaluationProof};
    use ark_bls12_381::{Bls12_381 as Bls12, G1Affine, G2Affine};

    fn fake_proof() -> AggregationProof<Bls12> {
        // create pairing, as pairing results can be compressed
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let a = Bls12::pairing(p, q);

        let proof = AggregationProof::<Bls12> {
            com_ab: Commitment(a, a),
            com_c: Commitment(a, a),
            ip_ab: a,
            agg_c: G1Affine::generator(),
            mmt_proof: MMTProof::<Bls12> {
                gipa: GipaProof {
                    num_proofs: 4,
                    comms_ab: vec![(Commitment(a, a), Commitment(a, a)), (Commitment(a, a), Commitment(a, a))],
                    comms_c: vec![(Commitment(a, a), Commitment(a, a)), (Commitment(a, a), Commitment(a, a))],
                    z_ab: vec![(a, a), (a, a)],
                    z_c: vec![
                        (G1Affine::generator(), G1Affine::generator()),
                        (G1Affine::generator(), G1Affine::generator()),
                    ],
                    final_a: G1Affine::generator(),
                    final_b: G2Affine::generator(),
                    final_c: G1Affine::generator(),
                    final_vkey: (G2Affine::generator(), G2Affine::generator()),
                    final_wkey: (G1Affine::generator(), G1Affine::generator()),
                },
                vkey_opening: EvaluationProof(G2Affine::generator(), G2Affine::generator()),
                wkey_opening: EvaluationProof(G1Affine::generator(), G1Affine::generator()),
            },
        };
        proof
    }

    #[test]
    fn test_proof_io() {
        let proof = fake_proof();
        let mut buffer = Vec::new();
        proof.write(&mut buffer).unwrap();
        let out = AggregationProof::<Bls12>::read(std::io::Cursor::new(&buffer)).unwrap();
        assert_eq!(proof, out);
    }

    #[test]
    fn test_proof_check() {
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let a = Bls12::pairing(p, q);

        let mut proof = fake_proof();
        proof.parsing_check().expect("proof should be valid");

        let oldn = proof.mmt_proof.gipa.num_proofs;
        proof.mmt_proof.gipa.num_proofs = 14;
        proof.parsing_check().expect_err("proof should be invalid");
        proof.mmt_proof.gipa.num_proofs = oldn;

        proof
            .mmt_proof
            .gipa
            .comms_ab
            .append(&mut vec![(Commitment(a, a), Commitment(a, a))]);
        proof.parsing_check().expect_err("Proof should be invalid");
    }
}
