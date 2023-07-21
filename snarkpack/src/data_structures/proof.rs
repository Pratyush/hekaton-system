use ark_ec::pairing::{Pairing, PairingOutput};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::io::{Read, Write};

use crate::Error;
use crate::{commitment::Commitment, mmt::data_structures::MMTProof, srs};

/// AggregateProof contains all elements to verify n aggregated Groth16 proofs
/// using inner pairing product arguments. This proof can be created by any
/// party in possession of valid Groth16 proofs.
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct AggregationProof<E: Pairing> {
    /// Commitment to A and B using the pair commitment scheme needed to verify
    /// TIPP relation.
    pub comm_ab: Commitment<E>,
    /// Commitment to C since we use it only in MIPP
    pub comm_c: Commitment<E>,
    /// $A^r * B = Z$ is the left side of the aggregated Groth16 equation
    pub aggregated_ab: PairingOutput<E>,
    /// $C^r$ is used on the right side of the aggregated Groth16 equation
    pub aggregated_c: E::G1Affine,
    /// The TIPP and MIPP proofs
    pub mmt_proof: MMTProof<E>,
}

impl<E: Pairing> PartialEq for AggregationProof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.comm_ab == other.comm_ab
            && self.comm_c == other.comm_c
            && self.aggregated_ab == other.aggregated_ab
            && self.aggregated_c == other.aggregated_c
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
        let all_same = ref_len == gipa.comms_lr_ab.len()
            && ref_len == gipa.comms_lr_c.len()
            && ref_len == gipa.lr_ab.len()
            && ref_len == gipa.lr_c.len();
        if !all_same {
            Err(Error::InvalidProof("Proof vectors unequal sizes".into()))?;
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

    use crate::{commitment::Commitment, kzg::EvaluationProof, mmt::data_structures::GipaProof};
    use ark_bls12_381::{Bls12_381 as Bls12, G1Affine, G2Affine};

    fn fake_proof() -> AggregationProof<Bls12> {
        // create pairing, as pairing results can be compressed
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let a = Bls12::pairing(p, q);

        let proof = AggregationProof::<Bls12> {
            comm_ab: Commitment::new(a, a),
            comm_c: Commitment::new(a, a),
            aggregated_ab: a,
            aggregated_c: G1Affine::generator(),
            mmt_proof: MMTProof::<Bls12> {
                gipa: GipaProof {
                    num_proofs: 4,
                    comms_lr_ab: vec![
                        (Commitment::new(a, a), Commitment::new(a, a)),
                        (Commitment::new(a, a), Commitment::new(a, a)),
                    ],
                    comms_lr_c: vec![
                        (Commitment::new(a, a), Commitment::new(a, a)),
                        (Commitment::new(a, a), Commitment::new(a, a)),
                    ],
                    lr_ab: vec![(a, a), (a, a)],
                    lr_c: vec![
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
            .comms_lr_ab
            .append(&mut vec![(Commitment::new(a, a), Commitment::new(a, a))]);
        proof.parsing_check().expect_err("Proof should be invalid");
    }
}
