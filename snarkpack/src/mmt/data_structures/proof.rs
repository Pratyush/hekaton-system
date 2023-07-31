use crate::{commitment::Commitment, kzg::EvaluationProof};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use ark_std::io::{Read, Write};

/// It contains all elements derived in the GIPA loop for both TIPP and MIPP at
/// the same time.
#[derive(Debug, Clone)]
pub struct GipaProof<E: Pairing> {
    pub num_proofs: u32,
    pub comms_lr_ab: Vec<(Commitment<E>, Commitment<E>)>,
    pub comms_lr_c: Vec<(Commitment<E>, Commitment<E>)>,
    pub lr_ab: Vec<(PairingOutput<E>, PairingOutput<E>)>,
    pub lr_c: Vec<(E::G1Affine, E::G1Affine)>,
    pub final_a: E::G1Affine,
    pub final_b: E::G2Affine,
    pub final_c: E::G1Affine,
    /// final commitment keys $v$ and $w$ - there is only one element at the
    /// end for v1 and v2 hence it's a tuple.
    pub final_vkey: (E::G2Affine, E::G2Affine),
    pub final_wkey: (E::G1Affine, E::G1Affine),
}

impl<E: Pairing> PartialEq for GipaProof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.num_proofs == other.num_proofs
            && self.comms_lr_ab == other.comms_lr_ab
            && self.comms_lr_c == other.comms_lr_c
            && self.lr_ab == other.lr_ab
            && self.lr_c == other.lr_c
            && self.final_a == other.final_a
            && self.final_b == other.final_b
            && self.final_c == other.final_c
            && self.final_vkey == other.final_vkey
            && self.final_wkey == other.final_wkey
    }
}

impl<E: Pairing> GipaProof<E> {
    fn log_num_proofs(nproofs: usize) -> usize {
        (nproofs as f32).log2().ceil() as usize
    }
}

impl<E: Pairing> CanonicalSerialize for GipaProof<E> {
    fn serialized_size(&self, compress: Compress) -> usize {
        let log_proofs = Self::log_num_proofs(self.num_proofs as usize);
        (self.num_proofs as u32).serialized_size(compress)
            + log_proofs
                * (self.comms_lr_ab[0].0.serialized_size(compress)
                    + self.comms_lr_ab[0].1.serialized_size(compress)
                    + self.comms_lr_c[0].0.serialized_size(compress)
                    + self.comms_lr_c[0].1.serialized_size(compress)
                    + self.lr_ab[0].0.serialized_size(compress)
                    + self.lr_ab[0].1.serialized_size(compress)
                    + self.lr_c[0].0.serialized_size(compress)
                    + self.lr_c[0].1.serialized_size(compress)
                    + self.final_a.serialized_size(compress)
                    + self.final_b.serialized_size(compress)
                    + self.final_c.serialized_size(compress)
                    + self.final_vkey.serialized_size(compress)
                    + self.final_wkey.serialized_size(compress))
    }

    fn serialize_with_mode<W: Write>(
        &self,
        mut out: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        // number of proofs
        self.num_proofs.serialize_with_mode(&mut out, compress)?;

        let log_proofs = Self::log_num_proofs(self.num_proofs as usize);
        assert_eq!(self.comms_lr_ab.len(), log_proofs);

        // comms_ab
        for (x, y) in &self.comms_lr_ab {
            x.serialize_with_mode(&mut out, compress)?;
            y.serialize_with_mode(&mut out, compress)?;
        }

        assert_eq!(self.comms_lr_c.len(), log_proofs);
        // comms_c
        for (x, y) in &self.comms_lr_c {
            x.serialize_with_mode(&mut out, compress)?;
            y.serialize_with_mode(&mut out, compress)?;
        }

        assert_eq!(self.lr_ab.len(), log_proofs);
        // z_ab
        for (x, y) in &self.lr_ab {
            x.serialize_with_mode(&mut out, compress)?;
            y.serialize_with_mode(&mut out, compress)?;
        }

        assert_eq!(self.lr_c.len(), log_proofs);
        // z_c
        for (x, y) in &self.lr_c {
            x.serialize_with_mode(&mut out, compress)?;
            y.serialize_with_mode(&mut out, compress)?;
        }

        // final values of the loop
        self.final_a.serialize_with_mode(&mut out, compress)?;
        self.final_b.serialize_with_mode(&mut out, compress)?;
        self.final_c.serialize_with_mode(&mut out, compress)?;

        // final commitment keys
        self.final_vkey.serialize_with_mode(&mut out, compress)?;
        self.final_wkey.serialize_with_mode(&mut out, compress)?;

        Ok(())
    }
}

impl<E> Valid for GipaProof<E>
where
    E: Pairing,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<E> CanonicalDeserialize for GipaProof<E>
where
    E: Pairing,
{
    fn deserialize_with_mode<R: Read>(
        mut source: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let result = {
            let nproofs = u32::deserialize_compressed(&mut source)?;
            if nproofs < 2 {
                return Err(SerializationError::InvalidData);
            }

            let log_proofs = Self::log_num_proofs(nproofs as usize);

            let comms_ab = (0..log_proofs)
                .map(|_| {
                    Ok((
                        Commitment::deserialize_with_mode(&mut source, compress, validate)?,
                        Commitment::deserialize_with_mode(&mut source, compress, validate)?,
                    ))
                })
                .collect::<Result<Vec<_>, SerializationError>>()?;

            let comms_c = (0..log_proofs)
                .map(|_| {
                    Ok((
                        Commitment::deserialize_with_mode(&mut source, compress, validate)?,
                        Commitment::deserialize_with_mode(&mut source, compress, validate)?,
                    ))
                })
                .collect::<Result<Vec<_>, SerializationError>>()?;

            let z_ab = (0..log_proofs)
                .map(|_| {
                    Ok((
                        PairingOutput::deserialize_with_mode(&mut source, compress, validate)?,
                        PairingOutput::deserialize_with_mode(&mut source, compress, validate)?,
                    ))
                })
                .collect::<Result<Vec<_>, SerializationError>>()?;

            let z_c = (0..log_proofs)
                .map(|_| {
                    Ok((
                        E::G1Affine::deserialize_with_mode(&mut source, compress, validate)?,
                        E::G1Affine::deserialize_with_mode(&mut source, compress, validate)?,
                    ))
                })
                .collect::<Result<Vec<_>, SerializationError>>()?;

            let final_a = E::G1Affine::deserialize_with_mode(&mut source, compress, validate)?;
            let final_b = E::G2Affine::deserialize_with_mode(&mut source, compress, validate)?;
            let final_c = E::G1Affine::deserialize_with_mode(&mut source, compress, validate)?;

            let final_vkey = (
                E::G2Affine::deserialize_with_mode(&mut source, compress, validate)?,
                E::G2Affine::deserialize_with_mode(&mut source, compress, validate)?,
            );
            let final_wkey = (
                E::G1Affine::deserialize_with_mode(&mut source, compress, validate)?,
                E::G1Affine::deserialize_with_mode(&mut source, compress, validate)?,
            );

            if let Validate::Yes = validate {
                nproofs.check()?;
                comms_ab.check()?;
                comms_c.check()?;
                z_ab.check()?;
                z_c.check()?;
                final_a.check()?;
                final_b.check()?;
                final_c.check()?;
                final_vkey.check()?;
                final_wkey.check()?;
            }

            GipaProof {
                num_proofs: nproofs,
                comms_lr_ab: comms_ab,
                comms_lr_c: comms_c,
                lr_ab: z_ab,
                lr_c: z_c,
                final_a,
                final_b,
                final_c,
                final_vkey,
                final_wkey,
            }
        };
        Ok(result)
    }
}

/// It contains the GIPA recursive elements as well as the KZG openings for v
/// and w
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct MMTProof<E: Pairing> {
    pub gipa: GipaProof<E>,
    pub vkey_opening: EvaluationProof<E::G2Affine>,
    pub wkey_opening: EvaluationProof<E::G1Affine>,
}

impl<E: Pairing> PartialEq for MMTProof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.gipa == other.gipa
            && self.vkey_opening == other.vkey_opening
            && self.wkey_opening == other.wkey_opening
    }
}
