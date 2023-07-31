use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Field;
use ark_groth16::Proof;
use ark_std::cfg_iter;

use rayon::prelude::*;

use crate::{
    mmt::{self, MMT},
    SnarkPack,
};

use super::{
    commitment, errors::Error, inner_product, srs::ProverSRS, transcript::Transcript,
    utils::structured_scalar_power,
};
use crate::data_structures::AggregationProof;

impl<E: Pairing> SnarkPack<E> {
    /// Aggregate `n` CP-Groth16 proofs, where `n` must be a power of two.
    ///
    /// *WARNING:* transcript_include represents everything that should be included in
    /// the transcript from outside the boundary of this function. This is especially
    /// relevant for ALL public inputs of ALL individual proofs. In the regular case,
    /// one should input ALL public inputs from ALL proofs aggregated.
    ///
    /// However, IF ALL the public inputs are **fixed, and public before the aggregation time**,
    /// then there is no need to hash those. The reason we specify this extra
    /// assumption is because hashing the public inputs from the decoded form can
    /// take quite some time depending on the number of proofs and public inputs
    /// (+100ms in our case). In the case of Filecoin, the only non-fixed part of
    /// the public inputs are the challenges derived from a seed. Even though this
    /// seed comes from a random beeacon, we are hashing this as a safety precaution.
    pub fn prove(
        srs: &ProverSRS<E>,
        transcript: &mut impl Transcript,
        proofs: &[Proof<E>],
    ) -> Result<AggregationProof<E>, Error> {
        if proofs.len() < 2 {
            return Err(Error::InvalidProof("invalid proof size < 2".into()));
        }
        if !proofs.len().is_power_of_two() {
            return Err(Error::InvalidProof(
                "invalid proof size: not power of two".into(),
            ));
        }

        if !srs.has_correct_len(proofs.len()) {
            return Err(Error::InvalidSRS("SRS len != proofs len".into()));
        }
        // We first commit to A B and C - these commitments are what the verifier
        // will use later to verify the TIPP and MIPP proofs
        let a = cfg_iter!(proofs).map(|proof| proof.a).collect::<Vec<_>>();
        let b = cfg_iter!(proofs).map(|proof| proof.b).collect::<Vec<_>>();
        let c = cfg_iter!(proofs).map(|proof| proof.c).collect::<Vec<_>>();

        // A and B are committed together in this scheme
        // we need to take the reference so the macro doesn't consume the value
        // first
        let ref_a = &a;
        let ref_b = &b;
        let ref_c = &c;
        try_par! {
            let comm_ab = commitment::commit_double::<E>(&srs.vkey, &srs.wkey, ref_a, ref_b),
            let comm_c = commitment::commit_single::<E>(&srs.vkey, ref_c)
        };

        // Derive a random scalar to perform a linear combination of proofs
        transcript.append(b"AB-commitment", &comm_ab);
        transcript.append(b"C-commitment", &comm_c);
        let r = transcript.challenge::<E::ScalarField>(b"r-random-fiatshamir");

        // 1,r, r^2, r^3, r^4 ...
        let r_s = structured_scalar_power(proofs.len(), r);
        // 1,r^-1, r^-2, r^-3
        let r_inv = r_s
            .par_iter()
            .map(|ri| ri.inverse().unwrap())
            .collect::<Vec<_>>();

        // B^{r}
        let b_r = b
            .par_iter()
            .zip(&r_s)
            .map(|(bi, ri)| *bi * *ri)
            .collect::<Vec<_>>();
        let b_r = E::G2::normalize_batch(&b_r);

        let ref_b_r = &b_r;
        let ref_r_s = &r_s;
        try_par! {
            // compute A * B^r for the verifier
            let aggregated_ab = inner_product::pairing::<E>(&ref_a, &ref_b_r),
            // compute C^r for the verifier
            let agg_c = inner_product::msm::<E::G1Affine>(&ref_c, &ref_r_s)
        };

        let aggregated_c = agg_c.into_affine();
        // w^{r^{-1}}
        let wkey_r_inv = srs.wkey.scale(&r_inv)?;
        debug_assert_eq!(
            commitment::commit_double::<E>(&srs.vkey, &wkey_r_inv, &a, &b_r).unwrap(),
            comm_ab
        );
        // we prove tipp and mipp using the same recursive loop
        let mmt_instance = mmt::Instance {
            size: proofs.len(),
            aggregated_ab,
            comm_ab: comm_ab.clone(),
            aggregated_c,
            comm_c: comm_c.clone(),
            random_challenge: r,
        };

        let mmt_witness = mmt::Witness { a, b, c };
        let mmt_proof = MMT::prove(&srs, &wkey_r_inv, &mmt_instance, &mmt_witness, transcript)?;

        Ok(AggregationProof {
            comm_ab,
            comm_c,
            aggregated_ab,
            aggregated_c,
            mmt_proof,
        })
    }
}
