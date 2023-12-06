use crate::{
    pairing_ops::{pairing, scalar_pairing, structured_scalar_power},
    par,
    util::{G16Proof, G16ProvingKey, ProtoTranscript, TranscriptProtocol},
};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_inner_products::{InnerProduct, PairingInnerProduct};
use ark_ip_proofs::{
    ip_commitment::snarkpack::TIPPCommitment,
    tipa::{Proof, TIPA},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer};
use pretty_assertions::assert_eq;
use rayon::prelude::*;
use sha2::Sha256;

pub type IppCom<E> = ark_ip_proofs::ip_commitment::Commitment<TIPPCommitment<E>>;
pub use ark_ip_proofs::ip_commitment::{IPCommKey, IPCommitment};
pub use ark_ip_proofs::tipa::ProverKey;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AggProvingKey<'b, E: Pairing> {
    /// This is the key used to produce ALL inner-pairing commitments
    pub tipp_pk: ProverKey<'b, E>,

    // The elements of si are the curve point representing the i-th public input in some set of
    // Groth16 CRSs. The first public input is always set to 1, so we have a total of 4 here
    pub(crate) s0: Vec<E::G1Affine>,
    pub(crate) s1: Vec<E::G1Affine>,
    pub(crate) s2: Vec<E::G1Affine>,
    pub(crate) s3: Vec<E::G1Affine>,

    // Commitments to the above
    com_s0: IppCom<E>,
    com_s1: IppCom<E>,
    com_s2: IppCom<E>,
    com_s3: IppCom<E>,

    // The CRS values that get paired with the sum of the s values above
    h: Vec<E::G2Affine>,
    // Commitment to h
    com_h: IppCom<E>,

    // The CRS values that get paired with D and C, respectively
    delta0: Vec<E::G2Affine>,
    delta1: Vec<E::G2Affine>,
    // Commitment to above
    com_delta0: IppCom<E>,
    com_delta1: IppCom<E>,

    // Temporary values. These are the alpha and beta from the CRSs
    alpha: Vec<E::G1Affine>,
    beta: Vec<E::G2Affine>,
}

impl<'b, E: Pairing> AggProvingKey<'b, E> {
    /// Creates an aggregation proving key using an IPP commitment key, a KZG commitment key, and a
    /// lambda that will fetch the Groth16 proving key of the given circuit
    pub fn new<'a>(
        tipp_pk: ProverKey<'b, E>,
        pk_fetcher: impl Fn(usize) -> &'a G16ProvingKey<E>,
    ) -> Self {
        let num_proofs = tipp_pk.supported_size;

        // Group elements in the CRS corresponding to the public inputs
        let mut s0 = Vec::with_capacity(num_proofs);
        let mut s1 = Vec::with_capacity(num_proofs);
        let mut s2 = Vec::with_capacity(num_proofs);
        let mut s3 = Vec::with_capacity(num_proofs);
        // Group elements in the CRS that get paired with the si values
        let mut h = Vec::with_capacity(num_proofs);
        // Group elements in the CRS that get paired with the si values
        let mut delta0 = Vec::with_capacity(num_proofs);
        let mut delta1 = Vec::with_capacity(num_proofs);
        // TODO: Remove this once we have proofs sharing alpha and beta
        let mut alpha = Vec::with_capacity(num_proofs);
        let mut beta = Vec::with_capacity(num_proofs);

        // Go through each Groth16 proving key and extract the values necessary to fill the above
        // vectors
        for i in 0..num_proofs {
            let pk = pk_fetcher(i);

            s0.push(pk.vk.gamma_abc_g[0].into_group());
            s1.push(pk.vk.gamma_abc_g[1].into_group());
            s2.push(pk.vk.gamma_abc_g[2].into_group());
            s3.push(pk.vk.gamma_abc_g[3].into_group());
            h.push(pk.vk.gamma_h.into_group());
            delta0.push(pk.vk.deltas_h[0].into_group());
            delta1.push(pk.vk.deltas_h[1].into_group());
            alpha.push(pk.vk.alpha_g.into_group());
            beta.push(pk.vk.beta_h.into_group());
        }

        // Commit to those group elements
        let com_s0 = TIPPCommitment::<E>::commit_only_left(&tipp_pk.pk.ck, &s0).unwrap();
        let com_s1 = TIPPCommitment::<E>::commit_only_left(&tipp_pk.pk.ck, &s1).unwrap();
        let com_s2 = TIPPCommitment::<E>::commit_only_left(&tipp_pk.pk.ck, &s2).unwrap();
        let com_s3 = TIPPCommitment::<E>::commit_only_left(&tipp_pk.pk.ck, &s3).unwrap();
        let com_h = TIPPCommitment::<E>::commit_only_right(&tipp_pk.pk.ck, &h).unwrap();
        let com_delta0 = TIPPCommitment::<E>::commit_only_right(&tipp_pk.pk.ck, &delta0).unwrap();
        let com_delta1 = TIPPCommitment::<E>::commit_only_right(&tipp_pk.pk.ck, &delta1).unwrap();

        // This is cheap because the vectors are constructed from affine form.
        let s0 = s0.into_iter().map(|s| s.into_affine()).collect();
        let s1 = s1.into_iter().map(|s| s.into_affine()).collect();
        let s2 = s2.into_iter().map(|s| s.into_affine()).collect();
        let s3 = s3.into_iter().map(|s| s.into_affine()).collect();
        let h = h.into_iter().map(|s| s.into_affine()).collect();
        let delta0 = delta0.into_iter().map(|s| s.into_affine()).collect();
        let delta1 = delta1.into_iter().map(|s| s.into_affine()).collect();
        let alpha = alpha.into_iter().map(|s| s.into_affine()).collect();
        let beta = beta.into_iter().map(|s| s.into_affine()).collect();

        AggProvingKey {
            tipp_pk,
            s0,
            s1,
            s2,
            s3,
            com_s0,
            com_s1,
            com_s2,
            com_s3,
            h,
            com_h,
            delta0,
            delta1,
            com_delta0,
            com_delta1,
            alpha,
            beta,
        }
    }

    /// Aggregates the subcircuit proofs
    pub fn agg_subcircuit_proofs(
        &self,
        pt: &mut ProtoTranscript,
        super_com: &IppCom<E>,
        proofs: &[G16Proof<E>],
        pub_inputs: &[E::ScalarField],
    ) -> Proof<E> {
        let start = start_timer!(|| format!("Aggregating {} proofs", proofs.len()));
        let ck = &self.tipp_pk.pk.ck;

        assert_eq!(
            pub_inputs.len(),
            3,
            "there are only 3 pub inputs: entry_chal, tr_chal, root"
        );

        let num_proofs = proofs.len();

        let a_vals = proofs.iter().map(|p| p.a.into_group()).collect::<Vec<_>>();
        let b_vals = proofs.iter().map(|p| p.b.into_group()).collect::<Vec<_>>();
        let c_vals = proofs.iter().map(|p| p.c.into_group()).collect::<Vec<_>>();
        // Each proof has only 1 commitment (it's stage0)
        let d_vals = proofs
            .iter()
            .map(|p| p.ds[0].into_group())
            .collect::<Vec<_>>();

        let com_ab = TIPPCommitment::<E>::commit_with_ip(&ck, &a_vals, &b_vals, None).unwrap();
        let com_c = TIPPCommitment::<E>::commit_only_left(&ck, &c_vals).unwrap();
        let com_d = super_com;
        let com_prepared_input = self.com_s0
            + self.com_s1 * pub_inputs[0]
            + self.com_s2 * pub_inputs[1]
            + self.com_s3 * pub_inputs[2];
        let a_vals = a_vals
            .into_iter()
            .map(|s| s.into_affine())
            .collect::<Vec<_>>();

        let b_vals = b_vals
            .into_iter()
            .map(|s| s.into_affine())
            .collect::<Vec<_>>();
        let c_vals = c_vals
            .into_iter()
            .map(|s| s.into_affine())
            .collect::<Vec<_>>();
        let d_vals = d_vals
            .into_iter()
            .map(|s| s.into_affine())
            .collect::<Vec<_>>();

        // Compute the combined public inputs. In the paper this is S₁^1 · S₂^pubinput₁ · ...
        let prepared_input = self
            .s0
            .par_iter()
            .zip(&self.s1)
            .zip(&self.s2)
            .zip(&self.s3)
            .map(|(((s0, s1), s2), s3)| {
                // Remember the first public input is always 1, so s0 gets no coeff
                *s0 + (*s1) * pub_inputs[0] + (*s2) * pub_inputs[1] + (*s3) * pub_inputs[2]
            })
            .collect::<Vec<_>>();
        // TODO: Rewrite scalar_pairing so that we don't need this to be affine
        let prepared_input = E::G1::normalize_batch(&prepared_input);

        // Sanity check. Does the first proof validate?
        for i in 0..num_proofs {
            debug_assert_eq!(
                E::pairing(&a_vals[i], &b_vals[i]),
                E::pairing(&self.alpha[i], &self.beta[i])
                    + E::pairing(&prepared_input[i], &self.h[i])
                    + E::pairing(&d_vals[i], &self.delta0[i])
                    + E::pairing(&c_vals[i], &self.delta1[i])
            );
        }

        // Derive a random scalar to perform a linear combination of proofs
        pt.append_serializable(b"AB-commitment", &com_ab);
        pt.append_serializable(b"C-commitment", &com_c);
        pt.append_serializable(b"D-commitment", com_d);
        let twist = pt.challenge_scalar::<E::ScalarField>(b"r-random-fiatshamir");

        // 1,r, r^2, r^3, r^4 ...
        let twist_powers = structured_scalar_power(num_proofs, twist);
        let twist_powers_ref = &twist_powers;
        // 1,r^-1, r^-2, r^-3
        let mut twist_inv_powers = twist_powers.clone();
        ark_ff::batch_inversion(&mut twist_inv_powers);

        let a_ref = &a_vals;
        let c_ref = &c_vals;
        let d_ref = &d_vals;
        let alpha_ref = &self.alpha;
        let input_ref = &prepared_input;
        par! {
            let a_r = scalar_pairing(a_ref, &twist_powers_ref);
            let c_r = scalar_pairing(c_ref, &twist_powers_ref);
            let d_r = scalar_pairing(d_ref, &twist_powers_ref);
            let alpha_r = scalar_pairing(alpha_ref, &twist_powers_ref);
            let prepared_input_r = scalar_pairing(input_ref, &twist_powers_ref)
        }
        // Check each individual equation holds with the r coeffs
        for i in 0..num_proofs {
            debug_assert_eq!(
                E::pairing(&a_r[i], &b_vals[i]),
                E::pairing(&alpha_r[i], &self.beta[i])
                    + E::pairing(&prepared_input_r[i], &self.h[i])
                    + E::pairing(&d_r[i], &self.delta0[i])
                    + E::pairing(&c_r[i], &self.delta1[i])
            );
        }

        // Multiply every LHS with every RHS
        let cross_terms = [&a_r, &prepared_input_r, &d_r, &c_r]
            .into_par_iter()
            .map(|lhs| {
                [&b_vals, &self.h, &self.delta0, &self.delta1]
                    .into_par_iter()
                    .map(|rhs| pairing::<E>(lhs, rhs))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Check that the pairing product equation holds with the r coeffs
        let z_ab = cross_terms[0][0];
        let z_sh = cross_terms[1][1];
        let z_ddelta0 = cross_terms[2][2];
        let z_cdelta1 = cross_terms[3][3];
        debug_assert_eq!(
            z_ab,
            pairing::<E>(&alpha_r, &self.beta) + z_sh + z_ddelta0 + z_cdelta1
        );

        // Get challenges s,t
        pt.append_serializable(b"cross-terms", &cross_terms);
        let s = pt.challenge_scalar::<E::ScalarField>(b"s-random-fiatshamir");
        let t = pt.challenge_scalar::<E::ScalarField>(b"t-random-fiatshamir");
        // Compute squares and cubes
        let s_sq = s * s;
        let s_cube = s_sq * s;
        let t_sq = t * t;
        let t_cube = t_sq * t;

        // Now compute a combination wrt powers of s and t
        let left = {
            // Compute L = A' · (S')^s · (D')^{s²} · (C')^{s³}
            par! {
                let s_to_the_s =
                    scalar_pairing(&prepared_input, vec![s; num_proofs].as_slice());
                let d_to_the_s2 = scalar_pairing(&d_vals, vec![s_sq; num_proofs].as_slice());
                let c_to_the_s3 = scalar_pairing(&c_vals, vec![s_cube; num_proofs].as_slice())
            };
            a_vals
                .into_par_iter()
                .zip(s_to_the_s)
                .zip(d_to_the_s2)
                .zip(c_to_the_s3)
                .map(|(((a, s), d), c)| a + s + d + c)
                .collect::<Vec<_>>()
        };
        let right = {
            // Compute R = B · H^t · δ₀^{t²} · δ₁^{t³}
            par! {
                let h_to_the_t = scalar_pairing(&self.h, vec![t; num_proofs].as_slice());
                let delta0_to_the_t2 =
                    scalar_pairing(&self.delta0, vec![t_sq; num_proofs].as_slice());
                let delta1_to_the_t3 =
                    scalar_pairing(&self.delta1, vec![t_cube; num_proofs].as_slice())
            };
            b_vals
                .into_par_iter()
                .zip(h_to_the_t)
                .zip(delta0_to_the_t2)
                .zip(delta1_to_the_t3)
                .map(|(((b, s), d), c)| b + s + d + c)
                .collect::<Vec<_>>()
        };
        // Compute the corresponding commitments
        let com_lr = {
            let s_partial_sum = com_ab + com_prepared_input * s + *com_d * s_sq + com_c * s_cube;
            let t_partial_sum = self.com_h * t + self.com_delta0 * t_sq + self.com_delta1 * t_cube;
            s_partial_sum + t_partial_sum
        };
        // Take the product of the left and right sides
        let z_lr = PairingInnerProduct::twisted_inner_product(&left, &right, twist).unwrap();

        let instance = ark_ip_proofs::gipa::Instance {
            size: num_proofs,
            output: z_lr,
            commitment: com_lr,
            twist,
        };

        let witness = ark_ip_proofs::gipa::Witness { left, right };

        let tipp_proof = TIPA::<_, Sha256>::prove(&self.tipp_pk, &instance, &witness).unwrap();

        let tipp_start = start_timer!(|| format!("Verifying TIPA for {num_proofs} proofs"));
        assert!(TIPA::<_, Sha256>::verify(&self.tipp_pk.vk(), &instance, &tipp_proof).unwrap());
        end_timer!(tipp_start);
        end_timer!(start);

        tipp_proof
    }
}
