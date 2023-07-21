use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Field;
use ark_std::cfg_iter_mut;

use crate::{
    commitment::{self, VKey, WKey},
    ip,
    srs::ProverSRS,
    utils::{compress, structured_scalar_power},
    Error, Transcript,
};

use super::{
    data_structures::{GipaProof, Instance, MMTProof, Witness},
    MMT,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

impl<E: Pairing> MMT<E> {
    /// Proves a TIPP relation between A and B as well as a MIPP relation with C and
    /// r. Commitment keys must be of size of A, B and C. In the context of Groth16
    /// aggregation, we have that B = B^r and wkey is scaled by r^{-1}. The
    /// commitment key v is used to commit to A and C recursively in GIPA such that
    /// only one KZG proof is needed for v. In the original paper version, since the
    /// challenges of GIPA would be different, two KZG proofs would be needed.
    pub fn prove(
        srs: &ProverSRS<E>,
        wkey: &WKey<E>, // scaled key w^r^-1
        instance: &Instance<E>,
        witness: &Witness<E>,
        transcript: &mut impl Transcript,
    ) -> Result<MMTProof<E>, Error> {
        assert_eq!(instance.size, witness.a.len());
        assert_eq!(instance.size, witness.b.len());
        assert_eq!(instance.size, witness.c.len());
        let r = instance.random_challenge;
        // Run GIPA
        let (proof, mut challenges, mut challenges_inv) =
            Self::prove_gipa(&srs.vkey, &wkey, instance, witness, transcript)?;

        // Prove final commitment keys are wellformed
        // we reverse the transcript so the polynomial in kzg opening is constructed
        // correctly - the formula indicates x_{l-j}. Also for deriving KZG
        // challenge point, input must be the last challenge.
        challenges.reverse();
        challenges_inv.reverse();
        let r_inverse = r.inverse().unwrap();

        // KZG challenge point
        transcript.append(b"kzg-challenge", &challenges[0]);
        transcript.append(b"vkey0", &proof.final_vkey.0);
        transcript.append(b"vkey1", &proof.final_vkey.1);
        transcript.append(b"wkey0", &proof.final_wkey.0);
        transcript.append(b"wkey1", &proof.final_wkey.1);
        let z = transcript.challenge::<E::ScalarField>(b"z-challenge");
        // Complete KZG proofs
        par! {
            let vkey_opening = crate::kzg::prove_commitment_v(
                &srs.h_alpha_powers_table,
                &srs.h_beta_powers_table,
                &challenges_inv,
                z,
            ),
            let wkey_opening = crate::kzg::prove_commitment_w(
                &srs.g_alpha_powers_table,
                &srs.g_beta_powers_table,
                &challenges,
                r_inverse,
                z,
            )
        };

        Ok(MMTProof {
            gipa: proof,
            vkey_opening: vkey_opening?,
            wkey_opening: wkey_opening?,
        })
    }

    /// gipa_tipp_mipp peforms the recursion of the GIPA protocol for TIPP and MIPP.
    /// It returns a proof containing all intermdiate committed values, as well as
    /// the challenges generated necessary to do the polynomial commitment proof
    /// later in TIPP.
    fn prove_gipa(
        vkey: &VKey<E>,
        wkey: &WKey<E>, // scaled key w^r^-1
        instance: &Instance<E>,
        witness: &Witness<E>,
        transcript: &mut impl Transcript,
    ) -> Result<(GipaProof<E>, Vec<E::ScalarField>, Vec<E::ScalarField>), Error> {
        let mut r = structured_scalar_power(instance.size, instance.random_challenge);
        // the values of vectors A and B rescaled at each step of the loop
        let (mut a, mut b) = (witness.a.to_vec(), witness.b.to_vec());
        // the values of vectors C and r rescaled at each step of the loop
        let mut c = witness.c.to_vec();
        // the values of the commitment keys rescaled at each step of the loop
        let (mut vkey, mut wkey) = (vkey.clone(), wkey.clone());

        // storing the values for including in the proof
        let mut comms_ab = Vec::new();
        let mut comms_c = Vec::new();
        let mut z_ab = Vec::new();
        let mut z_c = Vec::new();

        let mut challenges: Vec<E::ScalarField> = Vec::new();
        let mut challenges_inv: Vec<E::ScalarField> = Vec::new();

        transcript.append(b"Aggregated AB", &instance.aggregated_ab);
        transcript.append(b"Aggregated C", &instance.aggregated_c);
        let mut delta_inv: E::ScalarField =
            transcript.challenge::<E::ScalarField>(b"first-challenge");
        let mut delta = delta_inv.inverse().unwrap();

        let mut i = 0;

        while a.len() > 1 {
            // recursive step
            // Recurse with problem of half size
            let split = a.len() / 2;

            // TIPP ///
            let (a_left, a_right) = a.split_at_mut(split);
            let (b_left, b_right) = b.split_at_mut(split);
            // MIPP ///
            // c[:n']   c[n':]
            let (c_left, c_right) = c.split_at_mut(split);
            // r[:n']   r[:n']
            let (r_left, r_right) = r.split_at_mut(split);

            let (vk_left, vk_right) = vkey.split(split);
            let (wk_left, wk_right) = wkey.split(split);

            // since we do this in parallel we take reference first so it can be
            // moved within the macro's rayon scope.
            let (rvk_left, rvk_right) = (&vk_left, &vk_right);
            let (rwk_left, rwk_right) = (&wk_left, &wk_right);
            let (ra_left, ra_right) = (&a_left, &a_right);
            let (rb_left, rb_right) = (&b_left, &b_right);
            let (rc_left, rc_right) = (&c_left, &c_right);
            let (rr_left, rr_right) = (&r_left, &r_right);
            // See section 3.3 for paper version with equivalent names
            try_par! {
                /********************************************************/
                // Compute left and right inner products:
                //
                // For TIPP (i.e. A and B):
                // \prod e(A_right,B_left)
                let l_ab = ip::pairing::<E>(&ra_right, &rb_left),
                let r_ab = ip::pairing::<E>(&ra_left, &rb_right),

                // For MIPP (i.e. C and r):
                // z_l = c[n':] ^ r[:n']
                let l_c = ip::msm(rc_right, rr_left),
                // Z_r = c[:n'] ^ r[n':]
                let r_c = ip::msm(rc_left, rr_right),
                /********************************************************/

                /********************************************************/
                // Compute left cross commitments
                //
                // For TIPP:
                let cm_l_ab = commitment::commit_double::<E>(&rvk_left, &rwk_right, &ra_right, &rb_left),

                // For MIPP:
                // u_l = c[n':] * v[:n']
                let cm_l_c = commitment::commit_single::<E>(&rvk_left, rc_right),
                /********************************************************/

                /********************************************************/
                // Compute right cross commitments
                //
                // For TIPP:
                // T_ab_r = e(A_left,B_right)
                let cm_r_ab = commitment::commit_double::<E>(&rvk_right, &rwk_left, &ra_left, &rb_right),

                // For MIPP
                // u_r = c[:n'] * v[n':]
                let cm_r_c = commitment::commit_single::<E>(&rvk_right, rc_left)
                /********************************************************/
            };

            // Fiat-Shamir challenge
            // combine both TIPP and MIPP transcript
            if i == 0 {
                // already generated c_inv and c outside of the loop
            } else {
                transcript.append(b"delta_inv", &delta_inv);
                transcript.append(b"L_AB", &l_ab);
                transcript.append(b"R_AB", &r_ab);
                transcript.append(b"L_C", &l_c);
                transcript.append(b"R_C", &r_c);
                transcript.append(b"cm_L_AB", &cm_l_ab);
                transcript.append(b"cm_R_AB", &cm_r_ab);
                transcript.append(b"cm_L_C", &cm_l_c);
                transcript.append(b"cm_R_C", &cm_r_c);
                delta_inv = transcript.challenge::<E::ScalarField>(b"delta_inv_i");

                // Optimization for multiexponentiation to rescale G2 elements with
                // 128-bit challenge Swap 'c' and 'c_inv' since can't control bit size
                // of c_inv
                delta = delta_inv.inverse().unwrap();
            }

            // Set up values for next step of recursion
            // A[:n'] + delta * A[n':]
            compress(&mut a, split, delta);
            // B[:n'] + delta_inv * B[n':]
            compress(&mut b, split, delta_inv);

            // C[:n'] + delta * C[n':]
            compress(&mut c, split, delta);

            // Collapse randomness
            cfg_iter_mut!(r_left)
                .zip(r_right)
                .for_each(|(left, right)| {
                    // r[:n'] + delta_inv * r[n':]
                    *right *= &delta_inv;
                    *left += right;
                });
            let len = r_left.len();
            r.resize(len, E::ScalarField::ZERO); // shrink to new size

            // Compress commitment keys:
            // v_left + v_right^x^-1
            vkey = vk_left.compress(&vk_right, delta_inv)?;

            // w_left + w_right^x
            wkey = wk_left.compress(&wk_right, delta)?;

            comms_ab.push((cm_l_ab, cm_r_ab));
            comms_c.push((cm_l_c, cm_r_c));
            z_ab.push((l_ab, r_ab));
            z_c.push((l_c.into_affine(), r_c.into_affine()));
            challenges.push(delta);
            challenges_inv.push(delta_inv);

            i += 1;
        }

        assert!(a.len() == 1 && b.len() == 1);
        assert!(c.len() == 1 && r.len() == 1);
        assert!(vkey.a.len() == 1 && vkey.b.len() == 1);
        assert!(wkey.a.len() == 1 && wkey.b.len() == 1);

        let (final_a, final_b, final_c) = (a[0], b[0], c[0]);
        let (final_vkey, final_wkey) = (vkey.first(), wkey.first());

        Ok((
            GipaProof {
                num_proofs: a.len().try_into().unwrap(), // TODO: ensure u32
                comms_lr_ab: comms_ab,
                comms_lr_c: comms_c,
                lr_ab: z_ab,
                lr_c: z_c,
                final_a,
                final_b,
                final_c,
                final_vkey,
                final_wkey,
            },
            challenges,
            challenges_inv,
        ))
    }
}
