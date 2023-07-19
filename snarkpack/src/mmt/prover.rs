use ark_ec::{CurveGroup, pairing::{Pairing, PairingOutput}};
use ark_ff::Field;
use ark_std::cfg_iter_mut;

use crate::{srs::ProverSRS, commitment::{WKey, VKey, self}, Transcript, Error, ip, utils::compress};

use super::{data_structures::{MMTProof, GipaProof}, MMT};

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
        transcript: &mut impl Transcript,
        a: &[E::G1Affine],
        b: &[E::G2Affine],
        c: &[E::G1Affine],
        wkey: &WKey<E>, // scaled key w^r^-1
        r_s: &[E::ScalarField],
        ip_ab: &PairingOutput<E>,
        agg_c: &E::G1Affine,
    ) -> Result<MMTProof<E>, Error> {
        let r_shift = r_s[1].clone();
        // Run GIPA
        let (proof, mut challenges, mut challenges_inv) =
            Self::gipa_tipp_mipp(transcript, a, b, c, &srs.vkey, &wkey, r_s, ip_ab, agg_c)?;

        // Prove final commitment keys are wellformed
        // we reverse the transcript so the polynomial in kzg opening is constructed
        // correctly - the formula indicates x_{l-j}. Also for deriving KZG
        // challenge point, input must be the last challenge.
        challenges.reverse();
        challenges_inv.reverse();
        let r_inverse = r_shift.inverse().unwrap();

        // KZG challenge point
        transcript.append(b"kzg-challenge", &challenges[0]);
        transcript.append(b"vkey0", &proof.final_vkey.0);
        transcript.append(b"vkey1", &proof.final_vkey.1);
        transcript.append(b"wkey0", &proof.final_wkey.0);
        transcript.append(b"wkey1", &proof.final_wkey.1);
        let z = transcript.challenge_scalar::<E::ScalarField>(b"z-challenge");
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
    fn gipa_tipp_mipp(
        transcript: &mut impl Transcript,
        a: &[E::G1Affine],
        b: &[E::G2Affine],
        c: &[E::G1Affine],
        vkey: &VKey<E>,
        wkey: &WKey<E>, // scaled key w^r^-1
        r: &[E::ScalarField],
        ip_ab: &PairingOutput<E>,
        agg_c: &E::G1Affine,
    ) -> Result<(GipaProof<E>, Vec<E::ScalarField>, Vec<E::ScalarField>), Error> {
        // the values of vectors A and B rescaled at each step of the loop
        let (mut m_a, mut m_b) = (a.to_vec(), b.to_vec());
        // the values of vectors C and r rescaled at each step of the loop
        let (mut m_c, mut m_r) = (c.to_vec(), r.to_vec());
        // the values of the commitment keys rescaled at each step of the loop
        let (mut vkey, mut wkey) = (vkey.clone(), wkey.clone());

        // storing the values for including in the proof
        let mut comms_ab = Vec::new();
        let mut comms_c = Vec::new();
        let mut z_ab = Vec::new();
        let mut z_c = Vec::new();
        let mut challenges: Vec<E::ScalarField> = Vec::new();
        let mut challenges_inv: Vec<E::ScalarField> = Vec::new();

        transcript.append(b"inner-product-ab", ip_ab);
        transcript.append(b"comm-c", agg_c);
        let mut c_inv: E::ScalarField =
            transcript.challenge_scalar::<E::ScalarField>(b"first-challenge");
        let mut c = c_inv.inverse().unwrap();

        let mut i = 0;

        while m_a.len() > 1 {
            // recursive step
            // Recurse with problem of half size
            let split = m_a.len() / 2;

            // TIPP ///
            let (a_left, a_right) = m_a.split_at_mut(split);
            let (b_left, b_right) = m_b.split_at_mut(split);
            // MIPP ///
            // c[:n']   c[n':]
            let (c_left, c_right) = m_c.split_at_mut(split);
            // r[:n']   r[:n']
            let (r_left, r_right) = m_r.split_at_mut(split);

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
                // TIPP part
                let t_ab_l = commitment::commit_double::<E>(&rvk_left, &rwk_right, &ra_right, &rb_left),
                let t_ab_r = commitment::commit_double::<E>(&rvk_right, &rwk_left, &ra_left, &rb_right),
                // \prod e(A_right,B_left)
                let z_ab_l = ip::pairing::<E>(&ra_right, &rb_left),
                let z_ab_r = ip::pairing::<E>(&ra_left, &rb_right),

                // MIPP part
                // z_l = c[n':] ^ r[:n']
                let zc_l = ip::msm::<E::G1Affine>(rc_right, rr_left),
                // Z_r = c[:n'] ^ r[n':]
                let zc_r = ip::msm::<E::G1Affine>(rc_left, rr_right),
                // u_l = c[n':] * v[:n']
                let tuc_l = commitment::commit_single::<E>(&rvk_left, rc_right),
                // u_r = c[:n'] * v[n':]
                let tuc_r = commitment::commit_single::<E>(&rvk_right, rc_left)
            };

            // Fiat-Shamir challenge
            // combine both TIPP and MIPP transcript
            if i == 0 {
                // already generated c_inv and c outside of the loop
            } else {
                transcript.append(b"c_inv", &c_inv);
                transcript.append(b"z_ab_l", &z_ab_l);
                transcript.append(b"z_ab_r", &z_ab_r);
                transcript.append(b"zc_l", &zc_l);
                transcript.append(b"zc_r", &zc_r);
                transcript.append(b"t_ab_l", &t_ab_l);
                transcript.append(b"t_ab_r", &t_ab_r);
                transcript.append(b"tuc_l", &tuc_l);
                transcript.append(b"tuc_r", &tuc_r);
                c_inv = transcript.challenge_scalar::<E::ScalarField>(b"challenge_i");

                // Optimization for multiexponentiation to rescale G2 elements with
                // 128-bit challenge Swap 'c' and 'c_inv' since can't control bit size
                // of c_inv
                c = c_inv.inverse().unwrap();
            }

            // Set up values for next step of recursion
            // A[:n'] + A[n':] ^ x
            compress(&mut m_a, split, &c);
            // B[:n'] + B[n':] ^ x^-1
            compress(&mut m_b, split, &c_inv);

            // c[:n'] + c[n':]^x
            compress(&mut m_c, split, &c);
            cfg_iter_mut!(r_left)
                .zip(r_right)
                .for_each(|(r_l, r_r)| {
                    // r[:n'] + r[n':]^x^-1
                    *r_r *= &c_inv;
                    *r_l += r_r;
                });
            let len = r_left.len();
            m_r.resize(len, E::ScalarField::ZERO); // shrink to new size

            // v_left + v_right^x^-1
            vkey = vk_left.compress(&vk_right, &c_inv)?;
            // w_left + w_right^x
            wkey = wk_left.compress(&wk_right, &c)?;

            comms_ab.push((t_ab_l, t_ab_r));
            comms_c.push((tuc_l, tuc_r));
            z_ab.push((z_ab_l, z_ab_r));
            z_c.push((zc_l.into_affine(), zc_r.into_affine()));
            challenges.push(c);
            challenges_inv.push(c_inv);

            i += 1;
        }

        assert!(m_a.len() == 1 && m_b.len() == 1);
        assert!(m_c.len() == 1 && m_r.len() == 1);
        assert!(vkey.a.len() == 1 && vkey.b.len() == 1);
        assert!(wkey.a.len() == 1 && wkey.b.len() == 1);

        let (final_a, final_b, final_c) = (m_a[0], m_b[0], m_c[0]);
        let (final_vkey, final_wkey) = (vkey.first(), wkey.first());

        Ok((
            GipaProof {
                num_proofs: a.len() as u32, // TODO: ensure u32
                comms_ab,
                comms_c,
                z_ab,
                z_c,
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