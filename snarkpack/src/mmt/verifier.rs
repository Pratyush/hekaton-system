use std::{iter::Sum, time::Instant};

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::Field;
use ark_std::{cfg_iter, Zero};
use crossbeam_channel::Sender;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    cfg_fold, commitment::Commitment, ip, kzg::evaluate_ipa_polynomial,
    pairing_check::PairingCheck, srs::VerifierKey, Transcript,
};

use super::{
    data_structures::{Instance, MMTProof},
    MMT,
};

impl<E: Pairing> MMT<E> {
    /// verify_tipp_mipp returns a pairing equation to check the tipp proof.  $r$ is
    /// the randomness used to produce a random linear combination of A and B and
    /// used in the MIPP part with C
    pub fn verify(
        v_srs: &VerifierKey<E>,
        instance: &Instance<E>,
        proof: &MMTProof<E>,
        transcript: &mut (impl Transcript + Send),
        checks: Sender<Option<PairingCheck<E>>>,
    ) {
        let r = instance.random_challenge;
        println!("verify with srs shift");
        let now = Instant::now();
        // (T,U), Z for TIPP and MIPP  and all challenges
        let (final_res, final_r, challenges, challenges_inv) =
            Self::verify_gipa(&proof, instance, transcript);
        println!(
            "TIPP verify: gipa verify tipp {}ms",
            now.elapsed().as_millis()
        );

        // Verify commitment keys wellformed
        let final_vkey = proof.gipa.final_vkey;
        let final_wkey = proof.gipa.final_wkey;
        // KZG challenge point
        transcript.append(b"kzg-challenge", &challenges[0]);
        transcript.append(b"vkey0", &proof.gipa.final_vkey.0);
        transcript.append(b"vkey1", &proof.gipa.final_vkey.1);
        transcript.append(b"wkey0", &proof.gipa.final_wkey.0);
        transcript.append(b"wkey1", &proof.gipa.final_wkey.1);
        let c = transcript.challenge::<E::ScalarField>(b"z-challenge");
        // we take reference so they are able to be copied in the par! macro
        let final_a = proof.gipa.final_a;
        let final_b = proof.gipa.final_b;
        let final_c = proof.gipa.final_c;
        let final_aggregated_ab = final_res.aggregated_ab;
        let final_comm_ab = final_res.comm_ab;
        let final_comm_c = final_res.comm_c;

        let now = Instant::now();
        let v_clone = checks.clone();
        let w_clone = checks.clone();
        let z_clone = checks.clone();
        let ab_0_clone = checks.clone();
        let ab_1_clone = checks.clone();
        let t_clone = checks.clone();
        let u_clone = checks.clone();
        par! {
            // check the opening proof for v
            let _vtuple = crate::kzg::verify_kzg_v(
                v_srs,
                &final_vkey,
                &proof.vkey_opening,
                &challenges_inv,
                c,
                v_clone,
            ),
            // check the opening proof for w - note that w has been rescaled by $r^{-1}$
            let _wtuple = crate::kzg::verify_kzg_w(
                v_srs,
                &final_wkey,
                &proof.wkey_opening,
                &challenges,
                r.inverse().unwrap(),
                c,
                w_clone,
            ),
            //
            // We create a sequence of pairing tuple that we aggregate together at
            // the end to perform only once the final exponentiation.
            //
            // TIPP
            // z = e(A,B)
            let pcheckz = PairingCheck::rand(&[(final_a, final_b)], final_aggregated_ab),
            //  final_aB.0 = T = e(A,v1)e(w1,B)
            let pcheck_ab = PairingCheck::rand(&[(final_a, final_vkey.0),(final_wkey.0, final_b)], final_comm_ab.t),

            //  final_aB.1 = U = e(A,v2)e(w2,B)
            let pcheckab2 = PairingCheck::rand(&[(final_a, final_vkey.1), (final_wkey.1, final_b)], final_comm_ab.u),

            // MIPP
            // Verify base inner product commitment
            // Z ==  c ^ r
            let final_z = ip::msm::<E::G1Affine>(&[final_c], &[final_r]),
            // Check commiment correctness
            // T = e(C,v1)
            let pcheckt = PairingCheck::rand(&[(final_c, final_vkey.0)], final_comm_c.t),
            // U = e(A,v2)
            let pchecku = PairingCheck::rand(&[(final_c, final_vkey.1)], final_comm_c.u)
        };

        t_clone.send(Some(pcheckt)).unwrap();
        u_clone.send(Some(pchecku)).unwrap();
        ab_0_clone.send(Some(pcheck_ab)).unwrap();
        ab_1_clone.send(Some(pcheckab2)).unwrap();
        z_clone.send(Some(pcheckz)).unwrap();
        match final_z {
            Err(e) => {
                eprintln!("TIPP verify: INVALID with multi exp: {}", e);
                checks.send(None).unwrap();
            },
            Ok(z) => {
                println!(
                    "TIPP verify: parallel checks before merge: {}ms",
                    now.elapsed().as_millis()
                );
                // only check that doesn't require pairing so we can give a tuple
                // that will render the equation wrong in case it's false
                if z != final_res.aggregated_c {
                    eprintln!(
                        "tipp verify: INVALID final_z check {} vs {}",
                        z, final_res.aggregated_c
                    );
                    checks.send(None).unwrap()
                }
            },
        };
    }

    /// gipa_verify_tipp_mipp recurse on the proof and statement and produces the final
    /// values to be checked by TIPP and MIPP verifier, namely, for TIPP for example:
    /// * T,U: the final commitment values of A and B
    /// * Z the final product between A and B.
    /// * Challenges are returned in inverse order as well to avoid
    /// repeating the operation multiple times later on.
    /// * There are T,U,Z vectors as well for the MIPP relationship. Both TIPP and
    /// MIPP share the same challenges however, enabling to re-use common operations
    /// between them, such as the KZG proof for commitment keys.
    fn verify_gipa(
        proof: &MMTProof<E>,
        instance: &Instance<E>,
        transcript: &mut (impl Transcript + Send),
    ) -> (
        GipaVerifierState<E>,
        E::ScalarField,
        Vec<E::ScalarField>,
        Vec<E::ScalarField>,
    ) {
        let r = instance.random_challenge;
        println!("gipa verify TIPP");
        let gipa = &proof.gipa;
        // COM(A,B) = PROD e(A,B) given by prover
        let comms_lr_ab = &gipa.comms_lr_ab;
        // COM(C,r) = SUM C^r given by prover
        let comms_lr_c = &gipa.comms_lr_c;
        // Z vectors coming from the GIPA proofs
        let lrs_ab = &gipa.lr_ab;
        let lrs_c = &gipa.lr_c;

        let now = Instant::now();

        let mut challenges = Vec::new();
        let mut challenges_inv = Vec::new();

        transcript.append(b"Aggregated AB", &instance.aggregated_ab);
        transcript.append(b"Aggregated C", &instance.aggregated_c);
        let mut delta_inv = transcript.challenge::<E::ScalarField>(b"first-challenge");
        let mut delta = delta_inv.inverse().unwrap();

        // We first generate all challenges as this is the only consecutive process
        // that can not be parallelized then we scale the commitments in a
        // parallelized way
        for (i, ((comm_lr_ab, lr_ab), (comm_lr_c, lr_c))) in comms_lr_ab
            .iter()
            .zip(lrs_ab.iter())
            .zip(comms_lr_c.iter().zip(lrs_c.iter()))
            .enumerate()
        {
            let (cm_l_ab, cm_r_ab) = comm_lr_ab;
            let (cm_l_c, cm_r_c) = comm_lr_c;
            let (l_ab, r_ab) = lr_ab;
            let (l_c, r_c) = lr_c;

            // Fiat-Shamir challenge
            if i == 0 {
                // already generated c_inv and c outside of the loop
            } else {
                transcript.append(b"delta_inv", &delta_inv);
                transcript.append(b"L_AB", l_ab);
                transcript.append(b"R_AB", r_ab);
                transcript.append(b"L_C", l_c);
                transcript.append(b"R_C", r_c);
                transcript.append(b"cm_L_AB", cm_l_ab);
                transcript.append(b"cm_R_AB", cm_r_ab);
                transcript.append(b"cm_L_C", cm_l_c);
                transcript.append(b"cm_R_C", cm_r_c);

                delta_inv = transcript.challenge::<E::ScalarField>(b"challenge_i");
                delta = delta_inv.inverse().unwrap();
            }
            challenges.push(delta);
            challenges_inv.push(delta_inv);
        }

        println!(
            "TIPP verify: gipa challenge gen took {}ms",
            now.elapsed().as_millis()
        );

        let now = Instant::now();
        // output of the pair commitment T and U in TIPP -> COM((v,w),A,B)
        //let comab2 = proof.com_ab.clone();
        //let Output(t_ab, u_ab) = (comab2.0, comab2.1);
        let mut state = GipaVerifierState::from_instance(instance);

        // we first multiply each entry of the Z U and L vectors by the respective
        // challenges independently
        // Since at the end we want to multiple all "t" values together, we do
        // multiply all of them in parallel and then merge then back at the end.
        // same for u and z.
        #[allow(non_camel_case_types)]
        enum Op<'a, E: Pairing> {
            T_AB(&'a PairingOutput<E>, E::ScalarField),
            U_AB(&'a PairingOutput<E>, E::ScalarField),
            Z_AB(&'a PairingOutput<E>, E::ScalarField),
            T_C(&'a PairingOutput<E>, E::ScalarField),
            U_C(&'a PairingOutput<E>, E::ScalarField),
            Z_C(&'a E::G1Affine, E::ScalarField),
        }

        let ops = cfg_iter!(comms_lr_ab)
            .zip(lrs_ab)
            .zip(cfg_iter!(comms_lr_c).zip(lrs_c))
            .zip(cfg_iter!(challenges).zip(&challenges_inv))
            .flat_map(|(((comm_lr_ab, lr_ab), (comm_lr_c, lr_c)), (&c, &c_inv))| {
                let (cm_l_ab, cm_r_ab) = comm_lr_ab;
                let (cm_l_c, cm_r_c) = comm_lr_c;
                let (l_ab, r_ab) = lr_ab;
                let (l_c, r_c) = lr_c;

                // we multiple left side by x and right side by x^-1
                [
                    Op::T_AB(&cm_l_ab.t, c),
                    Op::T_AB(&cm_r_ab.t, c_inv),
                    Op::U_AB(&cm_l_ab.u, c),
                    Op::U_AB(&cm_r_ab.u, c_inv),
                    Op::Z_AB(l_ab, c),
                    Op::Z_AB(r_ab, c_inv),
                    Op::T_C(&cm_l_c.t, c),
                    Op::T_C(&cm_r_c.t, c_inv),
                    Op::U_C(&cm_l_c.u, c),
                    Op::U_C(&cm_r_c.u, c_inv),
                    Op::Z_C(l_c, c),
                    Op::Z_C(r_c, c_inv),
                ]
            });
        let res = cfg_fold!(
            ops,
            GipaVerifierState::<E>::default(),
            |mut res, op: Op<E>| {
                match op {
                    Op::T_AB(t, c) => res.comm_ab.t += *t * c,
                    Op::U_AB(u, c) => res.comm_ab.u += *u * c,
                    Op::Z_AB(z, c) => res.aggregated_ab += *z * c,
                    Op::T_C(t, c) => res.comm_c.t += *t * c,
                    Op::U_C(u, c) => res.comm_c.u += *u * c,
                    Op::Z_C(z, c) => res.aggregated_c += *z * c,
                }
                res
            }
        )
        .sum();

        // we reverse the order because the polynomial evaluation routine expects
        // the challenges in reverse order.Doing it here allows us to compute the final_r
        // in log time. Challenges are used as well in the KZG verification checks.
        challenges.reverse();
        challenges_inv.reverse();

        state.merge(&res);
        let final_r = evaluate_ipa_polynomial(&challenges_inv, r, E::ScalarField::ONE);

        println!(
            "TIPP verify: gipa prep and accumulate took {}ms",
            now.elapsed().as_millis()
        );
        (state, final_r, challenges, challenges_inv)
    }
}

/// Keeps track of the variables that have been sent by the prover and must
/// be multiplied together by the verifier. Both MIPP and TIPP are merged
/// together.
#[derive(Clone)]
struct GipaVerifierState<E: Pairing> {
    pub comm_ab: Commitment<E>,
    pub aggregated_ab: PairingOutput<E>,
    pub comm_c: Commitment<E>,
    pub aggregated_c: E::G1,
}

impl<E: Pairing> Default for GipaVerifierState<E> {
    fn default() -> Self {
        Self {
            comm_ab: Commitment::default(),
            aggregated_ab: PairingOutput(E::TargetField::ONE),
            comm_c: Commitment::default(),
            aggregated_c: E::G1::zero(),
        }
    }
}

impl<E: Pairing> GipaVerifierState<E> {
    fn from_instance(instance: &Instance<E>) -> Self {
        Self {
            comm_ab: instance.comm_ab.clone(),
            aggregated_ab: instance.aggregated_ab,
            comm_c: instance.comm_c.clone(),
            aggregated_c: instance.aggregated_c.into(),
        }
    }

    fn merge(&mut self, other: &Self) {
        self.comm_ab.t += &other.comm_ab.t;
        self.comm_ab.u += &other.comm_ab.u;
        self.aggregated_ab += &other.aggregated_ab;

        self.comm_c.t += &other.comm_c.t;
        self.comm_c.u += &other.comm_c.u;
        self.aggregated_c += &other.aggregated_c;
    }
}

impl<E: Pairing> Sum<GipaVerifierState<E>> for GipaVerifierState<E> {
    fn sum<I: Iterator<Item = GipaVerifierState<E>>>(iter: I) -> Self {
        iter.fold(GipaVerifierState::default(), |mut acc, res| {
            acc.merge(&res);
            acc
        })
    }
}
