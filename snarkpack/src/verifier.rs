use ark_ec::{pairing::{Pairing, PairingOutput}, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::PreparedVerifyingKey;
use ark_std::{One, Zero};
use crossbeam_channel::{bounded, Sender};
use rayon::prelude::*;
use std::ops::{AddAssign, Mul, MulAssign, Neg, SubAssign};

use super::{
    commitment::Commitment,
    ip,
    pairing_check::PairingCheck,
    proof::{AggregateProof, KZGOpening},
    prover::polynomial_evaluation_product_form_from_transcript,
    srs::VerifierKey,
    structured_scalar_power,
    transcript::Transcript,
};
use crate::Error;

use std::default::Default;
use std::time::Instant;

/// Verifies the aggregated proofs thanks to the Groth16 verifying key, the
/// verifier SRS from the aggregation scheme, all the public inputs of the
/// proofs and the aggregated proof.
pub fn verify_aggregate_proof<E: Pairing, T: Transcript + Send>(
    ip_vk: &VerifierKey<E>,
    pvk: &PreparedVerifyingKey<E>,
    public_inputs: &[Vec<<E as Pairing>::ScalarField>],
    proof: &AggregateProof<E>,
    mut transcript: &mut T,
) -> Result<(), Error> {
    dbg!("verify_aggregate_proof");
    proof.parsing_check()?;
    for pub_input in public_inputs {
        if (pub_input.len() + 1) != pvk.vk.gamma_abc_g1.len() {
            return Err(Error::MalformedVerifyingKey);
        }
    }

    if public_inputs.len() != proof.tmipp.gipa.nproofs as usize {
        return Err(Error::InvalidProof(
            "public inputs len != number of proofs".to_string(),
        ));
    }

    // Random linear combination of proofs
    transcript.append(b"AB-commitment", &proof.com_ab);
    transcript.append(b"C-commitment", &proof.com_c);
    let r = transcript.challenge_scalar::<<E as Pairing>::ScalarField>(b"r-random-fiatshamir");

    // channels to send/recv pairing checks so we aggregate them all in a
    // loop - 9 places where we send pairing checks
    let (send_checks, rcv_checks) = bounded(9);
    // channel to receive the final results so aggregate waits on all.
    let (valid_send, valid_rcv) = bounded(1);
    rayon::scope(move |s| {
        // Continuous loop that aggregate pairing checks together
        s.spawn(move |_| {
            let mut acc = PairingCheck::new();
            while let Ok(tuple) = rcv_checks.recv() {
                if let Some(tuple) = tuple {
                    acc.merge(&tuple);
                }
            }
            valid_send.send(acc.verify()).unwrap();
        });

        // 1.Check TIPA proof ab
        // 2.Check TIPA proof c
        let send_checks_copy = send_checks.clone();
        s.spawn(move |_| {
            let now = Instant::now();
            verify_tipp_mipp::<E, T>(
                ip_vk,
                proof,
                &r, // we give the extra r as it's not part of the proof itself - it is simply used on top for the groth16 aggregation
                &mut transcript,
                send_checks_copy,
            );
            dbg!("TIPP took {} ms", now.elapsed().as_millis(),);
        });

        // Check aggregate pairing product equation
        // SUM of a geometric progression
        // SUM a^i = (1 - a^n) / (1 - a) = -(1-a^n)/-(1-a)
        // = (a^n - 1) / (a - 1)
        dbg!("checking aggregate pairing");
        let mut r_sum = r.pow(&[public_inputs.len() as u64]);
        r_sum.sub_assign(&<E as Pairing>::ScalarField::one());
        let b = sub!(r, &<E as Pairing>::ScalarField::one())
            .inverse()
            .unwrap();
        r_sum.mul_assign(&b);

        // The following parts 3 4 5 are independently computing the parts of
        // the Groth16 verification equation NOTE From this point on, we are
        // only checking *one* pairing check (the Groth16 verification equation)
        // so we don't need to randomize as all other checks are being
        // randomized already. When merging all pairing checks together, this
        // will be the only one non-randomized.
        //
        let (r_vec_sender, r_vec_receiver) = bounded(1);
        //        s.spawn(move |_| {
        let now = Instant::now();
        r_vec_sender
            .send(structured_scalar_power(public_inputs.len(), &r))
            .unwrap();
        let elapsed = now.elapsed().as_millis();
        dbg!("generation of r vector: {}ms", elapsed);
        //        });

        par! {
            // 3. Compute left part of the final pairing equation
            let left = {
                let alpha_g1_r_suma = pvk.vk.alpha_g1;
                let alpha_g1_r_sum = alpha_g1_r_suma.mul(r_sum);

                E::miller_loop(E::G1Prepared::from(alpha_g1_r_sum.into()), E::G2Prepared::from(pvk.vk.beta_g2))

            },
            // 4. Compute right part of the final pairing equation
            let right = E::miller_loop(
                    // e(c^r vector form, h^delta)
                    E::G1Prepared::from(proof.agg_c),
                    E::G2Prepared::from(pvk.vk.delta_g2),
                ),
            // 5. compute the middle part of the final pairing equation, the one
            //    with the public inputs
            let middle = {
                    // We want to compute MUL(i:0 -> l) S_i ^ (SUM(j:0 -> n) ai,j * r^j)
                    // this table keeps tracks of incremental computation of each i-th
                    // exponent to later multiply with S_i
                    // The index of the table is i, which is an index of the public
                    // input element
                    // We incrementally build the r vector and the table
                    // NOTE: in this version it's not r^2j but simply r^j

                    let l = public_inputs[0].len();
                    let mut g_ic:<E as Pairing>::G1 = pvk.vk.gamma_abc_g1[0].into();
                    g_ic.mul_assign(r_sum);

                    let powers = r_vec_receiver.recv().unwrap();

                    let now = Instant::now();
                    // now we do the multi exponentiation
                    let summed = (0..l).into_par_iter().map(|i| {
                        // i denotes the column of the public input, and j denotes which public input
                        let mut c = public_inputs[0][i];
                        for j in 1..public_inputs.len() {
                            let mut ai = public_inputs[j][i];
                            ai.mul_assign(&powers[j]);
                            c.add_assign(&ai);
                        }
                        c
                    }).collect::<Vec<_>>();

                    let totsi = <E::G1 as VariableBaseMSM>::msm(&pvk.vk.gamma_abc_g1[1..],&summed).unwrap();

                    g_ic.add_assign(&totsi);

                    let ml = E::miller_loop(E::G1Prepared::from(g_ic.into_affine()), E::G2Prepared::from(pvk.vk.gamma_g2.clone()));
                    let elapsed = now.elapsed().as_millis();
                    dbg!("table generation: {}ms", elapsed);

                    ml
            }
        };
        // final value ip_ab is what we want to compare in the groth16
        // aggregated equation A * B
        let check = PairingCheck::from_products(vec![left, middle, right], proof.ip_ab);
        send_checks.send(Some(check)).unwrap();
    });
    let res = valid_rcv.recv().unwrap();
    dbg!(format!("aggregate verify done: valid ? {}", res));
    match res {
        true => Ok(()),
        false => Err(Error::InvalidProof("Proof Verification Failed".to_string())),
    }
}

/// verify_tipp_mipp returns a pairing equation to check the tipp proof.  $r$ is
/// the randomness used to produce a random linear combination of A and B and
/// used in the MIPP part with C
fn verify_tipp_mipp<E: Pairing, T: Transcript + Send>(
    v_srs: &VerifierKey<E>,
    proof: &AggregateProof<E>,
    r_shift: &E::ScalarField,
    transcript: &mut T,
    checks: Sender<Option<PairingCheck<E>>>,
) {
    dbg!("verify with srs shift");
    let now = Instant::now();
    // (T,U), Z for TIPP and MIPP  and all challenges
    let (final_res, final_r, challenges, challenges_inv) =
        gipa_verify_tipp_mipp(&proof, r_shift, transcript);
    dbg!(
        "TIPP verify: gipa verify tipp {}ms",
        now.elapsed().as_millis()
    );

    // Verify commitment keys wellformed
    let fvkey = proof.tmipp.gipa.final_vkey;
    let fwkey = proof.tmipp.gipa.final_wkey;
    // KZG challenge point
    transcript.append(b"kzg-challenge", &challenges[0]);
    transcript.append(b"vkey0", &proof.tmipp.gipa.final_vkey.0);
    transcript.append(b"vkey1", &proof.tmipp.gipa.final_vkey.1);
    transcript.append(b"wkey0", &proof.tmipp.gipa.final_wkey.0);
    transcript.append(b"wkey1", &proof.tmipp.gipa.final_wkey.1);
    let c = transcript.challenge_scalar::<E::ScalarField>(b"z-challenge");
    // we take reference so they are able to be copied in the par! macro
    let final_a = proof.tmipp.gipa.final_a;
    let final_b = proof.tmipp.gipa.final_b;
    let final_c = proof.tmipp.gipa.final_c;
    let final_zab = final_res.z_ab;
    let final_tab = final_res.t_ab;
    let final_uab = final_res.u_ab;
    let final_tc = final_res.t_c;
    let final_uc = final_res.u_c;

    let now = Instant::now();
    let vclone = checks.clone();
    let wclone = checks.clone();
    let zclone = checks.clone();
    let ab0clone = checks.clone();
    let ab1clone = checks.clone();
    let tclone = checks.clone();
    let uclone = checks.clone();
    par! {
        // check the opening proof for v
        let _vtuple = verify_kzg_v(
            v_srs,
            &fvkey,
            &proof.tmipp.vkey_opening,
            &challenges_inv,
            &c,
            vclone,
        ),
        // check the opening proof for w - note that w has been rescaled by $r^{-1}$
        let _wtuple = verify_kzg_w(
            v_srs,
            &fwkey,
            &proof.tmipp.wkey_opening,
            &challenges,
            &r_shift.inverse().unwrap(),
            &c,
            wclone,
        ),
        //
        // We create a sequence of pairing tuple that we aggregate together at
        // the end to perform only once the final exponentiation.
        //
        // TIPP
        // z = e(A,B)
        //let _check_z = zclone.send(PairingCheck::rand(&rng,&[(final_a, final_b)], final_zab)).unwrap(),
        let pcheckz = PairingCheck::rand(&[(final_a, final_b)], final_zab),
        //  final_aB.0 = T = e(A,v1)e(w1,B)
        //let check_ab0 = ab0clone.send(PairingCheck::rand(&rng,&[(final_a, &fvkey.0),(&fwkey.0, final_b)], final_tab)).unwrap(),
        let pcheck_ab = PairingCheck::rand(&[(final_a, fvkey.0),(fwkey.0, final_b)], final_tab),

        //  final_aB.1 = U = e(A,v2)e(w2,B)
        //let _check_ab1 = ab1clone.send(PairingCheck::rand(&rng,&[(final_a, &fvkey.1),(&fwkey.1, final_b)], final_uab)).unwrap(),
        let pcheckab2 = PairingCheck::rand(&[(final_a, fvkey.1),(fwkey.1, final_b)], final_uab),

        // MIPP
        // Verify base inner product commitment
        // Z ==  c ^ r
        let final_z = ip::multiexponentiation::<E::G1Affine>(&[final_c.clone()], &[final_r]),
        // Check commiment correctness
        // T = e(C,v1)
        //let _check_t = tclone.send(PairingCheck::rand(&rng,&[(final_c,&fvkey.0)],final_tc)).unwrap(),
        let pcheckt = PairingCheck::rand(&[(final_c, fvkey.0)],final_tc),
        // U = e(A,v2)
        //let _check_u = uclone.send(PairingCheck::rand(&rng,&[(final_c,&fvkey.1)],final_uc)).unwrap()
        let pchecku = PairingCheck::rand(&[(final_c, fvkey.1)],final_uc)
    };

    tclone.send(Some(pcheckt)).unwrap();
    uclone.send(Some(pchecku)).unwrap();
    ab0clone.send(Some(pcheck_ab)).unwrap();
    ab1clone.send(Some(pcheckab2)).unwrap();
    zclone.send(Some(pcheckz)).unwrap();
    match final_z {
        Err(e) => {
            dbg!("TIPP verify: INVALID with multi exp: {}", e);
            checks.send(None).unwrap();
        },
        Ok(z) => {
            dbg!(format!(
                "TIPP verify: parallel checks before merge: {}ms",
                now.elapsed().as_millis()
            ));
            // only check that doesn't require pairing so we can give a tuple
            // that will render the equation wrong in case it's false
            if z != final_res.z_c {
                dbg!(format!(
                    "tipp verify: INVALID final_z check {} vs {}",
                    z, final_res.z_c
                ));
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
fn gipa_verify_tipp_mipp<E: Pairing, T: Transcript + Send>(
    proof: &AggregateProof<E>,
    r_shift: &E::ScalarField,
    transcript: &mut T,
) -> (
    GipaTUZ<E>,
    E::ScalarField,
    Vec<E::ScalarField>,
    Vec<E::ScalarField>,
) {
    dbg!("gipa verify TIPP");
    let gipa = &proof.tmipp.gipa;
    // COM(A,B) = PROD e(A,B) given by prover
    let comms_ab = &gipa.comms_ab;
    // COM(C,r) = SUM C^r given by prover
    let comms_c = &gipa.comms_c;
    // Z vectors coming from the GIPA proofs
    let zs_ab = &gipa.z_ab;
    let zs_c = &gipa.z_c;

    let now = Instant::now();

    let mut challenges = Vec::new();
    let mut challenges_inv = Vec::new();

    transcript.append(b"inner-product-ab", &proof.ip_ab);
    transcript.append(b"comm-c", &proof.agg_c);
    let mut c_inv: E::ScalarField =
        transcript.challenge_scalar::<E::ScalarField>(b"first-challenge");
    let mut c = c_inv.inverse().unwrap();

    // We first generate all challenges as this is the only consecutive process
    // that can not be parallelized then we scale the commitments in a
    // parallelized way
    for (i, ((comm_ab, z_ab), (comm_c, z_c))) in comms_ab
        .iter()
        .zip(zs_ab.iter())
        .zip(comms_c.iter().zip(zs_c.iter()))
        .enumerate()
    {
        let (tab_l, tab_r) = comm_ab;
        let (tuc_l, tuc_r) = comm_c;
        let (zab_l, zab_r) = z_ab;
        let (zc_l, zc_r) = z_c;

        // Fiat-Shamir challenge
        if i == 0 {
            // already generated c_inv and c outside of the loop
        } else {
            transcript.append(b"c_inv", &c_inv);
            transcript.append(b"zab_l", zab_l);
            transcript.append(b"zab_r", zab_r);
            transcript.append(b"zc_l", zc_l);
            transcript.append(b"zc_r", zc_r);
            transcript.append(b"tab_l", tab_l);
            transcript.append(b"tab_r", tab_r);
            transcript.append(b"tuc_l", tuc_l);
            transcript.append(b"tuc_r", tuc_r);
            c_inv = transcript.challenge_scalar::<E::ScalarField>(b"challenge_i");
            c = c_inv.inverse().unwrap();
        }
        challenges.push(c);
        challenges_inv.push(c_inv);
    }

    dbg!(
        "TIPP verify: gipa challenge gen took {}ms",
        now.elapsed().as_millis()
    );

    let now = Instant::now();
    // output of the pair commitment T and U in TIPP -> COM((v,w),A,B)
    //let comab2 = proof.com_ab.clone();
    //let Output(t_ab, u_ab) = (comab2.0, comab2.1);
    let Commitment(t_ab, u_ab) = proof.com_ab;
    let z_ab = proof.ip_ab; // in the end must be equal to Z = A^r * B

    // COM(v,C)
    //let comc2 = proof.com_c.clone();
    //let (t_c, u_c) = (comc2.0, comc2.1);
    let Commitment(t_c, u_c) = proof.com_c.clone();
    let z_c = proof.agg_c.into_group(); // in the end must be equal to Z = C^r

    let mut final_res = GipaTUZ {
        t_ab,
        u_ab,
        z_ab,
        t_c,
        u_c,
        z_c,
    };

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

    let res = comms_ab
        .par_iter()
        .zip(zs_ab)
        .zip(comms_c.par_iter().zip(zs_c))
        .zip(challenges.par_iter().zip(&challenges_inv))
        .flat_map(|(((comm_ab, z_ab), (comm_c, z_c)), (&c, &c_inv))| {
            // T and U values for right and left for AB part
            let (Commitment(ref tab_l, ref uab_l), Commitment (ref tab_r, ref uab_r)) = comm_ab;
            let (ref zab_l, ref zab_r) = z_ab;
            // T and U values for right and left for C part
            let (Commitment ( ref tc_l, ref uc_l ), Commitment ( ref tc_r, ref uc_r )) = comm_c;
            let (ref zc_l, ref zc_r) = z_c;

            // we multiple left side by x and right side by x^-1
            [
                Op::T_AB::<E>(tab_l, c),
                Op::T_AB(tab_r, c_inv),
                Op::U_AB(uab_l, c),
                Op::U_AB(uab_r, c_inv),
                Op::Z_AB(zab_l, c),
                Op::Z_AB(zab_r, c_inv),
                Op::T_C::<E>(tc_l, c),
                Op::T_C(tc_r, c_inv),
                Op::U_C(uc_l, c),
                Op::U_C(uc_r, c_inv),
                Op::Z_C(zc_l, c),
                Op::Z_C(zc_r, c_inv),
            ]
        })
        .fold(GipaTUZ::<E>::default, |mut res, op: Op<E>| {
            match op {
                Op::T_AB(tx, c) => res.t_ab += *tx * c,
                Op::U_AB(ux, c) => res.u_ab += *ux * c,
                Op::Z_AB(zx, c) => res.z_ab += *zx * c,
                Op::T_C(tx, c) => res.t_c += *tx * c,
                Op::U_C(ux, c) => res.u_c += *ux * c,
                Op::Z_C(zx, c) => res.z_c += *zx * c,
            }
            res
        })
        .reduce(GipaTUZ::default, |mut acc_res, res| {
            acc_res.merge(&res);
            acc_res
        });
    // we reverse the order because the polynomial evaluation routine expects
    // the challenges in reverse order.Doing it here allows us to compute the final_r
    // in log time. Challenges are used as well in the KZG verification checks.
    challenges.reverse();
    challenges_inv.reverse();

    let ref_final_res = &mut final_res;
    let ref_challenges_inv = &challenges_inv;

    ref_final_res.merge(&res);
    let final_r = polynomial_evaluation_product_form_from_transcript(
        ref_challenges_inv,
        r_shift,
        &E::ScalarField::one(),
    );

    dbg!(
        "TIPP verify: gipa prep and accumulate took {}ms",
        now.elapsed().as_millis()
    );
    (final_res, final_r, challenges, challenges_inv)
}

/// verify_kzg_opening_g2 takes a KZG opening, the final commitment key, SRS and
/// any shift (in TIPP we shift the v commitment by r^-1) and returns a pairing
/// tuple to check if the opening is correct or not.
pub fn verify_kzg_v<E: Pairing>(
    v_srs: &VerifierKey<E>,
    final_vkey: &(E::G2Affine, E::G2Affine),
    vkey_opening: &KZGOpening<E::G2Affine>,
    challenges: &[E::ScalarField],
    kzg_challenge: &E::ScalarField,
    checks: Sender<Option<PairingCheck<E>>>,
) {
    // f_v(z)
    let vpoly_eval_z = polynomial_evaluation_product_form_from_transcript(
        challenges,
        kzg_challenge,
        &E::ScalarField::one(),
    );
    // -g such that when we test a pairing equation we only need to check if
    // it's equal 1 at the end:
    // e(a,b) = e(c,d) <=> e(a,b)e(-c,d) = 1
    let mut ng = v_srs.g.clone();
    // e(A,B) = e(C,D) <=> e(A,B)e(-C,D) == 1 <=> e(A,B)e(C,D)^-1 == 1
    ng = ng.neg();
    let ng = ng.into_affine();

    let v1clone = checks.clone();
    let v2clone = checks.clone();

    par! {
        // e(g, C_f * h^{-y}) == e(v1 * g^{-x}, \pi) = 1
        let _check1 = kzg_check_v::<E>(
            v_srs,
            ng,
            *kzg_challenge,
            vpoly_eval_z,
            final_vkey.0.into_group(),
            v_srs.g_alpha,
            vkey_opening.0,
            v1clone,
        ),

        // e(g, C_f * h^{-y}) == e(v2 * g^{-x}, \pi) = 1
        let _check2 = kzg_check_v::<E>(
            v_srs,
            ng,
            *kzg_challenge,
            vpoly_eval_z,
            final_vkey.1.into_group(),
            v_srs.g_beta,
            vkey_opening.1,
            v2clone,
        )
    };
}

fn kzg_check_v<E: Pairing>(
    v_srs: &VerifierKey<E>,
    ng: E::G1Affine,
    x: E::ScalarField,
    y: E::ScalarField,
    cf: E::G2,
    vk: E::G1,
    pi: E::G2Affine,
    checks: Sender<Option<PairingCheck<E>>>,
) {
    // KZG Check: e(g, C_f * h^{-y}) = e(vk * g^{-x}, \pi)
    // Transformed, such that
    // e(-g, C_f * h^{-y}) * e(vk * g^{-x}, \pi) = 1

    // C_f - (y * h)
    let b = (cf - v_srs.h * y).into();

    // vk - (g * x)
    let c = (vk - v_srs.g * x).into_affine();
    let p = PairingCheck::rand(&[(ng, b), (c, pi)], PairingOutput::default());
    checks.send(Some(p)).unwrap();
}

/// Similar to verify_kzg_opening_g2 but for g1.
pub fn verify_kzg_w<E: Pairing>(
    v_srs: &VerifierKey<E>,
    final_wkey: &(E::G1Affine, E::G1Affine),
    wkey_opening: &KZGOpening<E::G1Affine>,
    challenges: &[E::ScalarField],
    r_shift: &E::ScalarField,
    kzg_challenge: &E::ScalarField,
    checks: Sender<Option<PairingCheck<E>>>,
) {
    // compute in parallel f(z) and z^n and then combines into f_w(z) = z^n * f(z)
    par! {
        let fz = polynomial_evaluation_product_form_from_transcript(challenges, kzg_challenge, r_shift),
        let zn = kzg_challenge.pow(&[v_srs.n as u64])
    };

    let fwz = fz * zn;

    let nh = (-v_srs.h).into_affine();

    let w1clone = checks.clone();
    let w2clone = checks.clone();
    par! {
        // e(C_f * g^{-y}, h) = e(\pi, w1 * h^{-x})
        let _check1 = kzg_check_w::<E>(
            v_srs,
            nh,
            *kzg_challenge,
            fwz,
            final_wkey.0.into_group(),
            v_srs.h_alpha,
            wkey_opening.0,
            w1clone,
        ),

        // e(C_f * g^{-y}, h) = e(\pi, w2 * h^{-x})
        let _check2 = kzg_check_w::<E>(
            v_srs,
            nh,
            *kzg_challenge,
            fwz,
            final_wkey.1.into_group(),
            v_srs.h_beta,
            wkey_opening.1,
            w2clone,
        )
    };
}

fn kzg_check_w<E: Pairing>(
    v_srs: &VerifierKey<E>,
    nh: E::G2Affine,
    x: E::ScalarField,
    y: E::ScalarField,
    cf: E::G1,
    wk: E::G2,
    pi: E::G1Affine,
    checks: Sender<Option<PairingCheck<E>>>,
) {
    // KZG Check: e(C_f * g^{-y}, h) = e(\pi, wk * h^{-x})
    // Transformed, such that
    // e(C_f * g^{-y}, -h) * e(\pi, wk * h^{-x}) = 1

    // C_f - (y * g)
    let a = (cf - v_srs.g * y).into();

    // wk - (x * h)
    let d = (wk - v_srs.h * x).into();
    let p = PairingCheck::rand(&[(a, nh), (pi, d)], PairingOutput::default());
    checks.send(Some(p)).unwrap();
}

/// Keeps track of the variables that have been sent by the prover and must
/// be multiplied together by the verifier. Both MIPP and TIPP are merged
/// together.
struct GipaTUZ<E: Pairing> {
    pub t_ab: PairingOutput<E>,
    pub u_ab: PairingOutput<E>,
    pub z_ab: PairingOutput<E>,
    pub t_c: PairingOutput<E>,
    pub u_c: PairingOutput<E>,
    pub z_c: E::G1,
}

impl<E> Default for GipaTUZ<E>
where
    E: Pairing,
{
    fn default() -> Self {
        Self {
            t_ab: PairingOutput::default(),
            u_ab: PairingOutput::default(),
            z_ab: PairingOutput::default(),
            t_c: PairingOutput::default(),
            u_c: PairingOutput::default(),
            z_c: E::G1::zero(),
        }
    }
}

impl<E> GipaTUZ<E>
where
    E: Pairing,
{
    fn merge(&mut self, other: &Self) {
        self.t_ab += &other.t_ab;
        self.u_ab += &other.u_ab;
        self.z_ab += &other.z_ab;
        self.t_c += &other.t_c;
        self.u_c += &other.u_c;
        self.z_c += &other.z_c;
    }
}
