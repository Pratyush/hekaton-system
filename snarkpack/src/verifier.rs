use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::PreparedVerifyingKey;
use crossbeam_channel::bounded;
use rayon::prelude::*;
use std::ops::{AddAssign, Mul, MulAssign};

use super::{pairing_check::PairingCheck, srs::VerifierKey, transcript::Transcript};
use crate::data_structures::AggregationProof;
use crate::Error;
use crate::{utils::structured_scalar_power, SnarkPack};

use std::time::Instant;

impl<E: Pairing> SnarkPack<E> {
    /// Verifies the aggregated proofs thanks to the Groth16 verifying key, the
    /// verifier SRS from the aggregation scheme, all the public inputs of the
    /// proofs and the aggregated proof.
    pub fn verify(
        ip_vk: &VerifierKey<E>,
        pvk: &PreparedVerifyingKey<E>,
        public_inputs: &[Vec<<E as Pairing>::ScalarField>],
        proof: &AggregationProof<E>,
        transcript: &mut (impl Transcript + Send),
    ) -> Result<(), Error> {
        println!("verify_aggregate_proof");
        proof.parsing_check()?;
        for pub_input in public_inputs {
            if (pub_input.len() + 1) != pvk.vk.gamma_abc_g1.len() {
                return Err(Error::MalformedVerifyingKey);
            }
        }

        if public_inputs.len() != proof.mmt_proof.gipa.num_proofs as usize {
            return Err(Error::InvalidProof(
                "public inputs len != number of proofs".to_string(),
            ));
        }

        // Random linear combination of proofs
        transcript.append(b"AB-commitment", &proof.comm_ab);
        transcript.append(b"C-commitment", &proof.comm_c);
        let r = transcript.challenge::<<E as Pairing>::ScalarField>(b"r-random-fiatshamir");

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

            let mmt_instance = crate::mmt::Instance {
                size: proof.mmt_proof.gipa.num_proofs as usize,
                comm_ab: proof.comm_ab.clone(),
                aggregated_ab: proof.aggregated_ab,
                comm_c: proof.comm_c.clone(),
                aggregated_c: proof.aggregated_c,
                random_challenge: r,
            };

            // 1.Check TIPA proof ab
            // 2.Check TIPA proof c
            let send_checks_copy = send_checks.clone();
            s.spawn(move |_| {
                let now = Instant::now();
                crate::mmt::MMT::verify(
                    ip_vk,
                    &mmt_instance,
                    &proof.mmt_proof,
                    transcript,
                    send_checks_copy,
                );
                println!("TIPP took {} ms", now.elapsed().as_millis());
            });

            // Check aggregate pairing product equation
            // SUM of a geometric progression
            // SUM a^i = (1 - a^n) / (1 - a) = -(1-a^n)/-(1-a)
            // = (a^n - 1) / (a - 1)
            println!("checking aggregate pairing");
            let mut r_sum = r.pow(&[public_inputs.len() as u64]) - E::ScalarField::ONE;
            let b = (r - E::ScalarField::ONE).inverse().unwrap();
            r_sum *= &b;

            // The following parts 3 4 5 are independently computing the parts of
            // the Groth16 verification equation
            //  NOTE From this point on, we are
            // only checking *one* pairing check (the Groth16 verification equation)
            // so we don't need to randomize as all other checks are being
            // randomized already. When merging all pairing checks together, this
            // will be the only one non-randomized.
            //
            let (r_vec_sender, r_vec_receiver) = bounded(1);
            //        s.spawn(move |_| {
            let now = Instant::now();
            r_vec_sender
                .send(structured_scalar_power(public_inputs.len(), r))
                .unwrap();
            let elapsed = now.elapsed().as_millis();
            println!("generation of r vector: {}ms", elapsed);
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
                        E::G1Prepared::from(proof.aggregated_c),
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
                        println!("table generation: {}ms", elapsed);

                        ml
                }
            };
            // final value ip_ab is what we want to compare in the groth16
            // aggregated equation A * B
            let check = PairingCheck::from_products(vec![left, middle, right], proof.aggregated_ab);
            send_checks.send(Some(check)).unwrap();
        });
        let res = valid_rcv.recv().unwrap();
        println!("aggregate verify done: valid ? {}", res);
        match res {
            true => Ok(()),
            false => Err(Error::InvalidProof("Proof Verification Failed".to_string())),
        }
    }
}
