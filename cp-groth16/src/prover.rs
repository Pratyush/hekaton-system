use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_groth16::{r1cs_to_qap::R1CSToQAP, Proof as ProofWithoutComms};
// use ark_msm::msm::VariableBaseMSMExt;
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::Result as R1CSResult;
use ark_std::{cfg_into_iter, end_timer, rand::Rng, start_timer, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{CPGroth16, MultiStageConstraintSynthesizer, MultiStageConstraintSystem, ProvingKey};

type D<F> = GeneralEvaluationDomain<F>;

impl<E: Pairing, QAP: R1CSToQAP> CPGroth16<E, QAP> {
    /// Create a Groth16 proof that is zero-knowledge.
    /// This method samples randomness for zero knowledges via `rng`.
    #[inline]
    pub fn prove_last_stage_with_zk<C>(
        cs: &mut MultiStageConstraintSystem<E::ScalarField>,
        circuit: &mut C,
        pk: &ProvingKey<E>,
        rng: &mut impl Rng,
    ) -> R1CSResult<ProofWithoutComms<E>>
    where
        C: MultiStageConstraintSynthesizer<E::ScalarField>,
        // E::G1: VariableBaseMSMExt,
        // E::G2: VariableBaseMSMExt,
    {
        let r = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);

        Self::prove_last_stage(cs, circuit, pk, r, s)
    }

    /// Create a Groth16 proof that is *not* zero-knowledge.
    #[inline]
    pub fn prove_last_stage_without_zk<C>(
        cs: &mut MultiStageConstraintSystem<E::ScalarField>,
        circuit: &mut C,
        pk: &ProvingKey<E>,
    ) -> R1CSResult<ProofWithoutComms<E>>
    where
        C: MultiStageConstraintSynthesizer<E::ScalarField>,
        // E::G1: VariableBaseMSMExt,
        // E::G2: VariableBaseMSMExt,
    {
        let r = E::ScalarField::zero();
        let s = E::ScalarField::zero();

        Self::prove_last_stage(cs, circuit, pk, r, s)
    }

    /// Create a Groth16 proof using randomness `r` and `s` and the provided
    /// R1CS-to-QAP reduction.
    #[inline]
    pub fn prove_last_stage<C>(
        cs: &mut MultiStageConstraintSystem<E::ScalarField>,
        circuit: &mut C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> R1CSResult<ProofWithoutComms<E>>
    where
        E: Pairing,
        // E::G1: VariableBaseMSMExt,
        // E::G2: VariableBaseMSMExt,
        C: MultiStageConstraintSynthesizer<E::ScalarField>,
        QAP: R1CSToQAP,
    {
        let prover_time = start_timer!(|| "Groth16::Prover");

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        // We're generating the last stage of constraints.
        circuit.generate_constraints(circuit.last_stage(), cs)?;
        debug_assert!(cs.is_satisfied()?);
        end_timer!(synthesis_time);

        #[cfg(feature = "parallel")]
        println!("num_threads: {}", rayon::current_num_threads());


        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        let assignment = cs.full_assignment();
        let assignment = cfg_into_iter!(assignment)
                    .skip(1) // we're skipping the one-variable
                    .map(|e| e.into_bigint())
                    .collect::<Vec<_>>();


        let current_witness = cs.current_stage_witness_assignment();
        let c_acc_time = start_timer!(|| "Compute C");
        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map::<E::ScalarField, D<E::ScalarField>>(cs.cs.clone())?;
        end_timer!(witness_map_time);
        
        let mut pool = crate::parallel::ExecutionPool::<ResultWrapper<E>>::with_capacity(5);


        pool.add_job(|| {
            let h_time = start_timer!(|| format!("Compute H with size {}", h.len()));
            assert_eq!(h.len(), pk.h_g.len() + 1);
            let h_acc = E::G1::msm(&pk.h_g, &h[..pk.h_g.len()]).unwrap();
            end_timer!(h_time);
            ResultWrapper::G1(h_acc)
        });

        pool.add_job(|| {
            let l_aux_time = start_timer!(|| format!("Compute L with size {}", current_witness.len()));
            assert_eq!(current_witness.len(), pk.last_ck().len());
            let l_aux_acc = E::G1::msm(&pk.last_ck(), &current_witness).unwrap();
            end_timer!(l_aux_time);
            ResultWrapper::G1(l_aux_acc)
        });

        

        // Compute C

        
        let r_s_delta_g = pk.last_delta_g() * (r * s);

        end_timer!(c_acc_time);

        // Compute A
        pool.add_job(|| {
            let a_acc_time = start_timer!(|| "Compute A");
            let r_delta_g = pk.last_delta_g() * r;
            
            let a_g = Self::calculate_coeff(r_delta_g, &pk.a_g, pk.vk.alpha_g, &assignment);
            
            end_timer!(a_acc_time);
            ResultWrapper::G1(a_g)
        });
                // Compute B in G1 if needed
        pool.add_job(|| {
            let b_g = if r.is_zero() {
                E::G1::zero()
            } else {
                let b_g1_acc_time = start_timer!(|| "Compute B in G1");
                let s_g = pk.last_delta_g() * s;
                let b_g = Self::calculate_coeff(s_g, &pk.b_g, pk.beta_g, &assignment);
                
                end_timer!(b_g1_acc_time);
                
                b_g
            };
            ResultWrapper::G1(b_g)
        });
        

        pool.add_job(|| {
            // Compute B in G2
            let b_g2_acc_time = start_timer!(|| "Compute B in G2");
            let s_h = pk.last_delta_h() * s;
            let b_h = Self::calculate_coeff(s_h, &pk.b_h, pk.vk.beta_h, &assignment);
            end_timer!(b_g2_acc_time);
            ResultWrapper::G2(b_h)
        });

        let [h_acc, l_aux_acc, a_g, b_g, b_h]: [ResultWrapper<E>; 5] = pool.execute_all().try_into().unwrap();
        let h_acc = h_acc.unwrap_g1();
        let l_aux_acc = l_aux_acc.unwrap_g1();
        let a_g = a_g.unwrap_g1();
        let b_g = b_g.unwrap_g1();
        let b_h = b_h.unwrap_g2();
        let r_b_g = b_g * r;
        let s_a_g = a_g * s;

        
        drop(assignment);


        let c_time = start_timer!(|| "Finish C");
        let mut c_g = s_a_g;
        c_g += &r_b_g;
        c_g -= &r_s_delta_g;
        c_g += &l_aux_acc;
        c_g += &h_acc;
        end_timer!(c_time);

        end_timer!(prover_time);
        Ok(ProofWithoutComms {
            a: a_g.into_affine(),
            b: b_h.into_affine(),
            c: c_g.into_affine(),
        })
    }

    fn calculate_coeff<G: AffineRepr>(
        initial: G::Group,
        query: &[G],
        vk_param: G,
        assignment: &[<G::ScalarField as PrimeField>::BigInt],
    ) -> G::Group
    where
        G::Group: VariableBaseMSM,
        // G::Group: VariableBaseMSMExt,
    {
        let el = query[0];
        let acc = G::Group::msm_bigint(&query[1..], assignment);

        initial + el + acc + vk_param
    }
}

#[derive(Clone, Copy, Debug)]
enum ResultWrapper<E: Pairing> {
    G1(E::G1),
    G2(E::G2),
}

impl<E: Pairing> ResultWrapper<E> {
    fn unwrap_g1(self) -> E::G1 {
        match self {
            ResultWrapper::G1(g) => g,
            ResultWrapper::G2(_) => panic!("unwrap_g1 called on G2"),
        }
    }
    fn unwrap_g2(self) -> E::G2 {
        match self {
            ResultWrapper::G2(g) => g,
            ResultWrapper::G1(_) => panic!("unwrap_g2 called on G1"),
        }
    }
}
