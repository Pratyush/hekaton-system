use crate::{
    data_structures::{CommittingKey, ProvingKey, VerifyingKey},
    MultistageConstraintSystem, PlaceholderInputAllocator,
};

use core::iter;
use core::ops::Deref;
use std::boxed::Box;

use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, CurveGroup, Group};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{ConstraintSynthesizer, OptimizationGoal, SynthesisError, SynthesisMode};
use ark_std::{cfg_into_iter, cfg_iter, end_timer, rand::Rng, start_timer};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Generates a random common reference string for
/// a circuit using the provided R1CS-to-QAP reduction.
#[inline]
pub fn generate_random_parameters_with_reduction<C, E, QAP>(
    rng: &mut impl Rng,
    preallocators: &[Box<dyn PlaceholderInputAllocator<E::ScalarField>>],
    circuit: C,
) -> Result<ProvingKey<E>, SynthesisError>
where
    C: ConstraintSynthesizer<E::ScalarField>,
    E: Pairing,
    QAP: R1CSToQAP,
{
    let alpha = E::ScalarField::rand(rng);
    let beta = E::ScalarField::rand(rng);
    let gamma = E::ScalarField::rand(rng);
    let delta = E::ScalarField::rand(rng);
    let etas = iter::repeat_with(|| E::ScalarField::rand(rng))
        .take(preallocators.len())
        .collect();

    let g1_generator = E::G1::rand(rng);
    let g2_generator = E::G2::rand(rng);

    generate_parameters_with_qap::<_, _, QAP>(
        preallocators,
        circuit,
        alpha,
        beta,
        gamma,
        delta,
        etas,
        g1_generator,
        g2_generator,
        rng,
    )
}

/// Create parameters for a circuit, given some toxic waste, R1CS to QAP calculator and group generators
pub fn generate_parameters_with_qap<C, E, QAP>(
    preallocators: &[Box<dyn PlaceholderInputAllocator<E::ScalarField>>],
    circuit: C,
    alpha: E::ScalarField,
    beta: E::ScalarField,
    gamma: E::ScalarField,
    delta: E::ScalarField,
    etas: Vec<E::ScalarField>,
    g1_generator: E::G1,
    g2_generator: E::G2,
    rng: &mut impl Rng,
) -> Result<ProvingKey<E>, SynthesisError>
where
    C: ConstraintSynthesizer<E::ScalarField>,
    E: Pairing,
    QAP: R1CSToQAP,
{
    type D<F> = GeneralEvaluationDomain<F>;

    let setup_time = start_timer!(|| "Groth16::Generator");
    let mut mscs = MultistageConstraintSystem::default();
    mscs.cs.set_optimization_goal(OptimizationGoal::Constraints);
    mscs.cs.set_mode(SynthesisMode::Setup);

    // Run preallocation
    for a in preallocators {
        mscs.run_placeholder_allocator(a.deref())?;
    }

    // Synthesize the circuit.
    let synthesis_time = start_timer!(|| "Constraint synthesis");
    circuit.generate_constraints(mscs.cs.clone())?;
    end_timer!(synthesis_time);

    let lc_time = start_timer!(|| "Inlining LCs");
    mscs.cs.finalize();
    end_timer!(lc_time);

    // Deconstruct the multistage constraint system
    let MultistageConstraintSystem {
        cs,
        instance_var_idx_ranges,
    } = mscs;

    // Following is the mapping of symbols from the Groth16 paper to this implementation
    // l -> num_instance_variables
    // m -> qap_num_variables
    // x -> t
    // t(x) - zt
    // u_i(x) -> a
    // v_i(x) -> b
    // w_i(x) -> c

    ///////////////////////////////////////////////////////////////////////////
    let domain_time = start_timer!(|| "Constructing evaluation domain");

    let domain_size = cs.num_constraints() + cs.num_instance_variables();
    let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let t = domain.sample_element_outside_domain(rng);

    end_timer!(domain_time);
    ///////////////////////////////////////////////////////////////////////////

    let reduction_time = start_timer!(|| "R1CS to QAP Instance Map with Evaluation");
    let num_instance_variables = cs.num_instance_variables();
    let (a, b, c, zt, qap_num_variables, m_raw) =
        QAP::instance_map_with_evaluation::<E::ScalarField, D<E::ScalarField>>(cs, &t)?;
    end_timer!(reduction_time);

    // Compute query densities
    let non_zero_a: usize = cfg_into_iter!(0..qap_num_variables)
        .map(|i| usize::from(!a[i].is_zero()))
        .sum();

    let non_zero_b: usize = cfg_into_iter!(0..qap_num_variables)
        .map(|i| usize::from(!b[i].is_zero()))
        .sum();

    let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;

    // Step 1: For each pre-allocation stage, compute the polynomial corresponding to the instances
    // in that stage

    //let etas_abc: Vec<Vec<E::ScalarField>> = vec![vec![E::ScalarField::from(0u8)]];
    let mut etas_abc = Vec::new();
    for (eta, range) in etas.iter().zip(instance_var_idx_ranges.iter()) {
        let eta_inverse = eta.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;

        let eta_abc = cfg_iter!(a[dbg!(range).clone()])
            .zip(&b[range.clone()])
            .zip(&c[range.clone()])
            .map(|((a, b), c)| (beta * a + &(alpha * b) + c) * &eta_inverse)
            .collect::<Vec<_>>();

        etas_abc.push(eta_abc);
    }

    //
    // Step 2: Compute the polynomial correpsonding to the remaining public inputs
    //

    // Get the index of the first instance variable that's not preallocated
    let first_inst_var = instance_var_idx_ranges.last().map(|r| r.end).unwrap_or(0);

    // Compute the gamma ABCs
    let gamma_inverse = gamma.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;
    let mut gamma_abc = cfg_iter!(a[first_inst_var..num_instance_variables])
        .zip(&b[first_inst_var..num_instance_variables])
        .zip(&c[first_inst_var..num_instance_variables])
        .map(|((a, b), c)| (beta * a + &(alpha * b) + c) * &gamma_inverse)
        .collect::<Vec<_>>();

    // If we haven't already, we need to put the 0th instance var in the this list. This is the
    // variable that's always set to 1
    if first_inst_var != 0 {
        gamma_abc.insert(0, (beta * a[0] + &(alpha * b[0]) + c[0]) * &gamma_inverse);
    }

    //
    // Step 3: Compute the polynomial corresponding to the witnesses
    //

    let delta_inverse = delta.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;

    let l = cfg_iter!(a[num_instance_variables..])
        .zip(&b[num_instance_variables..])
        .zip(&c[num_instance_variables..])
        .map(|((a, b), c)| (beta * a + &(alpha * b) + c) * &delta_inverse)
        .collect::<Vec<_>>();

    drop(c);

    // Compute B window table
    let g2_time = start_timer!(|| "Compute G2 table");
    let g2_window = FixedBase::get_mul_window_size(non_zero_b);
    let g2_table = FixedBase::get_window_table::<E::G2>(scalar_bits, g2_window, g2_generator);
    end_timer!(g2_time);

    // Compute the B-query in G2
    let b_g2_time = start_timer!(|| "Calculate B G2");
    let b_g2_query = FixedBase::msm::<E::G2>(scalar_bits, g2_window, &g2_table, &b);
    drop(g2_table);
    end_timer!(b_g2_time);

    // Compute G window table
    let g1_window_time = start_timer!(|| "Compute G1 window table");
    let g1_window =
        FixedBase::get_mul_window_size(non_zero_a + non_zero_b + qap_num_variables + m_raw + 1);
    let g1_table = FixedBase::get_window_table::<E::G1>(scalar_bits, g1_window, g1_generator);
    end_timer!(g1_window_time);

    // Generate the R1CS proving key
    let proving_key_time = start_timer!(|| "Generate the R1CS proving key");

    let alpha_g1 = g1_generator.mul_bigint(&alpha.into_bigint());
    let beta_g1 = g1_generator.mul_bigint(&beta.into_bigint());
    let beta_g2 = g2_generator.mul_bigint(&beta.into_bigint());
    let delta_g1 = g1_generator.mul_bigint(&delta.into_bigint()).into_affine();
    let etas_g1 = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &etas);
    let delta_g2 = g2_generator.mul_bigint(&delta.into_bigint());
    let etas_g2 = etas
        .iter()
        .map(|e| g2_generator.mul_bigint(&e.into_bigint()).into_affine())
        .collect();

    // Compute the A-query
    let a_time = start_timer!(|| "Calculate A");
    let a_query = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &a);
    drop(a);
    end_timer!(a_time);

    // Compute the B-query in G1
    let b_g1_time = start_timer!(|| "Calculate B G1");
    let b_g1_query = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &b);
    drop(b);
    end_timer!(b_g1_time);

    // Compute the H-query
    let h_time = start_timer!(|| "Calculate H");
    let h_query = FixedBase::msm::<E::G1>(
        scalar_bits,
        g1_window,
        &g1_table,
        &QAP::h_query_scalars::<_, D<E::ScalarField>>(m_raw - 1, t, zt, delta_inverse)?,
    );

    end_timer!(h_time);

    // Compute the L-query
    let l_time = start_timer!(|| "Calculate L");
    let l_query = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &l);
    drop(l);
    end_timer!(l_time);

    end_timer!(proving_key_time);

    // Generate the R1CS commitment key
    let etas_abc_g1 = etas_abc
        .into_iter()
        .map(|v| {
            FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &v)
                .into_iter()
                .map(CurveGroup::into_affine)
                .collect()
        })
        .collect();
    let ck = CommittingKey {
        delta_g1,
        etas_abc_g1,
    };

    // Generate R1CS verification key
    let verifying_key_time = start_timer!(|| "Generate the R1CS verification key");
    let gamma_g2 = g2_generator.mul_bigint(&gamma.into_bigint());
    let gamma_abc_g1 = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &gamma_abc);

    drop(g1_table);

    end_timer!(verifying_key_time);

    let g16_vk = ark_groth16::VerifyingKey::<E> {
        alpha_g1: alpha_g1.into_affine(),
        beta_g2: beta_g2.into_affine(),
        gamma_g2: gamma_g2.into_affine(),
        delta_g2: delta_g2.into_affine(),
        gamma_abc_g1: E::G1::normalize_batch(&gamma_abc_g1),
    };

    let batch_normalization_time = start_timer!(|| "Convert proving key elements to affine");
    let a_query = E::G1::normalize_batch(&a_query);
    let b_g1_query = E::G1::normalize_batch(&b_g1_query);
    let b_g2_query = E::G2::normalize_batch(&b_g2_query);
    let h_query = E::G1::normalize_batch(&h_query);
    let l_query = E::G1::normalize_batch(&l_query);
    let etas_g1 = E::G1::normalize_batch(&etas_g1);
    end_timer!(batch_normalization_time);
    end_timer!(setup_time);

    let g16_pk = ark_groth16::ProvingKey {
        vk: g16_vk,
        beta_g1: beta_g1.into_affine(),
        delta_g1,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    };

    Ok(ProvingKey {
        g16_pk,
        ck,
        etas_g1,
        etas_g2,
    })
}

impl<E: Pairing> ProvingKey<E> {
    /// Returns the verifying key corresponding to this proving key
    pub fn vk(&self) -> VerifyingKey<E> {
        VerifyingKey::<E> {
            g16_vk: self.g16_pk.vk.clone(),
            etas_g2: self.etas_g2.clone(),
        }
    }
}
