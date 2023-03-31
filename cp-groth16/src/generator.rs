use crate::{
    constraint_synthesizer::MultiStageConstraintSynthesizer,
    data_structures::{CommitterKey, ProvingKey, VerifyingKey},
    MultiStageConstraintSystem,
};

use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, CurveGroup, Group};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{OptimizationGoal, SynthesisError, SynthesisMode};
use ark_std::{cfg_into_iter, cfg_iter, end_timer, rand::Rng, start_timer};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Generates a random common reference string for
/// a circuit using the provided R1CS-to-QAP reduction.
#[inline]
pub fn generate_random_parameters_with_reduction<C, E, QAP>(
    circuit: C,
    rng: &mut impl Rng,
) -> Result<ProvingKey<E>, SynthesisError>
where
    C: MultiStageConstraintSynthesizer<E::ScalarField>,
    E: Pairing,
    QAP: R1CSToQAP,
{
    let alpha = E::ScalarField::rand(rng);
    let beta = E::ScalarField::rand(rng);
    let gamma = E::ScalarField::rand(rng);
    let deltas = (0..circuit.total_num_stages())
        .map(|_| E::ScalarField::rand(rng))
        .collect();

    let g1_generator = E::G1::rand(rng);
    let g2_generator = E::G2::rand(rng);

    generate_parameters_with_qap::<_, _, QAP>(
        circuit,
        alpha,
        beta,
        gamma,
        deltas,
        g1_generator,
        g2_generator,
        rng,
    )
}

/// Create parameters for a circuit, given some toxic waste, R1CS to QAP calculator and group generators
pub fn generate_parameters_with_qap<C, E, QAP>(
    mut circuit: C,
    alpha: E::ScalarField,
    beta: E::ScalarField,
    gamma: E::ScalarField,
    deltas: Vec<E::ScalarField>,
    g1_generator: E::G1,
    g2_generator: E::G2,
    rng: &mut impl Rng,
) -> Result<ProvingKey<E>, SynthesisError>
where
    C: MultiStageConstraintSynthesizer<E::ScalarField>,
    E: Pairing,
    QAP: R1CSToQAP,
{
    type D<F> = GeneralEvaluationDomain<F>;

    let setup_time = start_timer!(|| "CPGroth16::Generator");
    let mut mscs = MultiStageConstraintSystem::default();
    mscs.cs.set_optimization_goal(OptimizationGoal::Constraints);
    mscs.cs.set_mode(SynthesisMode::Setup);

    // Synthesize the circuit.
    let synthesis_time = start_timer!(|| "Constraint synthesis");
    for stage in 0..circuit.total_num_stages() {
        circuit.generate_constraints(stage, &mut mscs)?;
    }
    end_timer!(synthesis_time);

    let lc_time = start_timer!(|| "Inlining LCs");
    mscs.finalize();
    end_timer!(lc_time);

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

    let domain_size = mscs.num_constraints() + mscs.num_instance_variables();
    let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let t = domain.sample_element_outside_domain(rng);

    end_timer!(domain_time);
    ///////////////////////////////////////////////////////////////////////////

    let reduction_time = start_timer!(|| "R1CS to QAP Instance Map with Evaluation");
    let num_instance_variables = dbg!(mscs.num_instance_variables());
    dbg!(mscs.num_constraints());
    dbg!(mscs.num_witness_variables());
    let (a, b, c, zt, qap_num_variables, m_raw) = QAP::instance_map_with_evaluation::<
        E::ScalarField,
        D<E::ScalarField>,
    >(mscs.cs.clone(), &t)?;
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

    let deltas_abc = deltas
        .iter()
        .zip(&mscs.variable_range_for_stage)
        .map(|(delta, range)| {
            let range =
                (range.start + num_instance_variables)..(range.end + num_instance_variables);
            let delta_inv = delta.inverse().expect("deltas should be non-zero");
            cfg_iter!(a[dbg!(range.clone())])
                .zip(&b[range.clone()])
                .zip(&c[range.clone()])
                .map(|((a, b), c)| (beta * a + alpha * b + c) * &delta_inv)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    //
    // Step 2: Compute the polynomial correpsonding to the public inputs
    //

    // Compute the gamma ABCs
    let gamma_inverse = gamma.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;
    let gamma_abc = cfg_iter!(a[..num_instance_variables])
        .zip(&b[..num_instance_variables])
        .zip(&c[..num_instance_variables])
        .map(|((a, b), c)| (beta * a + &(alpha * b) + c) * &gamma_inverse)
        .collect::<Vec<_>>();

    //
    // Step 3: Compute the polynomial corresponding to the witnesses
    //

    let last_delta = deltas.last().expect("we should have at least one witness.");
    let last_delta_inv = last_delta.inverse().expect("delta should not be zero");

    drop(c);

    // Compute B window table
    let g2_time = start_timer!(|| "Compute G2 table");
    let g2_window = FixedBase::get_mul_window_size(non_zero_b);
    let g2_table = FixedBase::get_window_table::<E::G2>(scalar_bits, g2_window, g2_generator);
    end_timer!(g2_time);
    // Compute the B-query in G2
    let b_g2_time = start_timer!(|| "Calculate B G2");
    let b_h = FixedBase::msm::<E::G2>(scalar_bits, g2_window, &g2_table, &b);
    end_timer!(b_g2_time);

    // Compute G window table
    let g1_window_time = start_timer!(|| "Compute G1 window table");
    let g1_window =
        FixedBase::get_mul_window_size(non_zero_a + non_zero_b + qap_num_variables + m_raw + 1);
    let g1_table = FixedBase::get_window_table::<E::G1>(scalar_bits, g1_window, g1_generator);
    end_timer!(g1_window_time);

    // Generate the R1CS proving key
    let proving_key_time = start_timer!(|| "Generate the R1CS proving key");

    let alpha_g = g1_generator.mul_bigint(&alpha.into_bigint()).into_affine();
    let beta_g = g1_generator.mul_bigint(&beta.into_bigint()).into_affine();
    let beta_h = g2_generator.mul_bigint(&beta.into_bigint()).into_affine();
    let deltas_g = {
        let t = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &deltas);
        E::G1::normalize_batch(&t)
    };
    let deltas_h = {
        let t = FixedBase::msm::<E::G2>(scalar_bits, g2_window, &g2_table, &deltas);
        E::G2::normalize_batch(&t)
    };
    drop(g2_table);
    let gamma_h = g2_generator.mul_bigint(&gamma.into_bigint()).into_affine();
    let gamma_abc_g = {
        let t = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &gamma_abc);
        E::G1::normalize_batch(&t)
    };

    let last_delta_g = *deltas_g.last().unwrap();
    let last_delta_h = *deltas_h.last().unwrap();

    // Compute the A-query
    let a_time = start_timer!(|| "Calculate A");
    let a_g = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &a);
    drop(a);
    end_timer!(a_time);

    // Compute the B-query in G1
    let b_g1_time = start_timer!(|| "Calculate B G1");
    let b_g = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &b);
    drop(b);
    end_timer!(b_g1_time);

    // Compute the H-query
    let h_time = start_timer!(|| "Calculate H");
    let h = QAP::h_query_scalars::<_, D<E::ScalarField>>(m_raw - 1, t, zt, last_delta_inv)?;
    let h_g = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &h);
    dbg!(h_g.len());
    dbg!(h.len());

    end_timer!(h_time);
    end_timer!(proving_key_time);

    // Generate the R1CS commitment key
    let ck_time = start_timer!(|| "Calculate Commitment Key");
    let deltas_abc_g = deltas_abc
        .into_iter()
        .map(|v| {
            FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &v)
                .into_iter()
                .map(E::G1::into_affine)
                .collect()
        })
        .collect::<Vec<_>>();
    end_timer!(ck_time);

    let ck = CommitterKey {
        last_delta_g,
        deltas_abc_g,
    };

    // Generate R1CS verification key
    let verifying_key_time = start_timer!(|| "Generate the R1CS verification key");

    drop(g1_table);

    end_timer!(verifying_key_time);

    let vk = VerifyingKey {
        alpha_g,
        beta_h,
        gamma_h,
        last_delta_h,
        gamma_abc_g,
        deltas_h,
    };

    let batch_normalization_time = start_timer!(|| "Convert proving key elements to affine");
    let a_g = E::G1::normalize_batch(&a_g);
    let b_g = E::G1::normalize_batch(&b_g);
    let b_h = E::G2::normalize_batch(&b_h);
    let h_g = E::G1::normalize_batch(&h_g);
    end_timer!(batch_normalization_time);
    end_timer!(setup_time);

    Ok(ProvingKey {
        vk,
        ck,
        beta_g,
        a_g,
        b_g,
        b_h,
        h_g,
        deltas_g,
    })
}
