pub mod committer;
pub mod constraint_synthesizer;
pub mod data_structures;
pub mod generator;
pub mod prover;
pub mod verifier;

pub use committer::CommitmentBuilder;
pub use constraint_synthesizer::*;
pub use data_structures::{CommitterKey, ProvingKey, VerifyingKey};
pub use prover::Groth16;

/// Impl the prover
#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
    use ark_std::vec::Vec;

    use super::*;
    use crate::{
        committer::CommitmentBuilder,
        generator::generate_random_parameters_with_reduction,
        verifier::{prepare_verifying_key, verify_proof_with_prepared_inputs},
    };
    use ark_ec::AffineRepr;
    use ark_relations::r1cs::ConstraintSynthesizer;

    use ark_bls12_381::{Bls12_381 as E, Fr as F};
    use ark_ff::{ToConstraintField, UniformRand};
    use ark_groth16::r1cs_to_qap::LibsnarkReduction as QAP;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::ns;
    use ark_std::test_rng;

    /// A circuit that proves knowledge of a root for a given monic polynomial
    #[derive(Clone)]
    struct PolynZeroCircuit {
        // A committed value that must be zero
        zero_var: FpVar<F>,
        // Coefficients of a monic polynomial, from lowest to highest degree
        polyn: Vec<F>,
        // An alleged root of the polynomial
        root: F,
    }

    impl ConstraintSynthesizer<F> for PolynZeroCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            // Input the polynomial P. P must be monic, i.e., the leading coefficient is 1.
            let polyn_var = self
                .polyn
                .into_iter()
                .map(|c| FpVar::new_input(ns!(cs, "coeff"), || Ok(c)))
                .collect::<Result<Vec<_>, _>>()?;
            /*
            polyn_var
                .last()
                .unwrap()
                .enforce_equal(&FpVar::Constant(F::ONE))?;
            */

            // Assert the zero var is zero
            // NOTE: If you comment out this line, the test succeeds
            self.zero_var.enforce_equal(&FpVar::Constant(F::ZERO))?;

            // The X on which we evaluate P(X)
            let x_var = FpVar::new_witness(ns!(cs, "root"), || Ok(self.root))?;

            // Evaluate the polynomial
            let mut poly_eval = FpVar::Constant(F::ZERO);
            let mut pow_x = FpVar::Constant(F::ONE);
            for coeff in polyn_var {
                poly_eval += coeff * &pow_x;
                pow_x *= &x_var;
            }

            // Assert that it's a root
            poly_eval.enforce_equal(&FpVar::Constant(F::ZERO))?;
            println!(
                "a constraints after poly_eval eq: {:?}",
                cs.constraint_names(),
            );

            Ok(())
        }
    }

    // Do a Groth16 test that involves no commitment
    #[test]
    fn nocommit() {
        let mut rng = test_rng();

        // Pick a root, then make a degree 10 polyn with that root
        let deg = 10;
        let root = F::rand(&mut rng);
        // Start with P(X) = X - root
        let mut polyn = vec![-root, F::ONE];
        // Now iteratively compute P'(X) = P(X) * (X - r) for some random r each time
        for _ in 0..deg - 1 {
            let rand_root = F::rand(&mut rng);
            // Multiply everything by X, i.e., shift all the coeffs down
            polyn.insert(0, F::ZERO);
            // Subtract rP(X)
            for i in 0..polyn.len() - 1 {
                let tmp = polyn[i + 1];
                polyn[i] -= rand_root * tmp;
            }
        }
        polyn = vec![F::ZERO; deg + 1];

        //
        // Sanity check
        //

        // Check that P(root) == 0
        let mut poly_eval = F::ZERO;
        let mut pow_x = F::ONE;
        for c in polyn.iter() {
            poly_eval += c * &pow_x;
            pow_x *= root;
        }
        assert_eq!(poly_eval, F::ZERO);

        //
        // Constraints check
        //

        // Now run the circuit and make sure it succeeds
        let mut circuit = PolynZeroCircuit {
            zero_var: FpVar::Constant(F::ZERO),
            polyn: polyn.clone(),
            root,
        };
        let cs = ConstraintSystem::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());

        //
        // Proof check
        //

        // Generate the proving key
        let placeholder_allocator = F::ZERO;
        let pk = generate_random_parameters_with_reduction::<_, E, QAP>(circuit.clone(), &mut rng)
            .unwrap();

        // Create the commitment and proof
        let allocator = F::ZERO;
        let mut cb = CommitmentBuilder::<_, QAP>::new(pk.ck.clone());
        let (com, rand, zero_var) = cb.commit(&mut rng, &allocator).unwrap();
        // Add the committed variable to the circuit context
        circuit.zero_var = zero_var;
        // Do the proof. The empty values are because we haven't committed to anything
        //let proof = prove(&mut rng, circuit, &pk, vec![com], &[rand]).unwrap();
        let proof = cb
            .prove(&mut rng, circuit, &pk, vec![com], &[rand])
            .unwrap();

        // Verify
        let pvk = prepare_verifying_key(&pk.vk());
        let inputs = polyn.to_field_elements().unwrap();
        let prepared_inputs =
            ark_groth16::Groth16::<E, QAP>::prepare_inputs(&pvk.g16_pvk, &inputs).unwrap();
        dbg!(pvk.g16_pvk.vk.gamma_abc_g1[0].into_group() == prepared_inputs);
        assert!(verify_proof_with_prepared_inputs(pvk, &proof, &prepared_inputs).unwrap());

        //let polyn = core::iter::repeat_with(|| F::rand(&mut rng) - root).take(
    }
}
