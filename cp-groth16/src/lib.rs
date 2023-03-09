use core::ops::Range;

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

pub mod committer;
pub mod data_structures;
pub mod generator;
pub mod verifier;

/// Represents a constraint system whose variables come from a number of distinct allocation
/// stages. Each allocation stage happens separately, and adds to the total instance variable
/// count.
pub struct MultistageConstraintSystem<F: Field> {
    pub cs: ConstraintSystemRef<F>,
    /// Keeps track of the instance variables. The value at element `i` is the set of instance
    /// variable indices in `self.cs` that correspond to stage `i` of allocation
    pub instance_var_idx_ranges: Vec<Range<usize>>,
}

impl<F: Field> Default for MultistageConstraintSystem<F> {
    fn default() -> Self {
        MultistageConstraintSystem {
            cs: ConstraintSystem::new_ref(),
            instance_var_idx_ranges: Vec::new(),
        }
    }
}

/// Defines a way for a type to allocate all its content as _instances_ or _constants_. It can
/// allocate witnesses too, but only the instances will be committed to.
pub trait InputAllocator<F: Field> {
    /// The ZK allocated vars version of this type
    type AllocatedSelf;

    fn alloc(&self, cs: ConstraintSystemRef<F>) -> Result<Self::AllocatedSelf, SynthesisError>;
}

/// An unfortunate helper trait we need in order to make Rust's generics work. This is the same
/// thing as [`InputAllocator`] but it doesn't return anything when allocating. This is used in
/// CRS generation
pub trait PlaceholderInputAllocator<F: Field> {
    fn alloc(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError>;
}

/// Every [`InputAllocator`] is an [`PlaceholderInputAllocator`]. The `alloc()` method just returns
/// nothing
impl<I, F> PlaceholderInputAllocator<F> for I
where
    I: InputAllocator<F>,
    F: Field,
{
    fn alloc(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        InputAllocator::alloc(self, cs).map(|_| ())
    }
}

impl<F: Field> MultistageConstraintSystem<F> {
    /// Runs the given allocator, records its allocations, and returns the output
    pub fn run_allocator<A: InputAllocator<F>>(
        &mut self,
        a: &A,
    ) -> Result<A::AllocatedSelf, SynthesisError> {
        // Mark the starting variable index (inclusive)
        let start_var_idx = self.cs.num_instance_variables();
        // Run the allocation routine and save the output
        let out = a.alloc(self.cs.clone())?;
        // Mark the ending variable index (exclusive)
        let end_var_idx = self.cs.num_instance_variables();

        // Record the variable range. If it's empty, do nothing
        let range = Range {
            start: start_var_idx,
            end: end_var_idx,
        };
        if !range.is_empty() {
            self.instance_var_idx_ranges.push(range);
        }

        Ok(out)
    }

    // TODO: Figure out a way to not repeat the code from above
    /// Runs the given placeholder allocator and records its allocations
    pub fn run_placeholder_allocator(
        &mut self,
        val: &dyn PlaceholderInputAllocator<F>,
    ) -> Result<(), SynthesisError> {
        // Mark the starting variable index (inclusive)
        let start_var_idx = self.cs.num_instance_variables();
        // Run the allocation routine
        val.alloc(self.cs.clone())?;
        // Mark the ending variable index (exclusive)
        let end_var_idx = self.cs.num_instance_variables();

        // Record the variable range. If it's empty, do nothing
        let range = Range {
            start: start_var_idx,
            end: end_var_idx,
        };
        if !range.is_empty() {
            self.instance_var_idx_ranges.push(range);
        }

        Ok(())
    }
}

/// Impl the prover
use crate::data_structures::{InputCom, InputComRandomness, Proof, ProvingKey};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_groth16::Groth16;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::Rng;

pub fn prove<C, E>(
    rng: &mut impl Rng,
    circuit: C,
    pk: &ProvingKey<E>,
    coms: Vec<InputCom<E>>,
    com_rands: &[InputComRandomness<E>],
) -> Result<Proof<E>, SynthesisError>
where
    C: ConstraintSynthesizer<E::ScalarField>,
    E: Pairing,
{
    let ark_groth16::Proof { a, b, c } =
        Groth16::<E>::create_random_proof_with_reduction(circuit, &pk.g16_pk, rng)?;

    // Compute Σ [κᵢηᵢ] and subtract it from C
    let kappas_etas_g1 =
        E::G1::msm(&pk.etas_g1, com_rands).expect("incorrect number of commitment randomness vals");
    let c = (c.into_group() - &kappas_etas_g1).into_affine();

    Ok(Proof { a, b, c, ds: coms })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generator::generate_random_parameters_with_reduction,
        verifier::{prepare_verifying_key, verify_proof_with_prepared_inputs},
    };

    use ark_bls12_381::{Bls12_381 as E, Fr as F};
    use ark_ff::{ToConstraintField, UniformRand};
    use ark_groth16::r1cs_to_qap::LibsnarkReduction as QAP;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::{
        ns,
        r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError},
    };
    use ark_std::test_rng;

    /// A circuit that proves knowledge of a root for a given monic polynomial
    #[derive(Clone)]
    struct PolynZeroCircuit {
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
            polyn_var
                .last()
                .unwrap()
                .enforce_equal(&FpVar::Constant(F::ONE))?;

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
        let circuit = PolynZeroCircuit {
            polyn: polyn.clone(),
            root,
        };
        let cs = ConstraintSystem::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());

        //
        // Proof check
        //

        // Make the proving key and compute the proof
        let pk =
            generate_random_parameters_with_reduction::<_, E, QAP>(&mut rng, &[], circuit.clone())
                .unwrap();
        // Do the proof. The empty values are because we haven't committed to anything
        let proof = prove(&mut rng, circuit, &pk, vec![], &[]).unwrap();

        // Verify. The public input
        let pvk = prepare_verifying_key(&pk.vk());
        let inputs = polyn.to_field_elements().unwrap();
        let prepared_inputs = Groth16::<E, QAP>::prepare_inputs(&pvk.g16_pvk, &inputs).unwrap();
        assert!(verify_proof_with_prepared_inputs(pvk, &proof, &prepared_inputs).unwrap());

        //let polyn = core::iter::repeat_with(|| F::rand(&mut rng) - root).take(
    }
}
