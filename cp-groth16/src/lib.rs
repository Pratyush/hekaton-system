use core::ops::Range;

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

pub mod committer;
pub mod data_structures;
pub mod generator;
pub mod prover;
pub mod verifier;

pub use committer::CommitmentBuilder;
pub use data_structures::{CommittingKey, ProvingKey, VerifyingKey};
pub use prover::Groth16;

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

// TODO: refactor this crate to only use AllocVar for input allocation. The reason this doesn't
// work right now is because
// 1) if you just give a Box<dyn AllocVar<V, F>> to an allocator, then this isn't sufficient
//    information for allocating a V=Vec<_>
// 2) for placeholder allocation, you need a &[Box<dyn PlaceholderAlloc<F>>]. It's important that V
//    is not part of the type, since otherwise it would be a heterogeneous slice. But how do you
//    rip V out of the type of AllocVar without doing an associated type (not allowed for Box dyn)
//    or making V the Self of the trait (what we effectively have now)?

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

        // Record the variable range. This may be empty. That's fine.
        self.instance_var_idx_ranges.push(Range {
            start: start_var_idx,
            end: end_var_idx,
        });

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

        // Record the variable range. This may be empty. That's fine.
        self.instance_var_idx_ranges.push(Range {
            start: start_var_idx,
            end: end_var_idx,
        });

        Ok(())
    }
}

/// Impl the prover
use crate::data_structures::{InputCom, InputComRandomness, Proof};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::Rng;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        committer::CommitmentBuilder,
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

    impl InputAllocator<F> for F {
        type AllocatedSelf = FpVar<F>;

        fn alloc(&self, cs: ConstraintSystemRef<F>) -> Result<Self::AllocatedSelf, SynthesisError> {
            FpVar::new_input(ns!(cs, "f"), || Ok(self))
        }
    }

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
        let pk = generate_random_parameters_with_reduction::<_, E, QAP>(
            &mut rng,
            &[Box::new(placeholder_allocator)],
            circuit.clone(),
        )
        .unwrap();

        // Create multistage circuit type
        // should be able to do circuit.alloc_stage::<1>() or something
        // circuit will save the allocd vars in its own struct for later stages.

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
