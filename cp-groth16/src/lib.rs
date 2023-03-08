use core::{marker::PhantomData, ops::Range};

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

// Impl the verifier

use data_structures::VerifyingKey;

use core::ops::Neg;

/// Verify a Groth16 proof `proof` against the prepared verification key `pvk` and prepared public
/// inputs. This should be preferred over [`verify_proof`] if the instance's public inputs are
/// known in advance.
pub fn verify_proof_with_prepared_inputs<E: Pairing>(
    vk: VerifyingKey<E>,
    proof: &Proof<E>,
    prepared_inputs: &E::G1,
) -> Result<bool, SynthesisError> {
    use core::iter::once;

    // Todo: Put this stuff in a PreparedVerifyingKey
    let alpha_g1_beta_g2 = E::pairing(vk.alpha_g1, vk.beta_g2).0;
    let gamma_g2_neg_pc: E::G2Prepared = vk.gamma_g2.into_group().neg().into_affine().into();
    let delta_g2_neg_pc: E::G2Prepared = vk.delta_g2.into_group().neg().into_affine().into();
    let etas_g2_neg_pc = vk
        .etas_g2
        .into_iter()
        .map(|p| p.into_group().neg().into_affine().into());

    let lhs = once(<E::G1Affine as Into<E::G1Prepared>>::into(proof.a))
        .chain(once(prepared_inputs.into_affine().into()))
        .chain(once(proof.c.into()))
        .chain(proof.ds.iter().map(E::G1Prepared::from));
    let rhs = once(proof.b.into())
        .chain(once(gamma_g2_neg_pc.clone()))
        .chain(once(delta_g2_neg_pc.clone()))
        .chain(etas_g2_neg_pc);

    let qap = E::multi_miller_loop(lhs, rhs);

    let test = E::final_exponentiation(qap).ok_or(SynthesisError::UnexpectedIdentity)?;

    Ok(test.0 == alpha_g1_beta_g2)
}
