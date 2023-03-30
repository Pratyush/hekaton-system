use crate::data_structures::{PreparedVerifyingKey, Proof, VerifyingKey};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_relations::r1cs::SynthesisError;

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_beta_gt: E::pairing(vk.alpha_g, vk.beta_h),
        neg_gamma_h: (-vk.gamma_h.into_group()).into_affine().into(),
        neg_deltas_h: vk.deltas_h.iter().map(|g| (-g.into_group()).into_affine().into()).collect(),
    }
}

/// Verify a Groth16 proof `proof` against the prepared verification key `pvk` and prepared public
/// inputs. This should be preferred over [`verify_proof`] if the instance's public inputs are
/// known in advance.
pub fn verify_proof_with_prepared_inputs<E: Pairing>(
    pvk: PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    prepared_inputs: &E::G1,
) -> Result<bool, SynthesisError> {
    use core::iter::once;

    let lhs = once(<E::G1Affine as Into<E::G1Prepared>>::into(proof.a))
        .chain(once(prepared_inputs.into_affine().into()))
        .chain(once(proof.c.into()))
        .chain(proof.ds.iter().map(E::G1Prepared::from));
    let rhs = once(proof.b.into())
        .chain(once(pvk.neg_gamma_h.clone()))
        .chain(pvk.neg_deltas_h.clone());

    let qap = E::multi_miller_loop(lhs, rhs);

    let test = E::final_exponentiation(qap).ok_or(SynthesisError::UnexpectedIdentity)?;

    Ok(test == pvk.alpha_beta_gt)
}
