use crate::data_structures::{PreparedVerifyingKey, Proof, VerifyingKey};

use core::ops::Neg;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_relations::r1cs::SynthesisError;

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        g16_pvk: ark_groth16::verifier::prepare_verifying_key(&vk.g16_vk),
        etas_g2_neg_pc: vk
            .etas_g2
            .iter()
            .map(|p| p.into_group().neg().into_affine().into())
            .collect(),
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
        .chain(once(pvk.g16_pvk.gamma_g2_neg_pc.clone()))
        .chain(once(pvk.g16_pvk.delta_g2_neg_pc.clone()))
        .chain(pvk.etas_g2_neg_pc);

    let qap = E::multi_miller_loop(lhs, rhs);

    let test = E::final_exponentiation(qap).ok_or(SynthesisError::UnexpectedIdentity)?;

    Ok(test.0 == pvk.g16_pvk.alpha_g1_beta_g2)
}
