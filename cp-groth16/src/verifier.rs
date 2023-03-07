use crate::data_structures::{PreparedVerifyingKey, VerifyingKey};

use core::ops::Neg;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2).0,
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
        etas_g2_neg_pc: vk
            .etas_g2
            .iter()
            .map(|p| p.into_group().neg().into_affine().into())
            .collect(),
    }
}
