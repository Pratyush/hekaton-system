mod proof;
use ark_ec::pairing::{Pairing, PairingOutput};
pub use proof::*;

use crate::commitment::Commitment;

/// An MMT instance
pub struct Instance<E: Pairing> {
    /// Size of aggregation
    pub size: usize,

    /// Corresponds to the $\mathsf{CM_D}.\mathsf{Commit}(A,B)$ from the paper.
    pub comm_ab: Commitment<E>,
    /// Corresponds to $Z_AB$ from the paper.
    pub aggregated_ab: PairingOutput<E>,

    /// Corresponds to the $\mathsf{CM_S}.\mathsf{Commit}(C)$ from the paper.
    pub comm_c: Commitment<E>,
    /// Corresponds to $Z_C$ from the paper.
    pub aggregated_c: E::G1Affine,

    /// The random challenge used for aggregating A and B, and C.
    pub random_challenge: E::ScalarField,
}

pub struct Witness<E: Pairing> {
    pub a: Vec<E::G1Affine>,
    pub b: Vec<E::G2Affine>,
    pub c: Vec<E::G1Affine>,
}
