use ark_ec::pairing::{Pairing, PairingOutput};
use ark_serialize::*;
use ark_std::vec::Vec;

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing> {
    /// The `A` element in `G1`.
    pub a: E::G1Affine,
    /// The `B` element in `G2`.
    pub b: E::G2Affine,
    /// The `C` element in `G1`.
    pub c: E::G1Affine,
    /// The `Cᵢ` elements in `G1`.
    pub ds: Vec<E::G1Affine>,
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: Pairing> {
    /// `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g: E::G1Affine,
    /// `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_h: E::G2Affine,
    /// `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_h: E::G2Affine,
    /// `delta * H`, where `H` is the generator of `E::G2`.
    pub last_delta_h: E::G2Affine,
    /// `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is the generator of `E::G1`.
    pub gamma_abc_g: Vec<E::G1Affine>,
    /// `deltaᵢ * H`, where `H` is the generator of `E::G2`.
    pub deltas_h: Vec<E::G2Affine>,
}

/// Preprocessed verification key parameters that enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedVerifyingKey<E: Pairing> {
    /// The unprepared verification key.
    pub vk: VerifyingKey<E>,
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_beta_gt: PairingOutput<E>,
    /// The element `- gamma * H` in `E::G2`, prepared for use in pairings.
    pub neg_gamma_h: E::G2Prepared,
    /// The element `- deltaᵢ * H` in `E::G2`, prepared for use in pairings.
    pub neg_deltas_h: Vec<E::G2Prepared>,
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// The prover key for for the Groth16 zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: Pairing> {
    /// The underlying verification key.
    pub vk: VerifyingKey<E>,
    /// The element `beta * G` in `E::G1`.
    pub beta_g: E::G1Affine,
    /// The elements `a_i * G` in `E::G1`.
    pub a_g: Vec<E::G1Affine>,
    /// The elements `b_i * G` in `E::G1`.
    pub b_g: Vec<E::G1Affine>,
    /// The elements `b_i * H` in `E::G2`.
    pub b_h: Vec<E::G2Affine>,
    /// The elements `h_i * G` in `E::G1`.
    pub h_g: Vec<E::G1Affine>,
    /// The committer key.
    pub ck: CommitterKey<E>,
    /// The elements `deltaᵢ * G` in `E::G1`.
    pub deltas_g: Vec<E::G1Affine>,
    /// The elements `deltaᵢ * H` in `E::G2`.
    pub deltas_h: Vec<E::G2Affine>,
}

impl<E: Pairing> ProvingKey<E> {
    /// Returns the verifying key corresponding to this proving key
    pub fn vk(&self) -> VerifyingKey<E> {
        self.vk.clone()
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// Holds all the elements from [`ProvingKey`] necessary to commit to inputs
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitterKey<E: Pairing> {
    /// The element `delta * G` in `E::G1`.
    pub last_delta_g: E::G1Affine,
    /// A vec where element `(j,i)` is `(beta * a_i + alpha * b_i + c_i)/deltaⱼ * G`, where `G`
    /// is the generator of `E::G1`.
    pub deltas_abc_g: Vec<Vec<E::G1Affine>>,
}

/// Represents the commitment to a set of Groth16 inputs
pub type Comm<E> = <E as Pairing>::G1Affine;

/// Represents the secret randomness used to blind an [`InputCom`]. Once the proof is done, this
/// should be deleted
pub type CommRandomness<E> = <E as Pairing>::ScalarField;
