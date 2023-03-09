use ark_ec::pairing::Pairing;
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
    /// The `Dᵢ` elements in `G1`.
    pub ds: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for Proof<E> {
    fn default() -> Self {
        Self {
            a: E::G1Affine::default(),
            b: E::G2Affine::default(),
            c: E::G1Affine::default(),
            ds: Vec::new(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: Pairing> {
    /// The verifying key for the underlying Groth16 system
    pub g16_vk: ark_groth16::VerifyingKey<E>,
    /// The `etaᵢ * H`, where `H` is the generator of `E::G2`.
    pub etas_g2: Vec<E::G2Affine>,
}

impl<E: Pairing> Default for VerifyingKey<E> {
    fn default() -> Self {
        Self {
            g16_vk: ark_groth16::VerifyingKey::default(),
            etas_g2: Vec::new(),
        }
    }
}

/// Preprocessed verification key parameters that enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedVerifyingKey<E: Pairing> {
    /// The unprepared verification key.
    pub g16_pvk: ark_groth16::PreparedVerifyingKey<E>,
    /// The elements `- etaᵢ * H` in `E::G2`, prepared for use in pairings.
    pub etas_g2_neg_pc: Vec<E::G2Prepared>,
}

impl<E: Pairing> Default for PreparedVerifyingKey<E> {
    fn default() -> Self {
        Self {
            g16_pvk: ark_groth16::PreparedVerifyingKey::default(),
            etas_g2_neg_pc: Vec::new(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// The prover key for for the Groth16 zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: Pairing> {
    /// The proving key for the Groth16 instance, not including any of the committing bits
    pub g16_pk: ark_groth16::ProvingKey<E>,
    /// The underlying committing key.
    pub ck: CommittingKey<E>,
    /// The elements `etaᵢ * G` in `E::G1`.
    pub etas_g1: Vec<E::G1Affine>,
    /// The elements `etaᵢ * H` in `E::G2`.
    pub etas_g2: Vec<E::G2Affine>,
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// Holds all the elements from [`ProvingKey`] necessary to commit to inputs
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommittingKey<E: Pairing> {
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: E::G1Affine,
    /// A vec where element `(j,i)` is`etaⱼ^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H`
    /// is the generator of `E::G1`.
    pub etas_abc_g1: Vec<Vec<E::G1Affine>>,
}

/// Represents the commitment to a set of Groth16 inputs
pub type InputCom<E> = <E as Pairing>::G1Affine;

/// Represents the secret randomness used to blind an [`InputCom`]. Once the proof is done, this
/// should be deleted
pub type InputComRandomness<E> = <E as Pairing>::ScalarField;
