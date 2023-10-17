use ark_ec::pairing::Pairing;
use ark_serialize::*;


#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Stage0Request<E: Pairing>(E::G1);

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Stage1Request<E: Pairing>(E::G1);

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Stage0Response<E: Pairing>(E::G1);

impl<E: Pairing> Default for Stage0Response<E> {
    fn default() -> Self {
        Self(E::G1::default())
    }
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Stage1Response<E: Pairing>(E::G1);

impl<E: Pairing> Default for Stage1Response<E> {
    fn default() -> Self {
        Self(E::G1::default())
    }
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: Pairing>(E::G1);

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing>(E::G1);
