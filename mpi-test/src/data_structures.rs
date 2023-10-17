use ark_ec::pairing::Pairing;
use ark_serialize::*;


#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Stage0Request<E: Pairing>(E::G1);

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Stage1Request<E: Pairing>(E::G1);

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Stage0Response<E: Pairing>(E::G1);

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Stage1Response<E: Pairing>(E::G1);