use ark_std::marker::PhantomData;

use ark_ec::pairing::Pairing;

pub mod data_structures;

pub mod prover;
pub mod verifier;

pub struct MMT<E: Pairing>(PhantomData<E>);