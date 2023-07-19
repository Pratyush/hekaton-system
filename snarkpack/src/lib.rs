#[macro_use]
mod macros;

mod prover;
mod verifier;

mod data_structures;

pub mod mmt;

mod commitment;
mod errors;
mod ip;
mod pairing_check;
pub mod srs;
pub mod transcript;
mod utils;

pub(crate) mod kzg;

use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
pub use errors::*;
pub use transcript::*;
pub use verifier::*;

pub struct SnarkPack<E: Pairing>(PhantomData<E>);
