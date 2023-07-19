#[macro_use]
mod macros;

mod commitment;
mod errors;
mod ip;
mod pairing_check;
mod proof;
mod prover;
pub mod srs;
pub mod transcript;
mod utils;
mod verifier;

pub(crate) mod kzg;

use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
pub use errors::*;
pub use transcript::*;
pub use verifier::*;

pub struct SnarkPack<E: Pairing>(PhantomData<E>);
