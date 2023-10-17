use std::marker::PhantomData;

use ark_ec::pairing::Pairing;

use crate::data_structures::{Stage0Request, Stage0Response, Stage1Request, Stage1Response, Proof, ProvingKey};

pub struct CoordinatorState<E: Pairing>(E::G1);

impl<E: Pairing> CoordinatorState<E> {
    pub fn new(size: usize) -> Self {
        Self(E::G1::default())
    }

    pub fn get_pk(&self) -> ProvingKey<E> {
        ProvingKey(E::G1::default())
    }

    pub fn stage_0(&mut self, ) -> Vec<Stage0Request<E>> {
        let dummy = Stage0Request(27u8, PhantomData);
        // TODO: remove hardcoding of 4
        vec![dummy; 3]
    }

    pub fn stage_1(&mut self, responses: &[Stage0Response<E>]) -> Vec<Stage1Request<E>> {
        let dummy = Stage1Request(E::G1::default());
        // TODO: remove hardcoding of 4
        vec![dummy; 3]

    }

    pub fn aggregate(&mut self, responses: &[Stage1Response<E>]) -> Proof<E> {
        Proof(E::G1::default())
    }
}
