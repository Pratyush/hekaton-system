use ark_ec::pairing::Pairing;

use crate::data_structures::{Stage0Request, Stage0Response, Stage1Request, Stage1Response, Proof, ProvingKey};

pub struct CoordinatorState<E: Pairing>(E::G1);

impl<E: Pairing> CoordinatorState<E> {
    pub fn new() -> Self {
        Self(E::G1::default())
    }

    pub fn get_pk(&self) -> ProvingKey<E> {
        unimplemented!()
    }

    pub fn stage_0(&mut self, ) -> Vec<Stage0Request<E>> {
        unimplemented!()
    }

    pub fn stage_1(&mut self, responses: &[Stage0Response<E>]) -> Vec<Stage1Request<E>> {
        unimplemented!()
    }

    pub fn aggregate(&mut self, responses: &[Stage1Response<E>]) -> Proof<E> {
        unimplemented!()
    }
}
