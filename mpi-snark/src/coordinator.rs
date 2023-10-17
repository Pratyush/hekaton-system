use ark_ec::pairing::Pairing;

use crate::data_structures::{
    G16Proof, G16ProvingKey, Stage0RequestRef, Stage0Response, Stage1RequestRef, Stage1Response,
};

pub struct CoordinatorState<E: Pairing>(E::G1);

impl<E: Pairing> CoordinatorState<E> {
    pub fn new(size: usize) -> Self {
        Self(E::G1::default())
    }

    pub fn get_pk(&self) -> G16ProvingKey {
        todo!()
    }

    pub fn stage_0(&mut self) -> Vec<Stage0RequestRef> {
        todo!()
    }

    pub fn stage_1(&mut self, responses: &[Stage0Response]) -> Vec<Stage1RequestRef> {
        todo!()
    }

    pub fn aggregate(&mut self, responses: &[Stage1Response]) -> G16Proof {
        todo!()
    }
}
