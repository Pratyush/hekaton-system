use ark_ec::pairing::Pairing;

use crate::data_structures::{Stage0Request, Stage0Response, Stage1Request, Stage1Response, ProvingKey};

pub struct WorkerState<E: Pairing>(E::G1);

impl<E: Pairing> WorkerState<E> {
    pub fn new(proving_key: ProvingKey<E>) -> Self {
        Self(E::G1::default())
    }

    pub fn stage_0(&mut self, request: &Stage0Request<E>) -> Stage0Response<E> {
        Stage0Response::default()
    }

    pub fn stage_1(&mut self, request: &Stage1Request<E>) -> Stage1Response<E> {
        Stage1Response::default()
    }
}
