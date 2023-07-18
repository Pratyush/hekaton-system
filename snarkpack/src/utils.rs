use ark_serialize::CanonicalSerialize;
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use digest::Digest;

pub fn rng_from_seed_bytes(seed: impl CanonicalSerialize) -> impl Rng {
    let buf_size = seed.uncompressed_size();
    let mut buf = Vec::with_capacity(buf_size);
    seed.serialize_uncompressed(&mut buf).unwrap();
    let hash = blake2::Blake2s256::digest(&buf);

    ChaChaRng::from_seed(hash.into())
}