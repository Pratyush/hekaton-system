use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub mod coordinator;
pub mod data_structures;
pub mod worker;

#[macro_export]
macro_rules! deserialize_flattened_bytes {
    ($flattened_item_bytes: expr, $default: expr, $item_type: ty) => {{
        let item_size = $default.uncompressed_size();
        $flattened_item_bytes
            .chunks_exact(item_size)
            .map(<$item_type>::deserialize_uncompressed_unchecked)
            .collect::<Result<Vec<_>, _>>()
    }};
}

pub fn serialize_to_vec(item: &impl CanonicalSerialize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(item.uncompressed_size());
    (*item).serialize_uncompressed(&mut bytes).unwrap();
    bytes
}
