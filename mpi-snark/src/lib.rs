use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpi::traits::Equivalence;

pub mod coordinator;
pub mod data_structures;
pub mod worker;

#[macro_export]
macro_rules! construct_partitioned_buffer_for_scatter {
    ($items:expr, $flattened_item_bytes: expr) => {{
        let item_bytes = ($items)
            .iter()
            .map(serialize_to_packed_vec)
            .collect::<Vec<_>>();
        let counts = std::iter::once(&vec![])
            .chain(item_bytes.iter())
            .map(|bytes| bytes.len() as Count)
            .collect::<Vec<_>>();
        let displacements: Vec<Count> = counts
            .iter()
            .scan(0, |acc, &x| {
                let tmp = *acc;
                *acc += x;
                Some(tmp)
            })
            .collect();
        *$flattened_item_bytes = item_bytes.concat();
        Partition::new(&*$flattened_item_bytes, counts, displacements)
    }};
}

#[macro_export]
macro_rules! construct_partitioned_mut_buffer_for_gather {
    ($size: expr, $default: expr, $flattened_item_bytes: expr) => {{
        let item_size = $default.uncompressed_size();
        let item_bytes = std::iter::once(vec![])
            .chain(std::iter::repeat(vec![0u8; item_size]))
            .take($size as usize)
            .collect::<Vec<_>>();
        let counts = item_bytes
            .iter()
            .map(|bytes| bytes.len() as Count)
            .collect::<Vec<_>>();
        let displacements: Vec<Count> = counts
            .iter()
            .scan(0, |acc, &x| {
                let tmp = *acc;
                *acc += x;
                Some(tmp)
            })
            .collect();
        *$flattened_item_bytes = item_bytes.concat();
        PartitionMut::new(&mut $flattened_item_bytes[..], counts, displacements)
    }};
}

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

pub fn serialize_to_packed_vec(item: &impl CanonicalSerialize) -> Vec<Packed> {
    serialize_to_vec(item)
        .chunks(Packed::BYTE_SIZE)
        .map(Packed::from_bytes)
        .collect::<Vec<_>>()
}

#[derive(Equivalence, Copy, Clone)]
#[repr(transparent)]
pub struct Packed([u8; 256]);

impl Packed {
    pub const BYTE_SIZE: usize = ark_std::mem::size_of::<Packed>();

    #[inline(always)]
    pub const fn zero() -> Self {
        Packed([0u8; 256])
    }

    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut packed = [0u8; 256];
        packed[..bytes.len()].copy_from_slice(bytes);
        Packed(packed)
    }
}

pub fn packed_to_bytes(packed: &[Packed]) -> &[u8] {
    let len = packed.len() * Packed::BYTE_SIZE;
    let ptr = packed.as_ptr() as *const u8;
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

pub fn deserialize_from_packed_bytes<T: CanonicalDeserialize>(
    packed: &[Packed],
) -> Result<T, ark_serialize::SerializationError> {
    let bytes = packed_to_bytes(packed);
    T::deserialize_uncompressed_unchecked(bytes)
}
