use ark_serialize::CanonicalSerialize;

#[macro_export]
macro_rules! construct_partitioned_buffer_for_scatter {
    ($items:expr, $flattened_item_bytes: expr) => {{

        let item_bytes = ($items)
            .iter()
            .map(serialize_to_vec)
            .collect::<Vec<_>>();
        let counts = 
            std::iter::once(&vec![])
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
    ($size:expr, $item_type:ty, $flattened_item_bytes: expr) => {{
        let item = <$item_type>::default();
        let item_size = item.uncompressed_size();
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
    ($flattened_item_bytes: expr, $item_type: ty) => {{
        let item = <$item_type>::default();
        let item_size = item.uncompressed_size();
        $flattened_item_bytes
            .chunks_exact(item_size)
            .map(<$item_type>::deserialize_uncompressed_unchecked)
            .collect::<Result<Vec<_>,_>>()
    }};
}

pub fn serialize_to_vec(item: &impl CanonicalSerialize) -> Vec<u8> {
    let mut bytes = vec![];
    (*item).serialize_uncompressed(&mut bytes).unwrap();
    bytes
}

pub mod coordinator;
pub mod worker;
pub mod data_structures;
