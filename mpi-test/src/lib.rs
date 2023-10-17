#[macro_export]
macro_rules! construct_partitioned_buffer {
    ($items:expr) => {{

        let stage0_reqs_bytes = ($items)
            .iter()
            .map(serialize_to_vec)
            .collect::<Vec<_>>();
        let counts = stage0_reqs_bytes
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
        let all_bytes = stage0_reqs_bytes.concat();
        Partition::new(&all_bytes, &counts[..], &displacements[..])
    }};
}


pub mod coordinator;
pub mod worker;
pub mod data_structures;
