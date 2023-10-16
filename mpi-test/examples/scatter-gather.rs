use mpi::topology::Rank;
use mpi::traits::*;

fn main() {
    let universe = mpi::initialize().unwrap();
    let world = universe.world();
    let root_rank = 0;
    let root_process = world.process_at_rank(root_rank);
    let rank = world.rank();

    let mut pk;
    // If you are root, broadcast 1024.
    if rank == root_rank {
        pk = 2_u64.pow(10);
        println!("Root broadcasting value: {}.", pk);
    } else {
        // Else, just initialize to nothing; you will receive
        // below.
        pk = 0_u64;
    }
    root_process.broadcast_into(&mut pk);
    println!("Rank {rank} received value: {pk}.");
    println!();

    /***************************************************************/
    /********************** Broadcast finished *********************/
    /***************************************************************/

    /***************************************************************/
    /*********************** Scatter starting **********************/
    /***************************************************************/

    let now = std::time::Instant::now();
    let size = world.size();
    // Scatter of inputs
    let mut stage0_reqs = 0 as Rank;
    if rank == root_rank {
        let v = (0..size).collect::<Vec<_>>();
        // Coordinator stageN code goes here.
        std::thread::sleep(std::time::Duration::from_secs(5));
        root_process.scatter_into_root(&v, &mut stage0_reqs);
    } else {
        root_process.scatter_into(&mut stage0_reqs);
        println!("Rank {rank} waiting for 5 seconds? {}", now.elapsed().as_secs_f64());
    }
    assert_eq!(stage0_reqs, rank);
    println!("Rank {rank} received value: {stage0_reqs}.");
    /***************************************************************/
    /*********************** Scatter finished **********************/
    /***************************************************************/

    let now = std::time::Instant::now();
    
    /***************************************************************/
    /*********************** Gather started ************************/
    /***************************************************************/
    let i = 2_u64.pow(world.rank() as u32 + 1);

    if rank == root_rank {
        let mut a = vec![0u64; size.try_into().unwrap()];
        root_process.gather_into_root(&i, &mut a[..]);
        println!("Root waiting for 2 seconds? {}", now.elapsed().as_secs_f64());
        println!("Root gathered sequence: {:?}.", a);
        assert!(a
            .iter()
            .enumerate()
            .all(|(a, &b)| b == 2u64.pow(a as u32 + 1)));
    } else {
        // Worker stageN code goes here.
        std::thread::sleep(std::time::Duration::from_secs(2));
        root_process.gather_into(&i);
        println!("Rank {rank} sent value: {i}.");
    }
    /***************************************************************/
    /*********************** Gather finished ************************/
    /***************************************************************/
}