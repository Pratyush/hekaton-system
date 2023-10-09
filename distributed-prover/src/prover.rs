use crate::{
    aggregation::IppCom,
    eval_tree::{
        ExecTreeLeaf, LeafParam, MerkleRoot, SerializedLeaf, SerializedLeafVar, TreeConfig,
        TreeConfigGadget, TwoToOneParam,
    },
    portal_manager::SetupPortalManager,
    subcircuit_circuit::SubcircuitWithPortalsProver,
    varname_hasher, CircuitWithPortals, RomTranscriptEntry, RunningEvals,
};

use std::{borrow::Borrow, collections::VecDeque, marker::PhantomData};

use ark_cp_groth16::{
    committer::CommitmentBuilder as G16CommitmentBuilder, r1cs_to_qap::LibsnarkReduction as QAP,
};
use ark_crypto_primitives::{
    crh::{
        sha256::{digest::Digest, Sha256},
        CRHScheme, TwoToOneCRHScheme,
    },
    merkle_tree::{MerkleTree, Path as MerklePath},
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read as ArkRead, SerializationError,
    Write as ArkWrite,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

const MERKLE_HASH_PARAMS_SEED: &'static [u8; 32] = b"horizontal-snark-hash-param-seed";

pub use ark_cp_groth16::data_structures::{Comm as G16Com, ProvingKey as G16ProvingKey};

fn get_subtraces<C, F, P>(mut circ: P) -> Vec<VecDeque<RomTranscriptEntry<F>>>
where
    C: TreeConfig,
    F: PrimeField,
    P: CircuitWithPortals<F>,
{
    let cs = ConstraintSystemRef::<F>::new(ConstraintSystem::default());
    let mut pm = SetupPortalManager::new(cs.clone());

    let num_subcircuits = circ.num_subcircuits();
    let circ_params = circ.get_params();

    for subcircuit_idx in 0..num_subcircuits {
        // Start a new subtrace and then run the subcircuit
        pm.start_subtrace();

        // To make sure errors are caught early, only set the witnesses that are earmarked for this
        // subcircuit. Make the rest empty
        let mut circ_copy = P::new(&circ_params);
        let wits = circ.get_serialized_witnesses(subcircuit_idx);
        circ_copy.set_serialized_witnesses(subcircuit_idx, &wits);

        // Now generate constraints on that pared down copy
        circ_copy
            .generate_constraints(cs.clone(), subcircuit_idx, &mut pm)
            .unwrap();
    }

    assert!(cs.is_satisfied().unwrap());

    pm.subtraces
}

pub(crate) fn gen_merkle_params<C>() -> (LeafParam<C>, TwoToOneParam<C>)
where
    C: TreeConfig,
{
    let mut rng = ChaCha12Rng::from_seed(*MERKLE_HASH_PARAMS_SEED);
    (
        <C::LeafHash as CRHScheme>::setup(&mut rng).unwrap(),
        <C::TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap(),
    )
}

pub(crate) fn gen_subcircuit_proving_keys<C, CG, E, P>(
    leaf_params: &LeafParam<C>,
    two_to_one_params: &TwoToOneParam<C>,
    circ: P,
) -> Vec<G16ProvingKey<E>>
where
    E: Pairing,
    C: TreeConfig<Leaf = SerializedLeaf>,
    CG: TreeConfigGadget<C, E::ScalarField, Leaf = SerializedLeafVar<E::ScalarField>>,
    P: CircuitWithPortals<E::ScalarField> + Clone,
{
    let mut rng = rand::thread_rng();
    let num_subcircuits = circ.num_subcircuits();
    let time_ordered_subtraces = get_subtraces::<C, _, _>(circ.clone());

    // Create a Groth16 instance for each subcircuit
    time_ordered_subtraces
        .into_iter()
        .enumerate()
        .map(|(subcircuit_idx, subtrace)| {
            let mut subcirc = SubcircuitWithPortalsProver::<_, P, _, CG>::new(
                leaf_params.clone(),
                two_to_one_params.clone(),
                num_subcircuits,
            );

            // Set the index and the underlying circuit
            subcirc.subcircuit_idx = subcircuit_idx;
            subcirc.circ = Some(circ.clone());

            // Make the subtraces the same. These are just placeholders anyway. They just have to be
            // the right length.
            subcirc.time_ordered_subtrace = subtrace.clone();
            subcirc.addr_ordered_subtrace = subtrace.clone();

            // Generate the CRS
            ark_cp_groth16::generator::generate_parameters::<_, E, QAP>(subcirc, &mut rng).unwrap()
        })
        .collect()
}

/// Commits to the full set of CP-Groth16 stage 0 commitments
// TODO: Make this an IPP commitment. For now it is just SHA256
fn commit_to_g16_coms<E: Pairing, B: Borrow<G16Com<E>>>(
    coms: impl IntoIterator<Item = B>,
) -> IppCom {
    let mut hasher = Sha256::default();
    for com in coms.into_iter() {
        let mut buf = Vec::new();
        com.borrow().serialize_uncompressed(&mut buf).unwrap();
        hasher.update(buf);
    }

    hasher.finalize().into()
}

/// A seed used for the RNG in stage 0 commitments. Each worker saves this and redoes the
/// commitment once it's asked to do stage 1
pub type G16ComSeed = [u8; 32];

// TODO: This will be outsourced to worker nodes
pub(crate) fn compute_stage0_response<E, P, C, CG>(
    stage0_request: Stage0WorkerPackage<E::ScalarField>,
    pk: &G16ProvingKey<E>,
    leaf_params: &LeafParam<C>,
    two_to_one_params: &TwoToOneParam<C>,
) -> Stage0Response<E>
where
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField> + Clone,
    C: TreeConfig<Leaf = SerializedLeaf>,
    CG: TreeConfigGadget<C, E::ScalarField, Leaf = SerializedLeafVar<E::ScalarField>>,
{
    let mut rng = rand::thread_rng();

    let Stage0WorkerPackage {
        subcircuit_idx,
        time_ordered_subtrace,
        addr_ordered_subtrace,
        ..
    } = stage0_request;

    // Commit to their stage 0 inputs (ie the subtraces), and save the commitments and RNG seeds

    // Make an empty prover
    // The number of subcircuits dictates the size of the Merkle tree. This is irrelevant
    // here because we're only running stage 0 of the circuit, which involves no tree ops.
    // Make it 2 so that we don't get underflow by accident
    let num_subcircuits = 2;
    // TODO: Make this circuit take refs. Avoid the cloning
    let mut prover = SubcircuitWithPortalsProver::<_, P, _, CG>::new(
        leaf_params.clone(),
        two_to_one_params.clone(),
        num_subcircuits,
    );

    // Fill in the correct subcircuit index and subtrace data
    prover.subcircuit_idx = subcircuit_idx;
    prover.time_ordered_subtrace = time_ordered_subtrace;
    prover.addr_ordered_subtrace = addr_ordered_subtrace;

    // Create a seed and make an RNG from it
    let com_seed = rng.gen::<G16ComSeed>();
    let mut subcircuit_rng = ChaCha12Rng::from_seed(com_seed);

    // Commit to the stage 0 values (the subtraces)
    let mut cb = G16CommitmentBuilder::<_, E, QAP>::new(prover, &pk);
    let (com, _) = cb
        .commit(&mut subcircuit_rng)
        .expect("failed to commit to subtrace");

    Stage0Response {
        subcircuit_idx,
        com,
        com_seed,
    }
}

/// Hashes the trace commitment and returns `(entry_chal, tr_chal)`
/// TODO: Add a lot of context binding here. Don't want a weak fiat shamir
fn get_chals<F: PrimeField>(com: &IppCom) -> (F, F) {
    // Generate two challenges by hashing com with two different context strings
    let entry_chal = {
        let mut hasher = Sha256::default();
        hasher.update(b"entry_chal");
        hasher.update(com);
        hasher.finalize()
    };
    let tr_chal = {
        let mut hasher = Sha256::default();
        hasher.update(b"tr_chal");
        hasher.update(com);
        hasher.finalize()
    };

    (
        F::from_le_bytes_mod_order(&entry_chal),
        F::from_le_bytes_mod_order(&tr_chal),
    )
}

/// Flattens the subtraces into one big trace, sorts it by address, and chunks it back into the
/// same-sized subtraces
fn sort_subtraces_by_addr<F: PrimeField>(
    time_ordered_subtraces: &[VecDeque<RomTranscriptEntry<F>>],
) -> Vec<VecDeque<RomTranscriptEntry<F>>> {
    // Make the (flattened) address-sorted trace
    // Flatten the trace
    let mut flat_trace = time_ordered_subtraces
        .iter()
        .flat_map(|st| st)
        .collect::<Vec<_>>();
    // Sort by address, i.e., the hash of the name
    flat_trace.sort_by_key(|entry| varname_hasher::<F>(&entry.name));

    // Chunk back up
    let mut out = Vec::new();
    let flat_iter = &mut flat_trace.into_iter();
    for chunk_size in time_ordered_subtraces.iter().map(|st| st.len()) {
        let chunk = flat_iter.take(chunk_size).cloned().collect();
        out.push(chunk);
    }
    out
}

/// Generates a Merkle tree whose i-th leaf is `(time_eval, addr_eval, last_trace_elem)` where
/// time_eval and addr_eval are the time- and address-ordered evals AFTER running subcircuit i, and
/// where `last_trace_elem` is the last element of the i-th address-ordered subtrace. Returns the
/// computed tree and its leaves
fn generate_exec_tree<E, C>(
    leaf_params: &LeafParam<C>,
    two_to_one_params: &TwoToOneParam<C>,
    super_com: IppCom,
    time_ordered_subtraces: &[VecDeque<RomTranscriptEntry<E::ScalarField>>],
    addr_ordered_subtraces: &[VecDeque<RomTranscriptEntry<E::ScalarField>>],
) -> (MerkleTree<C>, Vec<ExecTreeLeaf<E::ScalarField>>)
where
    E: Pairing,
    C: TreeConfig<Leaf = SerializedLeaf>,
{
    let (entry_chal, tr_chal) = get_chals(&super_com);

    // Generate the tree's leaves by computing the partial evals for each subtrace
    let mut evals = RunningEvals::default();
    evals.challenges = Some((entry_chal, tr_chal));

    let mut leaves = Vec::new();

    // Every leaf conttains the last entry of the addr-ordered subtrace
    let mut last_subtrace_entry = RomTranscriptEntry::<E::ScalarField>::padding();
    for (time_st, addr_st) in time_ordered_subtraces
        .iter()
        .zip(addr_ordered_subtraces.iter())
    {
        for (time_entry, addr_entry) in time_st.iter().zip(addr_st) {
            // Eval everything in this subtrace
            evals.update_time_ordered(time_entry);
            evals.update_addr_ordered(addr_entry);

            last_subtrace_entry = addr_entry.clone();
        }

        // Push the leaf
        let leaf = ExecTreeLeaf {
            evals: evals.clone(),
            last_subtrace_entry: last_subtrace_entry.clone(),
        };
        leaves.push(leaf);
    }

    let serialized_leaves = leaves.iter().map(|leaf| leaf.to_bytes());

    (
        MerkleTree::new(leaf_params, two_to_one_params, serialized_leaves).unwrap(),
        leaves,
    )
}

/// Generates the witnesses necessary for stage 1 of the subcircuit at the given index.
/// Specifically, generates `(cur_leaf, next_leaf_membership)`
fn stage1_witnesses<C, F>(
    subcircuit_idx: usize,
    eval_tree: &MerkleTree<C>,
    tree_leaves: &[ExecTreeLeaf<F>],
) -> (ExecTreeLeaf<F>, MerklePath<C>)
where
    C: TreeConfig,
    F: PrimeField,
{
    let cur_leaf = if subcircuit_idx > 0 {
        // If this is not the first subcircuit, just fetch the data from the end of the last subtrace
        tree_leaves.get(subcircuit_idx - 1).unwrap().clone()
    } else {
        // Otherwise we need to make a padding leaf. This is all 0s.
        let mut leaf = ExecTreeLeaf::padding();
        // Every copy of `challenges` is the same here
        leaf.evals.challenges = tree_leaves[0].evals.challenges.clone();
        leaf
    };

    let next_leaf_membership = eval_tree
        .generate_proof(subcircuit_idx)
        .expect("invalid subcircuit idx");

    (cur_leaf, next_leaf_membership)
}

/// All provers are given a copy of every subcircuit proving key. This lets us use workers
/// adatively in the proving phase. The worker doesn't bother deserializing them when receiving
/// them. It saves them directly to disk and deserializes the appropriate file when needed in
/// subsequent proving steps.
struct KeyPackage {
    proving_keys: Vec<Vec<u8>>,
}

/// A struct that has all the info necessary to construct a request from server to worker to
/// perform stage 0 of their subcircuit (i.e., the committing stage). This also includes the
/// circuit with all witness values filled in.
pub struct Stage0PackageBuilder<F, P>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
{
    circ: P,
    time_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<F>>>,
    addr_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<F>>>,
}

/// This is sent to every worker at the beginning of every distributed proof. It contains
/// everything the worker will need in order to do its stage0 and stage1 proof computations. It
/// also requests some stage0 commitments from the worker.
#[derive(Clone)]
pub struct Stage0WorkerPackage<F: PrimeField> {
    pub(crate) subcircuit_idx: usize,
    pub(crate) time_ordered_subtrace: VecDeque<RomTranscriptEntry<F>>,
    pub(crate) addr_ordered_subtrace: VecDeque<RomTranscriptEntry<F>>,
    pub(crate) serialized_witnesses: Vec<u8>,
}

pub struct Stage0WorkerPackageRef<'a, F: PrimeField> {
    subcircuit_idx: usize,
    pub time_ordered_subtrace: &'a VecDeque<RomTranscriptEntry<F>>,
    pub addr_ordered_subtrace: &'a VecDeque<RomTranscriptEntry<F>>,
    pub(crate) serialized_witnesses: Vec<u8>,
}

impl<'a, F: PrimeField> Stage0WorkerPackageRef<'a, F> {
    pub fn to_owned(&self) -> Stage0WorkerPackage<F> {
        Stage0WorkerPackage {
            subcircuit_idx: self.subcircuit_idx,
            time_ordered_subtrace: self.time_ordered_subtrace.clone(),
            addr_ordered_subtrace: self.addr_ordered_subtrace.clone(),
            serialized_witnesses: self.serialized_witnesses.to_vec(),
        }
    }
}

/// The repsonse is the Groth16 commitments and seeds for all the requested subcircuits
#[derive(Clone)]
pub struct Stage0Response<E: Pairing> {
    pub(crate) subcircuit_idx: usize,
    pub(crate) com: G16Com<E>,
    pub(crate) com_seed: G16ComSeed,
}

impl<F, P> Stage0PackageBuilder<F, P>
where
    F: PrimeField,
    P: CircuitWithPortals<F> + Clone,
{
    pub fn new<C: TreeConfig>(circ: P) -> Self {
        let time_ordered_subtraces = get_subtraces::<C, F, _>(circ.clone());
        let addr_ordered_subtraces = sort_subtraces_by_addr(&time_ordered_subtraces);

        Stage0PackageBuilder {
            circ,
            time_ordered_subtraces,
            addr_ordered_subtraces,
        }
    }

    /// Creates a stage0 package and request commitment for the given set of subcircuits
    pub fn gen_package(&self, subcircuit_idx: usize) -> Stage0WorkerPackageRef<F> {
        Stage0WorkerPackageRef {
            subcircuit_idx,
            time_ordered_subtrace: self
                .time_ordered_subtraces
                .get(subcircuit_idx)
                .as_ref()
                .unwrap(),
            addr_ordered_subtrace: self
                .addr_ordered_subtraces
                .get(subcircuit_idx)
                .as_ref()
                .unwrap(),
            serialized_witnesses: self.circ.get_serialized_witnesses(subcircuit_idx),
        }
    }

    /// Processes the stage 0 repsonses and move to stage 1
    pub fn process_stage0_responses<C, E>(
        self,
        responses: &[Stage0Response<E>],
    ) -> Stage1RequestBuilder<C, E>
    where
        C: TreeConfig<Leaf = SerializedLeaf>,
        E: Pairing<ScalarField = F>,
    {
        let (coms, com_seeds) = {
            // Sort responses by subcircuit idx
            let mut buf = responses.to_vec();
            buf.sort_by_key(|res| res.subcircuit_idx);

            // Extract the coms and the seeds separately
            (
                buf.iter().map(|res| res.com).collect(),
                buf.iter().map(|res| res.com_seed).collect(),
            )
        };

        // Commit to the commitments
        let super_com = commit_to_g16_coms::<E, _>(&coms);

        Stage1RequestBuilder::new(
            self.time_ordered_subtraces,
            self.addr_ordered_subtraces,
            coms,
            com_seeds,
            super_com,
        )
    }
}

pub struct Stage1RequestBuilder<C, E>
where
    C: TreeConfig<Leaf = SerializedLeaf>,
    E: Pairing,
{
    time_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    addr_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    coms: Vec<G16Com<E>>,
    seeds: Vec<G16ComSeed>,
    super_com: IppCom,
    leaf_params: LeafParam<C>,
    two_to_one_params: TwoToOneParam<C>,
    tree: MerkleTree<C>,
    leaves: Vec<ExecTreeLeaf<E::ScalarField>>,
}

impl<C, E> Stage1RequestBuilder<C, E>
where
    C: TreeConfig<Leaf = SerializedLeaf>,
    E: Pairing,
{
    fn new(
        time_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
        addr_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
        coms: Vec<G16Com<E>>,
        seeds: Vec<G16ComSeed>,
        super_com: IppCom,
    ) -> Self {
        let (leaf_params, two_to_one_params) = gen_merkle_params::<C>();

        let (tree, leaves) = generate_exec_tree::<E, C>(
            &leaf_params,
            &two_to_one_params,
            super_com,
            &time_ordered_subtraces,
            &addr_ordered_subtraces,
        );

        Stage1RequestBuilder {
            time_ordered_subtraces,
            addr_ordered_subtraces,
            coms,
            seeds,
            super_com,
            leaf_params,
            two_to_one_params,
            tree,
            leaves,
        }
    }

    pub fn gen_request(&self, subcircuit_idxs: &[usize]) -> Stage1Request<C, E::ScalarField> {
        let mut cur_leaves = Vec::new();
        let mut next_leaf_memberships = Vec::new();

        for idx in subcircuit_idxs {
            let (cur_leaf, next_leaf_membership) = stage1_witnesses(*idx, &self.tree, &self.leaves);

            cur_leaves.push(cur_leaf);
            next_leaf_memberships.push(next_leaf_membership);
        }

        Stage1Request {
            subcircuit_idxs: subcircuit_idxs.to_vec(),
            cur_leaves,
            next_leaf_memberships,
            root: self.tree.root(),
        }
    }
}

pub struct Stage1Request<C, F>
where
    C: TreeConfig,
    F: PrimeField,
{
    pub(crate) subcircuit_idxs: Vec<usize>,
    pub(crate) cur_leaves: Vec<ExecTreeLeaf<F>>,
    pub(crate) next_leaf_memberships: Vec<MerklePath<C>>,
    pub(crate) root: MerkleRoot<C>,
}
