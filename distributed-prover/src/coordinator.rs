use crate::{
    aggregation::{commit_to_g16_coms, IppCom, SuperComCommittingKey},
    eval_tree::{
        ExecTreeLeaf, LeafParam, MerkleRoot, SerializedLeaf, SerializedLeafVar, TreeConfig,
        TreeConfigGadget, TwoToOneParam,
    },
    portal_manager::SetupPortalManager,
    subcircuit_circuit::SubcircuitWithPortalsProver,
    util::{gen_merkle_params, G16Com, G16ComSeed, G16ProvingKey},
    varname_hasher,
    worker::Stage0Response,
    CircuitWithPortals, RomTranscriptEntry, RunningEvals,
};

use std::collections::VecDeque;

use ark_cp_groth16::r1cs_to_qap::LibsnarkReduction as QAP;
use ark_crypto_primitives::{
    crh::sha256::{digest::Digest, Sha256},
    merkle_tree::{MerkleTree, Path as MerklePath},
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;

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

/// Hashes the trace commitment and returns `(entry_chal, tr_chal)`
/// TODO: Add a lot of context binding here. Don't want a weak fiat shamir
fn get_chals<E: Pairing>(com: &IppCom<E>) -> (E::ScalarField, E::ScalarField) {
    // Serialize the commitment to bytes
    let com_bytes = {
        let mut buf = Vec::new();
        com.serialize_uncompressed(&mut buf).unwrap();
        buf
    };

    // Generate two challenges by hashing com with two different context strings
    let entry_chal = {
        let mut hasher = Sha256::default();
        hasher.update(b"entry_chal");
        hasher.update(&com_bytes);
        hasher.finalize()
    };
    let tr_chal = {
        let mut hasher = Sha256::default();
        hasher.update(b"tr_chal");
        hasher.update(&com_bytes);
        hasher.finalize()
    };

    (
        E::ScalarField::from_le_bytes_mod_order(&entry_chal),
        E::ScalarField::from_le_bytes_mod_order(&tr_chal),
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
    super_com: &IppCom<E>,
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
fn get_stage1_witnesses<C, F>(
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

/// A struct that has all the info necessary to construct a request from server to worker to
/// perform stage 0 of their subcircuit (i.e., the committing stage). This also includes the
/// circuit with all witness values filled in.
pub struct Stage0PackageBuilder<E, P>
where
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField>,
{
    circ: P,
    time_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    addr_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    // TODO: speedup: note that super_com_key isn't needed until we actually process the coms
    super_com_key: SuperComCommittingKey<E>,
}

/// This is sent to every worker at the beginning of every distributed proof. It contains
/// everything the worker will need in order to do its stage0 and stage1 proof computations. It
/// also requests some stage0 commitments from the worker.
#[derive(Clone)]
pub struct Stage0Request<F: PrimeField> {
    pub(crate) subcircuit_idx: usize,
    pub(crate) time_ordered_subtrace: VecDeque<RomTranscriptEntry<F>>,
    pub(crate) addr_ordered_subtrace: VecDeque<RomTranscriptEntry<F>>,
}

pub struct Stage0WorkerPackageRef<'a, F: PrimeField> {
    subcircuit_idx: usize,
    pub time_ordered_subtrace: &'a VecDeque<RomTranscriptEntry<F>>,
    pub addr_ordered_subtrace: &'a VecDeque<RomTranscriptEntry<F>>,
}

impl<'a, F: PrimeField> Stage0WorkerPackageRef<'a, F> {
    pub fn to_owned(&self) -> Stage0Request<F> {
        Stage0Request {
            subcircuit_idx: self.subcircuit_idx,
            time_ordered_subtrace: self.time_ordered_subtrace.clone(),
            addr_ordered_subtrace: self.addr_ordered_subtrace.clone(),
        }
    }
}

impl<E, P> Stage0PackageBuilder<E, P>
where
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField> + Clone,
{
    pub fn new<C: TreeConfig>(circ: P, super_com_key: SuperComCommittingKey<E>) -> Self {
        let time_ordered_subtraces = get_subtraces::<C, E::ScalarField, _>(circ.clone());
        let addr_ordered_subtraces = sort_subtraces_by_addr(&time_ordered_subtraces);

        Stage0PackageBuilder {
            circ,
            super_com_key,
            time_ordered_subtraces,
            addr_ordered_subtraces,
        }
    }

    /// Creates a stage0 package and request commitment for the given set of subcircuits
    pub fn gen_package(&self, subcircuit_idx: usize) -> Stage0WorkerPackageRef<E::ScalarField> {
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
        }
    }

    /// Processes the stage 0 repsonses and move to stage 1
    pub fn process_stage0_responses<C>(
        self,
        responses: &[Stage0Response<E>],
    ) -> Stage1RequestBuilder<C, E, P>
    where
        C: TreeConfig<Leaf = SerializedLeaf>,
    {
        let (coms, com_seeds) = {
            // Sort responses by subcircuit idx
            let mut buf = responses.to_vec();
            buf.sort_by_key(|res| res.subcircuit_idx);

            // Extract the coms and the seeds separately
            (
                buf.iter().map(|res| res.com).collect::<Vec<_>>(),
                buf.iter().map(|res| res.com_seed).collect(),
            )
        };

        // Commit to the commitments
        let super_com = commit_to_g16_coms(&self.super_com_key, &coms);

        Stage1RequestBuilder::new(
            self.circ,
            self.time_ordered_subtraces,
            self.addr_ordered_subtraces,
            coms,
            com_seeds,
            super_com,
        )
    }
}

pub struct Stage1RequestBuilder<C, E, P>
where
    C: TreeConfig<Leaf = SerializedLeaf>,
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField>,
{
    circ: P,
    time_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    addr_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    coms: Vec<G16Com<E>>,
    seeds: Vec<G16ComSeed>,
    super_com: IppCom<E>,
    leaf_params: LeafParam<C>,
    two_to_one_params: TwoToOneParam<C>,
    tree: MerkleTree<C>,
    leaves: Vec<ExecTreeLeaf<E::ScalarField>>,
}

impl<C, E, P> Stage1RequestBuilder<C, E, P>
where
    C: TreeConfig<Leaf = SerializedLeaf>,
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField>,
{
    fn new(
        circ: P,
        time_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
        addr_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
        coms: Vec<G16Com<E>>,
        seeds: Vec<G16ComSeed>,
        super_com: IppCom<E>,
    ) -> Self {
        let (leaf_params, two_to_one_params) = gen_merkle_params::<C>();

        let (tree, leaves) = generate_exec_tree::<E, C>(
            &leaf_params,
            &two_to_one_params,
            &super_com,
            &time_ordered_subtraces,
            &addr_ordered_subtraces,
        );

        Stage1RequestBuilder {
            circ,
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

    pub fn gen_request(&self, subcircuit_idx: usize) -> Stage1Request<C, E::ScalarField, P> {
        let (cur_leaf, next_leaf_membership) =
            get_stage1_witnesses(subcircuit_idx, &self.tree, &self.leaves);

        Stage1Request {
            subcircuit_idx,
            cur_leaf,
            next_leaf_membership,
            root: self.tree.root(),
            serialized_witnesses: self.circ.get_serialized_witnesses(subcircuit_idx),
            circ_params: self.circ.get_params(),
        }
    }
}

pub struct Stage1Request<C, F, P>
where
    C: TreeConfig,
    F: PrimeField,
    P: CircuitWithPortals<F>,
{
    pub(crate) subcircuit_idx: usize,
    pub(crate) cur_leaf: ExecTreeLeaf<F>,
    pub(crate) next_leaf_membership: MerklePath<C>,
    pub(crate) root: MerkleRoot<C>,
    pub(crate) serialized_witnesses: Vec<u8>,
    pub(crate) circ_params: P::Parameters,
}
