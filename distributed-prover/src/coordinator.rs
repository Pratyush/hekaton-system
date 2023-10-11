use crate::{
    aggregation::{IppCom, SuperComCommittingKey},
    eval_tree::{
        ExecTreeLeaf, ExecTreeParams, MerkleRoot, SerializedLeaf, SerializedLeafVar, TreeConfig,
        TreeConfigGadget,
    },
    portal_manager::SetupPortalManager,
    subcircuit_circuit::SubcircuitWithPortalsProver,
    util::{G16Com, G16ComSeed, G16ProvingKey},
    varname_hasher,
    worker::Stage0Response,
    CircuitWithPortals, RomTranscriptEntry, RunningEvals,
};

use core::marker::PhantomData;
use std::collections::VecDeque;

use ark_cp_groth16::r1cs_to_qap::LibsnarkReduction as QAP;
use ark_crypto_primitives::{
    crh::sha256::{digest::Digest, Sha256},
    merkle_tree::{MerkleTree, Path as MerklePath},
};
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, ToConstraintField};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Write,
};
use rand::RngCore;

/// Runs the full circuit (going through subcircuit 0..N in order) with a SetupPortalManager and
/// records the time-ordered subtraces. This will also `assert!` that the constraints are satisfied
/// if `check_satisfied` is set. This should always be set unless you're generating a proving key
/// with a dummy circuit.
fn get_subtraces<C, F, P>(circ: P, check_satisfied: bool) -> Vec<VecDeque<RomTranscriptEntry<F>>>
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

    if check_satisfied {
        assert!(cs.is_satisfied().unwrap());
    }

    pm.subtraces
}

/// Generates Groth16 proving keys
pub struct G16ProvingKeyGenerator<C, CG, E, P>
where
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField>,
    C: TreeConfig<Leaf = SerializedLeaf<E::ScalarField>>,
    CG: TreeConfigGadget<C, E::ScalarField, Leaf = SerializedLeafVar<E::ScalarField>>,
{
    tree_params: ExecTreeParams<C>,
    circ: P,
    time_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    _marker: PhantomData<(C, CG)>,
}

impl<C, CG, E, P> G16ProvingKeyGenerator<C, CG, E, P>
where
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField> + Clone,
    C: TreeConfig<Leaf = SerializedLeaf<E::ScalarField>>,
    CG: TreeConfigGadget<C, E::ScalarField, Leaf = SerializedLeafVar<E::ScalarField>>,
{
    pub fn new(circ: P, tree_params: ExecTreeParams<C>) -> Self {
        // Generate the traces. Do not bother to check whether the constraints are satisfied. This
        // circuit's contents might be placeholder values.
        let time_ordered_subtraces = get_subtraces::<C, _, _>(circ.clone(), false);

        G16ProvingKeyGenerator {
            tree_params,
            circ,
            time_ordered_subtraces,
            _marker: PhantomData,
        }
    }

    pub fn gen_pk<R: RngCore>(&self, mut rng: R, subcircuit_idx: usize) -> G16ProvingKey<E> {
        let num_subcircuits = self.circ.num_subcircuits();

        // Create a Groth16 instance for each subcircuit
        let subtrace = &self.time_ordered_subtraces[subcircuit_idx];
        // TODO: Avoid the clones here
        let mut subcirc = SubcircuitWithPortalsProver::<_, P, _, CG>::new(
            self.tree_params.clone(),
            num_subcircuits,
        );

        // Set the index and the underlying circuit
        subcirc.subcircuit_idx = subcircuit_idx;
        subcirc.circ = Some(self.circ.clone());

        // Make the subtraces the same. These are just placeholders anyway. They just have to be
        // the right length.
        subcirc.time_ordered_subtrace = subtrace.clone();
        subcirc.addr_ordered_subtrace = subtrace.clone();

        // Generate the CRS
        ark_cp_groth16::generator::generate_parameters::<_, E, QAP>(subcirc, &mut rng).unwrap()
    }
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
    tree_params: &ExecTreeParams<C>,
    super_com: &IppCom<E>,
    time_ordered_subtraces: &[VecDeque<RomTranscriptEntry<E::ScalarField>>],
    addr_ordered_subtraces: &[VecDeque<RomTranscriptEntry<E::ScalarField>>],
) -> (MerkleTree<C>, Vec<ExecTreeLeaf<E::ScalarField>>)
where
    E: Pairing,
    C: TreeConfig<Leaf = SerializedLeaf<E::ScalarField>>,
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

    let serialized_leaves = leaves.iter().map(|leaf| leaf.to_field_elements().unwrap());

    (
        MerkleTree::new(
            &tree_params.leaf_params,
            &tree_params.two_to_one_params,
            serialized_leaves,
        )
        .unwrap(),
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
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CoordinatorStage0State<E, P>
where
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField>,
{
    time_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    addr_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    all_serialized_witnesses: Vec<Vec<u8>>,
    circ_params: P::Parameters,
}

/// This is sent to every worker at the beginning of every distributed proof. It contains
/// everything the worker will need in order to do its stage0 and stage1 proof computations. It
/// also requests some stage0 commitments from the worker.
#[derive(Clone, CanonicalDeserialize)]
pub struct Stage0Request<F: PrimeField> {
    pub subcircuit_idx: usize,
    pub(crate) time_ordered_subtrace: VecDeque<RomTranscriptEntry<F>>,
    pub(crate) addr_ordered_subtrace: VecDeque<RomTranscriptEntry<F>>,
}

#[derive(Clone)]
pub struct Stage0RequestRef<'a, F: PrimeField> {
    subcircuit_idx: usize,
    pub time_ordered_subtrace: &'a VecDeque<RomTranscriptEntry<F>>,
    pub addr_ordered_subtrace: &'a VecDeque<RomTranscriptEntry<F>>,
}

// We need to manually implement this because CanonicalSerialize isn't implemented for &T
// where T: CanonicalSerialize
impl<'a, F: PrimeField> CanonicalSerialize for Stage0RequestRef<'a, F> {
    #[inline]
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.subcircuit_idx
            .serialize_with_mode(&mut writer, compress)?;
        self.time_ordered_subtrace
            .serialize_with_mode(&mut writer, compress)?;
        self.addr_ordered_subtrace
            .serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        self.subcircuit_idx.serialized_size(compress)
            + self.time_ordered_subtrace.serialized_size(compress)
            + self.addr_ordered_subtrace.serialized_size(compress)
    }
}

impl<'a, F: PrimeField> Stage0RequestRef<'a, F> {
    pub fn to_owned(&self) -> Stage0Request<F> {
        Stage0Request {
            subcircuit_idx: self.subcircuit_idx,
            time_ordered_subtrace: self.time_ordered_subtrace.clone(),
            addr_ordered_subtrace: self.addr_ordered_subtrace.clone(),
        }
    }
}

impl<E, P> CoordinatorStage0State<E, P>
where
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField>,
{
    pub fn new<C: TreeConfig>(circ: P) -> Self {
        // Extract everything we need to know from the circuit
        let circ_params = circ.get_params();
        // Serialize the circuit's witnesses
        let all_serialized_witnesses = (0..circ.num_subcircuits())
            .map(|idx| circ.get_serialized_witnesses(idx))
            .collect();

        // Run the circuit and collect the execution trace. Check that constraints are satisfied.
        let time_ordered_subtraces = get_subtraces::<C, E::ScalarField, _>(circ, true);
        let addr_ordered_subtraces = sort_subtraces_by_addr(&time_ordered_subtraces);

        CoordinatorStage0State {
            time_ordered_subtraces,
            addr_ordered_subtraces,
            all_serialized_witnesses,
            circ_params,
        }
    }

    /// Creates a stage0 request for commitment for the given set of subcircuits
    pub fn gen_request(&self, subcircuit_idx: usize) -> Stage0RequestRef<E::ScalarField> {
        Stage0RequestRef {
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
        super_com_key: &SuperComCommittingKey<E>,
        tree_params: ExecTreeParams<C>,
        responses: &[Stage0Response<E>],
    ) -> CoordinatorStage1State<C, E, P>
    where
        C: TreeConfig<Leaf = SerializedLeaf<E::ScalarField>>,
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

        // Commit to the commitments. These are in G1, so it's a "left" commitment. Don't worry
        // about what that means
        let super_com = super_com_key.commit_left(&coms);

        CoordinatorStage1State::new(
            tree_params,
            self.time_ordered_subtraces,
            self.addr_ordered_subtraces,
            self.all_serialized_witnesses,
            self.circ_params,
            coms,
            com_seeds,
            super_com,
        )
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CoordinatorStage1State<C, E, P>
where
    C: TreeConfig<Leaf = SerializedLeaf<E::ScalarField>>,
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField>,
{
    /// All the time-ordered subtraces
    time_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    /// All the addr-ordered subtraces
    addr_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
    /// The list of serialized witnesses, ordered by subcircuit
    all_serialized_witnesses: Vec<Vec<u8>>,
    /// Circuit metadata
    circ_params: P::Parameters,
    /// The commitments to all the Groth16 inputs
    coms: Vec<G16Com<E>>,
    /// The associated seeds for the randomness to the above commitments
    seeds: Vec<G16ComSeed>,
    /// The inner-pairing commitment to the above commitments
    pub super_com: IppCom<E>,
    // We can't store the exec tree directly because it's not CanonicalSerialize :shrug:
    /// The list of execution leaves. Index i contains the ith leaf in the exec tree.
    exec_tree_leaves: Vec<ExecTreeLeaf<E::ScalarField>>,
    /// The root of the tree with the leaves given above
    exec_tree_root: MerkleRoot<C>,
    /// The list of auth paths of the execution leaves that provers compute as output. Index i
    /// contains the auth path for the ith leaf in the exec tree.
    exec_tree_leaf_auth_paths: Vec<MerklePath<C>>,
}

impl<C, E, P> CoordinatorStage1State<C, E, P>
where
    C: TreeConfig<Leaf = SerializedLeaf<E::ScalarField>>,
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField>,
{
    fn new(
        tree_params: ExecTreeParams<C>,
        time_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
        addr_ordered_subtraces: Vec<VecDeque<RomTranscriptEntry<E::ScalarField>>>,
        all_serialized_witnesses: Vec<Vec<u8>>,
        circ_params: P::Parameters,
        coms: Vec<G16Com<E>>,
        seeds: Vec<G16ComSeed>,
        super_com: IppCom<E>,
    ) -> Self {
        // Generate the execution tree
        let (exec_tree, tree_leaves) = generate_exec_tree::<E, C>(
            &tree_params,
            &super_com,
            &time_ordered_subtraces,
            &addr_ordered_subtraces,
        );

        // Make the authentication paths
        let num_subcircuits = time_ordered_subtraces.len();
        let tree_leaf_auth_paths = (0..num_subcircuits)
            .map(|subcircuit_idx| {
                exec_tree
                    .generate_proof(subcircuit_idx)
                    .expect("invalid subcircuit idx")
            })
            .collect();

        CoordinatorStage1State {
            time_ordered_subtraces,
            addr_ordered_subtraces,
            all_serialized_witnesses,
            circ_params,
            coms,
            seeds,
            super_com,
            exec_tree_leaves: tree_leaves,
            exec_tree_root: exec_tree.root(),
            exec_tree_leaf_auth_paths: tree_leaf_auth_paths,
        }
    }

    pub fn gen_request(&self, subcircuit_idx: usize) -> Stage1RequestRef<C, E::ScalarField, P> {
        // The current leaf is the input to this subcircuit. This occurs at
        // self.exec_tree_leaves[idx-1]
        let cur_leaf = if subcircuit_idx > 0 {
            self.exec_tree_leaves
                .get(subcircuit_idx - 1)
                .unwrap()
                .clone()
        } else {
            // If this is the first subcircuit, then no such leaf exists. We have to construct the
            // initial leaf, i.e., the padding leaf
            let mut leaf = ExecTreeLeaf::padding();
            // Every copy of `challenges` is the same here
            leaf.evals.challenges = self.exec_tree_leaves[0].evals.challenges.clone();
            leaf
        };

        // Fetch the auth path
        let next_leaf_membership = self.exec_tree_leaf_auth_paths[subcircuit_idx].clone();

        Stage1RequestRef {
            subcircuit_idx,
            cur_leaf,
            next_leaf_membership,
            root: self.exec_tree_root.clone(),
            serialized_witnesses: self
                .all_serialized_witnesses
                .get(subcircuit_idx)
                .as_ref()
                .unwrap(),
            circ_params: &self.circ_params,
        }
    }
}

#[derive(CanonicalDeserialize)]
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

pub struct Stage1RequestRef<'a, C, F, P>
where
    C: TreeConfig,
    F: PrimeField,
    P: CircuitWithPortals<F>,
{
    pub(crate) subcircuit_idx: usize,
    pub(crate) cur_leaf: ExecTreeLeaf<F>,
    pub(crate) next_leaf_membership: MerklePath<C>,
    pub(crate) root: MerkleRoot<C>,
    pub(crate) serialized_witnesses: &'a [u8],
    pub(crate) circ_params: &'a P::Parameters,
}

// We need to manually implement this because CanonicalSerialize isn't implemented for &T
// where T: CanonicalSerialize
impl<'a, C, F, P> CanonicalSerialize for Stage1RequestRef<'a, C, F, P>
where
    C: TreeConfig,
    F: PrimeField,
    P: CircuitWithPortals<F>,
{
    #[inline]
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.subcircuit_idx
            .serialize_with_mode(&mut writer, compress)?;
        self.cur_leaf.serialize_with_mode(&mut writer, compress)?;
        self.next_leaf_membership
            .serialize_with_mode(&mut writer, compress)?;
        self.root.serialize_with_mode(&mut writer, compress)?;
        self.serialized_witnesses
            .serialize_with_mode(&mut writer, compress)?;
        self.circ_params
            .serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        self.subcircuit_idx.serialized_size(compress)
            + self.cur_leaf.serialized_size(compress)
            + self.next_leaf_membership.serialized_size(compress)
            + self.root.serialized_size(compress)
            + self.serialized_witnesses.serialized_size(compress)
            + self.circ_params.serialized_size(compress)
    }
}

impl<'a, C, F, P> Stage1RequestRef<'a, C, F, P>
where
    C: TreeConfig,
    F: PrimeField,
    P: CircuitWithPortals<F>,
{
    pub fn to_owned(&self) -> Stage1Request<C, F, P> {
        Stage1Request {
            subcircuit_idx: self.subcircuit_idx,
            cur_leaf: self.cur_leaf.clone(),
            next_leaf_membership: self.next_leaf_membership.clone(),
            root: self.root.clone(),
            serialized_witnesses: self.serialized_witnesses.to_vec(),
            circ_params: self.circ_params.clone(),
        }
    }
}
