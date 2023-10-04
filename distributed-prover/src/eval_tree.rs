use crate::{
    portal_manager::{ProverPortalManager, SetupPortalManager},
    util::log2,
    varname_hasher, CircuitWithPortals, RomTranscriptEntry, RomTranscriptEntryVar, RunningEvals,
    RunningEvalsVar, PADDING_VARNAME,
};

use core::{borrow::Borrow, marker::PhantomData};

use ark_cp_groth16::{
    committer::CommitmentBuilder as G16CommitmentBuilder,
    data_structures::{
        Comm as G16Com, ProvingKey as G16ProvingKey, VerifyingKey as G16VerifyingKey,
    },
    r1cs_to_qap::LibsnarkReduction as QAP,
    MultiStageConstraintSynthesizer, MultiStageConstraintSystem,
};

use ark_crypto_primitives::{
    crh::{
        constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
        sha256::{digest::Digest, Sha256},
    },
    merkle_tree::{
        constraints::{ConfigGadget as TreeConfigGadget, PathVar as MerklePathVar},
        Config as TreeConfig, LeafParam, MerkleTree, Path as MerklePath, TwoToOneParam,
    },
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::{boolean::Boolean, uint8::UInt8, ToBytesGadget},
    eq::EqGadget,
    fields::fp::FpVar,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

type MerkleRoot<C> = <C as TreeConfig>::InnerDigest;
type MerkleRootVar<C, F, CG> = <CG as TreeConfigGadget<C, F>>::InnerDigest;

type LeafParamVar<CG, C, F> = <<CG as TreeConfigGadget<C, F>>::LeafHash as CRHSchemeGadget<
    <C as TreeConfig>::LeafHash,
    F,
>>::ParametersVar;
type TwoToOneParamVar<CG, C, F> =
    <<CG as TreeConfigGadget<C, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
        <C as TreeConfig>::TwoToOneHash,
        F,
    >>::ParametersVar;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct Leaf<F: PrimeField> {
    evals: RunningEvals<F>,
    last_subtrace_entry: RomTranscriptEntry<F>,
}

impl<F: PrimeField> Leaf<F> {
    fn to_bytes(&self) -> Vec<u8> {
        [self.evals.to_bytes(), self.last_subtrace_entry.to_bytes()].concat()
    }
}

struct LeafVar<F: PrimeField> {
    evals: RunningEvalsVar<F>,
    last_subtrace_entry: RomTranscriptEntryVar<F>,
}

type SerializedLeaf = [u8];
type SerializedLeafVar<F> = [UInt8<F>];

impl<F: PrimeField> R1CSVar<F> for LeafVar<F> {
    type Value = Leaf<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.evals.cs().or(self.last_subtrace_entry.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(Leaf {
            evals: self.evals.value()?,
            last_subtrace_entry: self.last_subtrace_entry.value()?,
        })
    }
}

impl<F: PrimeField> ToBytesGadget<F> for LeafVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([self.evals.to_bytes()?, self.last_subtrace_entry.to_bytes()?].concat())
    }
}

impl<F: PrimeField> AllocVar<Leaf<F>, F> for LeafVar<F> {
    fn new_variable<T: Borrow<Leaf<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let leaf = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        let evals =
            RunningEvalsVar::new_variable(ns!(cs, "evals"), || leaf.map(|l| &l.evals), mode)?;
        let last_subtrace_entry = RomTranscriptEntryVar::new_variable(
            ns!(cs, "last entry"),
            || leaf.map(|l| &l.last_subtrace_entry),
            mode,
        )?;

        Ok(LeafVar {
            evals,
            last_subtrace_entry,
        })
    }
}

fn get_subtraces<C, F, P>(mut circuit: P) -> Vec<Vec<RomTranscriptEntry<F>>>
where
    C: TreeConfig,
    F: PrimeField,
    P: CircuitWithPortals<F>,
{
    let cs = ConstraintSystemRef::<F>::new(ConstraintSystem::default());
    let mut pm = SetupPortalManager::new(cs.clone());

    for subcircuit_idx in 0..circuit.num_subcircuits() {
        // Start a new subtrace and then run the subcircuit
        pm.start_subtrace();
        circuit
            .generate_constraints(cs.clone(), subcircuit_idx, &mut pm)
            .unwrap();
    }

    pm.subtraces
}

fn gen_subcircuit_proving_keys<C, CG, E, P>(
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

// TODO: This is clearly not an IPP com. Make it so once it's ready
type IppCom = [u8; 32];

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
type ComSeed = [u8; 32];

// TODO: This will be outsourced to worker nodes
fn compute_stage0_commitments<E, P, C, CG>(
    pks: &[G16ProvingKey<E>],
    leaf_params: &LeafParam<C>,
    two_to_one_params: &TwoToOneParam<C>,
    time_subtraces: &[Vec<RomTranscriptEntry<E::ScalarField>>],
    addr_subtraces: &[Vec<RomTranscriptEntry<E::ScalarField>>],
) -> Vec<(G16Com<E>, ComSeed)>
where
    E: Pairing,
    P: CircuitWithPortals<E::ScalarField> + Clone,
    C: TreeConfig<Leaf = SerializedLeaf>,
    CG: TreeConfigGadget<C, E::ScalarField, Leaf = SerializedLeafVar<E::ScalarField>>,
{
    let mut rng = rand::thread_rng();

    // Iterate through all the subcircuits, commit to their stage 0 inputs (ie the subtraces), and
    // save the commitments and RNG seeds
    time_subtraces
        .iter()
        .zip(addr_subtraces.iter())
        .zip(pks.iter())
        .enumerate()
        .map(|(subcircuit_idx, ((time_st, addr_st), pk))| {
            // Make an empty prover
            // The number of subcircuits dictates the size of the Merkle tree. This is irrelevant
            // here because we're only running stage 0 of the circuit, which involves no tree ops.
            // Make it 2 so that we don't get underflow by accident
            let num_subcircuits = 2;
            let mut prover = SubcircuitWithPortalsProver::<_, P, _, CG>::new(
                leaf_params.clone(),
                two_to_one_params.clone(),
                num_subcircuits,
            );

            // Fill in the correct subcircuit index and subtrace data
            prover.subcircuit_idx = subcircuit_idx;
            prover.time_ordered_subtrace = time_st.clone();
            prover.addr_ordered_subtrace = addr_st.clone();

            // Create a seed and make an RNG from it
            let com_seed = rng.gen::<ComSeed>();
            let mut subcircuit_rng = ChaCha12Rng::from_seed(com_seed);

            // Commit to the stage 0 values (the subtraces)
            let mut cb = G16CommitmentBuilder::<_, E, QAP>::new(prover.clone(), pk);
            let (com, _) = cb
                .commit(&mut subcircuit_rng)
                .expect("failed to commit to subtrace");

            (com, com_seed)
        })
        .collect()
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
    time_ordered_subtraces: &[Vec<RomTranscriptEntry<F>>],
) -> Vec<Vec<RomTranscriptEntry<F>>> {
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
fn generate_tree<E, C>(
    leaf_params: &LeafParam<C>,
    two_to_one_params: &TwoToOneParam<C>,
    super_com: IppCom,
    time_ordered_subtraces: &[Vec<RomTranscriptEntry<E::ScalarField>>],
    addr_ordered_subtraces: &[Vec<RomTranscriptEntry<E::ScalarField>>],
) -> (MerkleTree<C>, Vec<Leaf<E::ScalarField>>)
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
        let leaf = Leaf {
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
    tree_leaves: &[Leaf<F>],
) -> (Leaf<F>, MerklePath<C>)
where
    C: TreeConfig,
    F: PrimeField,
{
    let cur_leaf = if subcircuit_idx > 0 {
        // If this is not the first subcircuit, just fetch the data from the end of the last subtrace
        tree_leaves.get(subcircuit_idx - 1).unwrap().clone()
    } else {
        // Otherwise we need to make a padding leaf. This is all 0s.
        Leaf {
            evals: RunningEvals {
                time_ordered_eval: F::zero(),
                addr_ordered_eval: F::zero(),
                // Every copy of `challenges` is the same here
                challenges: tree_leaves[0].evals.challenges.clone(),
            },
            last_subtrace_entry: RomTranscriptEntry::padding(),
        }
    };

    let next_leaf_membership = eval_tree
        .generate_proof(subcircuit_idx)
        .expect("invalid subcircuit idx");

    (cur_leaf, next_leaf_membership)
}

// Define a way to commit and prove just one subcircuit
struct SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F>,
{
    subcircuit_idx: usize,
    circ: Option<P>,

    // Merkle tree things
    pub leaf_params: LeafParam<C>,
    pub two_to_one_params: TwoToOneParam<C>,

    // Stage 0 committed values
    pub time_ordered_subtrace: Vec<RomTranscriptEntry<F>>,
    pub addr_ordered_subtrace: Vec<RomTranscriptEntry<F>>,
    pub time_ordered_subtrace_var: Vec<RomTranscriptEntryVar<F>>,
    pub addr_ordered_subtrace_var: Vec<RomTranscriptEntryVar<F>>,

    // Stage 1 witnesses
    pub cur_leaf: Leaf<F>,
    pub next_leaf_membership: MerklePath<C>,

    // Stage 1 public inputs
    pub entry_chal: F,
    pub tr_chal: F,
    pub root: MerkleRoot<C>,

    _marker: PhantomData<CG>,
}

impl<F, P, C, CG> Clone for SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F> + Clone,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F>,
{
    fn clone(&self) -> Self {
        SubcircuitWithPortalsProver {
            subcircuit_idx: self.subcircuit_idx,
            circ: self.circ.clone(),
            leaf_params: self.leaf_params.clone(),
            two_to_one_params: self.two_to_one_params.clone(),
            time_ordered_subtrace: self.time_ordered_subtrace.clone(),
            addr_ordered_subtrace: self.addr_ordered_subtrace.clone(),
            time_ordered_subtrace_var: self.time_ordered_subtrace_var.clone(),
            addr_ordered_subtrace_var: self.addr_ordered_subtrace_var.clone(),
            cur_leaf: self.cur_leaf.clone(),
            next_leaf_membership: self.next_leaf_membership.clone(),
            entry_chal: self.entry_chal.clone(),
            tr_chal: self.tr_chal.clone(),
            root: self.root.clone(),
            _marker: self._marker.clone(),
        }
    }
}

impl<F, P, C, CG> SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F>,
{
    // Makes a new struct with subcircuit idx 0, no subtraces, and an empty Merkle auth path
    fn new(
        leaf_params: LeafParam<C>,
        two_to_one_params: TwoToOneParam<C>,
        num_subcircuits: usize,
    ) -> Self {
        // Create an auth path of the correct length
        let auth_path_len = log2(num_subcircuits) - 1;
        let mut auth_path = MerklePath::default();
        auth_path.auth_path = vec![C::InnerDigest::default(); auth_path_len];

        SubcircuitWithPortalsProver {
            subcircuit_idx: 0,
            circ: None,
            leaf_params,
            two_to_one_params,
            time_ordered_subtrace: Vec::new(),
            addr_ordered_subtrace: Vec::new(),
            time_ordered_subtrace_var: Vec::new(),
            addr_ordered_subtrace_var: Vec::new(),
            cur_leaf: Leaf::default(),
            next_leaf_membership: auth_path,
            entry_chal: F::zero(),
            tr_chal: F::zero(),
            root: MerkleRoot::<C>::default(),
            _marker: PhantomData,
        }
    }
}

impl<F, P, C, CG> MultiStageConstraintSynthesizer<F> for SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F, Leaf = SerializedLeafVar<F>>,
{
    /// Two stages: Subtrace commit, and the rest
    fn total_num_stages(&self) -> usize {
        2
    }

    /// Generates constraints for the i-th stage.
    fn generate_constraints(
        &mut self,
        stage: usize,
        cs: &mut MultiStageConstraintSystem<F>,
    ) -> Result<(), SynthesisError> {
        // At stage 0, witness both subtraces and exit
        if stage == 0 {
            return cs.synthesize_with(|c| {
                self.time_ordered_subtrace_var = self
                    .time_ordered_subtrace
                    .iter()
                    .map(|entry| RomTranscriptEntryVar::new_witness(ns!(c, "time"), || Ok(entry)))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                self.addr_ordered_subtrace_var = self
                    .addr_ordered_subtrace
                    .iter()
                    .map(|entry| RomTranscriptEntryVar::new_witness(ns!(c, "addr"), || Ok(entry)))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                Ok(())
            });
        }
        if stage > 1 {
            panic!("there are only two stages in the subcircuit prover");
        }

        // Everything below is stage 1
        cs.synthesize_with(|c| {
            // Witness all the necessary variables
            // This does NOT witness the RunningEvals challenges. That must be done separately
            let cur_leaf_var = LeafVar::new_witness(ns!(c, "leaf"), || Ok(&self.cur_leaf))?;
            let next_leaf_membership_var =
                MerklePathVar::<_, _, CG>::new_witness(ns!(c, "path"), || {
                    Ok(&self.next_leaf_membership)
                })?;
            let entry_chal_var = FpVar::new_input(ns!(c, "entry chal"), || Ok(&self.entry_chal))?;
            let tr_chal_var = FpVar::new_input(ns!(c, "tr chal"), || Ok(&self.tr_chal))?;
            let root_var = MerkleRootVar::<_, _, CG>::new_input(ns!(c, "root"), || Ok(&self.root))?;

            // Input the Merkle tree params as constants
            let leaf_params_var =
                LeafParamVar::<CG, _, _>::new_constant(ns!(c, "leaf param"), &self.leaf_params)?;
            let two_to_one_params_var = TwoToOneParamVar::<CG, _, _>::new_constant(
                ns!(c, "2-to-1 param"),
                &self.two_to_one_params,
            )?;

            // Set the challenge values so the running evals knows how to update itself
            let mut running_evals_var = cur_leaf_var.evals.clone();
            running_evals_var.challenges = Some((entry_chal_var, tr_chal_var));

            // Prepend the last subtrace entry to the addr-ordered subtrace. This necessary for the
            // consistency check.
            let full_addr_ordered_subtrace = [
                &[cur_leaf_var.last_subtrace_entry.clone()][..],
                &self.addr_ordered_subtrace_var,
            ]
            .concat();
            // Save the last subtrace entry for a check later
            let last_subtrace_entry = full_addr_ordered_subtrace.last().unwrap().clone();

            // Create the portal manager to give to the circuit
            let mut pm = ProverPortalManager {
                time_ordered_subtrace: self.time_ordered_subtrace_var.clone(),
                addr_ordered_subtrace: full_addr_ordered_subtrace,
                running_evals: running_evals_var,
            };

            // Run the circuit with the portal manager
            self.circ
                .as_mut()
                .expect("must provide circuit for stage 1 computation")
                .generate_constraints(c.clone(), self.subcircuit_idx, &mut pm)?;

            // Sanity checks: make sure all the subtraces were used. The addr-ordered one has 1
            // remaining because it starts with 1 extra. The last one is used, but it's not popped.
            assert_eq!(pm.time_ordered_subtrace.len(), 0);
            assert_eq!(pm.addr_ordered_subtrace.len(), 1);

            // Make sure the resulting tree leaf appears in the Merkle Tree
            let next_leaf = LeafVar {
                evals: pm.running_evals,
                last_subtrace_entry,
            };
            dbg!(next_leaf.value());
            next_leaf_membership_var
                .verify_membership(
                    &leaf_params_var,
                    &two_to_one_params_var,
                    &root_var,
                    &next_leaf.to_bytes()?,
                )?
                .enforce_equal(&Boolean::TRUE)?;
            /*

            // TODO: Ensure that at i==0, the provided given evals are 0 and the provided last
            // subtrace entry is (0, 0)
            */

            Ok(())
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tree_hash_circuit::*;

    use ark_std::test_rng;

    use ark_crypto_primitives::{
        crh::{bowe_hopwood, pedersen, CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{
            constraints::{BytesVarDigestConverter, ConfigGadget},
            ByteDigestConverter, Config,
        },
    };

    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_ed_on_bls12_381::{constraints::FqVar, JubjubConfig};

    #[derive(Clone, PartialEq, Eq, Hash)]
    struct LeafWindow;
    #[derive(Clone, PartialEq, Eq, Hash)]
    struct InnerWindow;

    impl pedersen::Window for LeafWindow {
        const WINDOW_SIZE: usize = 63;
        const NUM_WINDOWS: usize = 6;
    }

    impl pedersen::Window for InnerWindow {
        const WINDOW_SIZE: usize = 63;
        const NUM_WINDOWS: usize = 9;
    }

    type LeafH = bowe_hopwood::CRH<JubjubConfig, LeafWindow>;
    type LeafHG = bowe_hopwood::constraints::CRHGadget<JubjubConfig, FqVar>;

    type CompressH = bowe_hopwood::TwoToOneCRH<JubjubConfig, InnerWindow>;
    type CompressHG = bowe_hopwood::constraints::TwoToOneCRHGadget<JubjubConfig, FqVar>;

    #[derive(Clone)]
    struct TestParams;
    impl Config for TestParams {
        type Leaf = SerializedLeaf;

        type LeafHash = LeafH;
        type TwoToOneHash = CompressH;

        type LeafDigest = <LeafH as CRHScheme>::Output;
        type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
        type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;
    }

    struct TestParamsVar;
    impl ConfigGadget<TestParams, Fr> for TestParamsVar {
        type Leaf = SerializedLeafVar<Fr>;

        type LeafDigest = <LeafHG as CRHSchemeGadget<LeafH, Fr>>::OutputVar;
        type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, Fr>;
        type InnerDigest = <CompressHG as TwoToOneCRHSchemeGadget<CompressH, Fr>>::OutputVar;
        type LeafHash = LeafHG;
        type TwoToOneHash = CompressHG;
    }

    type JubJubMerkleTree = MerkleTree<TestParams>;

    fn gen_merkle_params(mut rng: impl Rng) -> (LeafParam<TestParams>, TwoToOneParam<TestParams>) {
        (
            <LeafH as CRHScheme>::setup(&mut rng).unwrap(),
            <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap(),
        )
    }

    #[test]
    fn test_subcircuit_portal_prover_satisfied() {
        let mut rng = test_rng();

        // Make a random Merkle tree
        let num_leaves = 4;
        let circ = MerkleTreeCircuit::rand(&mut rng, num_leaves);

        let (leaf_params, two_to_one_params) = gen_merkle_params(&mut rng);

        let time_subtraces = get_subtraces::<TestParams, Fr, _>(circ.clone());
        let addr_subtraces = sort_subtraces_by_addr(&time_subtraces);
        let super_com: IppCom = rng.gen();
        let (entry_chal, tr_chal) = get_chals(&super_com);

        let (tree, leaves) = generate_tree::<E, TestParams>(
            &leaf_params,
            &two_to_one_params,
            super_com,
            &time_subtraces,
            &addr_subtraces,
        );
        let root = tree.root();

        let (cur_leaf, next_leaf_membership) = stage1_witnesses(0, &tree, &leaves);

        // Now prove a subcircuit

        let subcircuit_idx = 0;

        dbg!(&leaves[subcircuit_idx]);

        let mut real_circ = SubcircuitWithPortalsProver {
            subcircuit_idx,
            circ: Some(circ),
            leaf_params,
            two_to_one_params,
            time_ordered_subtrace: time_subtraces[0].clone(),
            addr_ordered_subtrace: addr_subtraces[0].clone(),
            time_ordered_subtrace_var: Vec::new(),
            addr_ordered_subtrace_var: Vec::new(),
            cur_leaf,
            next_leaf_membership,
            entry_chal,
            tr_chal,
            root,
            _marker: PhantomData::<TestParamsVar>,
        };
        let mut mcs = MultiStageConstraintSystem::default();
        real_circ.generate_constraints(0, &mut mcs).unwrap();
        real_circ.generate_constraints(1, &mut mcs).unwrap();

        assert!(mcs.is_satisfied().unwrap());
    }

    #[test]
    fn test_e2e_prover() {
        let mut rng = test_rng();

        // Make a random Merkle tree
        let num_leaves = 4;
        let circ = MerkleTreeCircuit::rand(&mut rng, num_leaves);

        let (leaf_params, two_to_one_params) = gen_merkle_params(&mut rng);
        let pks: Vec<G16ProvingKey<E>> = gen_subcircuit_proving_keys::<
            TestParams,
            TestParamsVar,
            _,
            _,
        >(&leaf_params, &two_to_one_params, circ.clone());

        let time_subtraces = get_subtraces::<TestParams, Fr, _>(circ.clone());
        let addr_subtraces = sort_subtraces_by_addr(&time_subtraces);
        let coms_and_seeds =
            compute_stage0_commitments::<E, MerkleTreeCircuit, TestParams, TestParamsVar>(
                &pks,
                &leaf_params,
                &two_to_one_params,
                &time_subtraces,
                &addr_subtraces,
            );
        let super_com = commit_to_g16_coms::<E, _>(coms_and_seeds.iter().map(|(com, _)| com));
        let (entry_chal, tr_chal) = get_chals(&super_com);

        let (tree, leaves) = generate_tree::<E, TestParams>(
            &leaf_params,
            &two_to_one_params,
            super_com,
            &time_subtraces,
            &addr_subtraces,
        );
        let root = tree.root();

        let (cur_leaf, next_leaf_membership) = stage1_witnesses(0, &tree, &leaves);

        // Now prove a subcircuit

        let subcircuit_idx = 0;

        let real_circ = SubcircuitWithPortalsProver {
            subcircuit_idx,
            circ: Some(circ),
            leaf_params,
            two_to_one_params,
            time_ordered_subtrace: time_subtraces[0].clone(),
            addr_ordered_subtrace: addr_subtraces[0].clone(),
            time_ordered_subtrace_var: Vec::new(),
            addr_ordered_subtrace_var: Vec::new(),
            cur_leaf,
            next_leaf_membership,
            entry_chal,
            tr_chal,
            root,
            _marker: PhantomData::<TestParamsVar>,
        };

        let mut cb = G16CommitmentBuilder::<_, E, QAP>::new(real_circ, &pks[subcircuit_idx]);
        let mut subcircuit_rng = {
            let com_seed = coms_and_seeds[subcircuit_idx].1.clone();
            ChaCha12Rng::from_seed(com_seed)
        };

        let (com, rand) = cb.commit(&mut subcircuit_rng).unwrap();
        assert_eq!(com, coms_and_seeds[subcircuit_idx].0);

        let proof = cb.prove(&[com], &[rand], &mut rng).unwrap();
    }
}
