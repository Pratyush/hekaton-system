use crate::{
    portal_manager::{ProverPortalManager, SetupPortalManager},
    varname_hasher, CircuitWithPortals, RomTranscriptEntry, RomTranscriptEntryVar, RunningEvals,
    RunningEvalsVar, PADDING_VARNAME,
};

use core::borrow::Borrow;

use ark_cp_groth16::{MultiStageConstraintSynthesizer, MultiStageConstraintSystem};

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
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::CanonicalSerialize;

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

#[derive(Clone)]
struct Leaf<F: PrimeField> {
    evals: RunningEvals<F>,
    last_subtrace_entry: RomTranscriptEntry<F>,
}

struct LeafVar<F: PrimeField> {
    evals: RunningEvalsVar<F>,
    last_subtrace_entry: RomTranscriptEntryVar<F>,
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

// TODO: Fill in with a real IPP commitment at some point
type Com = [u8; 32];
fn commit_to_trace<F: PrimeField>(subtraces: &[Vec<RomTranscriptEntry<F>>]) -> Com {
    // This will eventually be a real commitment. In the meantime, just hash the entire trace
    let mut hasher = Sha256::default();
    for st in subtraces {
        for entry in st {
            let entry_addr: F = varname_hasher(&entry.name);
            let entry_val = entry.val;
            let mut buf = Vec::new();
            entry_addr.serialize_uncompressed(&mut buf).unwrap();
            entry_val.serialize_uncompressed(&mut buf).unwrap();
            hasher.update(buf);
        }
    }

    hasher.finalize().into()
}

// TODO: This will be outsourced to worker nodes
fn compute_stage0_commitments<F: PrimeField, C: CircuitWithPortals<F>>(
    time_subtraces: &[Vec<RomTranscriptEntry<F>>],
    addr_subtraces: &[Vec<RomTranscriptEntry<F>>],
) -> Vec<Com> {
    //let mut cb = CommitmentBuilder::<_, E, QAP>::new(circuit, &pk);
    //let (comm, rand) = cb.commit(&mut rng).unwrap();
    todo!()
}

/// Hashes the trace commitment and returns `(entry_chal, tr_chal)`
/// TODO: Add a lot of context binding here. Don't want a weak fiat shamir
fn get_chals<F: PrimeField>(com: &Com) -> (F, F) {
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
fn sort_subtrace_by_addr<F: PrimeField>(
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
fn generate_tree<F, C>(
    leaf_params: &LeafParam<C>,
    two_to_one_params: &TwoToOneParam<C>,
    subtraces: &[Vec<RomTranscriptEntry<F>>],
) -> (MerkleTree<C>, Vec<Leaf<F>>)
where
    F: PrimeField,
    C: TreeConfig<Leaf = Leaf<F>>,
{
    let com = commit_to_trace(subtraces);
    let (entry_chal, tr_chal) = get_chals(&com);

    // Make the (flattened) address-sorted trace
    let addr_ordered_trace = {
        // Flatten the trace
        let mut flat_trace = subtraces.iter().flat_map(|st| st).collect::<Vec<_>>();
        // Sort by address, i.e., the hash of the name
        flat_trace.sort_by_key(|entry| varname_hasher::<F>(&entry.name));
        flat_trace
    };
    let addr_trace_it = &mut addr_ordered_trace.into_iter();

    // Generate the tree's leaves by computing the partial evals for each subtrace
    let mut evals = RunningEvals::default();
    evals.challenges = Some((entry_chal, tr_chal));
    let mut leaves = Vec::new();
    for time_st in subtraces {
        let addr_st = addr_trace_it.take(time_st.len());

        // Every leaf conttains the last entry of the addr-ordered subtrace
        let mut last_subtrace_entry = RomTranscriptEntry::<F>::default();
        for (time_entry, addr_entry) in time_st.iter().zip(addr_st) {
            // Eval everything in this subtrace
            evals.update_time_ordered(time_entry);
            evals.update_addr_ordered(addr_entry);

            last_subtrace_entry = addr_entry.clone();
        }

        // Push the leaf
        let leaf = Leaf {
            evals: evals.clone(),
            last_subtrace_entry,
        };
        leaves.push(leaf);
    }

    (
        MerkleTree::new(leaf_params, two_to_one_params, &leaves).unwrap(),
        leaves,
    )
}

/// Generates the witnesses necessary for stage 1 of the subcircuit at the given index
fn stage1_witnesses<C, F>(subcircuit_idx: usize, eval_tree: MerkleTree<C>, tree_leaves: &[Leaf<F>])
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
            last_subtrace_entry: RomTranscriptEntry {
                name: PADDING_VARNAME.to_string(), // This makes the address 0
                val: F::zero(),
            },
        }
    };

    let next_leaf_membership = eval_tree.generate_proof(subcircuit_idx);
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
    pub cur_leaf_var: LeafVar<F>,
    pub next_leaf_membership_var: MerklePathVar<C, F, CG>,

    // Stage 1 public inputs
    pub entry_chal: F,
    pub tr_chal: F,
    pub root: MerkleRoot<C>,
    pub entry_chal_var: FpVar<F>,
    pub tr_chal_var: FpVar<F>,
    pub root_var: MerkleRootVar<C, F, CG>,
}

impl<F, P, C, CG> MultiStageConstraintSynthesizer<F> for SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F, Leaf = LeafVar<F>>,
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
            self.cur_leaf_var = LeafVar::new_witness(ns!(c, "leaf"), || Ok(&self.cur_leaf))?;
            self.next_leaf_membership_var =
                MerklePathVar::new_witness(ns!(c, "path"), || Ok(&self.next_leaf_membership))?;
            self.entry_chal_var = FpVar::new_input(ns!(c, "entry chal"), || Ok(&self.entry_chal))?;
            self.tr_chal_var = FpVar::new_input(ns!(c, "tr chal"), || Ok(&self.tr_chal))?;
            self.root_var =
                MerkleRootVar::<_, _, CG>::new_input(ns!(c, "root"), || Ok(&self.root))?;

            // Witness the Merkle tree params too
            let leaf_params_var =
                LeafParamVar::<CG, _, _>::new_witness(ns!(c, "leaf param"), || {
                    Ok(&self.leaf_params)
                })?;
            let two_to_one_params_var =
                TwoToOneParamVar::<CG, _, _>::new_witness(ns!(c, "2-to-1 param"), || {
                    Ok(&self.two_to_one_params)
                })?;

            // Set the challenge values so the running evals knows how to update itself
            let mut running_evals_var = self.cur_leaf_var.evals.clone();
            running_evals_var.challenges =
                Some((self.entry_chal_var.clone(), self.tr_chal_var.clone()));

            // Prepend the last subtrace entry to the addr-ordered subtrace. This necessary for the
            // consistency check.
            let full_addr_ordered_subtrace = [
                &[self.cur_leaf_var.last_subtrace_entry.clone()][..],
                &self.addr_ordered_subtrace_var,
            ]
            .concat();
            // Save the last subtrace entry for a check later
            let last_subtrace_entry = self.addr_ordered_subtrace_var.last().unwrap().clone();

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

            // Sanity checks: make sure all the subtraces were used
            assert!(pm.time_ordered_subtrace.is_empty() && pm.addr_ordered_subtrace.is_empty());

            // Make sure the resulting tree leaf appears in the Merkle Tree
            let next_leaf = LeafVar {
                evals: pm.running_evals,
                last_subtrace_entry,
            };
            self.next_leaf_membership_var
                .verify_membership(
                    &leaf_params_var,
                    &two_to_one_params_var,
                    &self.root_var,
                    &next_leaf,
                )?
                .enforce_equal(&Boolean::TRUE)?;

            // TODO: Ensure that at i==0, the provided given evals are 0 and the provided last
            // subtrace entry is (0, 0)

            Ok(())
        })
    }
}

/*
#[cfg(test)]
mod test {
    use ark_crypto_primitives::{
        crh::{bowe_hopwood, pedersen},
        merkle_tree::Config,
    };

    use ark_ed_on_bls12_381::EdwardsParameters;
    use ark_std::rand::RngCore;

    #[derive(Clone, PartialEq, Eq, Hash)]
    struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 63;
        const NUM_WINDOWS: usize = 9;
    }

    #[derive(Clone)]
    struct JubJubMerkleTreeParams;
    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }

    type JubJubMerkleTree = SparseMerkleTree<JubJubMerkleTreeParams>;
    type H = bowe_hopwood::CRH<EdwardsParameters, Window>;
}
*/
