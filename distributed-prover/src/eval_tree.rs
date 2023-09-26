use crate::{
    portal_manager::ProverPortalManager, CircuitWithPortals, RomTranscriptEntry,
    RomTranscriptEntryVar, RunningEvals, RunningEvalsVar,
};

use core::borrow::Borrow;

use ark_cp_groth16::{MultiStageConstraintSynthesizer, MultiStageConstraintSystem};

use ark_crypto_primitives::{
    crh::constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
    merkle_tree::{
        constraints::{ConfigGadget as TreeConfigGadget, PathVar as MerklePathVar},
        Config as TreeConfig, LeafParam, Path as MerklePath, TwoToOneParam,
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
    r1cs::{Namespace, SynthesisError},
};

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

// Define a way to commit and prove to just one subcircuit
struct CpPortalProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F>,
{
    subcircuit_idx: usize,
    circ: P,

    // Merkle tree things
    pub leaf_params: LeafParam<C>,
    pub two_to_one_params: TwoToOneParam<C>,

    // Stage 0 committed values
    pub time_ordered_subtrace: Vec<RomTranscriptEntry<F>>,
    pub addr_ordered_subtrace: Vec<RomTranscriptEntry<F>>,
    pub time_ordered_subtrace_var: Vec<RomTranscriptEntryVar<F>>,
    pub addr_ordered_subtrace_var: Vec<RomTranscriptEntryVar<F>>,

    // Stage 1 witnesses
    pub running_evals: RunningEvals<F>,
    pub cur_leaf: Leaf<F>,
    pub next_leaf_membership: MerklePath<C>,
    pub running_evals_var: RunningEvalsVar<F>,
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

impl<F, P, C, CG> MultiStageConstraintSynthesizer<F> for CpPortalProver<F, P, C, CG>
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
            self.running_evals_var =
                RunningEvalsVar::new_witness(ns!(c, "evals"), || Ok(&self.running_evals))?;
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
            self.running_evals_var.challenges =
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
                running_evals: self.running_evals_var.clone(),
            };

            // Run the circuit with the portal manager
            self.circ
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
