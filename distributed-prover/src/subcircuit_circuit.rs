use crate::{
    eval_tree::{
        ExecTreeLeaf, ExecTreeLeafVar, LeafParam, LeafParamVar, MerkleRoot, MerkleRootVar,
        SerializedLeafVar, TwoToOneParam, TwoToOneParamVar,
    },
    portal_manager::ProverPortalManager,
    util::log2,
    CircuitWithPortals, RomTranscriptEntry, RomTranscriptEntryVar,
};

use std::{collections::VecDeque, marker::PhantomData};

use ark_cp_groth16::{MultiStageConstraintSynthesizer, MultiStageConstraintSystem};
use ark_crypto_primitives::merkle_tree::{
    constraints::{ConfigGadget as TreeConfigGadget, PathVar as MerklePathVar},
    Config as TreeConfig, Path as MerklePath,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{boolean::Boolean, ToBytesGadget},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::{ns, r1cs::SynthesisError};

// A ZK circuit that takes a CircuitWithPortals and proves just 1 subcircuit
pub(crate) struct SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F>,
{
    pub subcircuit_idx: usize,
    pub circ: Option<P>,

    // Merkle tree things
    pub leaf_params: LeafParam<C>,
    pub two_to_one_params: TwoToOneParam<C>,

    // Stage 0 committed values
    pub time_ordered_subtrace: VecDeque<RomTranscriptEntry<F>>,
    pub addr_ordered_subtrace: VecDeque<RomTranscriptEntry<F>>,
    pub time_ordered_subtrace_var: VecDeque<RomTranscriptEntryVar<F>>,
    pub addr_ordered_subtrace_var: VecDeque<RomTranscriptEntryVar<F>>,

    // Stage 1 witnesses
    pub cur_leaf: ExecTreeLeaf<F>,
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
    pub(crate) fn new(
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
            time_ordered_subtrace: VecDeque::new(),
            addr_ordered_subtrace: VecDeque::new(),
            time_ordered_subtrace_var: VecDeque::new(),
            addr_ordered_subtrace_var: VecDeque::new(),
            cur_leaf: ExecTreeLeaf::default(),
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
                    .collect::<Result<VecDeque<_>, _>>()
                    .unwrap();
                self.addr_ordered_subtrace_var = self
                    .addr_ordered_subtrace
                    .iter()
                    .map(|entry| RomTranscriptEntryVar::new_witness(ns!(c, "addr"), || Ok(entry)))
                    .collect::<Result<VecDeque<_>, _>>()
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
            let cur_leaf_var = ExecTreeLeafVar::new_witness(ns!(c, "leaf"), || Ok(&self.cur_leaf))?;
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

            // Ensure that at subcircuit 0, the provided evals and last subtrace entry are the
            // defaults
            if self.subcircuit_idx == 0 {
                // Check the evals are (1, 1)
                cur_leaf_var
                    .evals
                    .time_ordered_eval
                    .enforce_equal(&FpVar::one())?;
                cur_leaf_var
                    .evals
                    .addr_ordered_eval
                    .enforce_equal(&FpVar::one())?;

                // Check the padding entry is (0, 0)
                cur_leaf_var
                    .last_subtrace_entry
                    .val
                    .enforce_equal(&FpVar::zero())?;
                cur_leaf_var
                    .last_subtrace_entry
                    .addr
                    .enforce_equal(&FpVar::zero())?;
            }

            // Set the challenge values so the running evals knows how to update itself
            let mut running_evals_var = cur_leaf_var.evals.clone();
            running_evals_var.challenges = Some((entry_chal_var, tr_chal_var));

            // Prepend the last subtrace entry to the addr-ordered subtrace. This necessary for the
            // consistency check.
            let full_addr_ordered_subtrace = core::iter::once(&cur_leaf_var.last_subtrace_entry)
                .chain(self.addr_ordered_subtrace_var.iter())
                .cloned()
                .collect::<VecDeque<_>>();
            // Save the last subtrace entry for a check later
            let last_subtrace_entry = full_addr_ordered_subtrace.back().unwrap().clone();

            // Create the portal manager to give to the circuit
            let mut pm = ProverPortalManager {
                time_ordered_subtrace: self.time_ordered_subtrace_var.clone(),
                addr_ordered_subtrace: full_addr_ordered_subtrace,
                running_evals: running_evals_var,
            };

            // Run the specific subcircuit and give it the prepared portal manager
            self.circ
                .as_mut()
                .expect("must provide circuit for stage 1 computation")
                .generate_constraints(c.clone(), self.subcircuit_idx, &mut pm)?;

            // Sanity checks: make sure all the subtraces were used. The addr-ordered one has 1
            // remaining because it starts with 1 extra. The last one is used, but it's not popped.
            assert_eq!(pm.time_ordered_subtrace.len(), 0);
            assert_eq!(pm.addr_ordered_subtrace.len(), 1);

            // Make sure the resulting tree leaf appears in the Merkle Tree
            let next_leaf = ExecTreeLeafVar {
                evals: pm.running_evals,
                last_subtrace_entry,
            };
            next_leaf_membership_var
                .verify_membership(
                    &leaf_params_var,
                    &two_to_one_params_var,
                    &root_var,
                    &next_leaf.to_bytes()?,
                )?
                .enforce_equal(&Boolean::TRUE)?;

            // If this is the last subcircuit, then verify that the time- and addr-ordered evals
            // are equal. This completes the permutation check.
            if self.subcircuit_idx == self.circ.as_ref().unwrap().num_subcircuits() - 1 {
                next_leaf
                    .evals
                    .time_ordered_eval
                    .enforce_equal(&next_leaf.evals.addr_ordered_eval)?;
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        eval_tree::{SerializedLeaf, SerializedLeafVar},
        prover::{
            compute_stage0_response, gen_merkle_params, gen_subcircuit_proving_keys, G16Com,
            G16ComSeed, G16ProvingKey, Stage0PackageBuilder, Stage0Response, Stage0WorkerPackage,
            Stage0WorkerPackageRef, Stage1Request,
        },
        tree_hash_circuit::*,
    };

    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_cp_groth16::{
        committer::CommitmentBuilder as G16CommitmentBuilder,
        r1cs_to_qap::LibsnarkReduction as QAP,
        verifier::{prepare_verifying_key, verify_proof},
    };
    use ark_crypto_primitives::{
        crh::{
            bowe_hopwood,
            constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
            pedersen, CRHScheme, TwoToOneCRHScheme,
        },
        merkle_tree::{
            constraints::{BytesVarDigestConverter, ConfigGadget},
            ByteDigestConverter, Config,
        },
    };
    use ark_ed_on_bls12_381::{constraints::FqVar, JubjubConfig};
    use ark_ff::{ToConstraintField, UniformRand};
    use ark_std::test_rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

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

    // Checks that the SubcircuitWithPortalsProver is satisfied when the correct inputs are given
    #[test]
    fn test_subcircuit_portal_prover_satisfied() {
        let mut rng = test_rng();
        let (leaf_params, two_to_one_params) = gen_merkle_params::<TestParams>();

        // Make a random Merkle tree
        let circ_params = MerkleTreeCircuitParams { num_leaves: 4 };
        let circ = MerkleTreeCircuit::rand(&mut rng, &circ_params);
        let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);

        let stage0_builder = Stage0PackageBuilder::new::<TestParams>(circ);
        let all_subcircuit_indices = (0..num_subcircuits).collect::<Vec<_>>();

        // Worker receives a stage0 package containing all the subtraces it will need for this run.
        // In this test, it's simply all of them. We imagine that the worker stores its copy of
        // this for later use in stage 1
        let stage0_reqs = all_subcircuit_indices
            .iter()
            .map(|idx| stage0_builder.gen_package(*idx).to_owned())
            .collect::<Vec<_>>();

        // Make fake stage0 responses that cover all the subcircuits and has random commitments
        let fake_stage0_resps = all_subcircuit_indices
            .iter()
            .map(|idx| Stage0Response::<E> {
                subcircuit_idx: *idx,
                com: G16Com::<E>::rand(&mut rng),
                com_seed: G16ComSeed::default(),
            })
            .collect::<Vec<_>>();

        // Move on to stage 1
        let stage1_builder = stage0_builder.process_stage0_responses(&fake_stage0_resps);

        // Compute the values needed to prove stage1. This is for all the subcircuits.
        let Stage1Request {
            subcircuit_idxs,
            cur_leaves,
            next_leaf_memberships,
            root,
        } = stage1_builder.gen_request(&all_subcircuit_indices);

        // Now for every subcircuit, instantiate a subcircuit prover and check that its constraints
        // are satisfied
        for (((subcircuit_idx, cur_leaf), next_leaf_membership), stage0_req) in subcircuit_idxs
            .into_iter()
            .zip(cur_leaves.into_iter())
            .zip(next_leaf_memberships.into_iter())
            .zip(stage0_reqs.into_iter())
        {
            let (entry_chal, tr_chal) = cur_leaf.evals.challenges.unwrap();

            // Make an empty version of the large circuit and fill in just the witnesses for the
            // subcircuit we're proving now
            let mut partial_circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::new(&circ_params);
            <MerkleTreeCircuit as CircuitWithPortals<Fr>>::set_serialized_witnesses(
                &mut partial_circ,
                subcircuit_idx,
                &stage0_req.serialized_witnesses,
            );

            let mut subcirc_circ = SubcircuitWithPortalsProver {
                subcircuit_idx,
                circ: Some(partial_circ),
                leaf_params: leaf_params.clone(),
                two_to_one_params: two_to_one_params.clone(),
                time_ordered_subtrace: stage0_req.time_ordered_subtrace.clone(),
                addr_ordered_subtrace: stage0_req.addr_ordered_subtrace.clone(),
                time_ordered_subtrace_var: VecDeque::new(),
                addr_ordered_subtrace_var: VecDeque::new(),
                cur_leaf,
                next_leaf_membership,
                entry_chal,
                tr_chal,
                root,
                _marker: PhantomData::<TestParamsVar>,
            };

            // Run both stages
            let mut mcs = MultiStageConstraintSystem::default();
            subcirc_circ.generate_constraints(0, &mut mcs).unwrap();
            subcirc_circ.generate_constraints(1, &mut mcs).unwrap();

            // Check that everything worked
            assert!(mcs.is_satisfied().unwrap());
        }
    }

    // Checks that the SubcircuitWithPortalsProver is satisfied when the correct inputs are given
    #[test]
    fn test_e2e_prover() {
        let mut rng = test_rng();
        let (leaf_params, two_to_one_params) = gen_merkle_params::<TestParams>();

        // Make a random Merkle tree
        let circ_params = MerkleTreeCircuitParams { num_leaves: 4 };
        let circ = MerkleTreeCircuit::rand(&mut rng, &circ_params);
        let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);

        // Generate proving keys
        let proving_keys: Vec<G16ProvingKey<E>> =
            gen_subcircuit_proving_keys::<TestParams, TestParamsVar, _, _>(
                &leaf_params,
                &two_to_one_params,
                circ.clone(),
            );

        let stage0_builder = Stage0PackageBuilder::new::<TestParams>(circ);
        let all_subcircuit_indices = (0..num_subcircuits).collect::<Vec<_>>();

        // Workers receives stage0 packages containing the subtraces it will need for this run. We
        // imagine the worker saves their package to disk.
        let stage0_reqs = all_subcircuit_indices
            .iter()
            .map(|idx| stage0_builder.gen_package(*idx).to_owned())
            .collect::<Vec<_>>();

        // Make stage0 responses wrt the real proving keys. This contains all the commitments
        let stage0_resps = stage0_reqs
            .iter()
            .zip(proving_keys.iter())
            .map(|(req, pk)| {
                compute_stage0_response::<E, MerkleTreeCircuit, TestParams, TestParamsVar>(
                    req.clone(),
                    pk,
                    &leaf_params,
                    &two_to_one_params,
                )
            })
            .collect::<Vec<_>>();

        // Move on to stage 1
        let stage1_builder = stage0_builder.process_stage0_responses(&stage0_resps);

        // Compute the values needed to prove stage1. This is for all the subcircuits.
        let Stage1Request {
            subcircuit_idxs,
            cur_leaves,
            next_leaf_memberships,
            root,
        } = stage1_builder.gen_request(&all_subcircuit_indices);

        // Now for every subcircuit, instantiate a subcircuit prover and check that its constraints
        // are satisfied
        for (((((subcircuit_idx, cur_leaf), next_leaf_membership), pk), stage0_req), stage0_resp) in
            subcircuit_idxs
                .into_iter()
                .zip(cur_leaves.into_iter())
                .zip(next_leaf_memberships.into_iter())
                .zip(proving_keys.into_iter())
                .zip(stage0_reqs.into_iter())
                .zip(stage0_resps.into_iter())
        {
            let (entry_chal, tr_chal) = cur_leaf.evals.challenges.unwrap();

            // Make an empty version of the large circuit and fill in just the witnesses for the
            // subcircuit we're proving now
            let mut partial_circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::new(&circ_params);
            <MerkleTreeCircuit as CircuitWithPortals<Fr>>::set_serialized_witnesses(
                &mut partial_circ,
                subcircuit_idx,
                &stage0_req.serialized_witnesses,
            );

            let real_circ = SubcircuitWithPortalsProver {
                subcircuit_idx,
                circ: Some(partial_circ),
                leaf_params: leaf_params.clone(),
                two_to_one_params: two_to_one_params.clone(),
                time_ordered_subtrace: stage0_req.time_ordered_subtrace.clone(),
                addr_ordered_subtrace: stage0_req.addr_ordered_subtrace.clone(),
                time_ordered_subtrace_var: VecDeque::new(),
                addr_ordered_subtrace_var: VecDeque::new(),
                cur_leaf,
                next_leaf_membership,
                entry_chal,
                tr_chal,
                root,
                _marker: PhantomData::<TestParamsVar>,
            };

            let mut cb = G16CommitmentBuilder::<_, E, QAP>::new(real_circ, &pk);
            let mut subcircuit_rng = {
                let com_seed = stage0_resp.com_seed.clone();
                ChaCha12Rng::from_seed(com_seed)
            };

            let (com, rand) = cb.commit(&mut subcircuit_rng).unwrap();
            assert_eq!(com, stage0_resp.com);

            let proof = cb.prove(&[com], &[rand], &mut rng).unwrap();

            // Verify
            let pvk = prepare_verifying_key(&pk.vk());
            let inputs = [
                entry_chal.to_field_elements().unwrap(),
                tr_chal.to_field_elements().unwrap(),
                root.to_field_elements().unwrap(),
            ]
            .concat();
            assert!(verify_proof(&pvk, &proof, &inputs).unwrap());
        }
    }
}
