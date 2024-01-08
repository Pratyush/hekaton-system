use crate::{
    eval_tree::{
        ExecTreeLeaf, ExecTreeLeafVar, ExecTreeParams, LeafParamVar, MerkleRoot, MerkleRootVar,
        SerializedLeafVar, TwoToOneParamVar,
    },
    portal_manager::ProverPortalManager,
    util::log2,
    CircuitWithPortals, RomTranscriptEntry, RomTranscriptEntryVar,
};

use std::marker::PhantomData;

use ark_cp_groth16::{MultiStageConstraintSynthesizer, MultiStageConstraintSystem};
use ark_crypto_primitives::merkle_tree::{
    constraints::{ConfigGadget as TreeConfigGadget, PathVar as MerklePathVar},
    Config as TreeConfig, Path as MerklePath,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    ToConstraintFieldGadget,
};
use ark_relations::{ns, r1cs::SynthesisError};

// A ZK circuit that takes a CircuitWithPortals and proves just 1 subcircuit
pub struct SubcircuitWithPortalsProver<F, P, C, CG>
where
    F: PrimeField,
    P: CircuitWithPortals<F>,
    C: TreeConfig,
    CG: TreeConfigGadget<C, F>,
{
    pub subcircuit_idx: usize,
    pub circ: Option<P>,

    // Merkle tree things
    pub tree_params: ExecTreeParams<C>,

    // Stage 0 committed values
    pub time_ordered_subtrace: Vec<RomTranscriptEntry<F>>,
    pub addr_ordered_subtrace: Vec<RomTranscriptEntry<F>>,
    pub(crate) time_ordered_subtrace_var: Vec<RomTranscriptEntryVar<F>>,
    pub(crate) addr_ordered_subtrace_var: Vec<RomTranscriptEntryVar<F>>,

    // Stage 1 witnesses
    pub(crate) cur_leaf: ExecTreeLeaf<F>,
    pub next_leaf_membership: MerklePath<C>,

    // Stage 1 public inputs
    pub entry_chal: F,
    pub tr_chal: F,
    pub root: MerkleRoot<C>,

    pub _marker: PhantomData<CG>,
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
            tree_params: self.tree_params.clone(),
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
    pub fn new(tree_params: ExecTreeParams<C>, num_subcircuits: usize) -> Self {
        // Create an auth path of the correct length
        let auth_path_len = log2(num_subcircuits) - 1;
        let mut auth_path = MerklePath::default();
        auth_path.auth_path = vec![C::InnerDigest::default(); auth_path_len];

        SubcircuitWithPortalsProver {
            subcircuit_idx: 0,
            circ: None,
            tree_params,
            time_ordered_subtrace: Vec::new(),
            addr_ordered_subtrace: Vec::new(),
            time_ordered_subtrace_var: Vec::new(),
            addr_ordered_subtrace_var: Vec::new(),
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
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                self.addr_ordered_subtrace_var = self
                    .addr_ordered_subtrace
                    .iter()
                    .map(|entry| RomTranscriptEntryVar::new_witness(ns!(c, "addr"), || Ok(entry)))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                println!(
                    "Witnessed trace of size {}",
                    self.time_ordered_subtrace.len()
                );
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
            let leaf_params_var = LeafParamVar::<CG, _, _>::new_constant(
                ns!(c, "leaf param"),
                &self.tree_params.leaf_params,
            )?;
            let two_to_one_params_var = TwoToOneParamVar::<CG, _, _>::new_constant(
                ns!(c, "2-to-1 param"),
                &self.tree_params.two_to_one_params,
            )?;

            println!(
                "Full subcircuit {} costs {} constraints",
                self.subcircuit_idx,
                c.num_constraints()
            );

            Ok(())
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        aggregation::AggProvingKey,
        coordinator::{CoordinatorStage0State, G16ProvingKeyGenerator, Stage1Request},
        poseidon_util::{
            gen_merkle_params, PoseidonTreeConfig as TestParams,
            PoseidonTreeConfigVar as TestParamsVar,
        },
        tree_hash_circuit::*,
        util::{G16Com, G16ComSeed},
        worker::{process_stage0_request, process_stage1_request, Stage0Response},
    };
    use sha2::Sha256;

    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_cp_groth16::verifier::{prepare_verifying_key, verify_proof};
    use ark_ff::UniformRand;
    use ark_ip_proofs::tipa::TIPA;
    use ark_std::test_rng;

    // Checks that the SubcircuitWithPortalsProver is satisfied when the correct inputs are given
    #[test]
    fn test_subcircuit_portal_prover_satisfied() {
        let mut rng = test_rng();
        let tree_params = gen_merkle_params();

        // Make a random Merkle tree
        let circ_params = MerkleTreeCircuitParams {
            num_leaves: 4,
            num_sha_iters_per_subcircuit: 4,
            num_portals_per_subcircuit: 12,
        };
        let circ = MerkleTreeCircuit::rand(&mut rng, &circ_params);
        let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);

        // Make the stage0 coordinator state. The value of the commitment key doesn't really matter
        // since we don't test aggregation here.
        let (tipp_pk, _tipp_vk) = TIPA::<_, Sha256>::setup(num_subcircuits, &mut rng).unwrap();
        let stage0_state = CoordinatorStage0State::new::<TestParams>(circ);
        let all_subcircuit_indices = (0..num_subcircuits).collect::<Vec<_>>();

        // Worker receives a stage0 package containing all the subtraces it will need for this run.
        // In this test, it's simply all of them. We imagine that the worker stores its copy of
        // this for later use in stage 1
        let stage0_reqs = all_subcircuit_indices
            .iter()
            .map(|idx| stage0_state.gen_request(*idx).to_owned())
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

        // Move on to stage 1. Make the coordinator state
        let stage1_state = stage0_state.process_stage0_responses(
            &tipp_pk,
            tree_params.clone(),
            &fake_stage0_resps,
        );

        // Compute the values needed to prove stage1 for all subcircuits
        let stage1_reqs = all_subcircuit_indices
            .iter()
            .map(|idx| stage1_state.gen_request(*idx))
            .collect::<Vec<_>>();

        // Now for every subcircuit, instantiate a subcircuit prover and check that its constraints
        // are satisfied
        for (stage0_req, stage1_req) in stage0_reqs.into_iter().zip(stage1_reqs.into_iter()) {
            assert_eq!(stage0_req.subcircuit_idx, stage1_req.subcircuit_idx);
            let subcircuit_idx = stage0_req.subcircuit_idx;

            let (entry_chal, tr_chal) = stage1_req.cur_leaf.evals.challenges.unwrap();

            // Make an empty version of the large circuit and fill in just the witnesses for the
            // subcircuit we're proving now
            let mut partial_circ = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::new(&circ_params);
            <MerkleTreeCircuit as CircuitWithPortals<Fr>>::set_serialized_witnesses(
                &mut partial_circ,
                subcircuit_idx,
                &stage1_req.serialized_witnesses,
            );

            let mut subcirc_circ = SubcircuitWithPortalsProver {
                subcircuit_idx,
                circ: Some(partial_circ),
                tree_params: tree_params.clone(),
                time_ordered_subtrace: stage0_req.time_ordered_subtrace.clone(),
                addr_ordered_subtrace: stage0_req.addr_ordered_subtrace.clone(),
                time_ordered_subtrace_var: Vec::new(),
                addr_ordered_subtrace_var: Vec::new(),
                cur_leaf: stage1_req.cur_leaf,
                next_leaf_membership: stage1_req.next_leaf_membership,
                entry_chal,
                tr_chal,
                root: stage1_req.root,
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
        let tree_params = gen_merkle_params();

        // Make a random Merkle tree
        let circ_params = MerkleTreeCircuitParams {
            num_leaves: 4096,
            num_sha_iters_per_subcircuit: 1,
            num_portals_per_subcircuit: 10,
        };
        let circ = MerkleTreeCircuit::rand(&mut rng, &circ_params);
        let num_subcircuits = <MerkleTreeCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);
        let all_subcircuit_indices = (0..num_subcircuits).collect::<Vec<_>>();

        // Coordinator generates all the proving keys
        println!("Generating proving key");
        let proving_key = {
            let generator = G16ProvingKeyGenerator::<TestParams, TestParamsVar, _, _>::new(
                circ.clone(),
                tree_params.clone(),
            );
            generator.gen_pk(&mut rng, 0)
        };

        // Make the stage0 coordinator state
        println!("Generating stage0 state");
        let stage0_state = CoordinatorStage0State::new::<TestParams>(circ);

        // Workers receives stage0 packages containing the subtraces it will need for this run. We
        // imagine the worker saves their package to disk.
        println!("Generating stage0 req");
        let stage0_req = stage0_state.gen_request(0).to_owned();

        // Make stage0 responses wrt the real proving keys. This contains all the commitments
        println!("Generating stage0 resp");
        let stage0_resp = process_stage0_request::<_, TestParamsVar, _, MerkleTreeCircuit, _>(
            &mut rng,
            tree_params.clone(),
            &proving_key,
            stage0_req.clone(),
        );
        let stage0_resps = core::iter::repeat(stage0_resp.clone())
            .take(num_subcircuits)
            .collect::<Vec<_>>();

        // Move on to stage 1. Make the coordinator state
        let (tipp_pk, _tipp_vk) = TIPA::<E, Sha256>::setup(num_subcircuits, &mut rng).unwrap();
        let stage1_state =
            stage0_state.process_stage0_responses(&tipp_pk, tree_params.clone(), &stage0_resps);

        // Compute the values needed to prove stage1 for all subcircuits
        println!("Generating stage1 req");
        let stage1_req = stage1_state.gen_request(0).to_owned();

        // Convert the coordinator state into a final aggregator state. We can throw away most of
        // our circuit data now
        let final_agg_state = stage1_state.into_agg_state();

        println!("Generating stage1 resp");
        let stage1_resp = process_stage1_request::<_, TestParamsVar, _, _, _>(
            &mut rng,
            tree_params.clone(),
            &proving_key,
            stage0_req,
            &stage0_resp,
            stage1_req,
        );
        let stage1_resps = core::iter::repeat(stage1_resp.clone())
            .take(num_subcircuits)
            .collect::<Vec<_>>();

        // Verify
        let public_inputs = &final_agg_state.public_inputs;
        let pvk = prepare_verifying_key(&proving_key.vk());
        assert!(verify_proof(&pvk, &stage1_resp.proof, &public_inputs).unwrap());

        // Do aggregation. Make up whatever keys are necessary
        println!("Generating agg ck");
        let agg_ck = AggProvingKey::new(tipp_pk, |_| &proving_key);

        // Compute the aggregate proof
        println!("Generating agg proof of {} responses", stage1_resps.len());
        final_agg_state.gen_agg_proof(&agg_ck, &stage1_resps);

        // TODO: Check verification
    }
}
