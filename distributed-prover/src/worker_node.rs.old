use ark_ff::{FftField, PrimeField};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_r1cs_std::{alloc::AllocVar, fp::FpVar, uint128::UInt128, uint64::UInt64};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

use crate::{RomTranscriptEntry, RomTranscriptEntryVar};

type MerkleRoot<F> = F;
type MerkleAuthPath<F> = F;
type MerkleAuthPathVar<F> = F;

// Represents the partial evaluations of the time-ordered trace polynomial and the addr-ordered
// trace polynomial
struct RunningEvaluations<F: PrimeField> {
    time_peval: F,
    addr_peval: F,
}

// The ZK version of RunningEvaluations
struct RunningEvaluationsVar<F: PrimeField> {
    time_peval: FpVar<F>,
    addr_peval: FpVar<F>,
}

struct SubcircuitProver<F: PrimeField> {
    // Witnesses to be set before stage 0
    subtrace_by_time: Vec<RomTranscriptEntry<F>>,
    subtrace_by_addr: Vec<RomTranscriptEntry<F>>,
    subtrace_by_time_var: Vec<RomTranscriptEntryVar<F>>,
    subtrace_by_addr_var: Vec<RomTranscriptEntryVar<F>>,

    // Public inputs to be set before stage 1
    // The X value used for the polynomial representing the trace
    tr_chal: F,
    // The X value used for the polynomial representing a trace entry
    entry_chal: F,
    merkle_root: MerkleRoot<F>,
    tr_chal_var: FpVar<F>,
    merkle_root_var: MerkleRoot<F>,

    // Witnesses to be set before stage 1
    running_evals: RunningEvaluations<F>,
    // Leaf should contain (running_evalsᵢ₊₁, fᵢ) where fᵢ == subtrace_by_addr.last()
    next_state_leaf: MerkleAuthPath<F>,
    prev_subtrace_by_addr_tail: RomTranscriptEntry<F>,
    running_evals_var: RunningEvaluationsVar<F>,
    next_running_evals_var: MerkleAuthPathVar<F>,
    prev_subtrace_by_addr_tail_var: RomTranscriptEntryVar<F>,
}

impl<F: PrimeField> SubcircuitProver<F> {
    fn stage0(&mut self, cs: &mut ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Witness the trace chunks
        self.subtrace_by_time_var = self.subtrace_by_time.map(|entry| {
            RomTranscriptEntryVar::new_witness(ns!(cs, "time trace chunk"), || Ok(entry))
        })?;
        self.subtrace_by_addr_var = self.subtrace_by_addr.map(|entry| {
            RomTranscriptEntryVar::new_witness(ns!(cs, "addr trace chunk"), || Ok(entry))
        })?;

        Ok(())
    }

    fn stage1(&mut self, cs: &mut ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Input the challenge and Merkle root
        self.chal_var = FpVar::new_input(ns!(cs, "chal"), || Ok(self.chal))?;
        self.merkle_root_var = MerkleRoot::new_input(ns!(cs, "root"), || Ok(self.merkle_root))?;

        // Witness the running evals, the auth path of the next running evals, and the previous
        // subtract

        // TODO: Run the rest of the circuit
        // Every time a transcript entry is accessed, it should compute
        self.running_evals *= chal - entry.as_fpvar();

        // Check consistency of the ROM

        // TODO: Assert that self.running_evals == 0 if this is the first subcircuit

        Ok(())
    }
}
