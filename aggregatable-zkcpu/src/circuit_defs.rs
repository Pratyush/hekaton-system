use crate::{
    exec_checker::CpuStateVar,
    transcript_checker::{
        transcript_checker, ProcessedTranscriptEntry, ProcessedTranscriptEntryVar,
        TranscriptCheckerEvals, TranscriptCheckerEvalsVar,
    },
    word::WordVar,
};

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use cp_groth16::{MultiStageConstraintSynthesizer, MultiStageConstraintSystem};
use tinyram_emu::{program_state::CpuState, word::Word, ProgramMetadata};

#[derive(Clone)]
struct TranscriptCheckerCircuit<const NUM_REGS: usize, W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    meta: ProgramMetadata,

    // Stage 0 values. Inputs that equal the output of the last tick.
    pub in_cpu_state: CpuState<NUM_REGS, W>,
    pub in_mem_tr_adj: ProcessedTranscriptEntry<W>,
    in_cpu_state_var: CpuStateVar<WV, F>,
    in_mem_tr_adj_var: ProcessedTranscriptEntryVar<WV, F>,

    // Stage 1 values. Outputs that equal the input of the next tick.
    pub out_cpu_state: CpuState<NUM_REGS, W>,
    pub out_mem_tr_adj: ProcessedTranscriptEntry<W>,
    out_cpu_state_var: CpuStateVar<WV, F>,
    out_mem_tr_adj_var: ProcessedTranscriptEntryVar<WV, F>,

    // Stage 2 values. Intermediate values not repeated anywhere.
    pub instr_loads: Vec<ProcessedTranscriptEntry<W>>,
    pub mem_ops: Vec<ProcessedTranscriptEntry<W>>,
    pub middle_mem_tr_adjs: Vec<ProcessedTranscriptEntry<W>>,
    instr_loads_var: Vec<ProcessedTranscriptEntryVar<WV, F>>,
    mem_ops_var: Vec<ProcessedTranscriptEntryVar<WV, F>>,
    middle_mem_tr_adjs_var: Vec<ProcessedTranscriptEntryVar<WV, F>>,

    // Stage 3 values. Inputs whose value depend on the commitments of all the above stages. This
    // is all the polynomial evals.
    pub in_evals: TranscriptCheckerEvals<F>,
    in_evals_var: TranscriptCheckerEvalsVar<F>,

    // Stage 4 values. Outputs whose value depend on the commitments of all the above stages. This
    // is all the polynomial evals.
    pub out_evals: TranscriptCheckerEvals<F>,
    out_evals_var: TranscriptCheckerEvalsVar<F>,

    // Stage 5 values. Repeated everywhere.
    pub chal: F,
    chal_var: FpVar<F>,
}

impl<const NUM_REGS: usize, W, WV, F> TranscriptCheckerCircuit<NUM_REGS, W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    /// Makes a new circuit with all placeholder values
    fn new(meta: ProgramMetadata, num_ticks: usize) -> Self {
        TranscriptCheckerCircuit {
            meta,
            in_cpu_state: Default::default(),
            in_mem_tr_adj: Default::default(),
            in_cpu_state_var: CpuStateVar::default::<NUM_REGS>(),
            in_mem_tr_adj_var: Default::default(),

            out_cpu_state: Default::default(),
            out_mem_tr_adj: Default::default(),
            out_cpu_state_var: CpuStateVar::default::<NUM_REGS>(),
            out_mem_tr_adj_var: Default::default(),

            instr_loads: vec![Default::default(); num_ticks],
            mem_ops: vec![Default::default(); num_ticks],
            middle_mem_tr_adjs: vec![Default::default(); 2 * num_ticks - 1],
            instr_loads_var: vec![Default::default()],
            mem_ops_var: vec![Default::default(); num_ticks],
            middle_mem_tr_adjs_var: vec![Default::default(); 2 * num_ticks - 1],

            in_evals: Default::default(),
            in_evals_var: Default::default(),

            out_evals: Default::default(),
            out_evals_var: Default::default(),

            chal: Default::default(),
            chal_var: FpVar::Constant(F::ZERO),
        }
    }
}

impl<const NUM_REGS: usize, W, WV, F> TranscriptCheckerCircuit<NUM_REGS, W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    /// Commit to the input state, i.e., the given CPU state and first item in the mem-sorted trace
    /// window
    fn stage0(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.in_cpu_state_var =
            CpuStateVar::new_witness(ns!(cs, "in cpu state"), || Ok(&self.in_cpu_state))?;
        self.in_mem_tr_adj_var =
            ProcessedTranscriptEntryVar::new_witness(ns!(cs, "mem tr adj 0"), || {
                Ok(&self.in_mem_tr_adj)
            })?;

        Ok(())
    }

    /// Commit to the output state, i.e., the given CPU state and last item in the mem-sorted trace
    /// window
    fn stage1(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.out_cpu_state_var =
            CpuStateVar::new_witness(ns!(cs, "out cpu state"), || Ok(&self.out_cpu_state))?;
        self.out_mem_tr_adj_var =
            ProcessedTranscriptEntryVar::new_witness(ns!(cs, "mem tr adj 2"), || {
                Ok(&self.out_mem_tr_adj)
            })?;

        Ok(())
    }

    /// Commit to the time-sorted memory operations, i.e., the instr load and CPU mem op
    fn stage2(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.instr_loads_var = self
            .instr_loads
            .iter()
            .map(|op| ProcessedTranscriptEntryVar::new_witness(ns!(cs, "instr load"), || Ok(op)))
            .collect::<Result<Vec<_>, _>>()?;
        self.mem_ops_var = self
            .mem_ops
            .iter()
            .map(|op| ProcessedTranscriptEntryVar::new_witness(ns!(cs, "mem op"), || Ok(op)))
            .collect::<Result<Vec<_>, _>>()?;
        self.middle_mem_tr_adjs_var = self
            .middle_mem_tr_adjs
            .iter()
            .map(|op| ProcessedTranscriptEntryVar::new_witness(ns!(cs, "mem tr adj 1"), || Ok(op)))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    /// Commit to the input evals
    fn stage3(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.in_evals_var =
            TranscriptCheckerEvalsVar::new_witness(ns!(cs, "in evals"), || Ok(&self.in_evals))?;

        Ok(())
    }

    /// Commit to the output evals
    fn stage4(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.out_evals_var =
            TranscriptCheckerEvalsVar::new_witness(ns!(cs, "out evals"), || Ok(&self.out_evals))?;

        Ok(())
    }

    fn stage5(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.chal_var = FpVar::new_witness(ns!(cs, "chal"), || Ok(self.chal))?;

        Ok(())
    }

    /// Do the transcript check
    fn stage6(&mut self, _cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        println!("Num constraints pre-stage6 {}", _cs.num_constraints());

        // Concat the memory-sorted trace elements into the a contiguous chunk. We will iterate
        // over this in windows of 3 with overlap of 1 (ie step size 2)
        let mem_tr_adj_seq_var = [
            &[self.in_mem_tr_adj_var.clone()][..],
            &self.middle_mem_tr_adjs_var.clone(),
            &[self.out_mem_tr_adj_var.clone()][..],
        ]
        .concat();

        let mut next_cpu_state = self.in_cpu_state_var.clone();
        let mut next_evals = self.in_evals_var.clone();
        for ((instr_load, mem_op), mem_sorted_tr_triple) in self
            .instr_loads_var
            .iter()
            .zip(self.mem_ops_var.iter())
            .zip(mem_tr_adj_seq_var.windows(3).step_by(2))
        {
            (next_cpu_state, next_evals) = transcript_checker::<NUM_REGS, _, _>(
                self.meta,
                &next_cpu_state,
                &self.chal_var,
                instr_load,
                mem_op,
                &mem_sorted_tr_triple,
                &next_evals,
            )?;
        }

        // The output values should be equal to the final next_* values
        next_cpu_state.enforce_equal(&self.out_cpu_state_var)?;
        next_evals.enforce_equal(&self.out_evals_var)?;

        println!("Num constraints post-stage6 {}", _cs.num_constraints());
        Ok(())
    }
}

impl<const NUM_REGS: usize, W, WV, F> MultiStageConstraintSynthesizer<F>
    for TranscriptCheckerCircuit<NUM_REGS, W, WV, F>
where
    W: Word,
    WV: WordVar<F, NativeWord = W>,
    F: PrimeField,
{
    fn total_num_stages(&self) -> usize {
        7
    }

    fn generate_constraints(
        &mut self,
        stage: usize,
        cs: &mut MultiStageConstraintSystem<F>,
    ) -> Result<(), SynthesisError> {
        match stage {
            0 => cs.synthesize_with(|c| self.stage0(c)),
            1 => cs.synthesize_with(|c| self.stage1(c)),
            2 => cs.synthesize_with(|c| self.stage2(c)),
            3 => cs.synthesize_with(|c| self.stage3(c)),
            4 => cs.synthesize_with(|c| self.stage4(c)),
            5 => cs.synthesize_with(|c| self.stage5(c)),
            6 => cs.synthesize_with(|c| self.stage6(c)),
            _ => panic!("unexpected stage stage {}", stage),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transcript_utils;
    use cp_groth16::{
        generator::generate_parameters,
        r1cs_to_qap::LibsnarkReduction as QAP,
        verifier::{prepare_verifying_key, verify_proof},
        CommitmentBuilder,
    };

    use tinyram_emu::{ProgramMetadata, TinyRamArch};

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::{Field, UniformRand};
    use ark_poly::Polynomial;
    use ark_r1cs_std::{alloc::AllocVar, uint32::UInt32, R1CSVar};
    use ark_relations::{ns, r1cs::ConstraintSystem};
    use ark_serialize::CanonicalSerialize;
    use ark_std::test_rng;
    use sha2::{Digest, Sha256};

    const NUM_REGS: usize = 16;
    type E = Bls12_381;
    type F = Fr;
    type WV = UInt32<F>;
    type W = <WV as WordVar<F>>::NativeWord;

    // Helper function that runs the given TinyRAM code through the symbolic transcript checker
    fn transcript_tester(code: &str, primary_input: Vec<W>, aux_input: Vec<W>) {
        let mut rng = test_rng();
        let start_tick = 0;
        let num_ticks = 1;

        let assembly = tinyram_emu::parser::assemble(code);

        // VonNeumann architecture, and no `read` operations.
        let meta = ProgramMetadata {
            arch: TinyRamArch::VonNeumann,
            primary_input_len: primary_input.len() as u32,
            aux_input_len: aux_input.len() as u32,
        };

        let (_output, exec_trace) = tinyram_emu::interpreter::run_program::<W, NUM_REGS>(
            TinyRamArch::VonNeumann,
            &assembly,
            primary_input,
            aux_input,
        );

        // TODO: Put primary reads into a different transcript

        let (time_sorted_transcript, mem_sorted_transcript) =
            transcript_utils::sort_and_pad(&exec_trace);

        let circuit = TranscriptCheckerCircuit::<NUM_REGS, _, WV, _>::new(meta, num_ticks);
        let pk = generate_parameters::<_, E, QAP>(circuit.clone(), &mut rng).unwrap();
        let mut cb = CommitmentBuilder::<_, E, QAP>::new(circuit, &pk);

        // Set stage 0 values for start tick and commit
        cb.circuit.in_cpu_state = if start_tick == 0 {
            CpuState::default()
        } else {
            exec_trace[start_tick - 1].cpu_after.clone()
        };
        cb.circuit.in_mem_tr_adj = mem_sorted_transcript[start_tick].clone();
        let (com0, rand0) = cb.commit(&mut rng).unwrap();

        // Set stage 1 values for final tick and commit
        cb.circuit.out_cpu_state = exec_trace[num_ticks - 1].cpu_after.clone();
        cb.circuit.out_mem_tr_adj = mem_sorted_transcript[2 * num_ticks].clone();
        let (com1, rand1) = cb.commit(&mut rng).unwrap();

        // Set stage 2 values for all the in between ticks and commit
        cb.circuit.instr_loads = time_sorted_transcript
            .iter()
            .step_by(2)
            .take(num_ticks)
            .cloned()
            .collect();
        cb.circuit.mem_ops = time_sorted_transcript
            .iter()
            .skip(1)
            .step_by(2)
            .take(num_ticks)
            .cloned()
            .collect();
        cb.circuit.middle_mem_tr_adjs =
            mem_sorted_transcript[start_tick + 1..start_tick + 2 * num_ticks].to_vec();
        let (com2, rand2) = cb.commit(&mut rng).unwrap();

        // Imagine we sent up all our commitments so far. The next step is to hash those
        // commitments together and produce a challenge. This is an approximation of that.
        let chal = {
            let mut buf = vec![];
            com0.serialize_compressed(&mut buf).unwrap();
            com1.serialize_compressed(&mut buf).unwrap();
            com2.serialize_compressed(&mut buf).unwrap();
            let d = Sha256::digest(&buf);
            F::from_be_bytes_mod_order(&d)
        };

        // Set stage 3 values for tick 0 and commit
        cb.circuit.in_evals = if start_tick == 0 {
            TranscriptCheckerEvals::default()
        } else {
            panic!("haven't defined in_evals for non-starting ticks");
        };
        let (com3, rand3) = cb.commit(&mut rng).unwrap();

        // Now compute the next evals
        let mut out_evals = cb.circuit.in_evals.clone();
        for ((instr_load, mem_op), mem_tr_triple) in cb
            .circuit
            .instr_loads
            .iter()
            .zip(cb.circuit.mem_ops.iter())
            .zip(
                mem_sorted_transcript[start_tick..start_tick + 2 * num_ticks + 1]
                    .windows(3)
                    .step_by(2),
            )
        {
            out_evals.update(chal, instr_load, mem_op, mem_tr_triple);
        }

        // Set stage 4 values for tick 0 and commit
        cb.circuit.out_evals = out_evals;
        let (com4, rand4) = cb.commit(&mut rng).unwrap();

        // Set stage 5 values for tick 0 and commit
        cb.circuit.chal = chal;
        let (com5, rand5) = cb.commit(&mut rng).unwrap();

        // Do the proof
        let proof = cb
            .prove(
                &[com0, com1, com2, com3, com4, com5],
                &[rand0, rand1, rand2, rand3, rand4, rand5],
                &mut rng,
            )
            .unwrap();

        // Verify
        let pvk = prepare_verifying_key(&pk.vk());
        assert!(verify_proof(&pvk, &proof, &[]).unwrap());
    }

    // Tests that a simple store and load passes the transcript checker
    #[test]
    fn simple_mem() {
        transcript_tester(
            "\
        ; TinyRAM V=2.000 M=vn W=32 K=8
        add r0, r0, 10     ; let r0 = 10
        store.w 998, r0    ; Dummy store: r0 -> RAM[999]
        load.w r7, 999     ; Dummy load:  r7 <- RAM[999]
        answer r7
        ",
            vec![],
            vec![],
        );
    }

    // Tests that a RAM-free skip3 program passes the transcript checker
    #[test]
    fn skip3_nomem() {
        transcript_tester(
            "\
        ; TinyRAM V=2.000 M=vn W=32 K=8
        _loop: add  r0, r0, 1     ; incr i
               add  r2, r2, 1     ; incr mul3_ctr
               cmpe r0, 17        ; if i == 17:
               cjmp _end          ;     jump to end
               cmpe r2, 3         ; else if mul3_ctr == 3:
               cjmp _acc          ;     jump to acc
               jmp  _loop         ; else jump to beginning

         _acc: add r1, r1, r0     ; Accumulate i into acc
               xor r2, r2, r2     ; Clear mul3_ctr
               jmp _loop          ; Jump back to the loop

         _end: answer r1          ; Return acc
        ",
            vec![],
            vec![],
        );
    }

    // Tests that a RAM-heavy skip3 program passes the transcript checker
    #[test]
    fn skip3_withmem() {
        transcript_tester(
            "\
        ; TinyRAM V=2.000 M=vn W=32 K=8
        _loop: load.w r1, 600     ; acc <- RAM[600]
               load.w r0, 604     ; i <- RAM[604]
               add  r0, r0, 1     ; incr i
               add  r2, r2, 1     ; incr mul3_ctr
               cmpe r0, 17        ; if i == 17:
               cjmp _end          ;     jump to end
               cmpe r2, 3         ; else if mul3_ctr == 3:
               cjmp _acc          ;     jump to acc
                                  ; else
               store.w 604, r0    ;     i -> RAM[604]
               jmp  _loop         ;     jump to beginning

         _acc: add r1, r1, r0     ; Accumulate i into acc
               xor r2, r2, r2     ; Clear mul3_ctr
               store.w 600, r1    ; acc -> RAM[600]
               store.w 604, r0    ; i -> RAM[604]
               jmp _loop          ; Jump back to the loop

         _end: answer r1          ; Return acc
        ",
            vec![],
            vec![],
        );
    }

    // Tests a basic `read` workload
    #[test]
    fn sum_tape() {
        // Sum [1, n] from primary tape, and sum 100*[1, n] from auxiliary tape. Then output the
        // sum of those sums.

        let n = 1;
        let primary_tape = (1..=n)
            .map(W::from_u64)
            .collect::<Result<Vec<W>, _>>()
            .unwrap();
        let aux_tape = (1..=n)
            .map(|x| W::from_u64(100 * x))
            .collect::<Result<Vec<W>, _>>()
            .unwrap();

        transcript_tester(
            "\
        ; TinyRAM V=2.000 M=vn W=32 K=8
        _loop: read r0, 0     ; r0 <- primary tape
               read r1, 1     ; r1 <- aux tape
               cjmp _end      ; if read failed, jump to end
               add r2, r2, r0 ; else, r2 += r0 and r3 += r1
               add r3, r3, r1
               jmp _loop      ; goto beginning
         _end: add r4, r2, r3 ; at the end: return r2 + r3
               answer r4
        ",
            primary_tape,
            aux_tape,
        );
    }
}
