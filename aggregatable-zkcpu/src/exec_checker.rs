use crate::{
    common::*,
    transcript_checker::TranscriptEntryVar,
    util::{arr_set, log2, uint8_to_fpvar},
    word::{DWordVar, WordVar},
};
use tinyram_emu::{instructions::Opcode, word::Word, TinyRamArch};

use core::cmp::Ordering;
use std::cmp::min;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    bits::ToBitsGadget,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

/// An `ExecTickMemData` can be a LOAD (=0), a STORE (=1), or no-mem (=2)
#[derive(Clone)]
pub(crate) struct ExecTickMemDataKind<F: PrimeField>(FpVar<F>);

impl<F: PrimeField> ExecTickMemDataKind<F> {
    /// Checks that this `ExecTickMemDataKind` is 0, 1, or 2
    pub(crate) fn enforce_well_formed(&self) -> Result<(), SynthesisError> {
        let x = ExecTickMemDataKind::load()
            * (&self.0 - ExecTickMemDataKind::store())
            * (&self.0 - ExecTickMemDataKind::no_mem());
        x.enforce_equal(&FpVar::zero())
    }

    pub(crate) fn load() -> FpVar<F> {
        FpVar::zero()
    }

    pub(crate) fn store() -> FpVar<F> {
        FpVar::one()
    }

    pub(crate) fn no_mem() -> FpVar<F> {
        FpVar::constant(F::from(2u8))
    }

    pub(crate) fn is_no_mem(&self) -> Result<Boolean<F>, SynthesisError> {
        self.0.is_eq(&ExecTickMemDataKind::no_mem())
    }

    pub(crate) fn is_store(&self) -> Result<Boolean<F>, SynthesisError> {
        self.0.is_eq(&ExecTickMemDataKind::store())
    }
}

/// Represents the decoded instruction and register information used to LOAD or STORE in a small
/// tick. `Load` doesn't carry the thing loaded because that has to come from outside the CPU, from
/// the memory.
#[derive(Clone)]
pub(crate) struct ExecTickMemData<W: WordVar<F>, F: PrimeField> {
    /// The kind of data this is. A LOAD, a STORE, or a no-op
    pub(crate) kind: ExecTickMemDataKind<F>,
    /// The RAM index loaded from or stored into. This is not checked when kind == no-op
    pub(crate) idx: RamIdxVar<W>,
    /// The value stored into RAM. This is not checked when kind == no-op or LOAD
    pub(crate) stored_word: W,
}

impl<W: WordVar<F>, F: PrimeField> Default for ExecTickMemData<W, F> {
    fn default() -> Self {
        ExecTickMemData {
            kind: ExecTickMemDataKind(ExecTickMemDataKind::no_mem()),
            idx: RamIdxVar::<W>::zero(),
            stored_word: W::zero(),
        }
    }
}

impl<W: WordVar<F>, F: PrimeField> CondSelectGadget<F> for ExecTickMemData<W, F> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let kind = ExecTickMemDataKind(FpVar::conditionally_select(
            cond,
            &true_value.kind.0,
            &false_value.kind.0,
        )?);
        let idx = RamIdxVar::conditionally_select(cond, &true_value.idx, &false_value.idx)?;
        let stored_word = RamIdxVar::conditionally_select(
            cond,
            &true_value.stored_word,
            &false_value.stored_word,
        )?;

        Ok(ExecTickMemData {
            kind,
            idx,
            stored_word,
        })
    }
}

/// Decodes an encoded instruction into an opcode, 2 registers, and an immediate-or-register. The
/// registers (including the imm-or-reg if applicable) are guaranteed to be less than `NUM_REGS`.
fn decode_instr<const NUM_REGS: usize, W: WordVar<F>, F: PrimeField>(
    encoded_instr: &DWordVar<W, F>,
) -> Result<
    (
        OpcodeVar<F>,
        RegIdxVar<F>,
        RegIdxVar<F>,
        ImmOrRegisterVar<W, F>,
    ),
    SynthesisError,
> {
    let num_regs = FpVar::constant(F::from(NUM_REGS as u64));
    let regidx_bitlen: usize = log2(NUM_REGS);
    let instr_bits: Vec<Boolean<F>> = encoded_instr.as_le_bits();

    let mut cur_bit_idx: usize = 0;

    // Structure of an instruction is
    // 000...0  is_imm  reg1  reg2  imm_or_reg  opcode
    // <-- MSB                                 LSB -->

    // Extract all the components

    let opcode: OpcodeVar<F> = OpcodeVar::<F>::from_bits_le(
        &instr_bits[cur_bit_idx..cur_bit_idx + OpcodeVar::<F>::BITLEN],
    );
    cur_bit_idx += OpcodeVar::<F>::BITLEN;

    let imm_or_reg_bits = &instr_bits[cur_bit_idx..cur_bit_idx + W::BITLEN];
    cur_bit_idx += W::BITLEN;

    let reg2: RegIdxVar<F> =
        RegIdxVar::<F>::from_bits_le(&instr_bits[cur_bit_idx..cur_bit_idx + regidx_bitlen]);
    cur_bit_idx += regidx_bitlen;

    let reg1: RegIdxVar<F> =
        RegIdxVar::<F>::from_bits_le(&instr_bits[cur_bit_idx..cur_bit_idx + regidx_bitlen]);
    cur_bit_idx += regidx_bitlen;

    let is_imm: Boolean<F> = instr_bits[cur_bit_idx].clone();

    // Make the imm-or-reg from the component bits and type flag
    let imm_or_reg: ImmOrRegisterVar<W, F> = ImmOrRegisterVar::<W, F> {
        is_imm,
        val: W::from_le_bits(imm_or_reg_bits),
    };

    // Check that the registers are within range
    reg1.to_fpvar()?
        .enforce_cmp(&num_regs, Ordering::Less, false)?;
    reg2.to_fpvar()?
        .enforce_cmp(&num_regs, Ordering::Less, false)?;

    return Ok((opcode, reg1, reg2, imm_or_reg));
}

#[derive(Clone, Debug)]
struct CpuAnswer<W, F>
where
    W: WordVar<F>,
    F: PrimeField,
{
    is_set: Boolean<F>,
    val: W,
}

impl<W: WordVar<F>, F: PrimeField> Default for CpuAnswer<W, F> {
    fn default() -> Self {
        CpuAnswer {
            is_set: Boolean::FALSE,
            val: W::zero(),
        }
    }
}

impl<W: WordVar<F>, F: PrimeField> CondSelectGadget<F> for CpuAnswer<W, F> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let is_set = Boolean::conditionally_select(cond, &true_value.is_set, &false_value.is_set)?;
        let val = W::conditionally_select(cond, &true_value.val, &false_value.val)?;

        Ok(CpuAnswer { is_set, val })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CpuState<W, F>
where
    W: WordVar<F>,
    F: PrimeField,
{
    pc: PcVar<W>,
    flag: Boolean<F>,
    regs: RegistersVar<W>,
    answer: CpuAnswer<W, F>,
}

impl<W: WordVar<F>, F: PrimeField> CpuState<W, F> {
    fn default<const NUM_REGS: usize>() -> Self {
        CpuState {
            pc: W::zero(),
            flag: Boolean::FALSE,
            regs: vec![W::zero(); NUM_REGS],
            answer: CpuAnswer::default(),
        }
    }
}

impl<W: WordVar<F>, F: PrimeField> CondSelectGadget<F> for CpuState<W, F> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let pc = PcVar::conditionally_select(cond, &true_value.pc, &false_value.pc)?;
        let flag = PcVar::conditionally_select(cond, &true_value.flag, &false_value.flag)?;
        let regs = true_value
            .regs
            .iter()
            .zip(false_value.regs.iter())
            .map(|(t, f)| PcVar::conditionally_select(cond, t, f))
            .collect::<Result<RegistersVar<_>, _>>()?;
        let answer = PcVar::conditionally_select(cond, &true_value.answer, &false_value.answer)?;

        Ok(CpuState {
            pc,
            flag,
            regs,
            answer,
        })
    }
}

/// A helper to `exec_checker`. This takes a native opcode and its zk parameters, executes it, and
/// returns `(new_state, err)`. `err` is set if the contents of `mem_op` do not match the
/// instruction.
fn run_instr<W: WordVar<F>, F: PrimeField>(
    op: Opcode,
    cpu_state: &CpuState<W, F>,
    mem_op: &TranscriptEntryVar<W, F>,
    reg1: &FpVar<F>,
    reg2_val: &W,
    imm_or_reg_val: &W,
    incrd_pc: &W,
    pc_overflow: &Boolean<F>,
) -> Result<(CpuState<W, F>, Boolean<F>), SynthesisError> {
    let CpuState {
        pc: _,
        flag,
        regs,
        answer,
    } = cpu_state;

    use Opcode::*;
    match op {
        Add => {
            let (output_val, new_flag) = reg2_val.carrying_add(&imm_or_reg_val)?;
            let new_regs = arr_set(&regs, reg1, &output_val)?;

            // The PC is incremented (need to check overflow), and the flag and registers are new.
            let state = CpuState {
                pc: incrd_pc.clone(),
                flag: new_flag,
                regs: new_regs,
                answer: answer.clone(),
            };
            // add is not a memory operation. This MUST be padding.
            let err = mem_op.is_padding.not();

            Ok((state, err))
        }
        Xor => {
            let output_val = reg2_val.xor(&imm_or_reg_val)?;
            let new_regs = arr_set(&regs, reg1, &output_val)?;

            // The PC is incremented (need to check overflow), and the registers are new.
            let state = CpuState {
                pc: incrd_pc.clone(),
                flag: flag.clone(),
                regs: new_regs,
                answer: answer.clone(),
            };
            // xor is not a memory operation. This MUST be padding.
            let err = mem_op.is_padding.not();

            Ok((state, err))
        }
        CmpE => {
            // Compare the two input values
            let new_flag = reg2_val.is_eq(&imm_or_reg_val)?;

            //  The PC is incremented (need to check overflow), and the flag is new
            pc_overflow.enforce_equal(&Boolean::FALSE)?;
            let state = CpuState {
                pc: incrd_pc.clone(),
                flag: new_flag,
                regs: regs.clone(),
                answer: answer.clone(),
            };
            // cmpe is not a memory operation. This MUST be padding.
            let err = mem_op.is_padding.not();

            Ok((state, err))
        }
        Jmp => {
            // Set the new PC to be the imm-or-reg
            let new_pc = imm_or_reg_val.clone();

            let state = CpuState {
                pc: new_pc,
                flag: flag.clone(),
                regs: regs.clone(),
                answer: answer.clone(),
            };
            // cmpe is not a memory operation. This MUST be padding.
            let err = mem_op.is_padding.not();

            Ok((state, err))
        }
        CJmp => {
            // Let pc' = imm_or_reg_val if flag is set. Otherwise, let pc' = pc + 1
            let new_pc = PcVar::conditionally_select(&flag, imm_or_reg_val, &incrd_pc)?;

            // Check that incrd pc, if used, didn't overflow
            let used_incrd_pc = flag.not();
            let relevant_pc_overflow = pc_overflow.and(&used_incrd_pc)?;
            relevant_pc_overflow.enforce_equal(&Boolean::FALSE)?;

            let state = CpuState {
                pc: new_pc,
                flag: flag.clone(),
                regs: regs.clone(),
                answer: answer.clone(),
            };
            // cjmp is not a memory operation. This MUST be padding.
            let err = mem_op.is_padding.not();

            Ok((state, err))
        }
        Answer => {
            let state = CpuState {
                pc: incrd_pc.clone(),
                flag: flag.clone(),
                regs: regs.clone(),
                answer: CpuAnswer {
                    is_set: Boolean::TRUE,
                    val: imm_or_reg_val.clone(),
                },
            };
            // answer is not a memory operation. This MUST be padding.
            let err = mem_op.is_padding.not();

            Ok((state, err))
        }
        _ => todo!(),
    }
}

/// Runs a single CPU tick with the given program counter, instruction, registers, and word loaded
/// from memory (if `instr isn't a `lw`, then the word is ignored). Returns the updated program
/// counter, updated set of registers, and a description of what, if any, memory operation occured.
pub(crate) fn exec_checker<const NUM_REGS: usize, W: WordVar<F>, F: PrimeField>(
    arch: TinyRamArch,
    mem_op: &TranscriptEntryVar<W, F>,
    cpu_state: &CpuState<W, F>,
    instr: &DWordVar<W, F>,
) -> Result<CpuState<W, F>, SynthesisError> {
    // Prepare to run all the instructions. This will hold new_state for all possible instructions,
    // and all_errors will hold the corresponding errors flags. At the end, we'll use the opcode to
    // select the output state we want to return, and assert that err == false.
    let mut all_output_states = vec![cpu_state.clone(); 32];
    // TODO: Figure out whether invalid instructions are necessarily errors
    let mut all_errors = vec![Boolean::TRUE; 32];

    // Unpack the state and decode the instruction
    let CpuState {
        pc,
        flag: _,
        regs,
        answer: _,
    } = cpu_state;
    let (opcode, reg1, reg2, imm_or_reg) = decode_instr::<NUM_REGS, _, _>(instr)?;

    // Create the default next program counter, which is the one that's incremented
    let (incrd_pc, pc_overflow) = match arch {
        TinyRamArch::Harvard => pc.checked_increment()?,
        TinyRamArch::VonNeumann => {
            // Increment PC by 1 dword
            let dword_bytelen = 2 * (W::BITLEN / 8) as u64;
            pc.carrying_add(&W::constant(
                W::NativeWord::from_u64(dword_bytelen).unwrap(),
            ))?
        }
    };

    // Enumerate all the opcodes we have to eval
    use tinyram_emu::instructions::Opcode::*;
    let opcodes = [Add, Xor, CmpE, Jmp, CJmp, Answer];

    // Read the registers
    // reg1 (if used) is always the output register. So we don't need to read that
    // reg2 (if used) is always a secondary input
    let reg2_val = reg2.value::<NUM_REGS, _>(&regs)?;
    // imm_or_reg is always present
    let imm_or_reg_val = {
        let reg_val = W::conditionally_select_power_of_two_vector(
            &imm_or_reg.as_selector::<NUM_REGS>()?,
            regs,
        )?;
        let imm_val = imm_or_reg.val.clone();

        W::conditionally_select(&imm_or_reg.is_imm, &imm_val, &reg_val)?
    };
    let reg1_fp = reg1.to_fpvar()?;

    // Go through every opcode, do the operation, and save the results in all_output_states and
    // all_mem_ops
    for opcode in opcodes {
        let (new_state, err) = run_instr(
            opcode,
            cpu_state,
            mem_op,
            &reg1_fp,
            &reg2_val,
            &imm_or_reg_val,
            &incrd_pc,
            &pc_overflow,
        )?;
        all_output_states[opcode as usize] = new_state;
        all_errors[opcode as usize] = err;
    }

    // Decode the opcode and use it to index into the vec of next CPU states
    let opcode_bits = opcode.to_bits_be()?;

    // Out of all the computed output states and memory operations, pick the ones that correspond
    // to this instruction's opcode
    let out_state =
        CpuState::conditionally_select_power_of_two_vector(&opcode_bits, &all_output_states[..])?;
    // Check that this operation didn't error
    let err = Boolean::conditionally_select_power_of_two_vector(&opcode_bits, &all_errors[..])?;
    err.enforce_equal(&Boolean::FALSE)?;

    Ok(out_state)
}

#[cfg(test)]
mod test {
    use super::*;

    use tinyram_emu::{
        instructions::Instr,
        interpreter::TranscriptEntry,
        register::{ImmOrRegister, RegIdx},
        word::Word,
    };

    use ark_bls12_381::Fr;
    use ark_r1cs_std::{alloc::AllocVar, uint32::UInt32, R1CSVar};
    use ark_relations::{ns, r1cs::ConstraintSystem};
    use rand::Rng;

    const NUM_REGS: usize = 16;
    type F = Fr;
    type WV = UInt32<F>;
    type W = <WV as WordVar<F>>::NativeWord;

    fn gen_regidx<R: Rng>(mut rng: R) -> RegIdx {
        RegIdx(rng.gen_range(0..NUM_REGS) as u8)
    }

    fn gen_imm_or_regidx<R: Rng>(mut rng: R) -> ImmOrRegister<W> {
        let is_imm = rng.gen();
        if is_imm {
            ImmOrRegister::Imm(rng.gen_range(0..=W::MAX))
        } else {
            ImmOrRegister::Register(gen_regidx(&mut rng))
        }
    }

    // Tests that ZK decoding is compatible with the native decoder
    #[test]
    fn test_decode() {
        let mut rng = rand::thread_rng();

        // Test 100 test cases of each kind of instruction
        for _ in 0..100 {
            // Make random test cases
            let test_cases: &[Instr<W>] = &[
                Instr::Answer {
                    in1: gen_imm_or_regidx(&mut rng),
                },
                Instr::CmpE {
                    in1: gen_regidx(&mut rng),
                    in2: gen_imm_or_regidx(&mut rng),
                },
                Instr::Or {
                    in1: gen_regidx(&mut rng),
                    in2: gen_imm_or_regidx(&mut rng),
                    out: gen_regidx(&mut rng),
                },
                Instr::Add {
                    in1: gen_regidx(&mut rng),
                    in2: gen_imm_or_regidx(&mut rng),
                    out: gen_regidx(&mut rng),
                },
                Instr::Not {
                    in1: gen_imm_or_regidx(&mut rng),
                    out: gen_regidx(&mut rng),
                },
                Instr::CJmp {
                    in1: gen_imm_or_regidx(&mut rng),
                },
                Instr::LoadW {
                    in1: gen_imm_or_regidx(&mut rng),
                    out: gen_regidx(&mut rng),
                },
                Instr::StoreW {
                    in1: gen_regidx(&mut rng),
                    out: gen_imm_or_regidx(&mut rng),
                },
            ];

            // Test equality after an encode-decode round trip
            for instr in test_cases {
                let cs = ConstraintSystem::new_ref();

                // Encode the instruction and witness it
                let encoded_instr = instr.to_dword::<NUM_REGS>();
                let encoded_instr_var =
                    DWordVar::<WV, _>::new_witness(ns!(cs, "dword"), || Ok(encoded_instr)).unwrap();

                let (opcode_var, reg1_var, reg2_var, imm_or_reg_var) =
                    decode_instr::<NUM_REGS, _, _>(&encoded_instr_var).unwrap();

                // Now decode normally
                let (opcode, reg1, reg2, imm_or_reg) =
                    Instr::<W>::decode::<NUM_REGS>(instr.to_u128::<NUM_REGS>());

                // Compare the decodings
                assert_eq!(opcode_var.value().unwrap(), opcode as u8);
                assert_eq!(reg1_var.0.value().unwrap(), reg1.0);
                assert_eq!(reg2_var.0.value().unwrap(), reg2.0);
                assert_eq!(imm_or_reg_var.val.value().unwrap(), imm_or_reg.raw());

                // Make sure nothing errored
                assert!(cs.is_satisfied().unwrap());
            }
        }
    }

    // The skip3 program
    pub(crate) const SKIP3_CODE: &str = "\
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
        ";

    #[test]
    fn test_skip3() {
        let cs = ConstraintSystem::new_ref();

        let assembly = tinyram_emu::parser::assemble(SKIP3_CODE);
        let arch = TinyRamArch::VonNeumann;

        let (output, transcript) = tinyram_emu::interpreter::run_program::<W, NUM_REGS>(
            TinyRamArch::VonNeumann,
            &assembly,
        );
        println!("Transcript len == {}", transcript.len());

        let non_mem_op = TranscriptEntryVar::default();

        // Run the CPU
        let mut cpu_state = CpuState::default::<NUM_REGS>();
        for (i, transcript_entry) in transcript.into_iter().enumerate() {
            let TranscriptEntry { instr, .. } = transcript_entry;
            // Encode the instruction and witness it
            let encoded_instr = instr.to_dword::<NUM_REGS>();
            let encoded_instr_var =
                DWordVar::<WV, _>::new_witness(ns!(cs, "dword"), || Ok(encoded_instr)).unwrap();

            println!("iteration {i}. Instr == {:?}", instr);
            cpu_state =
                exec_checker::<NUM_REGS, _, _>(arch, &non_mem_op, &cpu_state, &encoded_instr_var)
                    .unwrap();
        }

        // Make sure nothing errored
        assert!(cs.is_satisfied().unwrap());

        // Check the output is set and correct
        assert!(cpu_state.answer.is_set.value().unwrap());
        assert_eq!(output, cpu_state.answer.val.value().unwrap());
    }
}
