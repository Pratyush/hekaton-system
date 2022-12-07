use crate::{
    common::*,
    util::{arr_set, log2, uint8_to_fpvar},
    word::{DWordVar, WordVar},
};
use tinyram_emu::instructions::Opcode;

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
};
use ark_relations::r1cs::SynthesisError;

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

#[derive(Clone)]
struct CpuAnswer<W, F>
where
    W: WordVar<F>,
    F: PrimeField,
{
    is_set: Boolean<F>,
    val: W,
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

#[derive(Clone)]
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

/// A helper to `exec_checker`. This takes a native opcode and its zk parameters, and executes it
fn run_instr<W: WordVar<F>, F: PrimeField>(
    op: Opcode,
    cpu_state: &CpuState<W, F>,
    reg1: &FpVar<F>,
    reg2_val: &W,
    imm_or_reg_val: &W,
    incrd_pc: &W,
    pc_overflow: &Boolean<F>,
) -> Result<CpuState<W, F>, SynthesisError> {
    let CpuState {
        pc: _,
        flag,
        regs,
        answer,
    } = cpu_state;

    use Opcode::*;
    let new_state = match op {
        Add => {
            let (output_val, new_flag) = reg2_val.carrying_add(&imm_or_reg_val)?;
            let new_regs = arr_set(&regs, reg1, &output_val)?;

            // The PC is incremented (need to check overflow), and the flag and registers are new.
            CpuState {
                pc: incrd_pc.clone(),
                flag: new_flag,
                regs: new_regs,
                answer: answer.clone(),
            }
        }
        CmpE => {
            // Compare the two input values
            let new_flag = reg2_val.is_eq(&imm_or_reg_val)?;

            //  The PC is incremented (need to check overflow), and the flag is new
            pc_overflow.enforce_equal(&Boolean::FALSE)?;
            CpuState {
                pc: incrd_pc.clone(),
                flag: new_flag,
                regs: regs.clone(),
                answer: answer.clone(),
            }
        }
        Jmp => {
            // Set the new PC to be the imm-or-reg
            let new_pc = imm_or_reg_val.clone();

            CpuState {
                pc: new_pc,
                flag: flag.clone(),
                regs: regs.clone(),
                answer: answer.clone(),
            }
        }
        CJmp => {
            // Let pc' = imm_or_reg_val if flag is set. Otherwise, let pc' = pc + 1
            let new_pc = PcVar::conditionally_select(&flag, imm_or_reg_val, &incrd_pc)?;

            // Check that incrd pc, if used, didn't overflow
            let used_incrd_pc = flag.not();
            let relevant_pc_overflow = pc_overflow.and(&used_incrd_pc)?;
            relevant_pc_overflow.enforce_equal(&Boolean::FALSE)?;

            CpuState {
                pc: new_pc,
                flag: flag.clone(),
                regs: regs.clone(),
                answer: answer.clone(),
            }
        }
        Answer => CpuState {
            pc: incrd_pc.clone(),
            flag: flag.clone(),
            regs: regs.clone(),
            answer: CpuAnswer {
                is_set: Boolean::TRUE,
                val: imm_or_reg_val.clone(),
            },
        },
        _ => unimplemented!(),
    };

    Ok(new_state)
}

/// Runs a single CPU tick with the given program counter, instruction, registers, and word loaded
/// from memory (if `instr isn't a `lw`, then the word is ignored). Returns the updated program
/// counter, updated set of registers, and a description of what, if any, memory operation occured.
pub(crate) fn exec_checker<const NUM_REGS: usize, W: WordVar<F>, F: PrimeField>(
    cpu_state: &CpuState<W, F>,
    instr: &DWordVar<W, F>,
) -> Result<(CpuState<W, F>, ExecTickMemData<W, F>), SynthesisError> {
    // Prepare to run all the instructions. This will hold them all. At the end, we'll use the
    // opcode to select the output state we want to return.
    let mut all_output_states = vec![cpu_state.clone(); 32];
    // Similarly, create all the mem ops. By default, they are ExecTickMemDataKind::no_mem
    let mut all_mem_ops = vec![ExecTickMemData::default(); 32];

    // Unpack the state and decode the instruction
    let CpuState {
        pc,
        flag: _,
        regs,
        answer: _,
    } = cpu_state;
    let (opcode, reg1, reg2, imm_or_reg) = decode_instr::<NUM_REGS, _, _>(instr)?;

    // Create the default next program counter, which is the one that's incremented
    let (incrd_pc, pc_overflow) = pc.checked_increment()?;

    use tinyram_emu::instructions::Opcode::*;
    let opcodes = [Add, CmpE, Jmp, CJmp, Answer];

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
        let new_state = run_instr(
            opcode,
            cpu_state,
            &reg1_fp,
            &reg2_val,
            &imm_or_reg_val,
            &incrd_pc,
            &pc_overflow,
        )?;
        all_output_states[opcode as usize] = new_state;
    }

    // Out of all the computed output states and memory operations, pick the ones that correspond
    // to this instruction's opcode
    let out_state = CpuState::conditionally_select_power_of_two_vector(
        &opcode.to_bits_be()?,
        &all_output_states[..],
    )?;
    let out_mem_op = ExecTickMemData::conditionally_select_power_of_two_vector(
        &opcode.to_bits_be()?,
        &all_mem_ops[..],
    )?;

    Ok((out_state, out_mem_op))
}

#[cfg(test)]
mod test {
    use super::*;

    use tinyram_emu::{
        instructions::Instr,
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

                // Encode the instruction to bytes
                let mut encoded_instr = [0u8; W::INSTR_BYTELEN];
                instr.to_bytes::<NUM_REGS>(&mut encoded_instr);

                // Split the encoded instruction bytes into two. This is the encoded first and
                // second word
                let (word0, word1) = {
                    const WORD_BYTELEN: usize = W::BITLEN / 8;
                    let mut w0_buf = [0u8; WORD_BYTELEN];
                    let mut w1_buf = [0u8; WORD_BYTELEN];
                    w0_buf.copy_from_slice(&encoded_instr[..WORD_BYTELEN]);
                    w1_buf.copy_from_slice(&encoded_instr[WORD_BYTELEN..]);
                    (W::from_be_bytes(w0_buf), W::from_be_bytes(w1_buf))
                };

                // Witness those words and decode them in ZK
                let dword_var = {
                    let word0_var = WV::new_witness(ns!(cs, "word0"), || Ok(word0)).unwrap();
                    let word1_var = WV::new_witness(ns!(cs, "word1"), || Ok(word1)).unwrap();
                    DWordVar::new((word0_var, word1_var))
                };
                let (opcode_var, reg1_var, reg2_var, imm_or_reg_var) =
                    decode_instr::<NUM_REGS, _, _>(&dword_var).unwrap();

                // Now decode normally
                let instr_as_u128 = {
                    let mut buf = [0u8; 16];
                    buf[16 - encoded_instr.len()..16].copy_from_slice(&encoded_instr);
                    u128::from_be_bytes(buf)
                };
                let (opcode, reg1, reg2, imm_or_reg) =
                    Instr::<W>::decode::<NUM_REGS>(instr_as_u128);

                // Compare the decodings
                assert_eq!(opcode_var.value().unwrap(), opcode as u8);
                assert_eq!(reg1_var.0.value().unwrap(), reg1.0);
                assert_eq!(reg2_var.0.value().unwrap(), reg2.0);
                assert_eq!(imm_or_reg_var.val.value().unwrap(), imm_or_reg.raw());
            }
        }
    }
}
