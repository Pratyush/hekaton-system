use crate::{
    common::*,
    util::{arr_set, uint8_to_fpvar},
    word::WordVar,
};

use core::cmp::Ordering;

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
            idx: RamIdxVar::default(),
            stored_word: RamIdxVar::default(),
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

fn decode_instr<F: PrimeField, W: WordVar<F>>(
    encoded_instr: &W,
) -> (
    OpcodeVar<F>,
    RegIdxVar<F>,
    RegIdxVar<F>,
    ImmOrRegisterVar<W, F>,
) {
    unimplemented!()
}

#[derive(Clone)]
struct Answer<W, F>
where
    W: WordVar<F>,
    F: PrimeField,
{
    is_set: Boolean<F>,
    val: W,
}

impl<W: WordVar<F>, F: PrimeField> CondSelectGadget<F> for Answer<W, F> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let is_set = Boolean::conditionally_select(cond, &true_value.is_set, &false_value.is_set)?;
        let val = W::conditionally_select(cond, &true_value.val, &false_value.val)?;

        Ok(Answer { is_set, val })
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
    answer: Answer<W, F>,
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

/// Runs a single CPU tick with the given program counter, instruction, registers, and word loaded
/// from memory (if `instr isn't a `lw`, then the word is ignored). Returns the updated program
/// counter, updated set of registers, and a description of what, if any, memory operation occured.
pub(crate) fn exec_checker<W: WordVar<F>, F: PrimeField>(
    cpu_state: &CpuState<W, F>,
    instr: &W,
    opt_loaded_val: &W,
) -> Result<(CpuState<W, F>, ExecTickMemData<W, F>), SynthesisError> {
    // Prepare to run all the instructions. This will hold them all. At the end, we'll use the
    // opcode to select the output state we want to return.
    let mut all_output_states = vec![cpu_state.clone(); 32];
    // Similarly, create all the mem ops. By default, they are ExecTickMemDataKind::no_mem
    let mut all_mem_ops = vec![ExecTickMemData::default(); 32];

    // Unpack the state and decode the instruction
    let CpuState {
        pc,
        flag,
        regs,
        answer,
    } = cpu_state;
    let (opcode, reg1, reg2, imm_or_reg) = decode_instr(instr);

    // Create the default next program counter, which is the one that's incremented
    let (incrd_pc, pc_overflow) = pc.checked_increment();

    use tinyram_emu::instructions::Opcode::*;
    let opcodes = [Add, CmpE, CJmp, Answer];

    // Read the registers
    // reg1 (if used) is always the output register. So we don't need to read that
    // reg2 (if used) is always a secondary input
    let reg2_val = W::conditionally_select_power_of_two_vector(&reg2.to_bits_be()?, regs)?;
    // imm_or_reg is always present
    let imm_or_reg_val = {
        // We read imm_or_reg as both a register and an immediate, and then select the correct one
        let reg_val =
            W::conditionally_select_power_of_two_vector(&imm_or_reg.val.to_bits_be()?, regs)?;
        let imm_val = imm_or_reg.val.clone();

        W::conditionally_select(&imm_or_reg.is_imm, &imm_val, &reg_val)?
    };

    // Go through every opcode, do the operation, and save the results in all_output_states and
    // all_mem_ops
    for opcode in opcodes {
        match opcode {
            Add => {
                let (output_val, new_flag) = reg2_val.carrying_add(imm_or_reg_val)?;
                let new_regs = arr_set(&regs, &uint8_to_fpvar(&reg1)?, &output_val)?;

                // Save the resulting CPU state. The PC is incremented (need to check overflow),
                // and the flag and registers are new.
                pc_overflow.enforce_equal(&Boolean::FALSE)?;
                all_output_states[Add as usize] = CpuState {
                    pc: incrd_pc.clone(),
                    flag: new_flag,
                    regs: new_regs,
                    answer: answer.clone(),
                };
            }
            _ => unimplemented!(),
        }
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
