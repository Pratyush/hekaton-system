use crate::{
    common::*,
    transcript_checker::ProcessedTranscriptEntryVar,
    util::{arr_set, log2, uint32_to_fpvar},
    word::{DWordVar, WordVar},
};
use tinyram_emu::{
    instructions::Opcode, interpreter::MemOpKind, program_state::CpuState, word::Word,
    ProgramMetadata, TinyRamArch,
};

use core::{borrow::Borrow, cmp::Ordering};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    uint32::UInt32,
};
use ark_relations::{
    ns,
    r1cs::{Namespace, SynthesisError},
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
pub(crate) struct ExecTickMemData<WV: WordVar<F>, F: PrimeField> {
    /// The kind of data this is. A LOAD, a STORE, or a no-op
    pub(crate) kind: ExecTickMemDataKind<F>,
    /// The RAM index loaded from or stored into. This is not checked when kind == no-op
    pub(crate) idx: RamIdxVar<WV>,
    /// The value stored into RAM. This is not checked when kind == no-op or LOAD
    pub(crate) stored_word: WV,
}

impl<WV: WordVar<F>, F: PrimeField> Default for ExecTickMemData<WV, F> {
    fn default() -> Self {
        ExecTickMemData {
            kind: ExecTickMemDataKind(ExecTickMemDataKind::no_mem()),
            idx: RamIdxVar::<WV>::zero(),
            stored_word: WV::zero(),
        }
    }
}

impl<WV: WordVar<F>, F: PrimeField> CondSelectGadget<F> for ExecTickMemData<WV, F> {
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
fn decode_instr<const NUM_REGS: usize, WV: WordVar<F>, F: PrimeField>(
    encoded_instr: &DWordVar<WV, F>,
) -> Result<
    (
        OpcodeVar<F>,
        RegIdxVar<F>,
        RegIdxVar<F>,
        ImmOrRegisterVar<WV, F>,
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

    let imm_or_reg_bits = &instr_bits[cur_bit_idx..cur_bit_idx + WV::BITLEN];
    cur_bit_idx += WV::BITLEN;

    let reg2: RegIdxVar<F> =
        RegIdxVar::<F>::from_bits_le(&instr_bits[cur_bit_idx..cur_bit_idx + regidx_bitlen]);
    cur_bit_idx += regidx_bitlen;

    let reg1: RegIdxVar<F> =
        RegIdxVar::<F>::from_bits_le(&instr_bits[cur_bit_idx..cur_bit_idx + regidx_bitlen]);
    cur_bit_idx += regidx_bitlen;

    let is_imm: Boolean<F> = instr_bits[cur_bit_idx].clone();

    // Make the imm-or-reg from the component bits and type flag
    let imm_or_reg: ImmOrRegisterVar<WV, F> = ImmOrRegisterVar::<WV, F> {
        is_imm,
        val: WV::from_le_bits(imm_or_reg_bits),
    };

    // Check that the registers are within range
    reg1.to_fpvar()?
        .enforce_cmp(&num_regs, Ordering::Less, false)?;
    reg2.to_fpvar()?
        .enforce_cmp(&num_regs, Ordering::Less, false)?;

    return Ok((opcode, reg1, reg2, imm_or_reg));
}

#[derive(Clone, Debug)]
pub(crate) struct CpuAnswerVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    pub(crate) is_set: Boolean<F>,
    pub(crate) val: WV,
}

impl<WV: WordVar<F>, F: PrimeField> Default for CpuAnswerVar<WV, F> {
    fn default() -> Self {
        CpuAnswerVar {
            is_set: Boolean::FALSE,
            val: WV::zero(),
        }
    }
}

impl<WV, F> EqGadget<F> for CpuAnswerVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        self.is_set
            .is_eq(&other.is_set)?
            .and(&self.val.is_eq(&other.val)?)
    }
}

impl<WV: WordVar<F>, F: PrimeField> CondSelectGadget<F> for CpuAnswerVar<WV, F> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let is_set = Boolean::conditionally_select(cond, &true_value.is_set, &false_value.is_set)?;
        let val = WV::conditionally_select(cond, &true_value.val, &false_value.val)?;

        Ok(CpuAnswerVar { is_set, val })
    }
}

impl<WV: WordVar<F>, F: PrimeField> AllocVar<Option<WV::NativeWord>, F> for CpuAnswerVar<WV, F> {
    fn new_variable<T: Borrow<Option<WV::NativeWord>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|opt_word| {
            let opt_word = opt_word.borrow();
            Boolean::new_variable(ns!(cs, "is_set"), || Ok(opt_word.is_some()), mode).and_then(
                |is_set| {
                    WV::new_variable(
                        ns!(cs, "word"),
                        || Ok(opt_word.unwrap_or(WV::NativeWord::default())),
                        mode,
                    )
                    .and_then(|val| Ok(CpuAnswerVar { is_set, val }))
                },
            )
        })
    }
}

// TODO: Make this and RegistersVar take NUM_REGS: usize
#[derive(Clone, Debug)]
pub struct CpuStateVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    pub(crate) pc: PcVar<WV>,
    pub(crate) flag: Boolean<F>,
    pub(crate) regs: RegistersVar<WV>,
    pub(crate) answer: CpuAnswerVar<WV, F>,
    pub(crate) primary_tape_pos: UInt32<F>,
    pub(crate) aux_tape_pos: UInt32<F>,
}

impl<WV: WordVar<F>, F: PrimeField> CpuStateVar<WV, F> {
    pub(crate) fn default<const NUM_REGS: usize>() -> Self {
        CpuStateVar {
            pc: WV::zero(),
            flag: Boolean::FALSE,
            regs: vec![WV::zero(); NUM_REGS],
            answer: CpuAnswerVar::default(),
            primary_tape_pos: UInt32::zero(),
            aux_tape_pos: UInt32::zero(),
        }
    }
}

impl<WV, F> EqGadget<F> for CpuStateVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        self.pc
            .is_eq(&other.pc)?
            .and(&self.flag.is_eq(&other.flag)?)?
            .and(&self.regs.is_eq(&other.regs)?)?
            .and(&self.answer.is_eq(&other.answer)?)
    }
}

impl<WV: WordVar<F>, F: PrimeField> CondSelectGadget<F> for CpuStateVar<WV, F> {
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
        let primary_tape_pos = UInt32::conditionally_select(
            cond,
            &true_value.primary_tape_pos,
            &false_value.primary_tape_pos,
        )?;
        let aux_tape_pos = UInt32::conditionally_select(
            cond,
            &true_value.aux_tape_pos,
            &false_value.aux_tape_pos,
        )?;

        Ok(CpuStateVar {
            pc,
            flag,
            regs,
            answer,
            primary_tape_pos,
            aux_tape_pos,
        })
    }
}

impl<const NUM_REGS: usize, WV, F> AllocVar<CpuState<NUM_REGS, WV::NativeWord>, F>
    for CpuStateVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn new_variable<T: Borrow<CpuState<NUM_REGS, WV::NativeWord>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let f_res = f();

        let state: Result<&CpuState<NUM_REGS, WV::NativeWord>, _> =
            f_res.as_ref().map(|s| s.borrow()).map_err(|e| e.clone());

        let pc = PcVar::new_variable(ns!(cs, "pc"), || state.map(|s| s.program_counter), mode)?;
        let flag =
            Boolean::new_variable(ns!(cs, "flag"), || state.map(|s| s.condition_flag), mode)?;
        let regs =
            RegistersVar::new_variable(ns!(cs, "regs"), || state.map(|s| s.registers), mode)?;
        let answer =
            CpuAnswerVar::new_variable(ns!(cs, "answer"), || state.map(|s| s.answer), mode)?;
        let primary_tape_pos = UInt32::new_variable(
            ns!(cs, "primary head"),
            || state.map(|s| s.primary_input.pos),
            mode,
        )?;
        let aux_tape_pos =
            UInt32::new_variable(ns!(cs, "aux head"), || state.map(|s| s.aux_input.pos), mode)?;

        Ok(CpuStateVar {
            pc,
            flag,
            regs,
            answer,
            primary_tape_pos,
            aux_tape_pos,
        })
    }
}

/// A helper to `exec_checker`. This takes a native opcode and its zk parameters, executes it, and
/// returns `(new_state, err)`. `err` is set if the contents of `mem_op` do not match the
/// instruction.
fn run_instr<WV: WordVar<F>, F: PrimeField>(
    meta: ProgramMetadata,
    op: Opcode,
    cpu_state: &CpuStateVar<WV, F>,
    mem_op: &ProcessedTranscriptEntryVar<WV, F>,
    reg1: &FpVar<F>,
    reg2_val: &WV,
    imm_or_reg_val: &WV,
    incrd_pc: &WV,
    pc_overflow: &Boolean<F>,
) -> Result<(CpuStateVar<WV, F>, Boolean<F>), SynthesisError> {
    let CpuStateVar {
        pc: _,
        flag,
        regs,
        answer,
        primary_tape_pos,
        aux_tape_pos,
    } = cpu_state;

    use Opcode::*;
    match op {
        Add => {
            let (output_val, new_flag) = reg2_val.carrying_add(&imm_or_reg_val)?;
            let new_regs = arr_set(&regs, reg1, &output_val)?;

            // The PC is incremented (need to check overflow), and the flag and registers are new.
            let mut err = pc_overflow.clone();
            let state = CpuStateVar {
                pc: incrd_pc.clone(),
                flag: new_flag,
                regs: new_regs,
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
            };
            // add is not a memory operation. This MUST be padding.
            err = err.or(&mem_op.is_padding.not())?;

            Ok((state, err))
        },
        Xor => {
            let output_val = reg2_val.xor(&imm_or_reg_val)?;
            let new_regs = arr_set(&regs, reg1, &output_val)?;

            // The PC is incremented (need to check overflow), and the registers are new.
            let mut err = pc_overflow.clone();
            let state = CpuStateVar {
                pc: incrd_pc.clone(),
                flag: flag.clone(),
                regs: new_regs,
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
            };
            // xor is not a memory operation. This MUST be padding.
            err = err.or(&mem_op.is_padding.not())?;

            Ok((state, err))
        },
        CmpE => {
            // Compare the two input values
            let new_flag = reg2_val.is_eq(&imm_or_reg_val)?;

            //  The PC is incremented (need to check overflow), and the flag is new
            let mut err = pc_overflow.clone();
            let state = CpuStateVar {
                pc: incrd_pc.clone(),
                flag: new_flag,
                regs: regs.clone(),
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
            };
            // cmpe is not a memory operation. This MUST be padding.
            err = err.or(&mem_op.is_padding.not())?;

            Ok((state, err))
        },
        Jmp => {
            // Set the new PC to be the imm-or-reg
            let new_pc = imm_or_reg_val.clone();

            let state = CpuStateVar {
                pc: new_pc,
                flag: flag.clone(),
                regs: regs.clone(),
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
            };
            // cmpe is not a memory operation. This MUST be padding.
            let err = mem_op.is_padding.not();

            Ok((state, err))
        },
        CJmp => {
            // Let pc' = imm_or_reg_val if flag is set. Otherwise, let pc' = pc + 1
            let new_pc = PcVar::conditionally_select(&flag, imm_or_reg_val, &incrd_pc)?;

            // Check that incrd pc, if used, didn't overflow
            let used_incrd_pc = flag.not();
            let relevant_pc_overflow = pc_overflow.and(&used_incrd_pc)?;
            let mut err = relevant_pc_overflow.clone();

            let state = CpuStateVar {
                pc: new_pc,
                flag: flag.clone(),
                regs: regs.clone(),
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
            };
            // cjmp is not a memory operation. This MUST be padding.
            err = err.or(&mem_op.is_padding.not())?;

            Ok((state, err))
        },
        Answer => {
            let state = CpuStateVar {
                pc: incrd_pc.clone(),
                flag: flag.clone(),
                regs: regs.clone(),
                answer: CpuAnswerVar {
                    is_set: Boolean::TRUE,
                    val: imm_or_reg_val.clone(),
                },
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
            };
            // answer is not a memory operation. This MUST be padding.
            let err = mem_op.is_padding.not();

            Ok((state, err))
        },
        LoadW => {
            // Get the correct word from the memory op, and save it in the register
            let (loaded_word, mut err) = mem_op.select_word(&imm_or_reg_val)?;
            let new_regs = arr_set(&regs, reg1, &loaded_word)?;

            // The PC is incremented (need to check overflow), and the registers are new.
            err = err.or(pc_overflow)?;
            let state = CpuStateVar {
                pc: incrd_pc.clone(),
                flag: flag.clone(),
                regs: new_regs,
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
            };
            // load.w is a memory operation. This MUST NOT be padding.
            err = err.or(&mem_op.is_padding)?;

            Ok((state, err))
        },
        StoreW => {
            // Storing doesn't change anything. We don't have to do anything here

            // The PC is incremented (need to check overflow)
            let mut err = pc_overflow.clone();
            let state = CpuStateVar {
                pc: incrd_pc.clone(),
                flag: flag.clone(),
                regs: regs.clone(),
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
            };
            // store.w is a memory operation. This MUST NOT be padding.
            err = err.or(&mem_op.is_padding)?;

            Ok((state, err))
        },
        Read => {
            // Get the correct word from the memory op, and save it in the register
            let read_word = mem_op.val_low_word();
            let new_regs = arr_set(&regs, reg1, &read_word)?;

            // Learn which tape is being read
            let is_primary = mem_op
                .op
                .is_eq(&FpVar::Constant(F::from(MemOpKind::ReadPrimary as u8)))?;
            let is_aux = mem_op
                .op
                .is_eq(&FpVar::Constant(F::from(MemOpKind::ReadAux as u8)))?;
            let is_invalid_tape = { is_primary.not().and(&is_aux.not())? };

            // Find out the current tape position and the maximum tape position. This is nonsense
            // if is_invalid_tape == true, but that's fine because in either case, the value set
            // will be 0 and the condition flag will be true.
            let cur_tape_pos =
                UInt32::conditionally_select(&is_primary, primary_tape_pos, aux_tape_pos)?;
            let cur_tape_pos_fp = { uint32_to_fpvar(&cur_tape_pos)? };
            let tape_len = {
                let primary_len = FpVar::constant(F::from(meta.primary_input_len));
                let aux_len = FpVar::constant(F::from(meta.aux_input_len));
                FpVar::conditionally_select(&is_primary, &primary_len, &aux_len)?
            };
            let is_out_of_bounds =
                cur_tape_pos_fp.is_cmp(&tape_len, core::cmp::Ordering::Greater, true)?;

            // Check that the read head is at the expected position
            let mut err = cur_tape_pos_fp.is_neq(&mem_op.location_fp)?;

            // Increment the tape position
            let new_tape_pos = UInt32::addmany(&[cur_tape_pos, UInt32::one()])?;
            let new_primary_tape_pos =
                UInt32::conditionally_select(&is_primary, &new_tape_pos, primary_tape_pos)?;
            let new_aux_tape_pos =
                UInt32::conditionally_select(&is_aux, &new_tape_pos, aux_tape_pos)?;

            // Now determine if the read triggers the condition flag. It triggers the condition
            // flag iff either the tape index is > 1 or the tape head has reached the end of the
            // tape.
            let new_flag = is_invalid_tape.or(&is_out_of_bounds)?;

            // Make sure that the val is 0 when the flag is set
            err = err.or(&new_flag.and(&read_word.is_neq(&WV::zero())?)?)?;

            // The PC is incremented (need to check overflow), the registers are new, and so is one
            // of the tape heads.
            err = err.or(pc_overflow)?;
            let state = CpuStateVar {
                pc: incrd_pc.clone(),
                flag: new_flag,
                regs: new_regs,
                answer: answer.clone(),
                primary_tape_pos: new_primary_tape_pos,
                aux_tape_pos: new_aux_tape_pos,
            };
            // read is a memory operation. This MUST NOT be padding.
            err = err.or(&mem_op.is_padding)?;

            Ok((state, err))
        },
        _ => todo!(),
    }
}

/// Runs a single CPU tick with the given program counter, instruction, registers, and (optional)
/// associated memory operation. Returns the updated CPU state.
pub(crate) fn exec_checker<const NUM_REGS: usize, WV: WordVar<F>, F: PrimeField>(
    meta: ProgramMetadata,
    mem_op: &ProcessedTranscriptEntryVar<WV, F>,
    cpu_state: &CpuStateVar<WV, F>,
    instr: &DWordVar<WV, F>,
) -> Result<CpuStateVar<WV, F>, SynthesisError> {
    // Prepare to run all the instructions. This will hold new_state for all possible instructions,
    // and all_errors will hold the corresponding errors flags. At the end, we'll use the opcode to
    // select the output state we want to return, and assert that err == false.
    let mut all_output_states = vec![cpu_state.clone(); 32];
    // TODO: Figure out whether invalid instructions are necessarily errors
    let mut all_errors = vec![Boolean::TRUE; 32];

    // Unpack the CPu state and make sure it hasn't already halted
    let CpuStateVar {
        pc, regs, answer, ..
    } = cpu_state;
    answer.is_set.enforce_equal(&Boolean::FALSE)?;

    // Decode the instruction
    let (opcode, reg1, reg2, imm_or_reg) = decode_instr::<NUM_REGS, _, _>(instr)?;

    // Create the default next program counter, which is the one that's incremented
    let (incrd_pc, pc_overflow) = match meta.arch {
        TinyRamArch::Harvard => pc.checked_increment()?,
        TinyRamArch::VonNeumann => {
            // Increment PC by 1 dword
            let dword_bytelen = 2 * (WV::BITLEN / 8) as u64;
            pc.carrying_add(&WV::constant(
                WV::NativeWord::from_u64(dword_bytelen).unwrap(),
            ))?
        },
    };

    // Enumerate all the opcodes we have to eval
    use tinyram_emu::instructions::Opcode::*;
    let supported_opcodes = [Add, Xor, CmpE, Jmp, CJmp, Answer, LoadW, StoreW, Read];
    // let supported_opcodes = [
    //    And, Or, Xor, Not, Add, Sub, MulL, UMulH, SMulH, UDiv, UMod, Shl, Shr, CmpE, CmpA, CmpAe,
    //    CmpG, CmpGe, Mov, CMov, Jmp, CJmp, CnJmp, StoreB, LoadB, StoreW, LoadW, Read, Answer,
    //];

    // Read the registers
    // reg1 (if used) is always the output register. So we don't need to read that
    // reg2 (if used) is always a secondary input
    let reg2_val = reg2.value::<NUM_REGS, _>(&regs)?;
    // imm_or_reg is always present
    let imm_or_reg_val = {
        let reg_val = WV::conditionally_select_power_of_two_vector(
            &imm_or_reg.as_selector::<NUM_REGS>()?,
            regs,
        )?;
        let imm_val = imm_or_reg.val.clone();

        WV::conditionally_select(&imm_or_reg.is_imm, &imm_val, &reg_val)?
    };
    let reg1_fp = reg1.to_fpvar()?;

    // Go through every opcode, do the operation, and save the results in all_output_states and
    // all_mem_ops
    for opcode in supported_opcodes {
        let (new_state, err) = run_instr(
            meta,
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
    let out_state = CpuStateVar::conditionally_select_power_of_two_vector(
        &opcode_bits,
        &all_output_states[..],
    )?;
    // Check that this operation didn't error
    let err = Boolean::conditionally_select_power_of_two_vector(&opcode_bits, &all_errors[..])?;
    err.enforce_equal(&Boolean::FALSE)?;

    Ok(out_state)
}

#[cfg(test)]
mod test {
    use super::*;

    use tinyram_emu::{instructions::Instr, interpreter::TranscriptEntry};

    use ark_bls12_381::Fr;
    use ark_r1cs_std::{alloc::AllocVar, uint32::UInt32, R1CSVar};
    use ark_relations::{ns, r1cs::ConstraintSystem};

    const NUM_REGS: usize = 16;
    type F = Fr;
    type WV = UInt32<F>;
    type W = <WV as WordVar<F>>::NativeWord;

    // Tests that instructions decode to the same thing under the native and ZK decoders
    #[test]
    fn decoding_equality() {
        let mut rng = rand::thread_rng();
        let cs = ConstraintSystem::new_ref();

        // Test 200 randomly generated instructions
        for _ in 0..200 {
            let instr = Instr::rand::<NUM_REGS>(&mut rng);

            // Encode the instruction and witness it
            let encoded_instr = instr.to_dword::<NUM_REGS>();
            let encoded_instr_var =
                DWordVar::<WV, _>::new_witness(ns!(cs, "dword"), || Ok(encoded_instr)).unwrap();

            // Decode in ZK
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
        }
        // Make sure nothing errored
        assert!(cs.is_satisfied().unwrap());
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

    // Checks that the skip3 program above passes the exec checker
    #[test]
    fn skip3_exec_checker() {
        let cs = ConstraintSystem::new_ref();

        let assembly = tinyram_emu::parser::assemble(SKIP3_CODE);

        // VonNeumann architecture, and no `read` operations.
        let meta = ProgramMetadata {
            arch: TinyRamArch::VonNeumann,
            primary_input_len: 0,
            aux_input_len: 0,
        };

        let (output, transcript) = tinyram_emu::interpreter::run_program::<W, NUM_REGS>(
            TinyRamArch::VonNeumann,
            &assembly,
            &[],
            &[],
        );
        println!("Transcript len == {}", transcript.len());

        let non_mem_op = ProcessedTranscriptEntryVar::default();

        // Run the CPU
        let mut cpu_state = CpuStateVar::default::<NUM_REGS>();
        for (i, transcript_entry) in transcript.into_iter().enumerate() {
            let TranscriptEntry { instr, .. } = transcript_entry;
            // Encode the instruction and witness it
            let encoded_instr = instr.to_dword::<NUM_REGS>();
            let encoded_instr_var =
                DWordVar::<WV, _>::new_witness(ns!(cs, "dword"), || Ok(encoded_instr)).unwrap();

            println!("iteration {i}. Instr == {:?}", instr);
            cpu_state =
                exec_checker::<NUM_REGS, _, _>(meta, &non_mem_op, &cpu_state, &encoded_instr_var)
                    .unwrap();
        }

        // Make sure nothing errored
        assert!(cs.is_satisfied().unwrap());

        // Check the output is set and correct
        assert!(cpu_state.answer.is_set.value().unwrap());
        assert_eq!(output, cpu_state.answer.val.value().unwrap());
    }
}
