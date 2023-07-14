use crate::{
    common::*,
    transcript_checker::ProcessedTranscriptEntryVar,
    util::{arr_set, pack_to_fps, uint32_to_uint64},
    word::{DoubleWordVar, WordVar},
    TinyRamExt,
};
use tinyram_emu::{
    instructions::opcode::Opcode, word::Word, CpuState, MemOpKind, ProgramMetadata, TinyRamArch,
};

use core::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    cmp::CmpGadget,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    uint32::UInt32,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_std::log2;

/// The position of a tape head
type TapeHeadPosVar<F> = UInt32<F>;

mod cpu_answer;
mod cpu_state;
mod exec_tick_mem_data;
mod instruction_result;

pub(crate) use cpu_answer::CpuAnswerVar;
pub use cpu_state::CpuStateVar;
pub(crate) use exec_tick_mem_data::{ExecTickMemData, ExecTickMemDataKind};
pub(crate) use instruction_result::InstrResult;

/// Decodes an encoded instruction into an opcode, 2 registers, and an immediate-or-register. The
/// registers (including the imm-or-reg if applicable) are guaranteed to be less than `NUM_REGS`.
fn decode_instruction<T: TinyRamExt>(
    encoded_instr: &DoubleWordVar<T::WordVar, T::F>,
) -> Result<
    (
        OpcodeVar<T::F>,
        RegIdxVar<T::F>,
        RegIdxVar<T::F>,
        ImmOrRegisterVar<T>,
    ),
    SynthesisError,
> {
    let num_regs = UInt8::constant(T::NUM_REGS as u8);
    let regidx_bitlen = log2(T::NUM_REGS) as usize;
    let instr_bits: Vec<Boolean<T::F>> = encoded_instr.as_le_bits();

    let mut cur_bit_idx: usize = 0;

    // Structure of an instruction is
    // 000...0  is_imm  reg1  reg2  imm_or_reg  opcode
    // <-- MSB                                 LSB -->

    // Extract all the components

    let opcode = OpcodeVar::from_bits_le(
        &instr_bits[cur_bit_idx..cur_bit_idx + OpcodeVar::<T::F>::BIT_LENGTH],
    );
    cur_bit_idx += OpcodeVar::<T::F>::BIT_LENGTH;

    let imm_or_reg_bits = &instr_bits[cur_bit_idx..cur_bit_idx + T::Word::BIT_LENGTH];
    cur_bit_idx += T::Word::BIT_LENGTH;

    let reg2 = RegIdxVar::from_le_bits(&instr_bits[cur_bit_idx..cur_bit_idx + regidx_bitlen]);
    cur_bit_idx += regidx_bitlen;

    let reg1 = RegIdxVar::from_le_bits(&instr_bits[cur_bit_idx..cur_bit_idx + regidx_bitlen]);
    cur_bit_idx += regidx_bitlen;

    let is_imm: Boolean<T::F> = instr_bits[cur_bit_idx].clone();

    // Make the imm-or-reg from the component bits and type flag
    let imm_or_reg = ImmOrRegisterVar {
        is_imm,
        val: T::WordVar::from_le_bits(imm_or_reg_bits),
    };

    // Check that the registers are within range
    let reg1_in_range = reg1.0.is_lt(&num_regs)?;
    let reg2_in_range = &reg2.0.is_lt(&num_regs)?;
    reg1_in_range.enforce_equal(&Boolean::TRUE)?;
    reg2_in_range.enforce_equal(&Boolean::TRUE)?;

    return Ok((opcode, reg1, reg2, imm_or_reg));
}

/// A helper to `exec_checker`. This takes a native opcode and its zk parameters, executes it, and
/// returns `(new_state, err)`. `err` is set if the contents of `mem_op` do not match the
/// instruction.
fn run_instruction<T: TinyRamExt>(
    meta: ProgramMetadata,
    op: Opcode,
    cpu_state: &CpuStateVar<T>,
    mem_op: &ProcessedTranscriptEntryVar<T>,
    reg1: &RegIdxVar<T::F>,
    reg1_val: &T::WordVar,
    reg2_val: &T::WordVar,
    imm_or_reg_val: &T::WordVar,
    incrd_pc: &T::WordVar,
    pc_overflow: &Boolean<T::F>,
) -> Result<InstrResult<T>, SynthesisError> {
    let CpuStateVar {
        pc: _,
        flag,
        regs,
        answer,
        primary_tape_pos,
        aux_tape_pos,
    } = cpu_state;

    // The first register, if given, is always the output register
    let reg_to_write = reg1.clone();
    // The default value to write to the first register is itself, i.e., do a no-op.
    let reg_val = reg1_val.clone();

    use Opcode::*;
    match op {
        Add => {
            // New reg val is the sum of the inputs
            let (reg_val, new_flag) = reg2_val.carrying_add(&imm_or_reg_val)?;

            // The PC is incremented (need to check overflow), and the flag and registers are new.
            let mut err = pc_overflow.clone();
            // add is not a memory operation. This MUST be padding.
            err |= !&mem_op.is_padding;

            Ok(InstrResult {
                pc: incrd_pc.clone(),
                flag: new_flag,
                reg_to_write,
                reg_val,
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
                err,
            })
        },
        Xor => {
            // New reg val is the xor of the inputs
            let reg_val = reg2_val.clone() ^ imm_or_reg_val.clone();

            // The PC is incremented (need to check overflow), and the registers are new.
            let mut err = pc_overflow.clone();
            // xor is not a memory operation. This MUST be padding.
            err |= !&mem_op.is_padding;

            Ok(InstrResult {
                pc: incrd_pc.clone(),
                flag: flag.clone(),
                reg_to_write,
                reg_val,
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
                err,
            })
        },
        CmpE => {
            // Compare the two input values
            let new_flag = reg2_val.is_eq(&imm_or_reg_val)?;

            //  The PC is incremented (need to check overflow), and the flag is new
            let mut err = pc_overflow.clone();
            // cmpe is not a memory operation. This MUST be padding.
            err |= !&mem_op.is_padding;

            Ok(InstrResult {
                pc: incrd_pc.clone(),
                flag: new_flag,
                reg_to_write,
                reg_val,
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
                err,
            })
        },
        Jmp => {
            // Set the new PC to be the imm-or-reg
            let new_pc = imm_or_reg_val.clone();

            // cmpe is not a memory operation. This MUST be padding.
            let err = !&mem_op.is_padding;

            Ok(InstrResult {
                pc: new_pc,
                flag: flag.clone(),
                reg_to_write,
                reg_val,
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
                err,
            })
        },
        CJmp => {
            // Let pc' = imm_or_reg_val if flag is set. Otherwise, let pc' = pc + 1
            let new_pc = PcVar::conditionally_select(&flag, imm_or_reg_val, &incrd_pc)?;

            // Check that incrd pc, if used, didn't overflow
            let used_incrd_pc = !flag;
            let relevant_pc_overflow = pc_overflow & used_incrd_pc;
            let mut err = relevant_pc_overflow.clone();
            // cjmp is not a memory operation. This MUST be padding.
            err |= !&mem_op.is_padding;

            Ok(InstrResult {
                pc: new_pc,
                flag: flag.clone(),
                reg_to_write,
                reg_val,
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
                err,
            })
        },
        Answer => {
            // answer is not a memory operation. This MUST be padding.
            let err = !&mem_op.is_padding;

            Ok(InstrResult {
                pc: incrd_pc.clone(),
                flag: flag.clone(),
                reg_to_write,
                reg_val,
                answer: CpuAnswerVar::Some(imm_or_reg_val.clone()),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
                err,
            })
        },
        LoadW => {
            // Get the correct word from the memory op, and save it in the register
            let (reg_val, mut err) = mem_op.select_word(&imm_or_reg_val)?;

            // The PC is incremented (need to check overflow), and the registers are new.
            err |= pc_overflow;
            // load.w is a memory operation. This MUST NOT be padding.
            err |= &mem_op.is_padding;

            Ok(InstrResult {
                pc: incrd_pc.clone(),
                flag: flag.clone(),
                reg_to_write,
                reg_val,
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
                err,
            })
        },
        StoreW => {
            // Storing doesn't change anything. We don't have to do anything here

            // The PC is incremented (need to check overflow)
            let mut err = pc_overflow.clone();
            // store.w is a memory operation. This MUST NOT be padding.
            err |= &mem_op.is_padding;

            Ok(InstrResult {
                pc: incrd_pc.clone(),
                flag: flag.clone(),
                reg_to_write,
                reg_val,
                answer: answer.clone(),
                primary_tape_pos: primary_tape_pos.clone(),
                aux_tape_pos: aux_tape_pos.clone(),
                err,
            })
        },
        Read => {
            // Get the correct word from the memory op, and save it in the register
            let reg_val = mem_op.val_low_word();

            // Learn which tape is being read
            let is_primary = mem_op
                .op
                .is_eq(&FpVar::Constant(T::F::from(MemOpKind::ReadPrimary as u8)))?;
            let is_aux = mem_op
                .op
                .is_eq(&FpVar::Constant(T::F::from(MemOpKind::ReadAux as u8)))?;
            let is_invalid_tape = !&is_primary & !&is_aux;

            // Find out the current tape position and the maximum tape position. This is nonsense
            // if is_invalid_tape == true, but that's fine because in either case, the value set
            // will be 0 and the condition flag will be true.
            let cur_tape_pos =
                TapeHeadPosVar::conditionally_select(&is_primary, primary_tape_pos, aux_tape_pos)?;
            let tape_len = {
                let primary_len = TapeHeadPosVar::constant(meta.primary_input_len);
                let aux_len = TapeHeadPosVar::constant(meta.aux_input_len);
                TapeHeadPosVar::conditionally_select(&is_primary, &primary_len, &aux_len)?
            };
            let is_out_of_bounds = cur_tape_pos.is_ge(&tape_len)?;

            // Check that the read head is at the expected position
            let mut err = mem_op.location.is_neq(&uint32_to_uint64(&cur_tape_pos))?;

            // Increment the tape position
            let new_tape_pos =
                TapeHeadPosVar::wrapping_add_many(&[cur_tape_pos, TapeHeadPosVar::one()])?;
            let new_primary_tape_pos =
                TapeHeadPosVar::conditionally_select(&is_primary, &new_tape_pos, primary_tape_pos)?;
            let new_aux_tape_pos =
                TapeHeadPosVar::conditionally_select(&is_aux, &new_tape_pos, aux_tape_pos)?;

            // Now determine if the read triggers the condition flag. It triggers the condition
            // flag iff either the tape index is > 1 or the tape head has reached the end of the
            // tape.
            let new_flag = is_invalid_tape | is_out_of_bounds;

            // Make sure that the val is 0 when the flag is set
            err |= &new_flag & reg_val.is_neq(&T::WordVar::zero())?;
            // The PC is incremented (need to check overflow), the registers are new, and so is one
            // of the tape heads.
            err |= pc_overflow;
            // read is a memory operation. This MUST NOT be padding.
            err |= &mem_op.is_padding;

            Ok(InstrResult {
                pc: incrd_pc.clone(),
                flag: new_flag,
                reg_to_write,
                reg_val,
                answer: answer.clone(),
                primary_tape_pos: new_primary_tape_pos,
                aux_tape_pos: new_aux_tape_pos,
                err,
            })
        },
        _ => todo!(),
    }
}

/// Runs a single CPU tick with the given program counter, instruction, registers, and (optional)
/// associated memory operation. Returns the updated CPU state.
pub(crate) fn check_execution<T: TinyRamExt>(
    meta: ProgramMetadata,
    mem_op: &ProcessedTranscriptEntryVar<T>,
    cpu_state: &CpuStateVar<T>,
    instr: &DoubleWordVar<T::WordVar, T::F>,
) -> Result<CpuStateVar<T>, SynthesisError> {
    // Prepare to run all the instructions. This will hold new_state for all possible instructions,
    // and all_errors will hold the corresponding errors flags. At the end, we'll use the opcode to
    // select the output state we want to return, and assert that err == false.
    let mut all_outputs = vec![InstrResult::default(); 32];

    // Unpack the CPu state and make sure it hasn't already halted
    let CpuStateVar {
        pc, regs, answer, ..
    } = cpu_state;
    answer.is_set.enforce_equal(&Boolean::FALSE)?;

    // Decode the instruction
    let (opcode, reg1, reg2, imm_or_reg) = decode_instruction::<T>(instr)?;

    // Create the default next program counter, which is the one that's incremented
    let (incrd_pc, pc_overflow) = match meta.arch {
        TinyRamArch::Harvard => pc.checked_increment()?,
        TinyRamArch::VonNeumann => {
            // Increment PC by 1 double word
            let double_word_bytelen = T::DOUBLE_WORD_BYTE_LENGTH;
            pc.carrying_add(&T::WordVar::constant(T::WordVar::Native::from_u64(
                double_word_bytelen,
            )))?
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
    // reg1 (if used) is always the output register. We need to read that in case the operation
    //     doesn't modify registers, and we need to overwrite reg1 with itself (as a no-op)
    // reg2 (if used) is always a secondary input
    let reg1_val = reg1.value::<T>(&regs)?;
    let reg2_val = reg2.value::<T>(&regs)?;
    // imm_or_reg is always present
    let imm_or_reg_val = {
        let reg_val =
            T::WordVar::conditionally_select_power_of_two_vector(&imm_or_reg.as_selector()?, regs)?;
        let imm_val = imm_or_reg.val.clone();

        T::WordVar::conditionally_select(&imm_or_reg.is_imm, &imm_val, &reg_val)?
    };

    let cs = cpu_state.cs();
    println!(
        "Num constraints pre-exec_checker-loop {}",
        cs.num_constraints()
    );

    // Go through every opcode, do the operation, and save the results in all_outputs
    for opcode in supported_opcodes {
        let out = run_instruction(
            meta,
            opcode,
            cpu_state,
            mem_op,
            &reg1,
            &reg1_val,
            &reg2_val,
            &imm_or_reg_val,
            &incrd_pc,
            &pc_overflow,
        )?;
        all_outputs[opcode as usize] = out;
    }
    println!(
        "Num constraints post-exec_checker-loop {}",
        cs.num_constraints()
    );

    // Pack the output states for muxing. Transpose the packing so that the first index is the
    // vector of all the first packed FpVars, the second is the vector of all the second packed
    // FpVars etc.
    let packed_outputs: Vec<Vec<FpVar<T::F>>> = all_outputs.iter().map(pack_to_fps).collect();
    let transposed_packings = crate::util::transpose(packed_outputs);

    // Decode the opcode and use it to index into the vec of next CPU states
    let opcode_bits = opcode.to_bits_be()?;

    // Out of all the computed output states and memory operations, pick the ones that correspond
    // to this instruction's opcode
    let chosen_packed_output = transposed_packings
        .into_iter()
        .map(|fps| FpVar::conditionally_select_power_of_two_vector(&opcode_bits, &fps))
        .collect::<Result<Vec<_>, _>>()?;
    // Unpack the state
    let chosen_output = InstrResult::unpack_from_fps::<T::NUM_REGS>(&chosen_packed_output);

    // Check that this operation didn't error
    chosen_output.err.enforce_equal(&Boolean::FALSE)?;

    // Convert the result into a full CPU state. This means conditionally setting each register
    let reg_to_write = chosen_output.reg_to_write.to_fpvar()?;

    // Overwrite the `reg_to_write`-th register with the value in chosen_output.reg_val
    let new_regs = cpu_state
        .regs
        .iter()
        .enumerate()
        .map(|(i, existing_val)| {
            let idx_is_eq = reg_to_write.is_eq(&FpVar::constant(T::F::from(i as u8)))?;
            T::WordVar::conditionally_select(&idx_is_eq, &chosen_output.reg_val, existing_val)
        })
        .collect::<Result<Vec<_>, _>>()?;

    println!("Num constraints post-unpacking {}", cs.num_constraints());

    // Output the full CPU state
    Ok(CpuStateVar {
        pc: chosen_output.pc,
        flag: chosen_output.flag,
        regs: new_regs,
        answer: chosen_output.answer,
        primary_tape_pos: chosen_output.primary_tape_pos,
        aux_tape_pos: chosen_output.aux_tape_pos,
    })
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
    type W = <T::WordVar as WordVar<F>>::Native;

    // Tests that instructions decode to the same thing under the native and ZK decoders
    #[test]
    fn decoding_equality() {
        let mut rng = rand::thread_rng();
        let cs = ConstraintSystem::new_ref();

        // Test 200 randomly generated instructions
        for _ in 0..200 {
            let instr = Instr::rand::<NUM_REGS>(&mut rng);

            // Encode the instruction and witness it
            let encoded_instr = instr.to_double_word::<NUM_REGS>();
            let encoded_instr_var =
                DoubleWordVar::<T::WordVar, _>::new_witness(ns!(cs, "double word"), || {
                    Ok(encoded_instr)
                })
                .unwrap();

            // Decode in ZK
            let (opcode_var, reg1_var, reg2_var, imm_or_reg_var) =
                decode_instruction::<NUM_REGS, _, _>(&encoded_instr_var).unwrap();

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
            vec![],
            vec![],
        );
        println!("Transcript len == {}", transcript.len());

        let non_mem_op = ProcessedTranscriptEntryVar::default();

        // Run the CPU
        let mut cpu_state = CpuStateVar::default::<NUM_REGS>();
        for (i, transcript_entry) in transcript.into_iter().enumerate() {
            let TranscriptEntry { instr, .. } = transcript_entry;
            // Encode the instruction and witness it
            let encoded_instr = instr.to_double_word::<NUM_REGS>();
            let encoded_instr_var =
                DoubleWordVar::<T::WordVar, _>::new_witness(ns!(cs, "double word"), || {
                    Ok(encoded_instr)
                })
                .unwrap();

            println!("iteration {i}. Instr == {:?}", instr);
            cpu_state =
                check_execution::<T>(meta, &non_mem_op, &cpu_state, &encoded_instr_var).unwrap();

            // Check that packing/unpacking is a no-op
            assert_eq!(
                CpuStateVar::<T>::unpack_from_fps::<NUM_REGS>(&pack_to_fps(&cpu_state)).value(),
                cpu_state.value()
            );
        }

        // Make sure nothing errored
        assert!(cs.is_satisfied().unwrap());

        // Check the output is set and correct
        assert!(cpu_state.answer.is_set.value().unwrap());
        assert_eq!(output, cpu_state.answer.val.value().unwrap());
    }
}
