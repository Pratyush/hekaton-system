use crate::{common::*, word::WordVar};

use core::cmp::Ordering;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;

/// An `ExecTickMemData` can be a LOAD (=0), a STORE (=1), or no-mem (=2)
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
pub(crate) struct ExecTickMemData<W: WordVar<F>, F: PrimeField> {
    /// The kind of data this is. A LOAD, a STORE, or a no-op
    pub(crate) kind: ExecTickMemDataKind<F>,
    /// The RAM index loaded from or stored into. This is not checked when kind == no-op
    pub(crate) idx: RamIdxVar<W>,
    /// The value stored into RAM. This is not checked when kind == no-op or LOAD
    pub(crate) stored_word: W,
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

/// Runs a single CPU tick with the given program counter, instruction, registers, and word loaded
/// from memory (if `instr isn't a `lw`, then the word is ignored). Returns the updated program
/// counter, updated set of registers, and a description of what, if any, memory operation occured.
pub(crate) fn exec_checker<W: WordVar<F>, F: PrimeField>(
    pc: &PcVar<W>,
    instr: &W,
    regs: &RegistersVar<W>,
    opt_loaded_val: &W,
) -> (PcVar<W>, RegistersVar<W>, ExecTickMemData<W, F>) {
    let (opcode, reg1, reg2, imm_or_reg) = decode_instr(instr);
    unimplemented!()
}
