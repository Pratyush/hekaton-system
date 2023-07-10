use crate::{option::OptionVar, TinyRamExt};
use ark_r1cs_std::R1CSVar;
use tinyram_emu::TinyRam;

use super::*;

// TODO: Make this and RegistersVar take NUM_REGS: usize
#[derive(Clone, Debug)]
pub struct CpuStateVar<T: TinyRamExt> {
    pub(crate) pc: PcVar<T::WordVar>,
    pub(crate) flag: Boolean<T::F>,
    pub(crate) regs: RegistersVar<T::WordVar>,
    pub(crate) answer: OptionVar<T::WordVar, T::F>,
    pub(crate) primary_tape_pos: TapeHeadPosVar<T::F>,
    pub(crate) aux_tape_pos: TapeHeadPosVar<T::F>,
}

impl<T: TinyRamExt> CpuStateVar<T> {
    pub(crate) fn default() -> Self {
        Self {
            pc: T::WordVar::zero(),
            flag: Boolean::FALSE,
            regs: vec![T::WordVar::zero(); T::NUM_REGS].into_boxed_slice(),
            answer: CpuAnswerVar::default(),
            primary_tape_pos: TapeHeadPosVar::zero(),
            aux_tape_pos: TapeHeadPosVar::zero(),
        }
    }

    // TODO: Make a FromBitsGadget that has this method. This requires CpuStateVar being made
    // generic over NUM_REGS
    /// Returns the size of this CpuStateVar when serialized to bits
    fn bit_length() -> usize {
        let pc_len = T::WordVar::BIT_LENGTH;
        let flag_len = 1;
        let regs_len = T::NUM_REGS * T::WordVar::BIT_LENGTH;
        let answer_len = T::WordVar::BIT_LENGTH + 1;
        let primary_tape_pos_len = T::WordVar::BIT_LENGTH;
        let aux_tape_pos_len = T::WordVar::BIT_LENGTH;
        pc_len + flag_len + regs_len + answer_len + primary_tape_pos_len + aux_tape_pos_len
    }

    // TODO: Make a FromBitsGadget that has this method. This requires CpuStateVar being made
    // generic over NUM_REGS
    /// Converts the given bitstring to a `CpuStateVar`. Requires that `bits.len() == Self::bitlen`
    fn from_bits_le(bits: &[Boolean<T::F>]) -> Self {
        assert_eq!(bits.len(), Self::bit_length::<T::NUM_REGS>());

        let pc_len = T::WordVar::BIT_LENGTH;
        let answer_len = T::WordVar::BIT_LENGTH + 1;
        let tape_pos_len = T::WordVar::BIT_LENGTH;

        // Keep a cursor into the bits array
        let mut idx = 0;

        let pc = PcVar::from_le_bits(&bits[idx..idx + pc_len]);
        idx += pc_len;

        let flag = bits[idx].clone();
        idx += 1;

        let regs = (0..T::NUM_REGS)
            .map(|_| {
                let reg = T::WordVar::from_le_bits(&bits[idx..idx + T::WordVar::BIT_LENGTH]);
                idx += T::WordVar::BIT_LENGTH;
                reg
            })
            .collect();

        let answer = CpuAnswerVar::from_bits_le(&bits[idx..idx + answer_len]);
        idx += answer_len;

        let primary_tape_pos = TapeHeadPosVar::from_le_bits(&bits[idx..idx + tape_pos_len]);
        idx += tape_pos_len;
        let aux_tape_pos = TapeHeadPosVar::from_le_bits(&bits[idx..idx + tape_pos_len]);
        idx += tape_pos_len;

        _ = idx;

        CpuStateVar {
            pc,
            answer,
            flag,
            regs,
            primary_tape_pos,
            aux_tape_pos,
        }
    }

    /// Undoes `pack_to_fps`, i.e., deserializes from its packed representation as field
    /// elements.
    pub(super) fn unpack_from_fps(fps: &[FpVar<T::F>]) -> Self {
        let bits_per_fp = T::ConstraintField::MODULUS_BIT_SIZE as usize - 1;

        // Check that not too many field elements were given
        assert!(
            fps.len() * bits_per_fp < Self::bit_length::<T::NUM_REGS>() + bits_per_fp,
            "expected fewer field elements"
        );

        // Serialize the field elems
        let mut bits: Vec<Boolean<T::F>> = fps
            .iter()
            .flat_map(|f| {
                // We only packed BITLEN-1 bits. If there's a leading zero, cut it off.
                let mut bits = f.to_bits_le().unwrap();
                bits.truncate(T::F::MODULUS_BIT_SIZE as usize - 1);
                bits
            })
            .collect();
        // Truncate to the appropriate size
        bits.truncate(Self::bit_length::<T::NUM_REGS>());

        // Deserialize
        Self::from_bits_le::<T::NUM_REGS>(&bits)
    }
}

impl<T: TinyRamExt> R1CSVar<T::F> for CpuStateVar<T> {
    // TODO: This shouldn't be fixed to 16. This is only the case because CpuStateVar is not
    // generic over NUM_REGS. For debugging purposes this is fine so far, but don't make it
    // load-bearing!
    type Value = CpuState<T>;

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let condition_flag = self.flag.value()?;
        let program_counter = self.pc.value()?;
        let mut registers = [T::Word::ZERO; 16];
        for i in 0..self.regs.len() {
            registers[i] = self.regs[i].value()?;
        }
        let answer = self.answer.value()?;
        let primary_tape_pos = self.primary_tape_pos.value()?;
        let aux_tape_pos = self.aux_tape_pos.value()?;

        Ok(CpuState {
            condition_flag,
            program_counter,
            registers,
            answer,
            primary_tape_pos,
            aux_tape_pos,
        })
    }

    fn cs(&self) -> ConstraintSystemRef<T::F> {
        self.pc
            .cs()
            .or(self.flag.cs())
            .or(self.regs.cs())
            .or(self.answer.cs())
            .or(self.primary_tape_pos.cs())
            .or(self.aux_tape_pos.cs())
    }
}

impl<T: TinyRamExt> EqGadget<T::F> for CpuStateVar<T> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<T::F>, SynthesisError> {
        Ok(self.pc.is_eq(&other.pc)?
            & self.flag.is_eq(&other.flag)?
            & self.regs.is_eq(&other.regs)?
            & self.answer.is_eq(&other.answer)?
            & self.primary_tape_pos.is_eq(&other.primary_tape_pos)?
            & self.aux_tape_pos.is_eq(&other.aux_tape_pos)?)
    }
}

impl<T: TinyRamExt> CondSelectGadget<T::F> for CpuStateVar<T> {
    fn conditionally_select(
        cond: &Boolean<T::F>,
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
        let primary_tape_pos = TapeHeadPosVar::conditionally_select(
            cond,
            &true_value.primary_tape_pos,
            &false_value.primary_tape_pos,
        )?;
        let aux_tape_pos = TapeHeadPosVar::conditionally_select(
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

impl<T: TinyRamExt> AllocVar<CpuState<T>, T::F> for CpuStateVar<T> {
    fn new_variable<S: Borrow<CpuState<T>>>(
        cs: impl Into<Namespace<T::F>>,
        f: impl FnOnce() -> Result<S, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let f_res = f();

        let state: Result<&CpuState<T>, _> =
            f_res.as_ref().map(|s| s.borrow()).map_err(|e| e.clone());

        let pc = PcVar::new_variable(ns!(cs, "pc"), || state.map(|s| s.program_counter()), mode)?;
        let flag =
            Boolean::new_variable(ns!(cs, "flag"), || state.map(|s| s.condition_flag()), mode)?;
        let regs =
            RegistersVar::new_variable(ns!(cs, "regs"), || state.map(|s| s.registers), mode)?;
        let answer =
            CpuAnswerVar::new_variable(ns!(cs, "answer"), || state.map(|s| s.answer()), mode)?;
        let primary_tape_pos = TapeHeadPosVar::new_variable(
            ns!(cs, "primary head"),
            || state.map(|s| s.primary_tape_pos),
            mode,
        )?;
        let aux_tape_pos = TapeHeadPosVar::new_variable(
            ns!(cs, "aux head"),
            || state.map(|s| s.aux_tape_pos),
            mode,
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

impl<'a, T: TinyRamExt> ToBitsGadget<T::F> for &'a CpuStateVar<T> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<T::F>>, SynthesisError> {
        Ok([
            self.pc.as_le_bits(),
            vec![self.flag.clone()],
            self.regs.iter().flat_map(|w| w.as_le_bits()).collect(),
            self.answer.to_bits_le().unwrap(),
            self.primary_tape_pos.as_le_bits(),
            self.aux_tape_pos.as_le_bits(),
        ]
        .concat())
    }
}

impl<T: TinyRamExt> ToBitsGadget<T::F> for CpuStateVar<T> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<T::F>>, SynthesisError> {
        <&Self>::to_bits_le(&self)
    }
}
