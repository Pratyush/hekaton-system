use crate::{TinyRamExt, tape::TapeHeadsVar};
use ark_r1cs_std::R1CSVar;
use tinyram_emu::TinyRam;

use super::*;

// TODO: Make this and RegistersVar take NUM_REGS: usize
#[derive(Clone, Debug)]
pub struct CpuStateVar<T: TinyRamExt> {
    pub(crate) pc: PcVar<T::WordVar>,
    pub(crate) flag: Boolean<T::F>,
    pub(crate) regs: RegistersVar<T::WordVar>,
    pub(crate) answer: CpuAnswerVar<T>,
    pub(crate) tape_heads: TapeHeadsVar<T::WordVar>,
}

impl<T: TinyRamExt> CpuStateVar<T> {
    pub(crate) fn default() -> Self {
        Self {
            pc: T::WordVar::zero(),
            flag: Boolean::FALSE,
            regs: vec![T::WordVar::zero(); T::NUM_REGS].into_boxed_slice(),
            answer: CpuAnswerVar::default(),
            tape_heads: TapeHeadsVar::default(),
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
    fn from_bits_le(mut bits: &[Boolean<T::F>]) -> Self {
        assert_eq!(bits.len(), Self::bit_length::<T::NUM_REGS>());

        let pc_len = T::WordVar::BIT_LENGTH;
        let answer_len = T::WordVar::BIT_LENGTH + 1;
        let tape_heads_len = 2 * T::WordVar::BIT_LENGTH;

        // Keep a cursor into the bits array

        let pc = PcVar::from_le_bits(&bits);
        bits = &bits[pc_len..];

        let flag = bits[0].clone();
        bits = &bits[1..];

        let regs = (0..T::NUM_REGS)
            .map(|_| {
                let reg = T::WordVar::from_le_bits(&bits);
                bits = &bits[T::WordVar::BIT_LENGTH..];
                reg
            })
            .collect();

        let answer = CpuAnswerVar::from_bits_le(&bits);
        bits = &bits[answer_len..];

        let tape_heads = TapeHeadsVar::from_le_bits(&bits);
        bits = &bits[tape_heads_len..];

        CpuStateVar {
            pc,
            answer,
            flag,
            regs,
            tape_heads
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

    pub fn increment_pc(&self) -> (PcVar<T::WordVar>, Boolean<T::F>) {
        // Create the default next program counter, which is the one that's incremented
        match T::ARCH {
            TinyRamArch::Harvard => self.pc.checked_increment()?,
            TinyRamArch::VonNeumann => {
                // Increment PC by 1 double word
                self.pc.carrying_add(&T::WordVar::constant_u64(T::DOUBLE_WORD_BYTE_LENGTH))?
            },
        }
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
        let tape_heads = self.tape_heads.value()?;

        Ok(CpuState {
            condition_flag,
            program_counter,
            registers,
            answer,
            tape_heads,
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
        let tape_heads = TapeHeadsVar::conditionally_select(
            cond,
            &true_value.tape_heads,
            &false_value.tape_heads,
        )?;

        Ok(CpuStateVar {
            pc,
            flag,
            regs,
            answer,
            tape_heads,
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
            RegistersVar::new_variable(ns!(cs, "regs"), || state.map(|s| s.registers()), mode)?;
        let answer =
            CpuAnswerVar::new_variable(ns!(cs, "answer"), || state.map(|s| s.answer()), mode)?;
        let tape_heads = TapeHeadsVar::new_variable(
            ns!(cs, "tape heads"),
            || state.map(|s| s.tape_heads()),
            mode,
        )?;

        Ok(CpuStateVar {
            pc,
            flag,
            regs,
            answer,
            tape_heads,
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
