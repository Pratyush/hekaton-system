use super::*;

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
    pub(crate) primary_tape_pos: TapeHeadPosVar<F>,
    pub(crate) aux_tape_pos: TapeHeadPosVar<F>,
}

impl<WV: WordVar<F>, F: PrimeField> CpuStateVar<WV, F> {
    pub(crate) fn default<const NUM_REGS: usize>() -> Self {
        CpuStateVar {
            pc: WV::zero(),
            flag: Boolean::FALSE,
            regs: vec![WV::zero(); NUM_REGS],
            answer: CpuAnswerVar::default(),
            primary_tape_pos: TapeHeadPosVar::zero(),
            aux_tape_pos: TapeHeadPosVar::zero(),
        }
    }
    // TODO: Make a FromBitsGadget that has this method. This requires CpuStateVar being made
    // generic over NUM_REGS
    /// Returns the size of this CpuStateVar when serialized to bits
    fn bitlen<const NUM_REGS: usize>() -> usize {
        let pc_len = WV::BITLEN;
        let flag_len = 1;
        let regs_len = NUM_REGS * WV::BITLEN;
        let answer_len = WV::BITLEN + 1;
        let primary_tape_pos_len = <TapeHeadPosVar<F> as WordVar<F>>::BITLEN;
        let aux_tape_pos_len = <TapeHeadPosVar<F> as WordVar<F>>::BITLEN;
        pc_len + flag_len + regs_len + answer_len + primary_tape_pos_len + aux_tape_pos_len
    }

    // TODO: Make a FromBitsGadget that has this method. This requires CpuStateVar being made
    // generic over NUM_REGS
    /// Converts the given bitstring to a `CpuStateVar`. Requires that `bits.len() == Self::bitlen`
    fn from_bits_le<const NUM_REGS: usize>(bits: &[Boolean<F>]) -> Self {
        assert_eq!(bits.len(), Self::bitlen::<NUM_REGS>());

        let pc_len = WV::BITLEN;
        let answer_len = WV::BITLEN + 1;
        let tape_pos_len = <TapeHeadPosVar<F> as WordVar<F>>::BITLEN;

        // Keep a cursor into the bits array
        let mut idx = 0;

        let pc = PcVar::from_le_bits(&bits[idx..idx + pc_len]);
        idx += pc_len;

        let flag = bits[idx].clone();
        idx += 1;

        let regs = (0..NUM_REGS)
            .map(|_| {
                let reg = WV::from_le_bits(&bits[idx..idx + WV::BITLEN]);
                idx += WV::BITLEN;
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
    pub(super) fn unpack_from_fps<const NUM_REGS: usize>(fps: &[FpVar<F>]) -> Self {
        let bits_per_fp = F::MODULUS_BIT_SIZE as usize - 1;

        // Check that not too many field elements were given
        assert!(
            fps.len() * bits_per_fp < Self::bitlen::<NUM_REGS>() + bits_per_fp,
            "expected fewer field elements"
        );

        // Serialize the field elems
        let mut bits: Vec<Boolean<F>> = fps
            .iter()
            .flat_map(|f| {
                // We only packed BITLEN-1 bits. If there's a leading zero, cut it off.
                let mut bits = f.to_bits_le().unwrap();
                bits.truncate(F::MODULUS_BIT_SIZE as usize - 1);
                bits
            })
            .collect();
        // Truncate to the appropriate size
        bits.truncate(Self::bitlen::<NUM_REGS>());

        // Deserialize
        Self::from_bits_le::<NUM_REGS>(&bits)
    }
}

use ark_r1cs_std::R1CSVar;
impl<W, WV, F> R1CSVar<F> for CpuStateVar<WV, F>
where
    W: Word,
    WV: WordVar<F, Native = W>,
    F: PrimeField,
{
    // TODO: This shouldn't be fixed to 16. This is only the case because CpuStateVar is not
    // generic over NUM_REGS. For debugging purposes this is fine so far, but don't make it
    // load-bearing!
    type Value = CpuState<16, W>;

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let condition_flag = self.flag.value()?;
        let program_counter = self.pc.value()?;
        let mut registers = [W::ZERO; 16];
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

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.pc
            .cs()
            .or(self.flag.cs())
            .or(self.regs.cs())
            .or(self.answer.cs())
            .or(self.primary_tape_pos.cs())
            .or(self.aux_tape_pos.cs())
    }
}

impl<WV, F> EqGadget<F> for CpuStateVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        Ok(self.pc.is_eq(&other.pc)?
            & self.flag.is_eq(&other.flag)?
            & self.regs.is_eq(&other.regs)?
            & self.answer.is_eq(&other.answer)?
            & self.primary_tape_pos.is_eq(&other.primary_tape_pos)?
            & self.aux_tape_pos.is_eq(&other.aux_tape_pos)?)
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

impl<const NUM_REGS: usize, WV, F> AllocVar<CpuState<NUM_REGS, WV::Native>, F>
    for CpuStateVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn new_variable<T: Borrow<CpuState<NUM_REGS, WV::Native>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let f_res = f();

        let state: Result<&CpuState<NUM_REGS, WV::Native>, _> =
            f_res.as_ref().map(|s| s.borrow()).map_err(|e| e.clone());

        let pc = PcVar::new_variable(ns!(cs, "pc"), || state.map(|s| s.program_counter), mode)?;
        let flag =
            Boolean::new_variable(ns!(cs, "flag"), || state.map(|s| s.condition_flag), mode)?;
        let regs =
            RegistersVar::new_variable(ns!(cs, "regs"), || state.map(|s| s.registers), mode)?;
        let answer =
            CpuAnswerVar::new_variable(ns!(cs, "answer"), || state.map(|s| s.answer), mode)?;
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

impl<'a, WV, F> ToBitsGadget<F> for &'a CpuStateVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
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

impl<WV, F> ToBitsGadget<F> for CpuStateVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        <&Self>::to_bits_le(&self)
    }
}
