use super::*;

/// The output of a `run_instr()` invocation. This has the resulting CPU state, and a flag for if
/// an error occured
#[derive(Clone)]
pub(crate) struct InstrResult<T: TinyRamExt> {
    pub(crate) pc: PcVar<T::WordVar>,
    pub(crate) flag: Boolean<T::F>,
    pub(crate) reg_to_write: RegIdxVar<T::F>,
    pub(crate) reg_val: T::WordVar,
    pub(crate) answer: Option<T::WordVar, T::F>,
    pub(crate) primary_tape_pos: TapeHeadPosVar<T::F>,
    pub(crate) aux_tape_pos: TapeHeadPosVar<T::F>,
    pub(super) err: Boolean<T::F>,
}

impl<'a, T: TinyRamExt> ToBitsGadget<F> for &'a InstrResult<T> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<T::F>>, SynthesisError> {
        Ok([
            self.pc.as_le_bits(),
            vec![self.flag.clone()],
            self.reg_to_write.to_bits_le().unwrap(),
            self.reg_val.as_le_bits(),
            self.answer.to_bits_le().unwrap(),
            self.primary_tape_pos.as_le_bits(),
            self.aux_tape_pos.as_le_bits(),
            vec![self.err.clone()],
        ]
        .concat())
    }
}

impl<T: TinyRamExt> InstrResult<T> {
    // The default is an error. This is appropriate because it's used as padding in the CPU output
    // selector. Anything that isn't defined is an error by default.
    // TODO: Figure out whether invalid instructions are necessarily errors
    pub(super) fn default() -> Self {
        InstrResult {
            pc: T::WordVar::zero(),
            flag: Boolean::FALSE,
            reg_to_write: RegIdxVar::zero(),
            reg_val: T::WordVar::zero(),
            answer: OptionVar::default(),
            primary_tape_pos: TapeHeadPosVar::zero(),
            aux_tape_pos: TapeHeadPosVar::zero(),
            err: Boolean::TRUE,
        }
    }

    /// Returns the size of this CpuStateVar when serialized to bits
    pub(super) fn bit_length() -> usize {
        let pc_len = T::WordVar::BIT_LENGTH;
        let flag_len = 1;
        let reg_to_write_len = RegIdxVar::<T::F>::BIT_LENGTH;
        let reg_val_len = T::WordVar::BIT_LENGTH;
        let answer_len = T::WordVar::BIT_LENGTH + 1;
        let primary_tape_pos_len = T::WordVar::BIT_LENGTH;
        let aux_tape_pos_len = T::WordVar::BIT_LENGTH;
        let err_len = 1;
        pc_len
            + flag_len
            + reg_to_write_len
            + reg_val_len
            + answer_len
            + primary_tape_pos_len
            + aux_tape_pos_len
            + err_len
    }

    // TODO: Make a FromBitsGadget that has this method. This requires CpuStateVar being made
    // generic over NUM_REGS
    /// Converts the given bitstring to a `CpuStateVar`. Requires that `bits.len() == Self::bitlen`
    pub(super) fn from_bits_le<const NUM_REGS: usize>(bits: &[Boolean<F>]) -> Self {
        assert_eq!(bits.len(), Self::bitlen::<NUM_REGS>());

        let pc_len = WV::BIT_LENGTH;
        let answer_len = WV::BIT_LENGTH + 1;
        let tape_pos_len = <TapeHeadPosVar<F> as WordVar<F>>::BIT_LENGTH;

        // Keep a cursor into the bits array
        let mut idx = 0;

        let pc = PcVar::from_le_bits(&bits[idx..idx + pc_len]);
        idx += pc_len;

        let flag = bits[idx].clone();
        idx += 1;

        let reg_to_write = RegIdxVar::from_le_bits(&bits[idx..idx + RegIdxVar::<F>::BIT_LENGTH]);
        idx += RegIdxVar::<F>::BIT_LENGTH;

        let reg_val = WV::from_le_bits(&bits[idx..idx + WV::BIT_LENGTH]);
        idx += WV::BIT_LENGTH;

        let answer = CpuAnswerVar::from_bits_le(&bits[idx..idx + answer_len]);
        idx += answer_len;

        let primary_tape_pos = TapeHeadPosVar::from_le_bits(&bits[idx..idx + tape_pos_len]);
        idx += tape_pos_len;
        let aux_tape_pos = TapeHeadPosVar::from_le_bits(&bits[idx..idx + tape_pos_len]);
        idx += tape_pos_len;

        let err = bits[idx].clone();
        idx += 1;

        _ = idx;

        InstrResult {
            pc,
            flag,
            reg_to_write,
            reg_val,
            answer,
            primary_tape_pos,
            aux_tape_pos,
            err,
        }
    }

    // TODO: Make this generic for anything with `FromBitsGadget`. This is copied verbatim from
    // CpuStateVar
    /// Undoes `pack_to_fps`, i.e., deserializes from its packed representation as field
    /// elements.
    pub(super) fn unpack_from_fps<const NUM_REGS: usize>(fps: &[FpVar<F>]) -> Self {
        let bits_per_fp = F::MODULUS_BIT_SIZE as usize - 1;

        // Check that not too many field elements were given
        assert!(
            fps.len() * bits_per_fp < Self::bitlen::<NUM_REGS>() + bits_per_fp,
            "expected fewer field elements"
        );

        let cs = fps[0].cs();

        // Serialize the field elems
        let mut bits: Vec<Boolean<F>> = fps
            .iter()
            .flat_map(|f| {
                // We only packed BITLEN-1 bits. If there's a leading zero, cut it off.
                let pre_tobits = cs.num_constraints();

                // We don't need to use FpVar::to_bits_le. We don't set the top bit in our packing.
                // So it suffices to just ensure that the top bit isn't set in the non-unique
                // decoding
                let mut bits = f.to_non_unique_bits_le().unwrap();
                bits[F::MODULUS_BIT_SIZE as usize - 1]
                    .enforce_equal(&Boolean::FALSE)
                    .unwrap();

                bits.truncate(F::MODULUS_BIT_SIZE as usize - 1);
                println!(
                    "Num constraints to run FpVar::to_bits_le(): {}",
                    cs.num_constraints() - pre_tobits
                );
                bits
            })
            .collect();
        // Truncate to the appropriate size
        bits.truncate(Self::bitlen::<NUM_REGS>());

        // Deserialize
        Self::from_bits_le::<NUM_REGS>(&bits)
    }
}
