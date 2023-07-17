use crate::tape::TapeHeadsVar;

use super::*;

/// The output of a `run_instr()` invocation. This has the resulting CPU state, and a flag for if
/// an error occured
#[derive(Clone)]
pub(crate) struct InstrResult<T: TinyRamExt> {
    pub(crate) pc: PcVar<T::WordVar>,
    pub(crate) flag: Boolean<T::F>,
    pub(crate) reg_to_write: RegIdxVar<T::F>,
    pub(crate) reg_val: T::WordVar,
    pub(crate) answer: CpuAnswerVar<T>,
    pub(crate) tape_heads: TapeHeadsVar<T::WordVar>,
    pub(super) err: Boolean<T::F>,
}

impl<'a, T: TinyRamExt> ToBitsGadget<T::F> for &'a InstrResult<T> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<T::F>>, SynthesisError> {
        Ok([
            self.pc.as_le_bits(),
            vec![self.flag.clone()],
            self.reg_to_write.to_bits_le().unwrap(),
            self.reg_val.as_le_bits(),
            self.answer.to_bits_le().unwrap(),
            self.tape_heads.as_le_bits(),
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
            answer: CpuAnswerVar::default(),
            tape_heads: TapeHeadsVar::default(),
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
    /// Converts the given bitstring to a `CpuStateVar`. Requires that `bits.len() == Self::bit_length`
    pub(super) fn from_bits_le(mut bits: &[Boolean<T::F>]) -> Self {
        assert_eq!(bits.len(), Self::bit_length());

        let pc_len = T::WordVar::BIT_LENGTH;
        let answer_len = T::WordVar::BIT_LENGTH + 1;
        let tape_head_len = <TapeHeadsVar<_>>::BIT_LENGTH;

        let pc = PcVar::from_le_bits(&bits[..pc_len]);
        bits = &bits[pc_len..];

        let flag = bits[0].clone();
        bits = &bits[1..];

        let reg_to_write = RegIdxVar::from_le_bits(&bits[..RegIdxVar::<T::F>::BIT_LENGTH]);
        bits = &bits[RegIdxVar::<T::F>::BIT_LENGTH..];

        let reg_val = T::WordVar::from_le_bits(&bits[..T::WordVar::BIT_LENGTH]);
        bits = &bits[T::WordVar::BIT_LENGTH..];

        let answer = CpuAnswerVar::from_bits_le(&bits[..answer_len]);
        bits = &bits[answer_len..];

        let tape_heads = TapeHeadsVar::from_le_bits(&bits[..tape_head_len]);
        bits = &bits[tape_head_len..];

        let err = bits[0].clone();

        InstrResult {
            pc,
            flag,
            reg_to_write,
            reg_val,
            answer,
            tape_heads,
            err,
        }
    }

    // TODO: Make this generic for anything with `FromBitsGadget`. This is copied verbatim from
    // CpuStateVar
    /// Undoes `pack_to_fps`, i.e., deserializes from its packed representation as field
    /// elements.
    pub(super) fn unpack_from_fps(fps: &[FpVar<T::F>]) -> Self {
        let bits_per_fp = T::F::MODULUS_BIT_SIZE as usize - 1;

        // Check that not too many field elements were given
        assert!(
            fps.len() * bits_per_fp < Self::bit_length() + bits_per_fp,
            "expected fewer field elements"
        );

        let cs = fps[0].cs();

        // Serialize the field elems
        let mut bits: Vec<Boolean<T::F>> = fps
            .iter()
            .flat_map(|f| {
                // We only packed BITLEN-1 bits. If there's a leading zero, cut it off.
                let pre_tobits = cs.num_constraints();

                // We don't need to use FpVar::to_bits_le. We don't set the top bit in our packing.
                // So it suffices to just ensure that the top bit isn't set in the non-unique
                // decoding
                let mut bits = f.to_non_unique_bits_le().unwrap();
                bits[T::F::MODULUS_BIT_SIZE as usize - 1]
                    .enforce_equal(&Boolean::FALSE)
                    .unwrap();

                bits.truncate(T::F::MODULUS_BIT_SIZE as usize - 1);
                println!(
                    "Num constraints to run FpVar::to_bits_le(): {}",
                    cs.num_constraints() - pre_tobits
                );
                bits
            })
            .collect();
        // Truncate to the appropriate size
        bits.truncate(Self::bit_length());

        // Deserialize
        Self::from_bits_le(&bits)
    }
}
