use super::*;

/// This is a transcript entry with just 1 associated memory operation, and a padding flag. This is
/// easier to directly use than a [`TranscriptEntry`]
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProcessedTranscriptEntry<W: Word> {
    /// Tells whether or not this entry is padding
    pub is_padding: bool,
    /// The timestamp of this entry. This MUST be greater than 0
    pub timestamp: Timestamp,
    /// The memory operation that occurred at this timestamp
    pub mem_op: MemOp<W>,
}

impl<W: Word> ProcessedTranscriptEntry<W> {
    /// Encodes this transcript entry in the low bits of a field element for the purpose of
    /// representation as a coefficient in a polynomial. Does not include timestamp, i.e., sets
    /// `timestamp` to 0. `is_init` says whether this entry is part of the initial memory or not.
    pub(crate) fn as_fp_notime<F: PrimeField>(&self, is_init: bool) -> F {
        fn pow_two<G: PrimeField>(n: usize) -> G {
            G::from(2u8).pow([n as u64])
        }

        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp
        // The shape doesn't really matter as long as it's consistent.

        let mut shift = 0;
        let mut acc = F::zero();

        // Encode `timestamp` as 64 bits. It's all 0s here
        acc += F::zero() * pow_two::<F>(shift);
        shift += 64;

        // Encode `is_padding` as a bit
        acc += F::from(self.is_padding as u64) * pow_two::<F>(shift);
        shift += 1;

        // Encode `is_init` as a bit
        acc += F::from(is_init) * pow_two::<F>(shift);
        shift += 1;

        // Encode the memory op kind `op` as 2 bits
        acc += F::from(self.mem_op.kind() as u8) * pow_two::<F>(shift);
        shift += 2;

        // Encode `location` as a u64
        acc += F::from(self.mem_op.location()) * pow_two::<F>(shift);
        shift += 64;

        // val is a double word, so pack each of its words separately
        let val = self.mem_op.val();
        acc += F::from(val.1.into()) * pow_two::<F>(shift);
        shift += W::BIT_LENGTH;
        acc += F::from(val.0.into()) * pow_two::<F>(shift);
        shift += W::BIT_LENGTH;

        // Make sure we didn't over-pack the field element
        assert!(shift < F::MODULUS_BIT_SIZE as usize);

        acc
    }

    /// Encodes this transcript entry in the low bits of a field element for the purpose of
    /// representation as a coefficient in a polynomial. `is_init` says whether this entry is part
    /// of the initial memory or not.
    pub(crate) fn as_fp<F: PrimeField>(&self, is_init: bool) -> F {
        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp

        // Get the as_fp with timestamp 0
        let mut acc = self.as_fp_notime(is_init);

        // Add `timestamp` to the low bits
        acc += F::from(self.timestamp);

        acc
    }

    /// Converts the given transcript entry into two processed entries. If there is no mem op, then
    /// a padding entry is created.
    pub(crate) fn new_pair<const NUM_REGS: usize>(
        t: &TranscriptEntry<NUM_REGS, W>,
    ) -> [ProcessedTranscriptEntry<W>; 2] {
        // Get the instruction load. We stretch the timestamps to make every timestamp unique
        let first = ProcessedTranscriptEntry {
            is_padding: false,
            timestamp: 2 * t.timestamp + TIMESTAMP_OFFSET,
            mem_op: t.instr_load.clone(),
        };
        // The second entry is either the real memory operation, or it's a padding op that's just a
        // copy of the first instruction load. The reason it'd be a copy is because it's consistent
        // with the rest of the transcript.
        let second = match &t.mem_op {
            Some(op) => ProcessedTranscriptEntry {
                is_padding: false,
                timestamp: first.timestamp + 1,
                mem_op: op.clone(),
            },
            None => {
                let mut pad = first.clone();
                pad.is_padding = true;
                pad.timestamp = first.timestamp + 1;
                pad
            },
        };

        [first, second]
    }

    /// Returns a random `ProcessedTranscriptEntry`. Useful for testing
    pub(crate) fn rand(mut rng: impl Rng) -> Self {
        let is_padding = rng.gen();
        let timestamp = rng.gen();
        let mem_op = MemOp::rand(&mut rng);

        ProcessedTranscriptEntry {
            is_padding,
            timestamp,
            mem_op,
        }
    }

    /// Returns whether this memory operation is a `read`
    pub fn is_tape_op(&self) -> bool {
        match self.mem_op.kind() {
            MemOpKind::ReadPrimary | MemOpKind::ReadAux => true,
            _ => false,
        }
    }

    /// Returns whether this memory operation is a `load` or `store`
    pub(crate) fn is_ram_op(&self) -> bool {
        !self.is_tape_op()
    }
}

impl<W, WV, F> AllocVar<ProcessedTranscriptEntry<W>, F> for ProcessedTranscriptEntryVar<WV, F>
where
    W: Word,
    WV: WordVar<F, Native = W>,
    F: PrimeField,
{
    fn new_variable<T: Borrow<ProcessedTranscriptEntry<WV::Native>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let entry = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        // Witness the instruction load
        let timestamp_var = TimestampVar::new_variable(
            ns!(cs, "instr timestamp"),
            || entry.map(|e| e.timestamp),
            mode,
        )?;
        // Witness the padding flag
        let is_padding_var =
            Boolean::new_variable(ns!(cs, "padding?"), || entry.map(|e| e.is_padding), mode)?;
        // Witness the op var
        let op = MemOpKindVar::new_variable(
            ns!(cs, "opkind"),
            || entry.map(|e| F::from(e.mem_op.kind() as u8)),
            mode,
        )?;
        // Witness the mem op RAM idx (or 0 if it's a tape op)
        let location = UInt64::new_variable(
            ns!(cs, "ram idx"),
            || entry.map(|e| e.mem_op.location()),
            mode,
        )?;
        let location_fp = location.as_fpvar()?;
        // Witness the mem op loaded/stored double word
        let val = DoubleWordVar::new_variable(ns!(cs, "val"), || entry.map(|e| e.mem_op.val()), mode)?;
        let val_fp = val.as_fpvar()?;

        Ok(ProcessedTranscriptEntryVar {
            is_padding: is_padding_var,
            timestamp: timestamp_var,
            op,
            location,
            location_fp,
            val,
            val_fp,
        })
    }
}



/// The ZK version of `ProcessedTranscriptEntry`. It's also flattened so all the fields are right
/// here.
#[derive(Clone)]
pub struct ProcessedTranscriptEntryVar<WV: WordVar<F>, F: PrimeField> {
    /// Tells whether or not this entry is padding
    pub(crate) is_padding: Boolean<F>,
    /// The timestamp of this entry. This is at most 64 bits
    // TODO: Make sure this is 64 bits on construction
    pub(super) timestamp: TimestampVar<F>,
    /// The type of memory op this is. This is determined by the discriminant of [`MemOpKind`]
    pub(crate) op: MemOpKindVar<F>,
    /// The RAM index being loaded from or stored to, or the location of the tape head
    pub(crate) location: UInt64<F>,
    /// `location` as a field element
    pub(crate) location_fp: FpVar<F>,
    /// The value being loaded or stored
    pub(super) val: DoubleWordVar<WV, F>,
    /// `val` as a field element
    pub(super) val_fp: FpVar<F>,
}

impl<W, WV, F> R1CSVar<F> for ProcessedTranscriptEntryVar<WV, F>
where
    W: Word,
    WV: WordVar<F, Native = W>,
    F: PrimeField,
{
    type Value = ProcessedTranscriptEntry<W>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.timestamp
            .cs()
            .or(self.op.cs())
            .or(self.location.cs())
            .or(self.val.w0.cs())
            .or(self.val.w1.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let is_padding = self.is_padding.value()?;
        let timestamp = self.timestamp.value()?;
        // Get the discriminant of the memory op
        let op_disc = {
            let repr = self.op.value()?.into_bigint();

            // Make sure the op kind is at most one u64
            let limbs: &[u64] = repr.as_ref();
            // The number of limbs can exceed 1, but everything after the first must be 0
            assert!(limbs.iter().skip(1).all(|&x| x == 0));

            // Make sure the op kind is just 2 bits
            let disc = limbs[0];
            assert!(disc < 4);
            limbs[0] as u8
        };
        let val = self.val.value()?;
        let loc = self.location.value()?;

        // Make the mem op from the flattened values. The unwraps below are fine because if the
        // op_disc doesn't match the location type, this is a malformed value.
        let mem_op = if op_disc == MemOpKind::Load as u8 {
            MemOp::Load {
                val,
                location: W::from_u64(loc).unwrap(),
            }
        } else if op_disc == MemOpKind::Store as u8 {
            MemOp::Store {
                val,
                location: W::from_u64(loc).unwrap(),
            }
        } else if op_disc == MemOpKind::ReadPrimary as u8 {
            // The single-word value of a Read is located in the first word of val. And the
            // location is guaranteed to be a u32
            MemOp::ReadPrimary {
                val: val.0,
                location: loc as u32,
            }
        } else if op_disc == MemOpKind::ReadAux as u8 {
            // Same as above
            MemOp::ReadAux {
                val: val.0,
                location: loc as u32,
            }
        } else if op_disc == MemOpKind::ReadInvalid as u8 {
            MemOp::ReadInvalid
        } else {
            panic!("unexpected memop kind {op_disc}")
        };

        Ok(ProcessedTranscriptEntry {
            is_padding,
            timestamp,
            mem_op,
        })
    }
}

impl<WV: WordVar<F>, F: PrimeField> Default for ProcessedTranscriptEntryVar<WV, F> {
    fn default() -> Self {
        ProcessedTranscriptEntryVar {
            is_padding: Boolean::TRUE,
            timestamp: TimestampVar::zero(),
            op: MemOpKindVar::zero(),
            location: UInt64::zero(),
            location_fp: FpVar::zero(),
            val: DoubleWordVar::zero(),
            val_fp: FpVar::zero(),
        }
    }
}

impl<WV: WordVar<F>, F: PrimeField> ProcessedTranscriptEntryVar<WV, F> {
    /// Returns whether this memory operation is a `load`
    pub(crate) fn is_load(&self) -> Result<Boolean<F>, SynthesisError> {
        self.op
            .is_eq(&MemOpKindVar::Constant(F::from(MemOpKind::Load as u8)))
    }

    /// Returns whether this memory operation is a `store`
    pub(crate) fn is_store(&self) -> Result<Boolean<F>, SynthesisError> {
        self.op
            .is_eq(&MemOpKindVar::Constant(F::from(MemOpKind::Store as u8)))
    }

    /// Returns whether this memory operation is a `read`
    pub(crate) fn is_tape_op(&self) -> Result<Boolean<F>, SynthesisError> {
        let is_primary = self
            .op
            .is_eq(&FpVar::Constant(F::from(MemOpKind::ReadPrimary as u8)))?;
        let is_aux = self
            .op
            .is_eq(&FpVar::Constant(F::from(MemOpKind::ReadAux as u8)))?;
        Ok(is_primary | is_aux)
    }

    /// Returns whether this memory operation is a `load` or `store`
    pub(crate) fn is_ram_op(&self) -> Result<Boolean<F>, SynthesisError> {
        Ok(!self.is_tape_op()?)
    }
}

impl<WV: WordVar<F>, F: PrimeField> ProcessedTranscriptEntryVar<WV, F> {
    pub(crate) fn pow_two<G: PrimeField>(n: usize) -> FpVar<G> {
        FpVar::Constant(G::from(2u8).pow([n as u64]))
    }

    /// Encodes this transcript entry as a field element, not including `timestamp` (i.e., setting
    /// `timestamp` to 0). `is_init` says whether this entry is part of the initial memory or not.
    pub(crate) fn as_fp_without_timestamp(&self, is_init: bool) -> Result<FpVar<F>, SynthesisError> {
        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp
        // We set timestamp to 0
        let mut acc = FpVar::<F>::zero();
        let mut shift = 0;

        // Encode `timestamp` as 64 bits. It's all 0s here
        acc += FpVar::zero() * Self::pow_two(shift);
        shift += 64;

        // Encode `is_padding` as a bit
        acc += FpVar::from(self.is_padding.clone()) * Self::pow_two(shift);
        shift += 1;

        // Encode `is_init` as a bit
        acc += FpVar::Constant(F::from(is_init)) * Self::pow_two(shift);
        shift += 1;

        // Encode the memory op kind `op` as 2 bits
        acc += FpVar::from(self.op.clone()) * Self::pow_two(shift);
        shift += 2;

        // Encode `location` as a u64
        acc += &self.location_fp * Self::pow_two(shift);
        shift += 64;

        // Encode `val` as a double word
        acc += &self.val_fp * Self::pow_two(shift);
        // shift += 2 * W::NativeWord::BITLEN;

        Ok(acc)
    }

    /// Encodes this transcript entry as a field element.`is_init` says whether this entry is part
    /// of the initial memory or not.
    pub(crate) fn as_fp(&self, is_init: bool) -> Result<FpVar<F>, SynthesisError> {
        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp
        let mut field_repr = self.as_fp_without_timestamp(is_init)?;

        // Add timestamp in the low 64 bits
        field_repr += &self.timestamp.as_fpvar()?;

        Ok(field_repr)
    }

    // Extracts the word at the given RAM index, returning it and an error flag. `err = true` iff
    // `self.idx` and the high (non-byte-precision) bits of `idx` are not equal, or
    // `self.is_padding == true`.
    pub(crate) fn select_word(&self, idx: &WV) -> Result<(WV, Boolean<F>), SynthesisError> {
        // Check if this is padding
        let mut err = self.is_padding.clone();

        // Do the index check. Mask out the bottom bits of idx. We just need to make sure that this
        // load is the correct double word, i.e., all but the bottom bitmask bits of idx and self.location
        // match.
        let bytes_per_word = WV::BITLEN / 8;
        let word_bitmask_len = log2(bytes_per_word) as usize;
        let double_word_bitmask_len = word_bitmask_len + 1;

        let idx_bits = idx.as_le_bits();
        let word_aligned_idx_bits = &idx_bits[word_bitmask_len..];
        let double_word_aligned_idx_bits = &idx_bits[double_word_bitmask_len..];

        // Check that the double word-aligned indices match
        for (b1, b2) in double_word_aligned_idx_bits.iter().zip(
            self.location
                .as_le_bits()
                .into_iter()
                .skip(double_word_bitmask_len),
        ) {
            err |= b1.is_neq(&b2)?;
        }

        // Now get the word-aligned index and use the lowest word bit to select the word
        let word_selector = &word_aligned_idx_bits[0];
        let out = WV::conditionally_select(word_selector, &self.val.w1, &self.val.w0)?;

        Ok((out, err))
    }

    /// Returns the lower word of this double word
    pub(crate) fn val_low_word(&self) -> WV {
        self.val.w0.clone()
    }
}
