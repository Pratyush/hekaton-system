use super::*;

/// This is a transcript entry with just 1 associated memory operation, and a padding flag. This is
/// easier to directly use than a [`TranscriptEntry`]
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct MemTranscriptEntry<T: TinyRamExt> {
    /// Tells whether or not this entry is padding
    pub is_padding: bool,
    /// The timestamp of this entry. This MUST be greater than 0
    pub timestamp: Timestamp,
    /// The memory operation that occurred at this timestamp
    pub mem_op: MemOp<T::Word>,
}

impl<T: TinyRamExt> MemTranscriptEntry<T> {
    pub fn padding_with_timestamp(timestamp: Timestamp) -> Self {
        Self {
            is_padding: true,
            timestamp,
            mem_op: MemOp::default(),
        }
    }

    /// Encodes this transcript entry in the low bits of a field element for the purpose of
    /// representation as a coefficient in a polynomial. Does not include timestamp, i.e., sets
    /// `timestamp` to 0. `is_init` says whether this entry is part of the initial memory or not.
    pub(crate) fn as_fp_notime(&self, is_init: bool) -> T::F {
        fn pow_two<G: PrimeField>(n: usize) -> G {
            G::from(2u8).pow([n as u64])
        }

        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp
        // The shape doesn't really matter as long as it's consistent.

        let mut shift = 0;
        let mut acc = T::F::zero();

        // Encode `timestamp` as 64 bits. It's all 0s here
        acc += T::F::zero() * pow_two::<T::F>(shift);
        shift += 64;

        // Encode `is_padding` as a bit
        acc += T::F::from(self.is_padding as u64) * pow_two::<T::F>(shift);
        shift += 1;

        // Encode `is_init` as a bit
        acc += T::F::from(is_init) * pow_two::<T::F>(shift);
        shift += 1;

        // Encode the memory op kind `op` as 2 bits
        acc += T::F::from(self.mem_op.kind() as u8) * pow_two::<T::F>(shift);
        shift += 2;

        // Encode `location` as a u64
        acc += T::F::from(self.mem_op.location()) * pow_two::<T::F>(shift);
        shift += 64;

        // val is a double word, so pack each of its words separately
        let val = self.mem_op.val();
        acc += T::F::from(val.1.into()) * pow_two::<T::F>(shift);
        shift += T::Word::BIT_LENGTH;
        acc += T::F::from(val.0.into()) * pow_two::<T::F>(shift);
        shift += T::Word::BIT_LENGTH;

        // Make sure we didn't over-pack the field element
        assert!(shift < T::F::MODULUS_BIT_SIZE as usize);

        acc
    }

    /// Encodes this transcript entry in the low bits of a field element for the purpose of
    /// representation as a coefficient in a polynomial. `is_init` says whether this entry is part
    /// of the initial memory or not.
    pub(crate) fn as_fp(&self, is_init: bool) -> T::F {
        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp

        // Get the as_fp with timestamp 0
        let mut acc = self.as_fp_notime(is_init);

        // Add `timestamp` to the low bits
        acc += T::F::from(self.timestamp);

        acc
    }

    /// Converts the given execution transcript entry into two processed entries, one for
    /// instruction load operation, and one for any potential load/store instruction 
    /// executed at this step. If the current instruction was not a load/store, then the second
    /// entry is padding.
    pub(crate) fn extract_mem_ops(t: &ExecutionTranscriptEntry<T>) -> (MemTranscriptEntry<T>, MemTranscriptEntry<T>) {
        // Get the instruction load. We stretch the timestamps to make every timestamp unique
        let first = MemTranscriptEntry {
            is_padding: false,
            timestamp: 2 * t.timestamp + TIMESTAMP_OFFSET,
            mem_op: t.instr_load.clone(),
        };
        // The second entry is either the real memory operation, or it's a padding op that's just a
        // copy of the first instruction load. The reason it'd be a copy is because it's consistent
        // with the rest of the transcript.
        let second = match &t.mem_op {
            Some(op) => MemTranscriptEntry {
                is_padding: false,
                timestamp: first.timestamp + 1,
                mem_op: op.clone(),
            },
            None => Self::padding_with_timestamp(first.timestamp + 1),
        };

        [first, second]
    }

    /// Returns a random `ProcessedTranscriptEntry`. Useful for testing
    pub(crate) fn rand(mut rng: impl Rng) -> Self {
        let is_padding = rng.gen();
        let timestamp = rng.gen();
        let mem_op = MemOp::rand(&mut rng);

        MemTranscriptEntry {
            is_padding,
            timestamp,
            mem_op,
        }
    }
}

impl<T: TinyRamExt> AllocVar<MemTranscriptEntry<T>, T::F> for MemTranscriptEntryVar<T> {
    fn new_variable<S: Borrow<MemTranscriptEntry<T>>>(
        cs: impl Into<Namespace<T::F>>,
        f: impl FnOnce() -> Result<S, SynthesisError>,
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
            || entry.map(|e| T::F::from(e.mem_op.kind() as u8)),
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
        let val =
            DoubleWordVar::new_variable(ns!(cs, "val"), || entry.map(|e| e.mem_op.val()), mode)?;
        let val_fp = val.as_fpvar()?;

        Ok(MemTranscriptEntryVar {
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
pub struct MemTranscriptEntryVar<T: TinyRamExt> {
    /// Tells whether or not this entry is padding
    pub(crate) is_padding: Boolean<T::F>,
    /// The timestamp of this entry. This is at most 64 bits
    // TODO: Make sure this is 64 bits on construction
    pub(super) timestamp: TimestampVar<T::F>,
    /// The type of memory op this is. This is determined by the discriminant of [`MemOpKind`]
    pub(crate) op: MemOpKindVar<T::F>,
    /// The RAM index being loaded from or stored to.
    pub(crate) location: UInt64<T::F>,
    /// `location` as a field element
    pub(crate) location_fp: FpVar<T::F>,
    /// The value being loaded or stored
    pub(super) val: DoubleWordVar<T::WordVar, T::F>,
    /// `val` as a field element
    pub(super) val_fp: FpVar<T::F>,
}

impl<T: TinyRamExt> R1CSVar<T::F> for MemTranscriptEntryVar<T> {
    type Value = MemTranscriptEntry<T>;

    fn cs(&self) -> ConstraintSystemRef<T::F> {
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
            limbs[0] as u8 as MemOpKind
        };
        let val = self.val.value()?;
        let loc = self.location.value()?;

        // Make the mem op from the flattened values. The `from_u64` calls below will not panic
        // because if the op_disc doesn't match the location type, this is a malformed value.
        let mem_op = match op_disc {
            MemOpKind::Load => MemOp::Load {
                val,
                location: T::Word::from_u64(loc),
            },
            MemOpKind::Store => MemOp::Store {
                val,
                location: T::Word::from_u64(loc),
            },
        };
        
        Ok(MemTranscriptEntry {
            is_padding,
            timestamp,
            mem_op,
        })
    }
}

impl<T: TinyRamExt> Default for MemTranscriptEntryVar<T> {
    fn default() -> Self {
        MemTranscriptEntryVar {
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

impl<T: TinyRamExt> MemTranscriptEntryVar<T> {
    /// Returns whether this memory operation is a `load`
    pub(crate) fn is_load(&self) -> Result<Boolean<T::F>, SynthesisError> {
        self.op.is_eq(&MemOpKindVar::Constant((MemOpKind::Load as u8).into()))
    }

    /// Returns whether this memory operation is a `store`
    pub(crate) fn is_store(&self) -> Result<Boolean<T::F>, SynthesisError> {
        self.op.is_eq(&MemOpKindVar::Constant((MemOpKind::Store as u8).into()))
    }
}

impl<T: TinyRamExt> MemTranscriptEntryVar<T> {
    pub(crate) fn pow_two(n: usize) -> FpVar<T::F> {
        FpVar::Constant(T::F::from(2u8).pow([n as u64]))
    }

    /// Encodes this transcript entry as a field element, not including `timestamp` (i.e., setting
    /// `timestamp` to 0). `is_init` says whether this entry is part of the initial memory or not.
    pub(crate) fn as_fp_without_timestamp(
        &self,
        is_init: bool,
    ) -> Result<FpVar<T::F>, SynthesisError> {
        // The field element is of the form
        // 00...0 || memop_val || memop_location || memop_kind || is_init || is_padding || timestamp
        // We set timestamp to 0
        let mut acc = FpVar::<T::F>::zero();
        let mut shift = 0;

        // Encode `timestamp` as 64 bits. It's all 0s here
        acc += FpVar::zero() * Self::pow_two(shift);
        shift += 64;

        // Encode `is_padding` as a bit
        acc += FpVar::from(self.is_padding.clone()) * Self::pow_two(shift);
        shift += 1;

        // Encode `is_init` as a bit
        acc += FpVar::Constant(T::F::from(is_init)) * Self::pow_two(shift);
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
    pub(crate) fn as_fp(&self, is_init: bool) -> Result<FpVar<T::F>, SynthesisError> {
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
    pub(crate) fn select_word(
        &self,
        idx: &T::WordVar,
    ) -> Result<(T::WordVar, Boolean<T::F>), SynthesisError> {
        // Check if this is padding
        let mut err = self.is_padding.clone();

        // Do the index check. Mask out the bottom bits of idx. We just need to make sure that this
        // load is the correct double word, i.e., all but the bottom bitmask bits of idx and self.location
        // match.
        let bytes_per_word = T::Word::BIT_LENGTH / 8;
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
        let out = word_selector.select(&self.val.w1, &self.val.w0)?;

        Ok((out, err))
    }

    /// Returns the lower word of this double word
    pub(crate) fn val_low_word(&self) -> T::Word {
        self.val.w0.clone()
    }
}
