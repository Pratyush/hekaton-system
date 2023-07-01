use super::*;
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

impl<W, WV, F> R1CSVar<F> for CpuAnswerVar<WV, F>
where
    W: Word,
    WV: WordVar<F, Native = W>,
    F: PrimeField,
{
    type Value = Option<W>;

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let is_set = self.is_set.value()?;
        let val = self.val.value()?;
        if is_set {
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.is_set.cs().or(self.val.cs())
    }
}

impl<WV, F> EqGadget<F> for CpuAnswerVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        let is_set_eq = self.is_set.is_eq(&other.is_set)?;
        let val_eq = self.val.is_eq(&other.val)?;
        Ok(is_set_eq & val_eq)
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

impl<WV: WordVar<F>, F: PrimeField> AllocVar<Option<WV::Native>, F> for CpuAnswerVar<WV, F> {
    fn new_variable<T: Borrow<Option<WV::Native>>>(
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
                        || Ok(opt_word.unwrap_or(WV::Native::default())),
                        mode,
                    )
                    .and_then(|val| Ok(CpuAnswerVar { is_set, val }))
                },
            )
        })
    }
}

impl<'a, WV, F> ToBitsGadget<F> for &'a CpuAnswerVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        Ok([vec![self.is_set.clone()], self.val.as_le_bits()].concat())
    }
}

impl<WV, F> ToBitsGadget<F> for CpuAnswerVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        <&Self>::to_bits_le(&self)
    }
}

impl<WV, F> CpuAnswerVar<WV, F>
where
    WV: WordVar<F>,
    F: PrimeField,
{
    /// Create a `CpuAnswerVar` from a bitstring. Panics if `bits.len() != WV::BITLEN + 1`.
    pub(crate) fn from_bits_le(bits: &[Boolean<F>]) -> Self {
        assert_eq!(bits.len(), WV::BITLEN + 1);
        let is_set = bits[0].clone();
        let val = WV::from_le_bits(&bits[1..WV::BITLEN + 1]);

        CpuAnswerVar { is_set, val }
    }
}