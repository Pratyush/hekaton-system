use super::*;

/// An `ExecTickMemData` can be a LOAD (=0) or a STORE (=1), or no-mem (=2)
#[derive(Clone)]
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
#[derive(Clone)]
pub(crate) struct ExecTickMemData<WV: WordVar<F>, F: PrimeField> {
    /// The kind of data this is. A LOAD, a STORE, or a no-op
    pub(crate) kind: ExecTickMemDataKind<F>,
    /// The RAM index loaded from or stored into. This is not checked when kind == no-op
    pub(crate) idx: RamIdxVar<WV>,
    /// The value stored into RAM. This is not checked when kind == no-op or LOAD
    pub(crate) stored_word: WV,
}

impl<WV: WordVar<F>, F: PrimeField> Default for ExecTickMemData<WV, F> {
    fn default() -> Self {
        ExecTickMemData {
            kind: ExecTickMemDataKind(ExecTickMemDataKind::no_mem()),
            idx: RamIdxVar::<WV>::zero(),
            stored_word: WV::zero(),
        }
    }
}

impl<WV: WordVar<F>, F: PrimeField> CondSelectGadget<F> for ExecTickMemData<WV, F> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let kind = ExecTickMemDataKind(cond.select(&true_value.kind.0, &false_value.kind.0)?);
        let idx = cond.select(&true_value.idx, &false_value.idx)?;
        let stored_word = cond.select(&true_value.stored_word, &false_value.stored_word)?;

        Ok(ExecTickMemData {
            kind,
            idx,
            stored_word,
        })
    }
}
