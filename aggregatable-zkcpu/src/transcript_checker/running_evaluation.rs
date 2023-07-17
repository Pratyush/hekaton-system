use super::*;

// Represents the running polynomial evaluation of a transcript. E.g.,
// `time_tr_exec(X) = (X - op1)(X - op2) ...)` evaluated at some challenge point. This also
// is used for unordered evals, such as `tr_init_accessed`.
#[derive(Clone)]
pub struct RunningEvalVar<F: PrimeField>(pub FpVar<F>);

impl<F: PrimeField> Default for RunningEvalVar<F> {
    fn default() -> Self {
        RunningEvalVar(FpVar::one())
    }
}

impl<F: PrimeField> RunningEvalVar<F> {
    /// Updates the running eval with the given memory operation and challenge point if `bit ==
    /// true`. This is a no-op if `bit == false`. If the memory operation is a tape op or is
    /// padding, then it is encoded as a 0.
    pub(super) fn conditionally_update_with_ram_op<T: TinyRamExt<F = F>>(
        &mut self,
        bit: &Boolean<F>,
        mem_op: &MemTranscriptEntryVar<T>,
        chal: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // The field repr of mem_op is 0 iff it's a tape op or padding
        let field_repr = {
            let ff = mem_op.as_fp(false)?;
            let cond = mem_op.is_tape_op()? | &mem_op.is_padding;
            FpVar::conditionally_select(&cond, &FpVar::zero(), &ff)?
        };

        // Recall the polynoimal has factors (X - op). So to do an incremental computation, we
        // calculate `eval *= (chal - op)`. If `bit` == false, then the RHS is just 1.
        let rhs = FpVar::conditionally_select(bit, &(chal - field_repr), &FpVar::one())?;
        self.0 *= rhs;

        Ok(())
    }

    /// Updates the running eval with the given entry and challenge point
    pub(super) fn update_with_ram_op<T: TinyRamExt<F = F>>(
        &mut self,
        mem_op: &MemTranscriptEntryVar<T>,
        chal: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_update_with_ram_op(&Boolean::TRUE, mem_op, chal)
    }

    /// Updates the running eval with the given memory operation (excluding timestamp) and
    /// challenge point if `bit == true`. This is a no-op if `bit == false`. If the memory
    /// operation is a tape op or is padding, then it is encoded as a 0.
    pub(super) fn conditionally_update_with_ram_op_notime<T: TinyRamExt<F = F>>(
        &mut self,
        bit: &Boolean<F>,
        mem_op: &MemTranscriptEntryVar<T>,
        chal: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // The field repr of mem_op is 0 iff it's a tape op or padding
        let field_repr = {
            let ff = mem_op.as_fp_without_timestamp(false)?;
            let cond = mem_op.is_tape_op()? | &mem_op.is_padding;
            FpVar::conditionally_select(&cond, &FpVar::zero(), &ff)?
        };

        // Recall the polynoimal has factors (X - op). So to do an incremental computation, we
        // calculate `eval *= (chal - op)`. If `bit` == false, then the RHS is just 1.
        let rhs = FpVar::conditionally_select(bit, &(chal - field_repr), &FpVar::one())?;
        self.0 *= rhs;

        Ok(())
    }
}

impl<F: PrimeField> EqGadget<F> for RunningEvalVar<F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        self.0.is_eq(&other.0)
    }
}

impl<F: PrimeField> AllocVar<F, F> for RunningEvalVar<F> {
    fn new_variable<T: Borrow<F>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        FpVar::new_variable(cs, f, mode).map(RunningEvalVar)
    }
}
