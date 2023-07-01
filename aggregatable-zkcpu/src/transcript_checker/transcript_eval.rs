use super::*;

/// Running evals used inside `transcript_checker`
#[derive(Clone, Default)]
pub struct TranscriptCheckerEvals<F: PrimeField> {
    // The time-sorted trace of our execution
    pub time_tr_exec: F,

    // The mem-sorted trace of our execution
    pub mem_tr_exec: F,

    // The unsorted trace of the initial memory that's read in our execution
    pub tr_init_accessed: F,
}

/// ZK version of TranscriptCheckerEvals
#[derive(Clone, Default)]
pub struct TranscriptCheckerEvalsVar<F: PrimeField> {
    // The time-sorted trace of our execution
    pub time_tr_exec: RunningEvalVar<F>,

    // The mem-sorted trace of our execution
    pub mem_tr_exec: RunningEvalVar<F>,

    // The unsorted trace of the initial memory that's read in our execution
    pub tr_init_accessed: RunningEvalVar<F>,
}

impl<F: PrimeField> EqGadget<F> for TranscriptCheckerEvalsVar<F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        Ok(self.time_tr_exec.is_eq(&other.time_tr_exec)?
            & self.mem_tr_exec.is_eq(&other.mem_tr_exec)?
            & self.tr_init_accessed.is_eq(&other.tr_init_accessed)?)
    }
}

impl<F: PrimeField> AllocVar<TranscriptCheckerEvals<F>, F> for TranscriptCheckerEvalsVar<F> {
    fn new_variable<T: Borrow<TranscriptCheckerEvals<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        let evals = res.as_ref().map(|e| e.borrow()).map_err(|err| *err);

        // Allocate all the fields
        let time_tr_exec = FpVar::new_variable(
            ns!(cs, "time tr exec"),
            || evals.map(|e| F::from(e.time_tr_exec)),
            mode,
        )
        .map(RunningEvalVar)?;
        let mem_tr_exec = FpVar::new_variable(
            ns!(cs, "mem tr exec"),
            || evals.map(|e| F::from(e.mem_tr_exec)),
            mode,
        )
        .map(RunningEvalVar)?;
        let tr_init_accessed = FpVar::new_variable(
            ns!(cs, "tr init accessed"),
            || evals.map(|e| F::from(e.tr_init_accessed)),
            mode,
        )
        .map(RunningEvalVar)?;

        Ok(TranscriptCheckerEvalsVar {
            time_tr_exec,
            mem_tr_exec,
            tr_init_accessed,
        })
    }
}
