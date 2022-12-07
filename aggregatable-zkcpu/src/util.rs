use ark_ff::PrimeField;
use ark_r1cs_std::{
    bits::{uint8::UInt8, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
};
use ark_relations::r1cs::SynthesisError;

pub(crate) fn uint8_to_fpvar<F: PrimeField>(byte: &UInt8<F>) -> Result<FpVar<F>, SynthesisError> {
    Boolean::le_bits_to_fp_var(&byte.to_bits_le()?)
}

/// Returns `out` such that `out[i] == vals[i]` for all `i != idx_to_change`, and
/// `out[idx_to_change] = new_val`.
pub(crate) fn arr_set<T, F>(
    vals: &[T],
    idx_to_change: &FpVar<F>,
    new_val: &T,
) -> Result<Vec<T>, SynthesisError>
where
    T: Clone + CondSelectGadget<F>,
    F: PrimeField,
{
    let mut out = vals.to_vec();

    for i in 0..vals.len() {
        // Check if this i is the target one
        let change_this_idx = FpVar::constant(F::from(i as u64)).is_eq(idx_to_change)?;
        // Conditionally select either the old value or `new_val`
        let old_val = &vals[i as usize];
        let out_val = T::conditionally_select(&change_this_idx, new_val, old_val)?;
        // Save the result
        out[i] = out_val
    }

    Ok(out)
}

/// A log2 function for small `usize` values
pub(crate) fn log2(x: usize) -> usize {
    (x as f32).log2().ceil() as usize
}
