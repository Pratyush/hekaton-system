use ark_ff::{PrimeField};
use ark_r1cs_std::{
    uint32::UInt32, uint64::UInt64, convert::ToBitsGadget,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
};
use ark_relations::{r1cs::SynthesisError};

pub(crate) fn uint32_to_uint64<F: PrimeField>(v: &UInt32<F>) -> UInt64<F> {
    let all_bits = [v.to_bits_le().unwrap(), vec![Boolean::FALSE; 32]].concat();
    UInt64::from_bits_le(&all_bits)
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

/// Packs all the bits of the given value into as few `FpVars` as possible
pub(crate) fn pack_to_fps<F, T>(val: T) -> Vec<FpVar<F>>
where
    F: PrimeField,
    T: ToBitsGadget<F>,
{
    let bits = val.to_bits_le().unwrap();

    // Split into chunks of maximal size and make them field elements. The unwrap() is ok
    // because the only error condition is when #bits = MODULUS_BIT_SIZE
    bits.chunks(F::MODULUS_BIT_SIZE as usize - 1)
        .map(|chunk| Boolean::le_bits_to_fp(chunk).unwrap())
        .collect()
}

pub(crate) fn transpose<T: Clone>(matrix: Vec<Vec<T>>) -> Vec<Vec<T>> {
    let num_cols = matrix.first().unwrap().len();
    matrix
        .iter()
        .for_each(|row| assert_eq!(row.len(), num_cols));

    let mut row_iters: Vec<_> = matrix.into_iter().map(Vec::into_iter).collect();
    let mut out: Vec<Vec<_>> = (0..num_cols).map(|_| Vec::new()).collect();

    for out_row in out.iter_mut() {
        for it in row_iters.iter_mut() {
            out_row.push(it.next().unwrap());
        }
    }

    out
}