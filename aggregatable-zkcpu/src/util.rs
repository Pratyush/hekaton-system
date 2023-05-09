use ark_ff::PrimeField;
use ark_r1cs_std::{
    bits::{uint32::UInt32, uint64::UInt64, uint8::UInt8, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
};
use ark_relations::r1cs::SynthesisError;

pub(crate) fn uint8_to_fpvar<F: PrimeField>(v: &UInt8<F>) -> Result<FpVar<F>, SynthesisError> {
    Boolean::le_bits_to_fp_var(&v.to_bits_le()?)
}

pub(crate) fn uint32_to_fpvar<F: PrimeField>(v: &UInt32<F>) -> Result<FpVar<F>, SynthesisError> {
    Boolean::le_bits_to_fp_var(&v.to_bits_le())
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

/// Returns true iff a < b
// This function is adapted from subtle's ct_gt function
// https://github.com/dalek-cryptography/subtle/blob/6b6a81ad9a6a00c0b42c327eaf4b2f785774377e/src/lib.rs#L875
#[rustfmt::skip]
macro_rules! gen_uint_cmp {
    ($t:ident, $fn_name:ident, $bitwidth:expr) => {
        pub(crate) fn $fn_name<F: PrimeField>(
            a: &$t<F>,
            b: &$t<F>,
        ) -> Result<Boolean<F>, SynthesisError> {
            let a_bits = a.to_bits_le();
            let b_bits = b.to_bits_le();

            // All the bits in a that are greater than their corresponding bits in b.
            let gtb = a_bits
                .iter()
                .zip(b_bits.iter())
                .map(|(x, y)| x.and(&y.not()))
                .collect::<Result<Vec<_>, _>>()?;
            // All the bits in a that are less than their corresponding bits in b.
            let mut ltb = a_bits
                .iter()
                .zip(b_bits.iter())
                .map(|(x, y)| x.not().and(y))
                .collect::<Result<Vec<_>, _>>()?;

            // Bit-smear the highest set bit to the right

            // Previous methods of doing this smear
            /*
            for i in (0..32).rev() {
                for j in i + 1..32 {
                    ltb[i] = ltb[i].or(&ltb[j])?;
                }
            }
            */

            /*
            let mut pow = 1;
            while pow < $bitwidth {
                let shifted = ltb[pow..$bitwidth].to_vec();
                for i in 0..shifted.len() {
                    ltb[i] = ltb[i].or(&shifted[i])?;
                }

                pow *= 2;
            }
            */

            /*
            for i in 0..$bitwidth {
                ltb[i] = Boolean::kary_or(&ltb[i..])?;
            }
            */

            for i in (0..$bitwidth).rev().skip(1) {
                ltb[i] = ltb[i].or(&ltb[i+1])?;
            }


            // Select the highest set bit
            let mut bit = gtb
                .iter()
                .zip(ltb.iter())
                .map(|(x, y)| x.and(&y.not()))
                .collect::<Result<Vec<_>, _>>()?;

            // Shift to the right until we end up with either 0 or 1.
            for i in (0..$bitwidth).rev().skip(1) {
                bit[i] = bit[i].or(&bit[i+1])?;
            }

            let out = Boolean::kary_or(&bit)?;

            Ok(out)
        }
    };
}

gen_uint_cmp!(UInt32, uint32_gt, 32);
gen_uint_cmp!(UInt64, uint64_gt, 64);

pub(crate) fn uint32_le<F: PrimeField>(
    a: &UInt32<F>,
    b: &UInt32<F>,
) -> Result<Boolean<F>, SynthesisError> {
    Ok(uint32_gt(a, b)?.not())
}

pub(crate) fn uint32_lt<F: PrimeField>(
    a: &UInt32<F>,
    b: &UInt32<F>,
) -> Result<Boolean<F>, SynthesisError> {
    let le = uint32_le(a, b)?;
    let eq = a.is_eq(b)?;
    le.and(&eq.not())
}

pub(crate) fn uint64_le<F: PrimeField>(
    a: &UInt64<F>,
    b: &UInt64<F>,
) -> Result<Boolean<F>, SynthesisError> {
    Ok(uint64_gt(a, b)?.not())
}

pub(crate) fn uint64_lt<F: PrimeField>(
    a: &UInt64<F>,
    b: &UInt64<F>,
) -> Result<Boolean<F>, SynthesisError> {
    let le = uint64_le(a, b)?;
    let eq = a.is_eq(b)?;
    le.and(&eq.not())
}

#[cfg(test)]
mod test {
    use super::*;

    use ark_bls12_381::Fr;
    use ark_r1cs_std::{uint32::UInt32, R1CSVar};
    use ark_std::test_rng;
    use rand::Rng;

    type F = Fr;

    // Test that the ZK greater-than function works correctly
    #[test]
    fn test_uint64_gt() {
        let mut rng = test_rng();

        // Test 500 random pairs
        for _ in 0..500 {
            let x: u64 = rng.gen();
            let y: u64 = rng.gen();

            let x_var = UInt64::<F>::constant(x);
            let y_var = UInt64::constant(y);

            let is_gt = uint64_gt(&x_var, &y_var).unwrap().value().unwrap();
            if x > y {
                assert!(is_gt);
            } else {
                assert!(!is_gt);
            }
        }
    }
}
/*
impl ConstantTimeGreater for $t_u {
    /// Returns Choice::from(1) iff x > y, and Choice::from(0) iff x <= y.
    ///
    /// # Note
    ///
    /// This algoritm would also work for signed integers if we first
    /// flip the top bit, e.g. `let x: u8 = x ^ 0x80`, etc.
    #[inline]
    fn ct_gt(&self, other: &$t_u) -> Choice {
        let gtb = self & !other; // All the bits in self that are greater than their corresponding bits in other.
        let mut ltb = !self & other; // All the bits in self that are less than their corresponding bits in other.
        let mut pow = 1;

        // Less-than operator is okay here because it's dependent on the bit-width.
        while pow < $bit_width {
            ltb |= ltb >> pow; // Bit-smear the highest set bit to the right.
            pow += pow;
        }
        let mut bit = gtb & !ltb; // Select the highest set bit.
        let mut pow = 1;

        while pow < $bit_width {
            bit |= bit >> pow; // Shift it to the right until we end up with either 0 or 1.
            pow += pow;
        }
        // XXX We should possibly do the above flattening to 0 or 1 in the
        //     Choice constructor rather than making it a debug error?
        Choice::from((bit & 1) as u8)
    }
*/
