use crate::word::WordVar;

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    bits::{uint16::UInt16, uint32::UInt32, uint64::UInt64, uint8::UInt8, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, LinearCombination, Namespace, SynthesisError, Variable},
};

pub(crate) fn uint8_to_fpvar<F: PrimeField>(v: &UInt8<F>) -> Result<FpVar<F>, SynthesisError> {
    Boolean::le_bits_to_fp(&v.to_bits_le())
}

pub(crate) fn uint32_to_fpvar<F: PrimeField>(v: &UInt32<F>) -> Result<FpVar<F>, SynthesisError> {
    Boolean::le_bits_to_fp(&v.to_bits_le())
}

pub(crate) fn uint32_to_uint64<F: PrimeField>(v: &UInt32<F>) -> UInt64<F> {
    let all_bits = [v.to_bits_le(), vec![Boolean::FALSE; 32]].concat();
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

fn uint8_to_bits_le<F: PrimeField>(a: &UInt8<F>) -> Vec<Boolean<F>> {
    a.to_bits_le()
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

/*

pub(crate) fn uint16_lt<F: PrimeField>(
    a: &UInt16<F>,
    b: &UInt16<F>,
) -> Result<Boolean<F>, SynthesisError> {
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    // Take the difference of the values. We need to ensure that this is in [0, 2¹⁶)
    let cs = a.cs().or(b.cs());
    let diff = b.as_fpvar()? - a.as_fpvar()?;
    // Unwrap into an AllocatedFp
    let diff = match a.as_fpvar()? - b.as_fpvar()? {
        FpVar::Var(f) => f,
        FpVar::Constant(f) => {
            let is_within_uint_limit = f
                .into_bigint()
                .to_bits_le()
                .into_iter()
                .skip(16)
                .any(|b| b == false);
            return Ok(Boolean::constant(is_within_uint_limit));
        },
    };

    let low_bit_vals: Vec<Option<bool>> = match diff.value() {
        Ok(d) => ark_ff::BitIteratorLE::new(d.into_bigint())
            .take(16)
            .map(|b| Some(b))
            .collect(),
        Err(_) => vec![None; 16],
    };

    let low_bit_vars = low_bit_vals
        .into_iter()
        .map(|b| Boolean::new_witness(cs.clone(), || b.ok_or(SynthesisError::AssignmentMissing)))
        .collect::<Result<Vec<Boolean<F>>, _>>()?;

    let mut lc = LinearCombination::zero();
    let mut coeff = F::one();

    for bit in low_bit_vars.iter() {
        lc = &lc + bit.lc() * coeff;
        coeff.double_in_place();
    }
    lc = lc - diff.variable;
    cs.enforce_constraint(lc!(), lc!(), lc)?;

    // TODO: Make a boolean representing whether lc is satisfied

    Ok(())
}

/// Returns true iff a < b
// This function is adapted from subtle's ct_gt function
// https://github.com/dalek-cryptography/subtle/blob/6b6a81ad9a6a00c0b42c327eaf4b2f785774377e/src/lib.rs#L875
#[rustfmt::skip]
macro_rules! gen_uint_cmp {
    ($t:ident, $fn_name:ident, $bitwidth:expr, $tobits_le_fn:path) => {
        pub(crate) fn $fn_name<F: PrimeField>(
            a: &$t<F>,
            b: &$t<F>,
        ) -> Result<Boolean<F>, SynthesisError> {
            let a_bits = $tobits_le_fn(a);
            let b_bits = $tobits_le_fn(b);

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

gen_uint_cmp!(UInt8, uint8_gt, 8, uint8_to_bits_le);
gen_uint_cmp!(UInt32, uint32_gt, 32, UInt32::to_bits_le);
gen_uint_cmp!(UInt64, uint64_gt, 64, UInt64::to_bits_le);

pub(crate) fn uint8_ge<F: PrimeField>(
    a: &UInt8<F>,
    b: &UInt8<F>,
) -> Result<Boolean<F>, SynthesisError> {
    let gt = uint8_gt(a, b)?;
    let eq = a.is_eq(b)?;
    gt.or(&eq)
}

pub(crate) fn uint8_le<F: PrimeField>(
    a: &UInt8<F>,
    b: &UInt8<F>,
) -> Result<Boolean<F>, SynthesisError> {
    Ok(uint8_gt(a, b)?.not())
}

pub(crate) fn uint8_lt<F: PrimeField>(
    a: &UInt8<F>,
    b: &UInt8<F>,
) -> Result<Boolean<F>, SynthesisError> {
    let le = uint8_le(a, b)?;
    let eq = a.is_eq(b)?;
    le.and(&eq.not())
}

pub(crate) fn uint32_ge<F: PrimeField>(
    a: &UInt32<F>,
    b: &UInt32<F>,
) -> Result<Boolean<F>, SynthesisError> {
    let gt = uint32_gt(a, b)?;
    let eq = a.is_eq(b)?;
    gt.or(&eq)
}

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

pub(crate) fn uint64_ge<F: PrimeField>(
    a: &UInt64<F>,
    b: &UInt64<F>,
) -> Result<Boolean<F>, SynthesisError> {
    let gt = uint64_gt(a, b)?;
    let eq = a.is_eq(b)?;
    gt.or(&eq)
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
*/

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
