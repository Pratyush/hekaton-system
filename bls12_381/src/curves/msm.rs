use ark_std::{vec, vec::Vec};
use ark_ec::VariableBaseMSM;
use ark_ff::{PrimeField, BigInteger};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub(crate) fn msm_bigint_wnaf<V: VariableBaseMSM>(
    bases: &[V::MulBase],
    bigints: &[<V::ScalarField as PrimeField>::BigInt],
) -> V {

    let size = ark_std::cmp::min(bases.len(), bigints.len());
    let scalars = &bigints[..size];
    let bases = &bases[..size];
    #[cfg(feature = "parallel")]
    {
        use ark_std::cfg_chunks;
        let num_threads = rayon::current_num_threads();
        if num_threads > 1 {
            cfg_chunks!(bases, size / num_threads)
                .zip(cfg_chunks!(scalars, size / num_threads))
                .map(|(bases, scalars)| msm_bigint_wnaf_helper::<V>(bases, scalars))
                .sum()
        } else {
            msm_bigint_wnaf_helper(bases, scalars)
        }
    }
    #[cfg(not(feature = "parallel"))]
    msm_bigint_wnaf_helper(bases, scalars)
}

// Compute msm using windowed non-adjacent form
pub(crate) fn msm_bigint_wnaf_helper<V: VariableBaseMSM>(
    bases: &[V::MulBase],
    bigints: &[<V::ScalarField as PrimeField>::BigInt],
) -> V {
    /// The result of this function is only approximately `ln(a)`
    /// [`Explanation of usage`]
    ///
    /// [`Explanation of usage`]: https://github.com/scipr-lab/zexe/issues/79#issue-556220473
    fn ln_without_floats(a: usize) -> usize {
        // log2(a) * ln(2)
        (ark_std::log2(a) * 69 / 100) as usize
    }
    let size = ark_std::cmp::min(bases.len(), bigints.len());
    let scalars = &bigints[..size];
    let bases = &bases[..size];

    let c = if size < 32 {
        3
    } else {
        ln_without_floats(size) + 2
    };

    let num_bits = V::ScalarField::MODULUS_BIT_SIZE as usize;
    let digits_count = (num_bits + c - 1) / c;
    
    let scalar_digits = scalars
        .iter()
        .flat_map(|s| make_digits(s, c, num_bits))
        .collect::<Vec<_>>();
    let zero = V::zero();
    let window_sums: Vec<_> = ark_std::cfg_into_iter!(0..digits_count)
        .map(|i| {
            let mut buckets = vec![zero; 1 << c];
            for (digits, base) in scalar_digits.chunks(digits_count).zip(bases) {
                use ark_std::cmp::Ordering;
                // digits is the digits thing of the first scalar?
                let scalar = digits[i];
                match 0.cmp(&scalar) {
                    Ordering::Less => buckets[(scalar - 1) as usize] += base,
                    Ordering::Greater => buckets[(-scalar - 1) as usize] -= base,
                    Ordering::Equal => (),
                }
            }

            let mut running_sum = V::zero();
            let mut res = V::zero();
            buckets.into_iter().rev().for_each(|b| {
                running_sum += &b;
                res += &running_sum;
            });
            res
        })
        .collect();

    // We store the sum for the lowest window.
    let lowest = *window_sums.first().unwrap();

    // We're traversing windows from high to low.
    lowest
        + &window_sums[1..]
            .iter()
            .rev()
            .fold(zero, |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
}

// From: https://github.com/arkworks-rs/gemini/blob/main/src/kzg/msm/variable_base.rs#L20
fn make_digits(a: &impl BigInteger, w: usize, num_bits: usize) -> impl Iterator<Item = i64> + '_ {
    let scalar = a.as_ref();
    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let num_bits = if num_bits == 0 {
        a.num_bits() as usize
    } else {
        num_bits
    };
    let digits_count = (num_bits + w - 1) / w;

    (0..digits_count).into_iter().map(move |i| {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        // Read the bits from the scalar
        let bit_buf = if bit_idx < 64 - w || u64_idx == scalar.len() - 1 {
            // This window's bits are contained in a single u64,
            // or it's the last u64 anyway.
            scalar[u64_idx] >> bit_idx
        } else {
            // Combine the current u64's bits with the bits from the next u64
            (scalar[u64_idx] >> bit_idx) | (scalar[1 + u64_idx] << (64 - bit_idx))
        };

        // Read the actual coefficient value from the window
        let coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + radix / 2) >> w;
        let mut digit = (coef as i64) - (carry << w) as i64;

        if i == digits_count - 1 {
            digit += (carry << w) as i64;
        }
        digit
    })
}
