use core::{
    fmt::{Debug, Display},
    ops::{BitAnd, BitOr, BitXor, Div, Not, Rem, Sub},
};
use std::ops::{Add, AddAssign};

use ark_ff::PrimeField;
use rand::Rng;

/// A double word. The first element is the low word, the second is the high word.
pub type DoubleWord<W> = (W, W);

pub trait Word:
    'static
    + Debug
    + Display
    + Default
    + Eq
    + Ord
    + Copy
    + Sub<Output = Self>
    + Div<Output = Self>
    + Rem<Output = Self>
    + Not<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + BitAnd<Output = Self>
    + Add<Output = Self>
    + Sub<Output = Self>
    + AddAssign<Self>
    + TryFrom<u64>
    + Into<u64>
    + TryInto<usize>
{
    type Signed: Eq + Ord + Copy;

    const BIT_LENGTH: usize;
    const BYTE_LENGTH: usize = Self::BIT_LENGTH / 8;

    /// The number of bytes an instruction takes up. It's 2 words.
    const INSTR_BYTE_LENGTH: usize = 2 * Self::BIT_LENGTH / 8;
    const MAX: Self;
    const ZERO: Self;
    const ONE: Self;

    /// Convert from `u64`. Fails if the value exceeds `W::MAX`
    fn try_from_u64(val: u64) -> Option<Self> {
        Self::try_from(val).ok()
    }

    /// Convert from `u64`. Panics if the value exceeds `W::MAX`
    fn from_u64(val: u64) -> Self {
        Self::try_from_u64(val).unwrap()
    }

    /// Clears out the bottom bits of the word so that it can be used an index to double word-aligned
    /// memory, i.e., the memory format we use for transcripts
    fn align_to_double_word(&self) -> Self;

    /// Convert from big-endian bytes. Fails if `bytes.len() != Self::BYTE_LENGTH`.
    fn from_be_bytes(bytes: &[u8]) -> Option<Self>;

    /// Convert from little-endian bytes. Fails if `bytes.len() != Self::BYTE_LENGTH`.
    fn from_le_bytes(bytes: &[u8]) -> Option<Self>;

    /// Convert to little-endian bytes.
    fn to_le_bytes(&self) -> Vec<u8>;

    /// Convert `self` to a `BIT_SIZE`-bit signed integer.
    fn to_signed(self) -> Self::Signed;

    /// Convert `self` to a field element
    fn to_fp<F: PrimeField>(self) -> F {
        // Convert W -> u64 -> F
        self.into().into()
    }

    /// Returns a uniform word
    fn rand(rng: impl Rng) -> Self;

    /// Returns `Some(self + 1)` if `self != Self::MAX`.
    /// Returns `None` otherwise.
    fn checked_increment(self) -> Option<Self>;

    /// Computes the sum of `self` and `other`, and returns the carry bit (if any).
    fn carrying_add(self, other: Self) -> (Self, bool);

    /// Computes the sum of `self` and `other`, and returning `Some(result)` if the result
    /// was in bounds, and `None` otherwise.
    fn checked_add(self, other: Self) -> Option<Self> {
        let (res, carry) = self.carrying_add(other);
        (!carry).then(|| res)
    }

    /// Computes the sum of `self` and `other`, wrapping around the `MAX` value on overflow.
    fn wrapping_add(self, other: Self) -> Self;

    /// Computes the sum of `self` and `1`, wrapping around the `MAX` value on overflow.
    fn wrapping_increment(self) -> Self;

    /// Computes `self - other`, and returns the carry bit (if any).
    fn borrowing_sub(self, other: Self) -> (Self, bool);

    /// Computes the `BIT_SIZE` least-significant bits of `self * other`,
    /// and returns 1 if the full product does not fit in `BIT_SIZE` bits.
    fn mul_low(self, other: Self) -> (Self, bool);

    /// Computes the `BIT_SIZE` most-significant bits of `self * other`,
    /// and returns 1 if the product does not fit in `BIT_SIZE` bits.
    fn mul_high(self, other: Self) -> (Self, bool);

    /// Computes the `BIT_SIZE` most-significant bits of `self * other`,
    /// when `self` and `other` are viewed as `BIT_SIZE`-bit signed integers.
    /// and returns 1 if the product does not fit in `BIT_SIZE` bits.
    fn signed_mul_high(self, other: Self) -> (Self, bool);

    /// Computes `self / other`, where `/` represents unsigned integer division.
    /// If `other` is 0, returns `(0, true)`.
    /// Else, this method returns `(self / other, false)`.
    fn checked_div(self, other: Self) -> (Self, bool);

    /// Computes `self % other`.
    /// If `other` is 0, returns `(0, true)`.
    /// Else, this method returns `(self % other, false)`.
    fn checked_rem(self, other: Self) -> (Self, bool);

    /// Computes `self << other`, and additionally returns the MSB of the result.
    fn shl(self, other: Self) -> (Self, bool);

    /// Computes `self >> other`, and additionally returns the LSB of the result.
    fn shr(self, other: Self) -> (Self, bool);
}

macro_rules! impl_word {
    ($word: ty, $double_word: ty, $signed: ty, $double_signed: ty, $bit_size: expr) => {
        impl Word for $word {
            type Signed = $signed;

            const BIT_LENGTH: usize = $bit_size;
            const MAX: Self = <$word>::MAX;
            const ZERO: Self = <$word>::MIN;
            const ONE: Self = 1;

            fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
                (bytes.len() == Self::BYTE_LENGTH).then(|| {
                    let mut buf = [0u8; Self::BYTE_LENGTH];
                    buf.copy_from_slice(bytes);
                    <$word>::from_be_bytes(buf)
                })
            }

            fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
                (bytes.len() == Self::BYTE_LENGTH).then(|| {
                    let mut buf = [0u8; Self::BYTE_LENGTH];
                    buf.copy_from_slice(bytes);
                    <$word>::from_le_bytes(buf)
                })
            }

            // TODO: don't allocate for this
            fn to_le_bytes(&self) -> Vec<u8> {
                <$word>::to_le_bytes(*self).to_vec()
            }

            fn align_to_double_word(&self) -> Self {
                // Clear the low log2(Self::BYTE_LENGTH)+1 bits of this word
                let bitmask_len = log2(Self::BYTE_LENGTH) + 1;
                let bitmask = !((1 << bitmask_len) - 1);
                self & bitmask
            }

            fn to_signed(self) -> Self::Signed {
                self as Self::Signed
            }

            fn rand(mut rng: impl Rng) -> Self {
                rng.gen()
            }

            fn checked_increment(self) -> Option<Self> {
                self.checked_add(1)
            }

            fn wrapping_add(self, other: Self) -> Self {
                self.wrapping_add(other)
            }

            fn wrapping_increment(self) -> Self {
                self.wrapping_add(1)
            }

            fn carrying_add(self, other: Self) -> (Self, bool) {
                let result = self as $double_word + other as $double_word;
                (result as Self, (result >> $bit_size) != 0)
            }

            fn borrowing_sub(self, other: Self) -> (Self, bool) {
                let result = (1 << $bit_size) + (self as $double_word) - (other as $double_word);
                (result as Self, result >> $bit_size == 0)
            }

            fn mul_low(self, other: Self) -> (Self, bool) {
                let result = (self as $double_word) * (other as $double_word);
                (result as Self, (result >> $bit_size) != 0)
            }

            fn mul_high(self, other: Self) -> (Self, bool) {
                let result = (self as $double_word) * (other as $double_word);
                ((result >> $bit_size) as Self, (result >> $bit_size) != 0)
            }

            fn signed_mul_high(self, other: Self) -> (Self, bool) {
                let result: $double_signed = (self as $double_signed) * (other as $double_signed);
                ((result >> $bit_size) as Self, (result >> $bit_size) != 0)
            }

            fn checked_div(self, other: Self) -> (Self, bool) {
                if other == 0 {
                    (0, true)
                } else {
                    (self / other, false)
                }
            }

            fn checked_rem(self, other: Self) -> (Self, bool) {
                if other == 0 {
                    (0, true)
                } else {
                    (self % other, false)
                }
            }

            fn shl(self, other: Self) -> (Self, bool) {
                let result = self.checked_shl(other as u32).unwrap_or(0);
                (result, (result >> ($bit_size - 1)) == 1)
            }

            fn shr(self, other: Self) -> (Self, bool) {
                let result = self.checked_shr(other as u32).unwrap_or(0);
                (result, (result & 1) == 1)
            }
        }
    };
}

impl_word!(u8, u16, i8, i16, 8);
impl_word!(u16, u32, i16, i32, 16);
impl_word!(u32, u64, i32, i64, 32);
impl_word!(u64, u128, i64, i128, 64);

/// A log2 function for small `usize` values
pub(crate) fn log2(x: usize) -> usize {
    (x as f64).log2().ceil() as usize
}
