use core::fmt::Debug;
use std::ops::{BitAnd, BitOr, BitXor, Div, Not, Rem};

pub trait Word:
    Debug
    + Eq
    + Ord
    + Copy
    + Div<Output = Self>
    + Rem<Output = Self>
    + Not<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + BitAnd<Output = Self>
{
    const BIT_SIZE: u32;

    /// Computes the sum of `self` and `other`, and returns the carry bit (if any).
    fn carrying_add(self, other: Self) -> (Self, bool);

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
    ($word: ty, $double_word: ty, $bit_size: expr) => {
        impl Word for $word {
            const BIT_SIZE: u32 = $bit_size;

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
                let result = ((self as $double_word) as i128) * ((other as $double_word) as i128);
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
                let result = self << (other as u32);
                (result, (result >> ($bit_size - 1)) == 1)
            }

            fn shr(self, other: Self) -> (Self, bool) {
                let result = self >> (other as u32);
                (result, (result & 1) == 1)
            }
        }
    };
}

impl_word!(u8, u16, 8);
impl_word!(u16, u32, 16);
impl_word!(u32, u64, 32);
impl_word!(u64, u128, 64);
