use core::{
    fmt::{Debug, Display},
    ops::{BitAnd, BitOr, BitXor, Div, Not, Rem},
};

use ark_ff::Field;

pub type DWord<W> = (W, W);

pub trait Word:
    Debug
    + Display
    + Default
    + Eq
    + Ord
    + Copy
    + Div<Output = Self>
    + Rem<Output = Self>
    + Not<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + BitAnd<Output = Self>
    + TryFrom<u64>
    + Into<u64>
{
    type Signed: Eq + Ord + Copy;

    const BITLEN: usize;
    const BYTELEN: usize = Self::BITLEN / 8;

    /// The number of bytes an instruction takes up. It's 2 words.
    const INSTR_BYTELEN: usize = 2 * Self::BITLEN / 8;
    const MAX: Self;

    /// Convert from `u64`. Fails if the value exceeds `W::MAX`
    fn from_u64(val: u64) -> Result<Self, ()> {
        Self::try_from(val).map_err(|_| ())
    }

    /// Convert from big-endian bytes. Fails if `bytes.len() != Self::BYTELEN`
    fn from_be_bytes(bytes: &[u8]) -> Result<Self, ()>;

    /// Convert `self` to a `BIT_SIZE`-bit signed integer.
    fn to_signed(self) -> Self::Signed;

    /// Convert `self` to a field element
    fn to_ff<F: Field>(self) -> F {
        // Convert W -> u64 -> F
        self.into().into()
    }

    /// Returns `Some(self + 1)` if `self != Self::MAX`.
    /// Returns `None` otherwise.
    fn checked_increment(self) -> Option<Self>;

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
    ($word: ty, $double_word: ty, $signed: ty, $double_signed: ty, $bit_size: expr) => {
        impl Word for $word {
            type Signed = $signed;

            const BITLEN: usize = $bit_size;
            const MAX: Self = <$word>::MAX;

            fn from_be_bytes(bytes: &[u8]) -> Result<Self, ()> {
                if bytes.len() != Self::BYTELEN {
                    return Err(());
                }
                let mut buf = [0u8; Self::BYTELEN];
                buf.copy_from_slice(bytes);
                Ok(<$word>::from_be_bytes(buf))
            }

            fn to_signed(self) -> Self::Signed {
                self as Self::Signed
            }

            fn checked_increment(self) -> Option<Self> {
                self.checked_add(1)
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

impl_word!(u8, u16, i8, i16, 8);
impl_word!(u16, u32, i16, i32, 16);
impl_word!(u32, u64, i32, i64, 32);
impl_word!(u64, u128, i64, i128, 64);
